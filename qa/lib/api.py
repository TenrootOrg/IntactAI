"""Authenticated client for the Intact backend API.

Talks to the same endpoints the dashboard does, over the same nginx TLS, with
the same session cookie. That is the point: a QA that reached into the database
or ran VQL directly would prove the components work while proving nothing about
the product an operator actually uses.

TLS verification is off. The appliance ships a self-signed certificate — that
is the shipped design, not a QA shortcut — so verify=True would fail against a
correctly installed box. Nothing here is on an untrusted network: the harness
runs on the appliance and talks to its own address.
"""

import json
import time

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class APIError(RuntimeError):
    def __init__(self, method, path, status, body):
        self.status, self.body = status, body
        super().__init__(f"{method} {path} -> {status}: {str(body)[:400]}")


class Client:
    def __init__(self, host, tl=None, timeout=60, scheme="https"):
        self.base = f"{scheme}://{host}".rstrip("/")
        self.tl = tl
        self.timeout = timeout
        self.s = requests.Session()
        self.s.verify = False

    # --- plumbing --------------------------------------------------------

    def request(self, method, path, expect=(200, 201, 202), **kw):
        url = self.base + path
        kw.setdefault("timeout", self.timeout)
        r = self.s.request(method, url, **kw)

        try:
            body = r.json()
        except ValueError:
            body = r.text

        if self.tl:
            self.tl.event("api", status="ok" if r.status_code in expect else "fail",
                          detail={"method": method, "path": path,
                                  "status": r.status_code})

        if expect and r.status_code not in expect:
            raise APIError(method, path, r.status_code, body)
        return body

    def get(self, path, **kw):
        return self.request("GET", path, **kw)

    def post(self, path, payload=None, **kw):
        return self.request("POST", path, json=payload or {}, **kw)

    def raw(self, path, expect=(200,), **kw):
        """Response BYTES. `request` decodes to JSON or text, which mangles a
        PDF — and a PDF that arrives as a str is indistinguishable from an
        error page once it has been through .text."""
        kw.setdefault("timeout", self.timeout)
        r = self.s.get(self.base + path, **kw)
        if self.tl:
            self.tl.event("api", status="ok" if r.status_code in expect else "fail",
                          detail={"method": "GET", "path": path,
                                  "status": r.status_code, "bytes": len(r.content)})
        if expect and r.status_code not in expect:
            raise APIError("GET", path, r.status_code, r.text[:200])
        return r.content

    def status_of(self, path):
        """Status code only — for probing that an endpoint is guarded."""
        try:
            return self.s.get(self.base + path, timeout=self.timeout,
                              allow_redirects=False).status_code
        except requests.RequestException:
            return None

    # --- auth ------------------------------------------------------------

    def auth_status(self):
        """The full auth picture: mode, whether this session is authenticated,
        and whether the account is locked out."""
        body = self.get("/api/auth/status", expect=(200,))
        return body if isinstance(body, dict) else {}

    def auth_mode(self):
        """'setup' | 'login'. The appliance ships in setup mode with
        first_login: true."""
        return self.auth_status().get("mode")

    def is_authenticated(self):
        """Whether THIS session is logged in.

        Uses /api/auth/status rather than /api/auth/verify. The latter looks
        like the obvious choice and is not: nginx declares it `internal` so it
        can serve as the auth_request target for /velociraptor/ and
        /api/uploads/, which means an external GET returns 404 whether or not
        you hold a valid session. Probing it would report every authenticated
        run as unauthenticated.
        """
        st = self.auth_status()
        return bool(st.get("authenticated")) or st.get("session_state") == "ok"

    def setup(self, username, password):
        return self.post("/api/auth/setup",
                         {"username": username, "password": password,
                          "confirm": password})

    def login(self, username, password):
        return self.post("/api/auth/login",
                         {"username": username, "password": password})

    def ensure_session(self, username, password):
        """Claim the appliance if it is unclaimed, otherwise log in.

        Handles the re-run case: the second QA run against the same box finds
        setup already closed, and must log in rather than fail.
        """
        mode = self.auth_mode()
        if mode == "setup":
            self.setup(username, password)
            return "setup"
        self.login(username, password)
        return "login"

    # --- polling ---------------------------------------------------------

    def run_status(self, run_id):
        """A workflow run's current state, or None if it is not visible yet.

        Not raising on 404 is deliberate: a run that has just been created can
        briefly 404, and treating that as fatal would make every launch a race.
        """
        try:
            body = self.get(f"/api/dashboard/automation/{run_id}",
                            expect=(200, 404))
        except APIError:
            return None
        if not isinstance(body, dict) or body.get("error"):
            return None
        # The dashboard transform renames run_id -> id (dashboard_routes.py
        # _transform_run). Normalise it back so callers have one spelling.
        body.setdefault("run_id", body.get("id"))
        return body

    def run_logs(self, run_id):
        try:
            body = self.get(f"/api/dashboard/automation/{run_id}/logs",
                            expect=(200, 404))
        except APIError:
            return []
        if isinstance(body, dict):
            return body.get("logs") or []
        return body or []

    def wait_for_run(self, run_id, timeout_s, tl, what=None,
                     terminal=("completed", "success", "failed", "error",
                               "cancelled", "stopped"),
                     poll_s=15):
        """Wait for a workflow run to reach a terminal state.

        Returns the final run dict, or None on timeout. Progress is echoed
        through the timeline so a 45-minute ingest is visibly progressing
        rather than silent.
        """
        what = what or f"run {run_id}"
        seen = {"progress": None, "phase": None}

        def probe():
            run = self.run_status(run_id)
            if not run:
                return None
            state = (run.get("status") or "").lower()
            prog = run.get("progress")
            phase = (run.get("details") or {}).get("phase")
            if (prog, phase) != (seen["progress"], seen["phase"]):
                seen.update(progress=prog, phase=phase)
                tl.event("run_progress", ids={"run_id": run_id},
                         detail={"status": state, "progress": prog,
                                 "phase": phase})
            return run if state in terminal else None

        run, _ = tl.wait(what, timeout_s=timeout_s, poll_s=poll_s, probe=probe,
                         describe=lambda r: (r.get("status") or "?"))
        return run


def run_succeeded(run):
    """Whether a terminal workflow run actually succeeded.

    The backend uses several success words across automation types, and the
    absence of a failure word is not the same as success — a run stuck at
    'running' when the wait timed out must not read as a pass.
    """
    if not isinstance(run, dict):
        return False
    return (run.get("status") or "").lower() in ("completed", "success", "succeeded")
