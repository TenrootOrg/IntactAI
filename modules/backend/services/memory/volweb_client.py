"""Thin client over VolWeb's REST API.

Wraps the four flows the memory pipeline needs:

  1. **Cases + chunked upload** — find/create case, initiate upload,
     stream chunks, complete (port of ``volweb-poc/upload.py``).
  2. **Selective plugin extraction** — POST the curated plugin list
     against an evidence; one call (multiple calls would wipe prior
     rows, a real trap we hit during the PoC).
  3. **Yarascan** — separate Celery queue; pre-stage ``media/<id>/``
     to dodge the race observed in the PoC where the worker tried to
     write ``yara_rules_<ts>.yara`` to a not-yet-existing directory
     and the task succeeded silently with zero hits.
  4. **Result reads** — paginated plugin/yarascan artefact pull for
     the LLM analyzers.

JWT tokens have a 5-minute lifetime; the client refreshes on demand
and once when a 401 surfaces mid-call. Auth credentials come from
``frontend_config.memory.volweb`` (set at install time) or fall back
to the documented ``admin / password`` defaults the standalone
VolWeb image ships with.

This module deliberately knows nothing about IntactAI's workflow
service — the orchestrator in :mod:`services.memory.pipeline` owns
``add_log_to_run`` / ``update_run_status`` / ``is_cancelled`` calls.
That keeps this client unit-testable against a bare VolWeb instance.
"""

from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path
from typing import Any, Callable, Iterable

import requests


# ---------------------------------------------------------------------------
# Config — defaults match the in-tree VolWeb stack the install will deploy.
# The standalone PoC at 127.0.0.1:8002 is also supported via env vars.
# ---------------------------------------------------------------------------

VOLWEB_BASE_DEFAULT = "http://intact_volweb_backend:8000"
VOLWEB_BASE_POC = "http://127.0.0.1:8002"

_YARASCAN_PLUGIN_NAME = "volatility3.plugins.yarascan.latest"


def _config_value(*keys: str, default: str = "") -> str:
    """Pull a string config value from the IntactAI runtime config DB.

    Looks up ``frontend_config['memory']['volweb'][key]`` first
    (set via the Maintenance / Settings page when present), falling
    back to the env var named ``VOLWEB_<KEY>`` and finally the
    documented default.

    The frontend_config lookup is wrapped in try/except: this module
    is imported by the workflow service early in app boot, before the
    storage layer is necessarily ready.
    """
    env_name = "VOLWEB_" + "_".join(k.upper() for k in keys)
    env = os.environ.get(env_name)
    if env:
        return env

    try:
        from services.storage.config_store import load_frontend_config  # local import — avoid boot ordering
        cfg = load_frontend_config() or {}
        node: Any = cfg
        for k in ("memory", "volweb", *keys):
            if not isinstance(node, dict):
                node = None
                break
            node = node.get(k)
        if isinstance(node, str) and node:
            return node
    except Exception:
        pass

    return default


def _volweb_base() -> str:
    return _config_value("base_url", default=VOLWEB_BASE_DEFAULT).rstrip("/")


def _config_yaml_volweb(key: str) -> str:
    """Read `modules.volweb.<key>` from the platform `config.yaml`.

    Why we go here instead of hardcoding ``admin:password``:
    `install.sh:seed_volweb_admin` creates the admin user with the
    creds in ``config.yaml:modules.volweb.{id,password}`` (default
    ``tenroot:123123``). The backend has to authenticate against
    the SAME creds — otherwise every fresh install would need an
    extra Settings → Memory → VolWeb step before the pipeline
    works. By reading config.yaml here, fresh installs Just Work.
    """
    try:
        from config import load_main_config
        cfg = load_main_config() or {}
        node = (cfg.get("modules") or {}).get("volweb") or {}
        val = node.get(key)
        if isinstance(val, str):
            return val
    except Exception:
        pass
    return ""


def _volweb_user() -> str:
    return _config_value("username", default=_config_yaml_volweb("id") or "tenroot")


def _volweb_pass() -> str:
    return _config_value("password", default=_config_yaml_volweb("password") or "123123")


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class VolWebError(RuntimeError):
    """Raised on any VolWeb API failure the pipeline can't recover from.

    Pipeline catches this and marks the workflow ``status=failed``
    with the message preserved verbatim in the log timeline.
    """


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------


class VolWebClient:
    """Stateful client.  One instance per pipeline run is the intended
    usage; the JWT cache lives on the instance so we don't pound the
    token endpoint between calls.
    """

    def __init__(
        self,
        base_url: str | None = None,
        username: str | None = None,
        password: str | None = None,
        *,
        logger: Callable[[str, str], None] | None = None,
    ):
        self.base_url = (base_url or _volweb_base()).rstrip("/")
        self.username = username or _volweb_user()
        self.password = password or _volweb_pass()
        self._token: str | None = None
        self._token_acquired: float = 0.0
        self._logger = logger or (lambda msg, level="info": None)

    # -- logging shim ------------------------------------------------------

    def _log(self, msg: str, level: str = "info") -> None:
        try:
            self._logger(msg, level)
        except Exception:
            # Never let a broken upstream logger crash the pipeline.
            pass

    # -- auth -------------------------------------------------------------

    def _refresh_token(self) -> str:
        # See _headers() for the rationale on the Host override.
        r = requests.post(
            f"{self.base_url}/core/token/",
            json={"username": self.username, "password": self.password},
            headers={"Host": "localhost"},
            timeout=10,
        )
        if r.status_code != 200:
            raise VolWebError(
                f"VolWeb auth failed (HTTP {r.status_code}): {r.text[:300]}"
            )
        token = r.json().get("access")
        if not token:
            raise VolWebError("VolWeb auth returned no 'access' field")
        self._token = token
        self._token_acquired = time.time()
        return token

    def _token_value(self) -> str:
        # JWT lifetime is 5 min server-side; refresh at 4:30 to leave
        # headroom for long uploads / polling loops.
        if not self._token or (time.time() - self._token_acquired) > 270:
            self._refresh_token()
        assert self._token  # for type checkers
        return self._token

    def _headers(self) -> dict[str, str]:
        # Host header override: Django's get_host() rejects underscored
        # hostnames per RFC 1034/1035 (DisallowedHost). Our in-tree
        # convention names the VolWeb backend `intact_volweb_backend`
        # (with underscores) so any HTTP request that uses the container
        # name as the Host gets 400'd before reaching the view.
        # Sending `Host: localhost` matches ALLOWED_HOSTS=['*'] AND
        # passes the RFC validator. The actual TCP connection still
        # resolves the container name through docker DNS.
        return {
            "Authorization": f"Bearer {self._token_value()}",
            "Host": "localhost",
        }

    # -- low-level HTTP wrappers with one-shot 401 retry ------------------

    # Retry policy ---------------------------------------------------------
    # Backed by hard-earned lessons:
    #   * `requests.exceptions.ConnectionError`  → docker is briefly NATing,
    #     transient. Retry with backoff.
    #   * HTTP 502/503/504                       → upstream is restarting
    #     (postgres/redis briefly unreachable). Retry.
    #   * HTTP 401                                → JWT just aged out
    #     (5-min lifetime). Refresh + retry exactly once.
    #   * HTTP 4xx (non-401)                      → operator error. Fail
    #     fast; retry won't help.
    # Upload requests (`files=...`) are NEVER retried on the body — that
    # would re-send the chunk and corrupt the assembled file. Retry only
    # the auth-refresh case there.
    _MAX_ATTEMPTS = 4
    _RETRY_STATUSES = (502, 503, 504)
    _BACKOFF_BASE_SECONDS = 0.5
    # A bare ConnectionError (Errno 111 "Connection refused") means the
    # VolWeb backend isn't listening AT ALL — almost always because the
    # container is mid-restart. During a long memory pipeline the heavy
    # yarascan (full rule corpus vs a multi-GB dump) can OOM-kill or
    # crash the volweb backend; `restart: unless-stopped` brings it back
    # but a container + daphne cold-start takes ~10-30s — far longer than
    # the 4-attempt / ~3.5s default budget. 2026-06-16: a memory run died
    # with "Connection refused to intact_volweb_backend:8000" after the
    # 4 short retries, losing a successfully-acquired 5 GB dump. For
    # connection-refused specifically we retry on a much longer budget
    # (capped backoff, ~90s total) so a backend restart is ridden out.
    _CONN_REFUSED_MAX_ATTEMPTS = 18
    _CONN_REFUSED_BACKOFF_CAP_SECONDS = 8.0

    def _request(
        self,
        method: str,
        path: str,
        *,
        json: Any | None = None,
        params: dict | None = None,
        files: dict | None = None,
        data: dict | None = None,
        timeout: int = 30,
    ) -> requests.Response:
        url = f"{self.base_url}{path}"
        is_upload = files is not None
        last_exc: BaseException | None = None
        conn_refused_attempts = 0  # tracked separately from the main counter
        max_attempts = 2 if is_upload else self._MAX_ATTEMPTS

        # `attempt` counts NON-connection-refused tries (capped at
        # max_attempts); connection-refused tries are counted + capped
        # separately on the longer budget (see _CONN_REFUSED_*). The
        # while-loop lets a backend-restart wait outlast the short
        # max_attempts budget without inflating it.
        attempt = 0
        while True:
            attempt += 1
            try:
                r = requests.request(
                    method,
                    url,
                    headers=(
                        self._headers() if not files
                        else {"Authorization": f"Bearer {self._token_value()}", "Host": "localhost"}
                    ),
                    json=json,
                    params=params,
                    files=files,
                    data=data,
                    timeout=timeout,
                )
            except requests.RequestException as e:
                last_exc = e
                # Connection-refused = backend not listening (mid-restart).
                # Retry on the long budget so a container + daphne
                # cold-start (~10-30s) is ridden out instead of failing
                # the whole memory pipeline. Only the FIRST request of a
                # call benefits from this; uploads still never replay
                # their body (the auth-refresh path handles those).
                is_conn_refused = (
                    isinstance(e, requests.exceptions.ConnectionError)
                    and not is_upload
                )
                if is_conn_refused:
                    conn_refused_attempts += 1
                    attempt -= 1  # don't count refused tries against the short budget
                    if conn_refused_attempts < self._CONN_REFUSED_MAX_ATTEMPTS:
                        wait = min(
                            self._BACKOFF_BASE_SECONDS * (2 ** (conn_refused_attempts - 1)),
                            self._CONN_REFUSED_BACKOFF_CAP_SECONDS,
                        )
                        self._log(
                            f"VolWeb {method} {path} connection refused — backend may be "
                            f"restarting; waiting {wait:.1f}s then retrying "
                            f"({conn_refused_attempts}/{self._CONN_REFUSED_MAX_ATTEMPTS})",
                            "warning",
                        )
                        time.sleep(wait)
                        continue
                    raise VolWebError(
                        f"{method} {path}: VolWeb backend unreachable after "
                        f"{conn_refused_attempts} attempts (~90s) — it never came "
                        f"back. Check `docker logs intact_volweb_backend` (likely "
                        f"OOM during yarascan). {e}"
                    ) from e
                if attempt >= max_attempts:
                    raise VolWebError(
                        f"{method} {path}: network error after {attempt} attempt(s) — {e}"
                    ) from e
                wait = self._BACKOFF_BASE_SECONDS * (2 ** (attempt - 1))
                self._log(
                    f"VolWeb {method} {path} transient {type(e).__name__} — retrying in {wait:.1f}s "
                    f"({attempt}/{max_attempts})",
                    "warning",
                )
                time.sleep(wait)
                continue

            if r.status_code == 401 and attempt == 1:
                # Token may have just aged out (5-min JWT). Refresh once
                # silently and retry.
                self._token = None
                continue

            if r.status_code in self._RETRY_STATUSES and not is_upload and attempt < max_attempts:
                wait = self._BACKOFF_BASE_SECONDS * (2 ** (attempt - 1))
                self._log(
                    f"VolWeb {method} {path} → HTTP {r.status_code} — retrying in {wait:.1f}s "
                    f"({attempt}/{max_attempts})",
                    "warning",
                )
                time.sleep(wait)
                continue

            return r
        # Exhausted attempts via the request-exception branch above.
        raise VolWebError(f"{method} {path}: retries exhausted ({last_exc})")

    def _get_json(self, path: str, *, params: dict | None = None) -> Any:
        r = self._request("GET", path, params=params)
        if r.status_code != 200:
            raise VolWebError(f"GET {path} → HTTP {r.status_code}: {r.text[:300]}")
        return r.json()

    def _post_json(self, path: str, payload: dict, *, timeout: int = 30) -> Any:
        r = self._request("POST", path, json=payload, timeout=timeout)
        if r.status_code not in (200, 201):
            raise VolWebError(f"POST {path} → HTTP {r.status_code}: {r.text[:300]}")
        # Some endpoints return 204 No Content even though declared 200.
        if not r.content:
            return {}
        return r.json()

    # ------------------------------------------------------------------
    # Cases
    # ------------------------------------------------------------------

    def ensure_case(self, name: str, description: str | None = None) -> int:
        """Return id of a case named ``name``, creating it if missing.

        Matches the PoC's behaviour exactly so existing engagement
        cases (``"Memory PoC"``) stay reachable across the migration.
        """
        cases = self._get_json("/api/cases/")
        if isinstance(cases, dict):
            cases = cases.get("results") or []
        for c in cases:
            if c.get("name") == name:
                self._log(f"case {name!r} exists (id={c['id']})")
                return int(c["id"])
        created = self._post_json(
            "/api/cases/",
            {"name": name, "description": description or f"Memory case: {name}"},
        )
        self._log(f"created case {name!r} (id={created['id']})")
        return int(created["id"])

    # ------------------------------------------------------------------
    # Chunked upload
    # ------------------------------------------------------------------

    def upload_evidence(
        self,
        dump_path: Path | str,
        case_id: int,
        *,
        os_name: str = "windows",
        chunk_bytes: int = 64 * 1024 * 1024,
        cancel_check: Callable[[], bool] | None = None,
        progress_cb: Callable[[int, int, float], None] | None = None,
    ) -> int:
        """Upload a memory dump to VolWeb. Returns the new evidence_id.

        Streams the file in ``chunk_bytes`` blocks via VolWeb's chunked
        upload protocol. ``cancel_check`` is polled per chunk so the
        pipeline's Stop button kills the upload promptly; ``progress_cb``
        receives ``(bytes_sent, bytes_total, mb_per_sec)`` per chunk for
        the workflow progress bar.
        """
        src = Path(dump_path).expanduser().resolve()
        if not src.is_file():
            raise VolWebError(f"upload source not found: {src}")
        total = src.stat().st_size
        if total == 0:
            raise VolWebError(f"upload source is empty: {src}")

        # initiate
        init = self._post_json(
            "/api/cases/upload/initiate/",
            {"filename": src.name, "case_id": case_id, "os": os_name},
        )
        upload_id = init.get("upload_id")
        if not upload_id:
            raise VolWebError(f"upload initiate returned no upload_id: {init}")
        self._log(f"upload initiated: id={upload_id} size={total:,} bytes")

        # chunks
        sent = 0
        part = 0
        t0 = time.time()
        with src.open("rb") as f:
            while True:
                if cancel_check and cancel_check():
                    raise VolWebError("upload cancelled by operator")
                buf = f.read(chunk_bytes)
                if not buf:
                    break
                part += 1
                files = {"chunk": (f"part_{part}", buf, "application/octet-stream")}
                data = {"upload_id": upload_id, "part_number": str(part)}
                r = self._request(
                    "POST", "/api/cases/upload/chunk/",
                    files=files, data=data, timeout=600,
                )
                if r.status_code != 200:
                    raise VolWebError(
                        f"chunk {part} failed: HTTP {r.status_code} {r.text[:200]}"
                    )
                sent += len(buf)
                if progress_cb:
                    dt = time.time() - t0
                    mbps = (sent / 1024 / 1024) / max(dt, 0.001)
                    try:
                        progress_cb(sent, total, mbps)
                    except Exception:
                        pass

        # complete
        resp = self._post_json(
            "/api/cases/upload/complete/", {"upload_id": upload_id}, timeout=600
        )
        evidence_id = resp.get("evidence_id")
        if not evidence_id:
            raise VolWebError(f"upload complete returned no evidence_id: {resp}")
        self._log(f"upload complete: evidence_id={evidence_id} parts={part}")
        return int(evidence_id)

    def register_existing_file(
        self,
        basename: str,
        *,
        case_id: int,
        os_name: str = "windows",
    ) -> int:
        """Skip the chunked-upload phase and register an already-present
        .raw as a new VolWeb evidence.

        Pre-condition: the file lives at
        ``/home/app/web/media/staging/<basename>`` inside the VolWeb
        backend container (the ``intact_memory_dumps`` shared volume,
        also mounted into Velociraptor at /data/memory_dumps and into
        intact_backend at the same path).

        Implementation:
          1. Verify the file is present in the staging mount (the
             ``intact_memory_dumps`` shared volume mounted into VolWeb
             at ``/home/app/web/media/staging``).
          2. Insert the Evidence row via the Django ORM (``manage.py
             shell``) with ``file='staging/<basename>'`` — pointing
             directly at the file on the shared volume. We deliberately
             do NOT ``mv`` the file into ``evidences/``: a move across
             two docker volumes is a full 5 GB copy, which defeats the
             whole point of skipping the HTTP upload.
          3. Django's storage layer resolves ``Evidence.file`` to
             ``MEDIA_ROOT + file.name`` = ``/home/app/web/media/staging/<basename>``,
             which is where the file already lives. The selective
             engine and yarascan workers both read via Django storage
             so they see the file transparently.

        Returns the new evidence_id.

        Time saved vs ``upload_evidence``: ~6 min on a 5 GB dump
        (the entire chunked HTTP upload phase is gone — bytes never
        leave the volume).
        """
        import json
        import subprocess

        backend_container = self._resolve_backend_container()
        if not backend_container:
            raise VolWebError(
                "register_existing_file: VolWeb backend container not found. "
                "Did the in-tree VolWeb stack come up?"
            )

        staging_path = f"/home/app/web/media/staging/{basename}"

        # 1) Verify the file actually exists on the shared volume +
        #    fix ownership (Velociraptor wrote it as root from the
        #    other side of the bind mount; VolWeb workers run as `app`).
        check = subprocess.run(
            [
                "docker", "exec", backend_container, "sh", "-c",
                f"chown app:app '{staging_path}' 2>/dev/null; stat -c '%s' '{staging_path}'",
            ],
            capture_output=True, text=True, timeout=10,
        )
        if check.returncode != 0:
            raise VolWebError(
                f"register_existing_file: staging file missing: {staging_path} "
                f"(stat error: {check.stderr.strip()[:200]})"
            )
        try:
            size = int((check.stdout or "0").strip())
        except ValueError:
            size = 0
        if size < 1024 * 1024:
            raise VolWebError(
                f"register_existing_file: file too small ({size} bytes) — refusing to register"
            )
        self._log(
            f"register: staging file {staging_path} ({size // 1024 // 1024} MB) — inserting DB row (no copy)",
            "info",
        )

        # 2) Insert the DB row via Django shell. The Evidence model's
        #    actual schema (verified by reading /home/app/web/evidences/
        #    models.py inside the VolWeb backend) uses these fields:
        #
        #       name           CharField                       (required)
        #       etag           CharField(unique=True)          (required, must be unique)
        #       os             choices=('windows','linux')     (required)
        #       linked_case    FK→Case                         (required, NOT the name `case`)
        #       url            "file://<absolute path>"        (read by Vol3's URL handler)
        #       status         IntegerField, default=0         (CompleteUploadView sets -2)
        #
        #    The url's "file://" scheme lets Vol3's default file handler
        #    open it — the URL handler for "s3://" is hooked separately
        #    via volweb_open() in volatility_engine/utils.py.
        import uuid as _uuid
        etag = f"local-{_uuid.uuid4().hex}"
        file_url = f"file://{staging_path}"
        py = (
            "import json\n"
            "from evidences.models import Evidence\n"
            "from cases.models import Case\n"
            f"case = Case.objects.get(pk={int(case_id)})\n"
            f"ev = Evidence.objects.create(\n"
            f"    name={basename!r},\n"
            f"    url={file_url!r},\n"
            f"    linked_case=case,\n"
            f"    os={os_name!r},\n"
            f"    etag={etag!r},\n"
            f"    source='FILESYSTEM',\n"
            f"    status=-2,\n"
            f")\n"
            "print(json.dumps({'evidence_id': ev.id}))\n"
        )
        # Run Django shell as the `app` user, with /home/app/web as cwd,
        # so PYTHONPATH picks up the venv at /home/app/.local. The
        # default `docker exec` runs as root, which doesn't have Django
        # on its sys.path.
        ins = subprocess.run(
            [
                "docker", "exec", "-i",
                "--user", "app", "-w", "/home/app/web",
                backend_container, "python3", "manage.py", "shell",
            ],
            input=py, capture_output=True, text=True, timeout=60,
        )
        if ins.returncode != 0:
            raise VolWebError(
                f"register_existing_file: Django shell failed: "
                f"stderr={ins.stderr.strip()[-400:]}"
            )
        # The shell prints a banner + our final JSON line. Find the JSON.
        evidence_id: int | None = None
        for line in (ins.stdout or "").splitlines():
            line = line.strip()
            if line.startswith("{") and "evidence_id" in line:
                try:
                    evidence_id = int(json.loads(line)["evidence_id"])
                except (ValueError, KeyError, json.JSONDecodeError):
                    continue
        if not evidence_id:
            raise VolWebError(
                f"register_existing_file: could not parse evidence_id from shell output: "
                f"{ins.stdout[-400:]!r}"
            )
        self._log(f"register: evidence_id={evidence_id} (url={file_url})", "success")
        return evidence_id

    def get_evidence(self, evidence_id: int) -> dict:
        return self._get_json(f"/api/evidences/{evidence_id}/")

    def delete_evidence(self, evidence_id: int) -> None:
        """Hard-delete an evidence row + cascade plugin/yarascan rows.

        The on-disk ``.raw`` does NOT always cascade through Django's
        delete signal (a real bug observed in the PoC — orphan 5 GB
        ``.raw`` files left in ``volweb_media/_data/evidences/`` even
        after the row went away). Pipeline.cleanup follows up with a
        belt-and-suspenders host-level ``rm``.
        """
        r = self._request("DELETE", f"/api/evidences/{evidence_id}/")
        if r.status_code not in (200, 204):
            raise VolWebError(f"delete evidence {evidence_id}: HTTP {r.status_code}")

    # ------------------------------------------------------------------
    # Selective plugin extraction
    # ------------------------------------------------------------------

    def trigger_extraction(self, evidence_id: int, plugins: Iterable[str]) -> None:
        """Dispatch the curated plugin set in ONE call.

        **Important:** VolWeb's ``/api/evidence/tasks/selective-
        extraction/`` endpoint resets the entire plugin table for an
        evidence on each call. Two successive calls would wipe the
        first run's results. The pipeline always issues exactly one
        invocation per evidence, with the full plugin list.
        """
        plugin_list = list(plugins)
        if not plugin_list:
            raise VolWebError("trigger_extraction: empty plugin list")
        resp = self._post_json(
            "/api/evidence/tasks/selective-extraction/",
            {"id": int(evidence_id), "plugins": plugin_list},
        )
        self._log(
            f"selective-extraction queued: evidence={evidence_id} plugins={len(plugin_list)}"
        )
        if isinstance(resp, dict) and resp.get("error"):
            raise VolWebError(f"selective-extraction error: {resp.get('error')}")

    def list_plugins(self, evidence_id: int) -> list[dict]:
        """Return ALL VolatilityPlugin rows for an evidence.

        Uses Django shell directly (not the HTTP API) because the HTTP
        view at ``/api/evidence/<id>/plugins/`` filters out rows with
        ``display=False`` — that's the right behaviour for the UI but
        wrong for our wait_for_plugin_results() which needs to see EVERY
        row to know what completed. PsTree, for example, is stored with
        ``display=False`` because the Processes view surfaces PsList
        instead; the API hides it but the plugin actually ran and has
        artefacts.

        Falls back to the HTTP path if the docker exec fails (e.g.
        backend container missing — unit-test environments).
        """
        import json
        import subprocess
        container = self._resolve_backend_container()
        if container:
            try:
                r = subprocess.run(
                    [
                        "docker", "exec", "--user", "app", "-w", "/home/app/web",
                        container, "python3", "-c",
                        "import django,os,json; "
                        "os.environ['DJANGO_SETTINGS_MODULE']='backend.settings'; "
                        "django.setup(); "
                        "from volatility_engine.models import VolatilityPlugin; "
                        f"rows = list(VolatilityPlugin.objects.filter(evidence_id={int(evidence_id)})"
                        ".values('name','results','icon','error_message')); "
                        "print(json.dumps(rows))",
                    ],
                    capture_output=True, text=True, timeout=15,
                )
                if r.returncode == 0 and r.stdout:
                    raw = r.stdout.strip().splitlines()[-1]
                    rows = json.loads(raw)
                    # Normalize: API used `error`, model uses `error_message`.
                    for row in rows:
                        row["error"] = row.pop("error_message", None)
                    return rows
            except Exception:
                pass
        return self._get_json(f"/api/evidence/{evidence_id}/plugins/") or []

    def fetch_plugin(self, evidence_id: int, plugin_name: str) -> dict | None:
        try:
            return self._get_json(f"/api/evidence/{evidence_id}/plugin/{plugin_name}/")
        except VolWebError as e:
            # Treat a missing plugin row as None rather than fatal — the
            # analyzers filter on "results=True" anyway and a 404 here
            # is normal for plugins that errored out cleanly.
            if "404" in str(e):
                return None
            raise

    # ------------------------------------------------------------------
    # Yarascan
    # ------------------------------------------------------------------

    def _resolve_backend_container(self) -> str | None:
        """Find the VolWeb backend container name on this host.

        Tries, in order:
          1. ``frontend_config.memory.volweb.backend_container`` (operator override)
          2. ``intact_volweb_backend`` (the in-tree compose name)
          3. ``volweb-volweb-backend-1`` (upstream PoC compose name)
          4. any container whose image is ``forensicxlab/volweb-backend``

        Returns the resolved name or ``None`` if nothing matches —
        callers treat ``None`` as "skip best-effort step silently".
        """
        explicit = _config_value("backend_container", default=None)
        if explicit:
            return explicit
        try:
            r = subprocess.run(
                ["docker", "ps", "--format", "{{.Names}}\t{{.Image}}"],
                capture_output=True, text=True, timeout=5,
            )
            if r.returncode != 0:
                return None
            candidates: list[str] = []
            for line in (r.stdout or "").splitlines():
                parts = line.split("\t", 1)
                if not parts:
                    continue
                name = parts[0].strip()
                image = parts[1].strip() if len(parts) > 1 else ""
                if name == "intact_volweb_backend":
                    return name   # in-tree first
                if "forensicxlab/volweb-backend" in image and "workers" not in name:
                    candidates.append(name)
            return candidates[0] if candidates else None
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            return None

    def stage_media_dir(self, evidence_id: int) -> None:
        """Best-effort: ensure ``/home/app/web/media/<evidence_id>/``
        exists inside the VolWeb backend container BEFORE triggering
        yarascan, closing the race window we hit in the PoC at
        11:18:57 (worker writes ``yara_rules_<ts>.yara`` to a missing
        dir, 500s, task reports success with 0 hits).

        Hardening lessons from the PoC + first E2E:
          * Container name is auto-detected (not hardcoded). The
            in-tree compose calls it ``intact_volweb_backend``; the
            upstream PoC calls it ``volweb-volweb-backend-1``. Either
            works.
          * Newer VolWeb releases auto-create the directory at write
            time. The "container not found" error in that case is
            noise, not a real failure — we silently skip rather than
            scaring the operator.
          * Failure here NEVER aborts the pipeline. Worst case is the
            zero-hit-on-first-run bug, which the operator catches via
            the chat UI ("0 hits looks wrong — rerun") rather than via
            a workflow failure.
        """
        container = self._resolve_backend_container()
        if not container:
            # No reachable VolWeb container — likely in-tree not yet
            # deployed and PoC stack on a different network. The
            # extraction will still work via the HTTP API; just skip
            # the directory pre-stage silently.
            return
        cmd = [
            "docker", "exec", container,
            "sh", "-c",
            f"mkdir -p /home/app/web/media/{int(evidence_id)} 2>/dev/null "
            f"&& chown app:app /home/app/web/media/{int(evidence_id)} 2>/dev/null "
            f"|| true",
        ]
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            # Don't log on failure — the `|| true` swallows non-zero
            # exit and the worker will auto-create. Logging only
            # creates noise.
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    def trigger_yarascan(
        self, evidence_id: int,
        *,
        rulesets: list[int] | None = None,
        rules: list[int] | None = None,
    ) -> None:
        """Queue a yarascan against ``evidence_id``.

        ``rulesets=[]`` / ``rules=[]`` (the defaults) means *all
        active rulesets* per VolWeb's API contract — i.e. every YARA
        rule seeded at install + Maintenance refresh time.

        Caller MUST have called :meth:`stage_media_dir` first to
        avoid the empty-dir race documented there.
        """
        payload = {
            "id": int(evidence_id),
            "rulesets": list(rulesets or []),
            "rules": list(rules or []),
        }
        resp = self._post_json("/api/evidence/tasks/yarascan/", payload)
        self._log(
            f"yarascan queued: evidence={evidence_id} "
            f"rulesets={len(payload['rulesets']) or 'all'} "
            f"rules={len(payload['rules']) or 'all'}"
        )
        if isinstance(resp, dict) and resp.get("error"):
            raise VolWebError(f"yarascan error: {resp.get('error')}")

    def resolve_yara_rule_ids(self, keywords: list[str]) -> list[int]:
        """Resolve name-substring keywords to active YARA rule IDs.

        Turns a blueprint's ``yara_categories`` (expanded to keywords by
        the pipeline) into the concrete ``rules=[...]`` list for
        :meth:`trigger_yarascan`. Runs the match inside the backend
        container via the Django ORM — same approach as
        :meth:`list_plugins` — so it's an exact case-insensitive
        ``name__icontains`` union and costs one ``docker exec`` instead
        of paginating (and deserialising) the HTTP rules API.

        Only ``is_active=True, status=100`` (compiled-and-valid) rules
        are eligible, mirroring what VolWeb's own all-rules scan uses.

        Returns ``[]`` on any failure or zero match. Callers treat empty
        as "couldn't scope — fall back to scanning the full corpus";
        never as "scan nothing".
        """
        import json
        import subprocess

        kws = [k for k in (keywords or []) if k]
        if not kws:
            return []
        container = self._resolve_backend_container()
        if not container:
            self._log(
                "yara: backend container not found — can't scope rules, "
                "will scan full corpus", "warning",
            )
            return []
        code = (
            "import django,os,json,sys,operator;"
            "from functools import reduce;"
            "os.environ['DJANGO_SETTINGS_MODULE']='backend.settings';"
            "django.setup();"
            "from django.db.models import Q;"
            "from yararules.models import YaraRule;"
            "kws=json.loads(sys.argv[1]);"
            "q=reduce(operator.or_,[Q(name__icontains=k) for k in kws]);"
            "ids=list(YaraRule.objects.filter(is_active=True,status=100)"
            ".filter(q).values_list('id',flat=True));"
            "print(json.dumps(ids))"
        )
        try:
            r = subprocess.run(
                ["docker", "exec", "--user", "app", "-w", "/home/app/web",
                 container, "python3", "-c", code, json.dumps(kws)],
                capture_output=True, text=True, timeout=20,
            )
            if r.returncode == 0 and r.stdout:
                ids = json.loads(r.stdout.strip().splitlines()[-1])
                return [int(i) for i in ids]
            self._log(
                f"yara rule resolution exited {r.returncode}: "
                f"{(r.stderr or '').strip()[:200]} — will scan full corpus",
                "warning",
            )
        except Exception as e:
            self._log(
                f"yara rule resolution failed ({e!s}) — will scan full corpus",
                "warning",
            )
        return []

    def yarascan_history(self, evidence_id: int) -> list[dict]:
        return self._get_json(f"/api/evidence/{evidence_id}/yarascan/history/") or []

    def yarascan_results(
        self, evidence_id: int, *, max_hits: int = 500
    ) -> list[dict]:
        """Return up to ``max_hits`` yarascan hits for ``evidence_id``.

        Walks paginated pages of 100 until the cap is reached or the
        endpoint reports no ``next`` page. VolWeb uses DRF's
        ``PageNumberPagination`` shape: ``{count, next, previous,
        results}``.
        """
        hits: list[dict] = []
        page = 1
        while True:
            resp = self._get_json(
                f"/api/evidence/{evidence_id}/yarascan/results/",
                params={"page": page, "page_size": 100},
            )
            if not isinstance(resp, dict):
                break
            rows = resp.get("results") or []
            if not rows:
                break
            for row in rows:
                hits.append(row)
                if len(hits) >= max_hits:
                    return hits
            if not resp.get("next"):
                break
            page += 1
        return hits

    # ------------------------------------------------------------------
    # Polling helpers used by the orchestrator
    # ------------------------------------------------------------------

    def wait_for_plugin_results(
        self,
        evidence_id: int,
        expected_plugins: Iterable[str],
        *,
        timeout_s: int = 1800,
        poll_s: int = 15,
        cancel_check: Callable[[], bool] | None = None,
        on_progress: Callable[[int, int], None] | None = None,
        idle_grace_s: int = 300,
    ) -> dict[str, dict]:
        """Block until every expected plugin reaches a terminal state.

        Terminal state = ``results=True`` (success), an error indicator
        in the row, OR the plugin never inserts a row at all (this
        happens when an automagic step kills the worker before it can
        post a row, observed in production with ``PsTree`` /
        ``PrintKey`` on some Win10 builds).

        The pre-hardening version of this method only counted
        ``results=True`` rows — when VolWeb skipped a row entirely or
        a plugin errored out, it deadlocked until ``timeout_s`` fired.
        Now we:

          * Treat ``error``/``icon=mdi-alert-circle`` rows as terminal-but-failed
            (returned via the warnings channel, not the success map)
          * After ``idle_grace_s`` of no row count change with at least
            ``min_floor`` plugins done, give up on the missing ones and
            return — the partial results are still useful, and the
            operator gets a clear "X/N plugins succeeded" log line.
          * Log per-plugin status snapshots every poll so the operator
            can see WHICH plugin is stuck instead of staring at a
            silent progress bar.
        """
        wanted = set(expected_plugins)
        deadline = time.time() + timeout_s
        last_row_count = -1
        last_change_at = time.time()
        # Track which plugins we've already logged a status change for
        # so we don't spam the timeline on every poll.
        announced: set[str] = set()
        min_floor = max(1, int(len(wanted) * 0.66))   # 2/3 is the partial-success floor

        while True:
            if cancel_check and cancel_check():
                raise VolWebError("plugin extraction cancelled by operator")
            rows = self.list_plugins(evidence_id)

            done: dict[str, dict] = {}
            errored: dict[str, dict] = {}
            # VolWeb writes a `VolWebSelective` row with results=True the
            # moment the celery selective-extraction task finishes (see
            # volatility_engine/engine.py inside the VolWeb image). This
            # is the AUTHORITATIVE "task done" signal — far better than
            # the 5-min idle-grace fallback because it fires the second
            # the worker actually completes. Whatever curated plugins
            # haven't surfaced by now genuinely won't (they either
            # crashed in Vol3 automagic without inserting a row, or ran
            # with empty results which the row already captures).
            task_done = any(
                (r.get("name") or "").endswith("VolWebSelective") and r.get("results")
                for r in rows
            )

            for r in rows:
                name = r.get("name") or ""
                if name not in wanted:
                    suffix = name.rsplit(".", 1)[-1]
                    matched = next(
                        (w for w in wanted if w.rsplit(".", 1)[-1] == suffix),
                        None,
                    )
                    if not matched:
                        continue
                    name = matched
                # Terminal-success: row carries a results payload.
                if r.get("results"):
                    if name not in announced:
                        self._log(f"plugin done: {name.rsplit('.',1)[-1]}", "info")
                        announced.add(name)
                    done[name] = r
                    continue
                # Terminal-failure: VolWeb marks erroring plugins with
                # a red icon and / or an `error` payload.
                icon = (r.get("icon") or "").lower()
                if r.get("error") or "alert" in icon or "error" in icon:
                    if name not in announced:
                        err_msg = r.get("error") or "(plugin row marked errored)"
                        self._log(
                            f"plugin errored: {name.rsplit('.',1)[-1]} — {err_msg!s:.180}",
                            "warning",
                        )
                        announced.add(name)
                    errored[name] = r

            if on_progress:
                try:
                    on_progress(len(done), len(wanted))
                except Exception:
                    pass

            # Fast-exit: the worker's terminal-marker row says we're done.
            # Anything still missing from the curated set isn't coming —
            # log what's missing so the operator sees it, then return.
            if task_done:
                missing = sorted(
                    w.rsplit(".", 1)[-1]
                    for w in wanted - set(done.keys()) - set(errored.keys())
                )
                if missing:
                    self._log(
                        f"plugin extract: VolWeb task finished — {len(done)}/{len(wanted)} done, "
                        f"missing (no row or empty results): {', '.join(missing)}",
                        "warning",
                    )
                return done

            # All wanted plugins reached a terminal state — done.
            if len(done) + len(errored) >= len(wanted):
                if errored:
                    self._log(
                        f"plugin extract: {len(done)}/{len(wanted)} succeeded, "
                        f"{len(errored)} errored — proceeding with partial results",
                        "warning",
                    )
                return done

            # Idle-grace soft-exit: if the row count hasn't changed for
            # idle_grace_s AND we already have min_floor done, accept that
            # the missing plugins won't show up.
            row_count = len(rows)
            if row_count != last_row_count:
                last_row_count = row_count
                last_change_at = time.time()
            elif (
                time.time() - last_change_at > idle_grace_s
                and len(done) >= min_floor
            ):
                missing = sorted(
                    w.rsplit(".", 1)[-1]
                    for w in wanted - set(done.keys()) - set(errored.keys())
                )
                self._log(
                    f"plugin extract: row count stable for {idle_grace_s}s at "
                    f"{len(done)}/{len(wanted)} done — proceeding without "
                    f"missing plugins: {', '.join(missing)}",
                    "warning",
                )
                return done

            if time.time() > deadline:
                self._log(
                    f"plugin extraction timed out at {len(done)}/{len(wanted)} after {timeout_s}s",
                    "warning",
                )
                return done

            # Sleep in 1 s steps so the cancel button cuts through quickly.
            slept = 0
            while slept < poll_s:
                if cancel_check and cancel_check():
                    raise VolWebError("plugin extraction cancelled by operator")
                time.sleep(1)
                slept += 1

    def has_active_yara_rules(self) -> bool:
        """Quick pre-check: does VolWeb have any active YARA rules?

        When zero rules are configured (fresh in-tree install before
        ``seed_yara_rulesets`` has run), the yarascan worker logs
        ``No active YARA rules found in database`` and completes in
        <1 s WITHOUT writing a history row. ``wait_for_yarascan``
        would then poll forever waiting on a row that never lands.

        This pre-flight call lets the orchestrator skip the scan
        entirely in that case (and inform the operator clearly via
        the workflow log).
        """
        container = self._resolve_backend_container()
        if not container:
            # No way to know — assume yes and let the regular flow run.
            return True
        try:
            import subprocess
            r = subprocess.run(
                [
                    "docker", "exec", "--user", "app", "-w", "/home/app/web",
                    container, "python3", "-c",
                    "import django,os; os.environ['DJANGO_SETTINGS_MODULE']='backend.settings'; django.setup(); "
                    "from yararules.models import YaraRule; "
                    # Field is `is_active` (not `enabled`) on this VolWeb release.
                    "print(YaraRule.objects.filter(is_active=True).count())",
                ],
                capture_output=True, text=True, timeout=10,
            )
            count = int((r.stdout or "0").strip().splitlines()[-1])
            return count > 0
        except Exception:
            return True   # conservative

    def wait_for_yarascan(
        self,
        evidence_id: int,
        *,
        timeout_s: int = 2400,
        poll_s: int = 15,
        cancel_check: Callable[[], bool] | None = None,
        no_rules_grace_s: int = 30,
    ) -> tuple[int, bool]:
        """Block until yarascan has emitted at least one history entry
        for the evidence (signaling completion).

        Returns ``(count, completed)``:
          * ``completed=True``  — a real terminal state was reached (a
            history row appeared, or there are no active rules). The
            scan is DONE; cleanup of the per-evidence media dir is safe.
          * ``completed=False`` — the wait hit ``timeout_s`` while the
            scan was still running. The worker may STILL be streaming
            results to media/<id>/yarascan_results.jsonl; the caller
            must NOT remove that dir or it will destroy in-flight
            matches (2026-06-17 incident: a 700s override on a 5 GB
            dump whose scan needed ~1595s timed out, cleanup removed
            media/<id>, and 84 real matches were lost — "Output path
            does not exist: media/1/").

        A scan with zero matches still produces a history entry with
        ``count=0`` on a successful run — UNLESS VolWeb has no active
        YARA rules at all (fresh install pre-seeding), in which case
        the task succeeds without writing a row. We short-circuit
        that case via ``has_active_yara_rules`` so the wait doesn't
        hang for ``timeout_s``.
        """
        # Zero-rules short-circuit (fresh install).
        if not self.has_active_yara_rules():
            self._log(
                "yarascan: no active YARA rules in VolWeb — treating as 0-hit completion "
                "(seed rulesets via Maintenance → YARA → Refresh to enable scanning)",
                "warning",
            )
            return 0, True

        deadline = time.time() + timeout_s
        # Secondary safety net: if rules ARE configured but no history
        # row appears within `no_rules_grace_s` of the first poll, the
        # scan probably ran-but-didn't-write. Fall back to 0-hits.
        first_seen_at = time.time()
        # Heartbeat cadence so a long scan doesn't leave the workflow log
        # silent — an operator saw a ~4-minute gap on a 5 GB dump and thought
        # the run had stalled. Emit one "still scanning" line per heartbeat_s.
        heartbeat_s = 60
        last_beat = first_seen_at
        while True:
            if cancel_check and cancel_check():
                raise VolWebError("yarascan cancelled by operator")
            hist = self.yarascan_history(evidence_id)
            if hist:
                count = int(hist[0].get("count", 0))
                self._log(f"yarascan completed: {count} hits")
                return count, True
            now = time.time()
            elapsed = now - first_seen_at
            if elapsed > no_rules_grace_s and elapsed < no_rules_grace_s + poll_s:
                # No results row yet after the grace window. The scan is most
                # likely still running — large dumps write the row LATE (this
                # very path produced 33 hits at ~294s), so do NOT predict
                # "0 hits"; just note it and keep polling with heartbeats.
                self._log(
                    f"yarascan: no results row yet after {int(elapsed)}s — scan "
                    f"still running, will keep waiting (up to {timeout_s}s).",
                    "info",
                )
                last_beat = now
            elif now - last_beat >= heartbeat_s:
                self._log(
                    f"yarascan: still scanning evidence={evidence_id}… "
                    f"({int(elapsed)}s elapsed, budget {timeout_s}s)",
                    "info",
                )
                last_beat = now
            if now > deadline:
                self._log(
                    f"yarascan wait hit the {timeout_s}s budget — the scan may STILL "
                    f"be running in the worker. Reporting hits=0 for now, but the "
                    f"per-evidence results dir will be PRESERVED (not cleaned up) so "
                    f"any matches the scan finds aren't lost. Bump yarascan_timeout_s "
                    f"for large dumps to capture the count in this run.",
                    "warning",
                )
                return 0, False
            slept = 0
            while slept < poll_s:
                if cancel_check and cancel_check():
                    raise VolWebError("yarascan cancelled by operator")
                time.sleep(1)
                slept += 1


__all__ = ["VolWebClient", "VolWebError"]
