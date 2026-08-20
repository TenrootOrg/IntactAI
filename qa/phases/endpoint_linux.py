"""Enrol the Velociraptor LINUX client on the appliance itself.

The appliance becomes its own endpoint. That sounds like a shortcut and is
actually the point: without it, a run on a machine with no lab hardware — CI, a
laptop, anyone without a spare Windows box — can prove that the server starts and
answers HTTP, and can prove nothing whatsoever about collection. A real
`C.<hex>` client is the difference between "the API is up" and "the product
works".

Nothing here is a bespoke build. `scripts/generate_clients.sh` already runs
`velociraptor config repack --exe` at deploy time, which writes the server's own
client configuration INTO the binary, and the platform serves that exact file
from `/api/clients/download/linux`. So this phase downloads the artefact an
operator downloads, runs it unmodified, and waits for the server to notice —
which is also why it is worth testing: if the repack is broken, every Linux
customer is broken, and nothing else in the suite would catch it.

Why the client can reach its own server: the repacked config points at
`https://<domain>:8000/`, and 8000 is the one Velociraptor port published on all
interfaces. `domain` must therefore be a real address of this host. It must NOT
be 127.0.0.1 — beyond breaking the client, that would make every "unauthenticated
caller is rejected" check in this suite meaningless, because the backend's auth
gate exempts loopback by design.

Deliberately NOT critical. A client that fails to check in is worth a red mark,
not a reason to abandon the ~150 API checks that follow.
"""

import os
import socket

from lib import clients as clients_lib, shell

# One name for the unit, the binary and the writeback file, so teardown is
# unambiguous and so nothing here can be confused with a real deployment.
UNIT = "intact-qa-velociraptor"
CLIENT_BIN = "/usr/local/bin/intact-qa-velociraptor-client"
WRITEBACK = "/etc/velociraptor.writeback.yaml"

# A repacked client is ~27 MB. The realistic failure is not "no file" but "a
# 200 carrying an HTML error page" or a truncated body, both of which write a
# perfectly valid small file that then fails to execute for reasons that look
# nothing like the actual cause.
MIN_CLIENT_BYTES = 10 * 2**20


def register(runner, cfg):
    if not cfg.linux_client:
        return

    tl = runner.ctx.tl

    # ------------------------------------------------------------------ 2L --
    @runner.phase("enrol_linux",
                  "Enrol the Velociraptor Linux client on the appliance itself",
                  needs=("auth",))
    def enrol_linux(ctx):
        c = ctx.get("client")
        detail = {}

        before = clients_lib._client_ids(c, include_offline=True)
        detail["clients_before"] = len(before)

        path = _download_linux_client(c, ctx.run_dir, tl)
        ctx.check("platform served a Linux client binary", bool(path),
                  actual=path and os.path.basename(path))
        if not path:
            return detail

        size = os.path.getsize(path)
        detail["client_bytes"] = size
        ctx.check("the Linux client is a plausible binary, not an error page",
                  size >= MIN_CLIENT_BYTES,
                  expected=f">={MIN_CLIENT_BYTES // 2**20} MB",
                  actual=f"{size / 2**20:.1f} MB",
                  note="a 200 carrying HTML writes a valid small file that fails "
                       "to execute for reasons that look unrelated")
        if size < MIN_CLIENT_BYTES:
            return detail

        # `install`, not cp+chmod: one call, and the mode is set at creation
        # rather than filtered through the process umask afterwards. The same
        # masked-execute-bit bug has bitten the Velociraptor CLI and the legacy
        # client downloads already; the security phase checks for both.
        r = shell.sudo(["install", "-m", "0755", path, CLIENT_BIN],
                       cfg.sudo_password, timeout=120, tl=tl, stage="enrol_linux")
        ctx.check("the client is installed and executable", r.ok,
                  actual=CLIENT_BIN)
        if not r.ok:
            return detail

        started, how = _start_client(cfg, tl)
        detail["start_method"] = how
        ctx.check("the client process started", started, actual=how)
        if not started:
            return detail

        # Match on hostname rather than taking whatever id is new. On a shared
        # or re-run box "the first id I have not seen" can be someone else's
        # agent, and the resulting run then asserts against a client this phase
        # never installed — passing or failing for reasons unconnected to the
        # code under test.
        me = socket.gethostname()
        detail["hostname_expected"] = me

        def probe():
            items = clients_lib._clients(c, include_offline=True)
            fresh = {cid: it for cid, it in items.items() if cid not in before}
            if not fresh:
                return None
            mine = [cid for cid, it in fresh.items()
                    if (it.get("hostname") or "").split(".")[0] == me.split(".")[0]]
            return (mine or sorted(fresh))[0]

        # `describe` is a CALLABLE that renders the found value for the log,
        # not a description of what is being waited for. Passing a string threw
        # TypeError from inside tl.wait -- and only on the SUCCESS path, since
        # describe(value) is reached solely when the probe returns something.
        # So the client enrolled correctly and the harness then crashed
        # reporting it, turning a working phase into an errored one.
        client_id, waited = tl.wait(
            "linux client checks in", timeout_s=600, poll_s=10, probe=probe,
            describe=lambda cid: cid)
        detail["waited_s"] = waited

        if not client_id:
            # This wait is the single most likely thing in the phase to fail,
            # and the journal is the entire diagnosis — a TLS mismatch, a wrong
            # server_urls, a port nothing is listening on. Losing it costs a
            # whole re-run to learn what one command would have said.
            _dump_journal(cfg, ctx.run_dir, tl)
            ctx.check("a Linux client enrolled", False,
                      expected="a new C.<hex> within 600s",
                      actual="none appeared",
                      note=f"see logs/{UNIT}.log — the client's own view of why "
                           f"it could not reach https://<domain>:8000/")
            return detail

        detail["client_id"] = client_id
        detail["hostname_actual"] = clients_lib._client_hostname(c, client_id)
        ctx.set(client_id=client_id, client_name=detail["hostname_actual"] or me)

        ctx.check("a Linux client enrolled", True, actual=client_id)
        ctx.check("the enrolled client is this host",
                  (detail["hostname_actual"] or "").split(".")[0] == me.split(".")[0],
                  expected=me, actual=detail["hostname_actual"],
                  note="a different hostname means this picked up somebody "
                       "else's agent, not the one just installed")
        return detail

    # ---------------------------------------------------------------- 9L --
    @runner.phase("teardown_linux", "Remove the Linux client from the appliance",
                  needs=("enrol_linux",))
    def teardown_linux(ctx):
        detail = {}

        shell.sudo(["systemctl", "stop", UNIT + ".service"], cfg.sudo_password,
                   timeout=120, tl=tl, stage="teardown_linux")
        shell.sudo(["rm", "-f", CLIENT_BIN, WRITEBACK], cfg.sudo_password,
                   timeout=60, tl=tl, stage="teardown_linux")

        r = shell.run(["systemctl", "is-active", UNIT + ".service"])
        still_running = r.out.strip() == "active"
        detail["unit_active_after"] = still_running
        ctx.check("the client service is stopped", not still_running,
                  expected="inactive", actual=r.out.strip() or "gone")
        ctx.check("the client binary is removed", not os.path.exists(CLIENT_BIN),
                  actual=CLIENT_BIN)

        # The server-side record outlives the agent, and there is no route to
        # remove it: /api/client/<id> is a 501 stub. Warn so the next run knows
        # why it sees an offline client, but never fail — nothing is wrong.
        cid = ctx.get("client_id")
        if cid:
            detail["client_record_remains"] = cid
            tl.warn("client_record_remains", detail={
                "client_id": cid,
                "note": "no API removes a client record (/api/client/<id> is a "
                        "501 stub); it will show as offline"})
        return detail


# --- helpers ---------------------------------------------------------------


def _download_linux_client(c, run_dir, tl, platform="linux"):
    """Fetch the platform-generated Linux client.

    'linux' is the pre-generated repack (scripts/generate_clients.sh writes
    client_installers/velociraptor-client-linux at velociraptor startup). Only
    it and windows-msi are actually pre-generated; the other names in the
    route's vocabulary are built on demand or 404.
    """
    dest = os.path.join(run_dir, "artifacts", "velociraptor-client-linux")
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    url = f"/api/clients/download/{platform}"
    try:
        r = c.s.get(c.base + url, timeout=300, stream=True)
    except Exception as exc:                                  # noqa: BLE001
        if tl:
            tl.event("client_download", status="fail",
                     detail={"path": url, "error": str(exc)[:200]})
        return None
    if r.status_code != 200:
        if tl:
            tl.event("client_download", status="fail",
                     detail={"path": url, "status": r.status_code})
        return None
    with open(dest, "wb") as fh:
        for chunk in r.iter_content(chunk_size=2**20):
            if chunk:
                fh.write(chunk)
    os.chmod(dest, 0o600)
    if tl:
        tl.event("client_download", status="ok",
                 detail={"path": url, "bytes": os.path.getsize(dest)})
    return dest


def _start_client(cfg, tl):
    """Run the client so it outlives this python process.

    `systemd-run --unit=` over a hand-written unit file or a bare nohup: it
    gives a named unit that `journalctl -u` can be pointed at, a one-word stop
    in teardown, and no state left in /etc/systemd/system for anyone to reason
    about later.

    Explicitly NOT the binary's own `service install`. On a real appliance that
    would collide with a genuine client deployment and leave behind exactly the
    kind of half-owned service this harness must never create.
    """
    r = shell.sudo(
        ["systemd-run", f"--unit={UNIT}", "--collect", "--property=Restart=no",
         CLIENT_BIN, "client", "-v"],
        cfg.sudo_password, timeout=120, tl=tl, stage="enrol_linux")
    if r.ok:
        return True, "systemd-run"

    # Containers and minimal images have no systemd. The fallback loses the
    # journal, so it writes its own log instead of leaving nothing behind.
    r = shell.sudo(
        ["bash", "-c",
         f"nohup setsid {CLIENT_BIN} client -v > /var/log/{UNIT}.log 2>&1 &"],
        cfg.sudo_password, timeout=120, tl=tl, stage="enrol_linux")
    return r.ok, "nohup" if r.ok else "failed"


def _dump_journal(cfg, run_dir, tl):
    """The client's own account of why it never checked in."""
    dest = os.path.join(run_dir, "logs", f"{UNIT}.log")
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    r = shell.sudo(["journalctl", "-u", UNIT, "--no-pager", "-n", "300"],
                   cfg.sudo_password, timeout=60, tl=tl, stage="enrol_linux")
    text = r.out or ""
    if not text.strip():
        r2 = shell.sudo(["tail", "-n", "300", f"/var/log/{UNIT}.log"],
                        cfg.sudo_password, timeout=60, tl=tl, stage="enrol_linux")
        text = r2.out or "(no journal and no fallback log)"
    with open(dest, "w", encoding="utf-8") as fh:
        fh.write(text)
    os.chmod(dest, 0o600)
    return dest
