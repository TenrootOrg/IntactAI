"""Velociraptor client versions -- what Settings → Velociraptor shows before an upgrade.

The server is upgraded by the upgrade engine (lib/upgrade/velociraptor/); its
clients are not. This reads the running server's version and every client's
agent version so the operator can see who is behind. Read-only: the one write
is "Refresh client info", a Generic.Client.Info hunt that makes each client
report its version (a client never interrogated reports none -- 9 of 10 on the
lab box, 2026-10-11).
"""
import time

ONLINE_SECONDS = 600     # same window as get_clients_from_snapshot / the dashboard
REFRESH_HUNT_DAYS = 7    # an offline client answers when it is next seen, within this


def version_key(v):
    """'0.77.2' -> (0, 77, 2); '' / unparsable -> None. Pre-release suffixes
    ('0.78.0-rc1') compare by their numeric part."""
    parts = []
    for p in str(v or "").strip().lstrip("v").split("."):
        num = ""
        for ch in p:
            if not ch.isdigit():
                break
            num += ch
        if not num:
            break
        parts.append(int(num))
    return tuple(parts) or None


def classify(rows, server_version, now=None):
    """Rows from clients() -> the status payload. Each client is current, behind,
    ahead or unknown (no version reported), and online or not."""
    now = time.time() if now is None else now
    server = version_key(server_version)
    clients, counts = [], {"current": 0, "behind": 0, "ahead": 0, "unknown": 0, "online": 0}
    for r in rows:
        v = (r.get("version") or "").strip()
        key = version_key(v)
        if key is None or server is None:
            state = "unknown"
        elif key == server:
            state = "current"
        else:
            state = "behind" if key < server else "ahead"
        seen = r.get("last_seen_at") or 0
        seen_s = seen / 1e6 if seen > 1e12 else seen          # clients() gives microseconds
        online = bool(seen_s) and now - seen_s < ONLINE_SECONDS
        counts[state] += 1
        counts["online"] += online
        clients.append({"client_id": r.get("client_id"), "hostname": r.get("hostname") or "",
                        "os": r.get("os") or "", "version": v, "state": state, "online": online,
                        "last_seen": int(seen_s) if seen_s else None})
    order = {"behind": 0, "unknown": 1, "ahead": 2, "current": 3}
    clients.sort(key=lambda c: (order[c["state"]], not c["online"], c["hostname"].lower()))
    return {"server_version": server_version or "", "clients": clients, "counts": counts,
            "total": len(clients)}


def _query(vql):
    from pyvelociraptor import api_pb2_grpc
    from services.velociraptor_service import setup_velociraptor_connection
    from services.vql_utils import execute_vql
    channel = setup_velociraptor_connection()
    if not channel:
        raise RuntimeError("Velociraptor is not reachable")
    try:
        return execute_vql(api_pb2_grpc.APIStub(channel), vql)
    finally:
        channel.close()


def client_versions():
    """The running server's version and every client's, classified (offline ones too)."""
    server = (_query("SELECT version.version AS v FROM config") or [{}])[0].get("v") or ""
    rows = _query("SELECT client_id, os_info.hostname AS hostname, os_info.system AS os, "
                  "agent_information.version AS version, last_seen_at "
                  "FROM clients() WHERE client_id != 'server'")
    return classify(rows, server)


def refresh_client_info():
    """Hunt Generic.Client.Info on every client: each one re-reports its version
    (and OS). Open for REFRESH_HUNT_DAYS so offline clients answer later.
    Returns the hunt id, or None."""
    from services.velociraptor_service import create_velociraptor_hunt
    return create_velociraptor_hunt(
        "Generic.Client.Info", description="Settings → Velociraptor: refresh client versions",
        cpu_limit=50, expire_seconds=REFRESH_HUNT_DAYS * 86400, timeout_seconds=300,
        max_rows=100000, max_bytes=50 * 1024 * 1024)


# ---------------------------------------------------------------------------
# Step 2 -- the packages the upgrade hunts install.
#
# Windows: Admin.Client.Upgrade.Windows (built in) runs the `WindowsMSI` tool.
# On the box (2026-10-11) that tool was EMPTY, and the nearby
# `VelociraptorWindowsMSI` was the plain upstream MSI with NO client config:
# pushed, every client would come back unable to find the server. Linux:
# Intact installs a repacked binary + systemd unit (Downloads page), not a
# .deb/.rpm, so the built-in Debian/RedHat upgrades do not fit;
# Intact.Client.Upgrade.Linux (config/) swaps the running binary instead.
# Only a package repacked with THIS server's client config, read back and
# compared, is ever registered.
# ---------------------------------------------------------------------------
import os as _os

OS_UPGRADE = {
    "windows": {"tool": "WindowsMSI", "artifact": "Admin.Client.Upgrade.Windows"},
    "linux": {"tool": "IntactVelociraptorLinux", "artifact": "Intact.Client.Upgrade.Linux"},
}
SOURCE_MSI_TOOL = "VelociraptorWindowsMSI"
LINUX_SOURCE = "/opt/velociraptor/linux/velociraptor"     # staged by the image: the server's version
SERVER_BIN = "/velociraptor/velociraptor"
CLIENT_CONFIG = "/velociraptor/client.config.yaml"
LINUX_ARTIFACT_FILE = _os.path.join(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))),
                                    "config", "Intact.Client.Upgrade.Linux.yaml")
PACKAGE_STATE = "/app/data/velociraptor_client_package.json"


def _velo_exec(*args, timeout=120, text=True):
    import subprocess
    from config import VELOCIRAPTOR_CONTAINER
    return subprocess.run(["docker", "exec", VELOCIRAPTOR_CONTAINER, *args],
                          capture_output=True, text=text, timeout=timeout)


def package_state():
    import json
    try:
        with open(PACKAGE_STATE) as fh:
            st = json.load(fh)
        return st if st.get("package_id") else {}       # a Windows-only state from before Linux: prepare again
    except (OSError, ValueError):
        return {}


def msi_config_text(blob):
    """The client config a repacked Velociraptor MSI installs, as text ("" if none).

    `velociraptor --embedded_config <msi> config show` cannot read it ("Unable to
    find signature": that reads configs embedded in an EXE). In the MSI the config
    is an uncompressed file `Config` inside the cabinet, written by repack over a
    fixed-size placeholder (23,898 bytes in 0.77.2) and installed as
    client.config.yaml. The plain upstream MSI carries no `Client:` section at all.
    """
    i = blob.find(b"\nClient:\n")
    if i < 0:
        return ""
    start = blob.rfind(b"version:\n", 0, i)
    start = start if start >= 0 and i - start < 4096 else i + 1
    end = blob.find(b"\x00", i)
    end = end if end > 0 and end - start < 65536 else start + 65536
    return blob[start:end].decode("utf-8", "replace")


def check_embedded_config(config_text, expected_urls, expected_ca):
    """"" when a package's embedded client config points at THIS server, else why not."""
    import yaml
    try:
        cfg = yaml.safe_load(config_text) or {}
    except yaml.YAMLError as e:
        return f"the embedded config is not readable ({e})"
    client = cfg.get("Client") or {}
    if not client:
        return "no client config is embedded"
    if sorted(client.get("server_urls") or []) != sorted(expected_urls or []):
        return f"it points at {client.get('server_urls')}, the server is {expected_urls}"
    if (client.get("ca_certificate") or "").strip() != (expected_ca or "").strip():
        return "its CA certificate is not this server's"
    return ""


def _register_tool(tool, path, name, version, sha):
    _query(f"SELECT inventory_add(tool='{tool}', file='{path}', accessor='file', filename='{name}', "
           f"serve_locally=TRUE, version='{version}') AS r FROM scope()")
    got = (_query(f"SELECT inventory_get(tool='{tool}').Definition AS d FROM scope()") or [{}])[0].get("d") or {}
    if got.get("filename") != name or (got.get("hash") or sha) != sha:
        raise RuntimeError(f"registering {tool} did not take (got {got.get('filename')!r})")


def _build_windows(server, cc, log):
    import time
    src = (_query(f"SELECT inventory_get(tool='{SOURCE_MSI_TOOL}').Definition AS d FROM scope()") or [{}])[0].get("d") or {}
    fname = src.get("filename") or ""
    if f"v{server}-" not in fname:
        raise RuntimeError(f"the {SOURCE_MSI_TOOL} tool is {fname or 'not set'}, not the {server} MSI -- "
                           "refresh the Velociraptor tools (upgrade --velo-refresh) first")
    log(f"Windows: repacking {fname} with this server's client config (Server.Utils.CreateMSI)")
    flow_id = ((_query("SELECT collect_client(client_id='server', artifacts='Server.Utils.CreateMSI') AS f "
                       "FROM scope()") or [{}])[0].get("f") or {}).get("flow_id")
    if not flow_id:
        raise RuntimeError("Velociraptor did not start Server.Utils.CreateMSI")
    state = ""
    for _ in range(90):                                       # up to ~3 min
        time.sleep(2)
        state = ((_query(f"SELECT state FROM flows(client_id='server', flow_id='{flow_id}')") or [{}])[0]
                 .get("state") or "")
        if state in ("FINISHED", "ERROR"):
            break
    if state != "FINISHED":
        raise RuntimeError(f"Server.Utils.CreateMSI ended {state or 'without finishing'} (flow {flow_id})")
    msi = _velo_exec("sh", "-c", f"ls -1 /var./clients/server/collections/{flow_id}/uploads/scope/*.msi "
                                 "| head -1").stdout.strip()
    if not msi:
        raise RuntimeError(f"Server.Utils.CreateMSI produced no MSI (flow {flow_id})")
    why = check_embedded_config(msi_config_text(_velo_exec("cat", msi, text=False).stdout),
                                cc.get("server_urls"), cc.get("ca_certificate"))
    if why:
        raise RuntimeError("the repacked Windows MSI is NOT safe to push: " + why)
    sha = _velo_exec("sha256sum", msi).stdout.split()[0]
    name = f"velociraptor-v{server}-windows-amd64-intact.msi"
    _register_tool(OS_UPGRADE["windows"]["tool"], msi, name, server, sha)
    log(f"Windows: config verified (points at {', '.join(cc['server_urls'])}, this server's CA); "
        f"registered as WindowsMSI (sha256 {sha[:12]}...)")
    return {"filename": name, "sha256": sha}


def _build_linux(server, cc, log):
    tmp = f"/tmp/intact-velociraptor-linux-{server}"
    try:
        r = _velo_exec(SERVER_BIN, "config", "repack", "--exe", LINUX_SOURCE, CLIENT_CONFIG, tmp)
        if r.returncode != 0:
            raise RuntimeError(f"repacking the Linux client failed: {(r.stderr or r.stdout).strip()[-300:]}")
        why = check_embedded_config(_velo_exec(SERVER_BIN, "--embedded_config", tmp, "config", "show").stdout,
                                    cc.get("server_urls"), cc.get("ca_certificate"))
        if why:
            raise RuntimeError("the repacked Linux client is NOT safe to push: " + why)
        ver = next((ln.split(":", 1)[1].strip() for ln in _velo_exec(tmp, "version").stdout.splitlines()
                    if ln.startswith("version:")), "")
        if ver != server:
            raise RuntimeError(f"the Linux client binary is {ver or 'unreadable'}, not the server's {server}")
        sha = _velo_exec("sha256sum", tmp).stdout.split()[0]
        name = f"velociraptor-v{server}-linux-amd64-intact"
        _register_tool(OS_UPGRADE["linux"]["tool"], tmp, name, server, sha)
    finally:
        _velo_exec("rm", "-f", tmp)
    _define_linux_artifact()
    log(f"Linux: repacked {server} binary, config verified; registered as IntactVelociraptorLinux "
        f"(sha256 {sha[:12]}...) with the Intact.Client.Upgrade.Linux artifact")
    return {"filename": name, "sha256": sha}


def _define_linux_artifact():
    """Load config/Intact.Client.Upgrade.Linux.yaml into the server. Passed as a VQL
    env value: the YAML holds both quote kinds and a triple-quoted script."""
    from pyvelociraptor import api_pb2, api_pb2_grpc
    from services.velociraptor_service import setup_velociraptor_connection
    with open(LINUX_ARTIFACT_FILE) as fh:
        definition = fh.read()
    channel = setup_velociraptor_connection()
    if not channel:
        raise RuntimeError("Velociraptor is not reachable")
    try:
        req = api_pb2.VQLCollectorArgs(
            env=[api_pb2.VQLEnv(key="Definition", value=definition)],
            Query=[api_pb2.VQLRequest(VQL="SELECT artifact_set(definition=Definition) AS a FROM scope()")])
        out = "".join(r.Response for r in api_pb2_grpc.APIStub(channel).Query(req, timeout=60) if r.Response)
    finally:
        channel.close()
    if "Intact.Client.Upgrade.Linux" not in out:
        raise RuntimeError(f"Velociraptor did not accept the Linux upgrade artifact ({out[:200]})")


def prepare_packages(log=print):
    """Build, verify and register the Windows MSI and the Linux binary for the
    server's version. Raises RuntimeError with the reason; nothing is recorded as
    ready unless both passed every check."""
    import hashlib
    import json
    import tempfile
    from datetime import datetime, timezone
    busy = running_upgrade()
    if busy:
        raise RuntimeError(f"an upgrade is still being followed ({busy.get('name')}); its offline clients "
                           "would get the new packages -- prepare once it has finished")
    server = (_query("SELECT version.version AS v FROM config") or [{}])[0].get("v") or ""
    cc = (_query("SELECT server_urls, ca_certificate FROM config") or [{}])[0]
    if not server or not cc.get("server_urls"):
        raise RuntimeError("could not read the server's version / client config")
    log(f"Server {server}; clients will be pointed at {', '.join(cc['server_urls'])}")
    win = _build_windows(server, cc, log)
    lin = _build_linux(server, cc, log)
    out = {"version": server, "windows": win, "linux": lin, "server_urls": cc["server_urls"],
           "package_id": hashlib.sha256((win["sha256"] + lin["sha256"]).encode()).hexdigest()[:12],
           "built_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    fd, tmp = tempfile.mkstemp(dir=_os.path.dirname(PACKAGE_STATE))
    with _os.fdopen(fd, "w") as fh:
        json.dump(out, fh, indent=1)
    _os.replace(tmp, PACKAGE_STATE)
    try:   # registered with admin_override, the tool is a copy in the filestore (/public/<hash>)
        from services.msi_generator_service import purge_msi_collection_uploads
        purge_msi_collection_uploads()
    except Exception:  # noqa: BLE001 -- disk hygiene only
        pass
    return out


# ---------------------------------------------------------------------------
# Step 3 -- the upgrade: pilot first, then the rest.
#
# Each run labels its targets and hunts each OS's upgrade artifact on that
# label only, so a client that is offline picks it up when next seen (the hunt
# stays open). Success is the client coming back reporting the server's
# version (the Windows MSI kills the client mid-flow; the Linux artifact
# returns, then restarts it). The run is the operator's record in Settings →
# Actions: the pilot is checked every 20 s for 15 min; the rest for 24 hours,
# once an hour (light on the server), each check logging "N of M upgraded".
# A backend restart resumes the watch (resume_upgrade_runs, at boot).
#
# Known gaps (left to a human): legacy agents (versions.velociraptor_legacy,
# 0.7.x -- they exist because 0.77 cannot run on Win7/2008R2/old glibc);
# musl-only Linux (the glibc binary fails its `version` check and nothing is
# changed); macOS (no upgrade artifact in Velociraptor 0.77.2).
# ---------------------------------------------------------------------------
RUN_TYPE = "velociraptor_client_upgrade"
ROLLBACK_SECONDS = 180          # Linux: OK reported, still old this long after = it was rolled back
WATCH = {"pilot": {"seconds": 15 * 60, "every": 20, "open_days": 1, "sleep": 5},
         "rest": {"seconds": 24 * 3600, "every": 3600, "open_days": 7, "sleep": 600}}


def _legacy_version():
    try:
        from services.legacy_velociraptor_service import _read_default_legacy_version
        return _read_default_legacy_version()
    except Exception:  # noqa: BLE001
        return "0.7.1"


def upgrade_targets(status, stage, client_ids=None, legacy=None):
    """(targets, refusals) for a stage. Only Windows/Linux clients known to be
    BEHIND the server are ever targeted -- never current, never newer (no
    downgrade), never unknown (refresh client info first), never a legacy agent."""
    legacy_mm = (version_key(legacy if legacy is not None else _legacy_version()) or ())[:2]
    by_id = {c["client_id"]: c for c in status["clients"]}

    def is_legacy(c):
        return (version_key(c["version"]) or ())[:2] == legacy_mm

    def eligible(c):
        return c["state"] == "behind" and c["os"] in OS_UPGRADE and not is_legacy(c)
    if stage == "pilot":
        ids = client_ids or [c["client_id"] for c in status["clients"] if eligible(c) and c["online"]][:1]
    else:
        ids = client_ids or [c["client_id"] for c in status["clients"] if eligible(c)]
    targets, refused = [], []
    for cid in ids:
        c = by_id.get(cid)
        if not c:
            refused.append(f"{cid}: not a known client")
        elif c["os"] not in OS_UPGRADE:
            refused.append(f"{c['hostname']}: {c['os'] or 'unknown OS'} -- only Windows and Linux clients "
                           "are upgraded from here")
        elif c["state"] != "behind":
            refused.append(f"{c['hostname']}: {c['state']} ({c['version'] or 'no version reported'}) "
                           "-- not behind the server")
        elif is_legacy(c):
            refused.append(f"{c['hostname']}: legacy agent {c['version']} -- it runs where the current version "
                           "cannot (Win7/2008R2, old glibc); upgrade by hand")
        elif stage == "pilot" and not c["online"]:
            refused.append(f"{c['hostname']}: offline -- a pilot must be online to be checked")
        else:
            targets.append(c)
    return targets, refused


def pilot_passed(package_id):
    """True when a pilot run with THESE packages upgraded every one of its clients."""
    from services.workflow_service import get_automation_runs_by_case, _system_case_id
    for r in get_automation_runs_by_case(_system_case_id()) or []:
        d = r.get("details") or {}
        if (r.get("automation_type") == RUN_TYPE and d.get("stage") == "pilot"
                and d.get("package_id") == package_id and r.get("status") == "completed"
                and d.get("upgraded") and not d.get("failed")):
            return True
    return False


def running_upgrade():
    """The upgrade run still being followed, if any. Only one at a time: a second
    run would hunt the same clients twice, and re-preparing the packages under a
    running one would change what its offline clients install later."""
    from services.workflow_service import get_automation_runs_by_case, _system_case_id
    return next((r for r in get_automation_runs_by_case(_system_case_id()) or []
                 if r.get("automation_type") == RUN_TYPE and r.get("status") in ("running", "pending")), None)


def start_upgrade(stage, client_ids=None):
    """Preflight, then start the run. Returns run_id; raises ValueError (the
    operator's reason) when it must not start."""
    import threading
    import time
    from services.workflow_service import create_automation_run, add_log_to_run, update_run_status
    if stage not in WATCH:
        raise ValueError("stage must be pilot or rest")
    busy = running_upgrade()
    if busy:
        raise ValueError(f"an upgrade is still being followed ({busy.get('name')}) -- wait for it to finish "
                         "or stop it in Settings → Actions")
    pkg = package_state()
    status = client_versions()
    server = status["server_version"]
    if pkg.get("version") != server:
        raise ValueError(f"no verified packages for the server's version {server} -- Prepare packages first")
    for os_name, spec in OS_UPGRADE.items():
        tool = (_query(f"SELECT inventory_get(tool='{spec['tool']}').Definition AS d FROM scope()")
                or [{}])[0].get("d") or {}
        if tool.get("filename") != pkg[os_name]["filename"]:
            raise ValueError(f"the {spec['tool']} tool is {tool.get('filename')!r}, not the verified package "
                             "-- Prepare packages again")
    if stage == "rest" and not pilot_passed(pkg["package_id"]):
        raise ValueError("upgrade a pilot client with these packages first; the rest follow once it succeeded")
    targets, refused = upgrade_targets(status, stage, client_ids)
    if not targets:
        raise ValueError("no client to upgrade" + (": " + "; ".join(refused) if refused else
                                                   " -- every Windows/Linux client is on the server's version"))
    label = f"intact-upgrade-{pkg['package_id'][:8]}-{stage}"
    run_id = create_automation_run(
        RUN_TYPE, f"Upgrade Velociraptor clients to {server} ({stage}: {len(targets)})",
        details={"stage": stage, "package_version": server, "package_id": pkg["package_id"], "label": label,
                 "targets": [{"client_id": c["client_id"], "hostname": c["hostname"], "os": c["os"],
                              "from": c["version"]} for c in targets],
                 "watch_until": time.time() + WATCH[stage]["seconds"],
                 "upgraded": [], "failed": [], "pending": [c["client_id"] for c in targets]})
    for why in refused:
        add_log_to_run(run_id, f"Skipped {why}", "warning")
    update_run_status(run_id, "running", progress=1)
    threading.Thread(target=_run_upgrade, args=(run_id,), daemon=True, name=f"velo-upgrade-{run_id}").start()
    return run_id


def resume_upgrade_runs():
    """At boot: keep watching upgrade runs a restart interrupted (their hunts
    already exist; the clients upgrade with or without us)."""
    import threading
    from services.workflow_service import get_automation_runs_by_case, _system_case_id, add_log_to_run
    for r in get_automation_runs_by_case(_system_case_id()) or []:
        if r.get("automation_type") == RUN_TYPE and r.get("status") in ("running", "pending"):
            add_log_to_run(r["run_id"], "Backend restarted -- still following this upgrade")
            threading.Thread(target=_run_upgrade, args=(r["run_id"],), daemon=True,
                             name=f"velo-upgrade-{r['run_id']}").start()


def hunt_flow_id(hunt_id):
    """A hunt's flow on each client: H.XYZ -> F.XYZ.H (first version used H.XYZ.H,
    which matches nothing -- every failure went unseen until the watch ended)."""
    return "F." + hunt_id.split(".", 1)[-1] + ".H"


def _upgrade_failed(client_id, os_name, hunt_id):
    """Why the upgrade failed on this client, or "" (not run yet / still running /
    succeeded). Seen live 2026-10-12: msiexec 1603 within a second, the client
    left on the old version -- and the run waited the full 15 minutes to say so."""
    import time
    flow_id = hunt_flow_id(hunt_id)
    flow = (_query(f"SELECT state, active_time FROM flows(client_id='{client_id}', flow_id='{flow_id}')")
            or [{}])[0]
    if flow.get("state") != "FINISHED":
        return ""
    rows = _query(f"SELECT ReturnCode, Stdout FROM source(client_id='{client_id}', flow_id='{flow_id}', "
                  f"artifact='{OS_UPGRADE[os_name]['artifact']}')")
    codes = [r.get("ReturnCode") for r in rows]
    if os_name == "linux" and 0 in codes:
        # "OK: replaced" and yet -- the caller only asks while the client is still on
        # the old version -- 3 minutes on: the new binary did not stay up and the
        # artifact's watchdog put the old one back (tested: broken build, back in 33 s).
        ended = (flow.get("active_time") or 0) / 1e6
        if ended and time.time() - ended > ROLLBACK_SECONDS:
            return ("installed, but the new version did not stay up -- the old binary was put back "
                    "(see `journalctl -u velociraptor_client` on that host)")
        return ""
    if not codes or any(c == 0 for c in codes):
        return ""
    if os_name == "linux":
        said = next((str(r.get("Stdout") or "").strip() for r in rows if r.get("Stdout")), "")
        return said or f"the upgrade returned {codes[0]}"
    hint = (" (Windows Installer failed; 1603 when the same version is already installed from an "
            "installer file that no longer exists -- see the MsiInstaller events on that host)"
            if 1603 in codes else "")
    return f"msiexec returned {', '.join(str(c) for c in codes)}{hint}"


def _run_upgrade(run_id):
    """Create the hunts (once), then watch until every target upgraded or the
    watch window closes. All state lives in the run's details, so a restart
    resumes exactly here."""
    import time
    from services.workflow_service import (add_log_to_run, update_run_status, get_automation_run,
                                           register_cancel_event, unregister_cancel)
    log = lambda m, lvl="info": add_log_to_run(run_id, m, lvl)          # noqa: E731
    cancel = register_cancel_event(run_id)        # Settings → Actions → Stop wakes the wait at once
    try:
        d = (get_automation_run(run_id) or {}).get("details") or {}
        stage, server, label = d["stage"], d["package_version"], d["label"]
        w = WATCH[stage]
        by_id = {t["client_id"]: t for t in d["targets"]}
        total = len(by_id)
        hunts = dict(d.get("hunts") or {})
        if not hunts:
            for cid in by_id:
                _query(f"SELECT label(client_id='{cid}', labels=['{label}'], op='set') FROM scope()")
            for os_name in sorted({t["os"] for t in by_id.values()}):
                art = OS_UPGRADE[os_name]["artifact"]
                hunt = (_query(
                    "LET h = hunt(description='Settings → Velociraptor: upgrade clients to " + server
                    + f" ({stage}, {os_name})', artifacts='{art}', "
                    f"spec=dict(`{art}`=dict(SleepDuration='{w['sleep']}')), include_labels=['{label}'], "
                    f"expires=now() + {w['open_days'] * 86400}, timeout=900, cpu_limit=50) "
                    "SELECT HuntId FROM h") or [{}])[0].get("HuntId")
                if not hunt:
                    raise RuntimeError(f"Velociraptor did not create the {os_name} upgrade hunt")
                hunts[os_name] = hunt
                log(f"Hunt {hunt}: {art} on {sum(t['os'] == os_name for t in by_id.values())} {os_name} "
                    f"client(s) labelled {label} (open {w['open_days']} day(s); offline clients upgrade "
                    "when next seen)")
            update_run_status(run_id, "running", progress=5, details={"hunts": hunts})
            log(f"Following the upgrade: every {w['every'] // 60 or w['every']} "
                f"{'min' if w['every'] >= 60 else 's'} for {w['seconds'] // 3600 or w['seconds'] // 60} "
                f"{'hour(s)' if w['seconds'] >= 3600 else 'min'}")

        done = set(d.get("upgraded") or [])
        failed = set(d.get("failed") or [])
        asked, checks = {}, 0
        until = float(d.get("watch_until") or time.time() + w["seconds"])

        def pending():
            return [cid for cid in by_id if cid not in done and cid not in failed]
        while pending() and time.time() < until:
            if cancel.wait(min(w["every"], max(1, until - time.time()))):
                break
            checks += 1
            rows = {r["client_id"]: r for r in client_versions()["clients"]}
            for cid in pending():
                row, t = rows.get(cid) or {}, by_id[cid]
                if row.get("version") and version_key(row["version"]) == version_key(server):
                    done.add(cid)
                    log(f"{t['hostname']} ({t['os']}): upgraded {t['from']} → {row['version']}", "success")
                    _query(f"SELECT label(client_id='{cid}', labels=['{label}'], op='remove') FROM scope()")
                elif (why := _upgrade_failed(cid, t["os"], hunts[t["os"]])):
                    # It ran and failed: the client is alive on the old version and
                    # will stay there -- say so now, not at the end of the watch.
                    failed.add(cid)
                    log(f"{t['hostname']} ({t['os']}): {why}", "error")
                elif row.get("online") and time.time() - asked.get(cid, 0) > 120:
                    # The server may keep the old version on record after a restart:
                    # ask the client to re-report (cheap, read-only).
                    _query(f"SELECT collect_client(client_id='{cid}', artifacts='Generic.Client.Info') FROM scope()")
                    asked[cid] = time.time()
            left = pending()
            offline = [cid for cid in left if not (rows.get(cid) or {}).get("online")]
            update_run_status(run_id, "running", progress=5 + int(90 * (len(done) + len(failed)) / total),
                              details={"upgraded": sorted(done), "failed": sorted(failed), "pending": left})
            if stage == "rest":       # the hourly line the operator follows
                log(f"Hour {checks}: {len(done)} of {total} upgraded, {len(left)} pending "
                    f"({len(offline)} offline), {len(failed)} failed")

        if cancel.is_set():
            # Stopped by the operator (request_stop already marked the run cancelled):
            # stop the hunts and unlabel who is left, so nothing else is upgraded.
            for hunt in hunts.values():
                _query(f"SELECT hunt_update(hunt_id='{hunt}', stop=TRUE) FROM scope()")
            for cid in pending():
                _query(f"SELECT label(client_id='{cid}', labels=['{label}'], op='remove') FROM scope()")
            # force: the run is already 'cancelled', and this IS the work the stop did
            add_log_to_run(run_id, f"Stopped: {len(done)} of {total} upgraded, {len(failed)} failed; hunts "
                                   f"stopped -- the {len(pending())} not upgraded yet will not be",
                           "warning", force=True)
            return
        rows = {r["client_id"]: r for r in client_versions()["clients"]}
        left = pending()
        offline = [cid for cid in left if not (rows.get(cid) or {}).get("online")]
        for cid in left:
            t = by_id[cid]
            if cid in offline:
                log(f"{t['hostname']}: offline -- it still upgrades when next seen (hunt {hunts[t['os']]} "
                    f"open {w['open_days']} day(s))", "warning")
            else:
                log(f"{t['hostname']}: still {t['from']} -- check the upgrade hunt's flow on that client "
                    "in Velociraptor", "error")
        bad = sorted(failed | (set(left) - set(offline)))
        for cid in bad:       # offline ones keep it: the open hunt reaches them through the label
            _query(f"SELECT label(client_id='{cid}', labels=['{label}'], op='remove') FROM scope()")
        status = "failed" if bad or (stage == "pilot" and left) else "completed"
        update_run_status(run_id, status, progress=100,
                          error=(f"{len(bad)} client(s) did not upgrade" if bad else None),
                          details={"upgraded": sorted(done), "failed": bad, "pending": offline})
        log(f"Done: {len(done)} of {total} upgraded"
            + (f", {len(offline)} pending (offline)" if offline else "")
            + (f", {len(bad)} failed" if bad else ""), "success" if status == "completed" else "warning")
    except Exception as e:  # noqa: BLE001
        log(f"Upgrade stopped: {e}", "error")
        update_run_status(run_id, "failed", progress=100, error=str(e)[:300])
    finally:
        unregister_cancel(run_id)
