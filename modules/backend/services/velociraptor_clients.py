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
    ahead, unknown (no version reported) or imported, and online or not.

    "imported" = the record an offline-collection import leaves: no agent ever
    ran there (no agent name, never interrogated, no version). It is not part of
    the fleet and can never answer or be upgraded -- the 9 AdatumLab hosts on the
    lab box read as "version unknown, Refresh client info" until 2026-10-12."""
    now = time.time() if now is None else now
    server = version_key(server_version)
    clients, counts = [], {"current": 0, "behind": 0, "ahead": 0, "unknown": 0, "imported": 0, "online": 0}
    for r in rows:
        v = (r.get("version") or "").strip()
        key = version_key(v)
        if "agent" in r and not r.get("agent") and not r.get("interrogated") and not v:
            state = "imported"
        elif key is None or server is None:
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
                        "os": r.get("os") or "", "release": r.get("release") or "",
                        "labels": list(r.get("labels") or []),
                        "version": v, "state": state, "online": online,
                        "last_seen": int(seen_s) if seen_s else None})
    order = {"behind": 0, "unknown": 1, "ahead": 2, "current": 3, "imported": 4}
    clients.sort(key=lambda c: (order[c["state"]], not c["online"], c["hostname"].lower()))
    return {"server_version": server_version or "", "clients": clients, "counts": counts,
            "total": len(clients)}


def _query(vql, timeout=120):
    """Rows of one VQL query (max_row is a batch size, not a cap: checked with 2,500
    rows; a fleet of thousands comes back whole)."""
    from pyvelociraptor import api_pb2_grpc
    from services.velociraptor_service import setup_velociraptor_connection
    from services.vql_utils import execute_vql
    channel = setup_velociraptor_connection()
    if not channel:
        raise RuntimeError("Velociraptor is not reachable")
    try:
        return execute_vql(api_pb2_grpc.APIStub(channel), vql, timeout=timeout, max_row=5000)
    finally:
        channel.close()


def client_versions():
    """The running server's version and every client's, classified (offline ones too)."""
    server = (_query("SELECT version.version AS v FROM config") or [{}])[0].get("v") or ""
    rows = _query("SELECT client_id, os_info.hostname AS hostname, os_info.system AS os, "
                  "os_info.release AS release, agent_information.version AS version, labels, last_seen_at, "
                  "agent_information.name AS agent, last_interrogate_flow_id AS interrogated "
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
# Known gaps (left to a human): Windows too old for the current build (Go
# 1.21+ needs Windows 10 / Server 2016: Win7/8, 2008 R2, 2012 keep their legacy
# agent -- decided by the OS RELEASE, not the client's version: a RISX fleet on
# 0.7.x running Windows 10 must be upgradable); old-glibc or musl-only Linux
# (the new binary fails its `version` check on the host and nothing is
# changed); macOS (no upgrade artifact in Velociraptor 0.77.2).
# ---------------------------------------------------------------------------
RUN_TYPE = "velociraptor_client_upgrade"
ROLLBACK_SECONDS = 180          # Linux: OK reported, still old this long after = it was rolled back
WATCH = {"pilot": {"seconds": 15 * 60, "every": 20, "open_days": 1, "sleep": 5},
         "rest": {"seconds": 24 * 3600, "every": 3600, "open_days": 7, "sleep": 600}}


_OLD_WINDOWS = __import__("re").compile(
    r"\bWindows (?:XP|Vista|7|8(?:\.1)?)\b|\bServer (?:20(?:03|08|12))\b", __import__("re").I)
_LABEL_RE = __import__("re").compile(r"^[A-Za-z0-9_.:-]{1,64}$")


def windows_can_run_current(release):
    """(ok, why). The current Velociraptor build needs Windows 10 / Server 2016+;
    pushing its MSI to an older Windows leaves a client that cannot start, and
    Windows has no rollback. An unknown release is refused too."""
    if not (release or "").strip():
        return False, "Windows release unknown -- Refresh client info first"
    if _OLD_WINDOWS.search(release):
        return False, (f"{release} cannot run the current build (Windows 10 / Server 2016 or newer "
                       "needed) -- it keeps its legacy agent; upgrade by hand")
    return True, ""


# Why a client is not upgraded from here, grouped for the summary: a fleet of
# thousands gets one line per reason with a count, never one line per client.
NOT_UPGRADABLE = {
    "unknown_version": "Version unknown — Refresh client info",
    "unsupported_os": "macOS or another OS — upgrade by hand",
    "old_windows": "Windows older than 10 / Server 2016 — keeps its legacy agent",
    "unknown_release": "Windows release unknown — Refresh client info",
}


def eligibility(c):
    """(key, why) -- key is None when the client may be upgraded from here."""
    if c["state"] == "imported":
        return "imported", "an offline-collection import -- no agent runs there"
    if c["state"] == "current":
        return "current", "on the server's version"
    if c["state"] == "ahead":
        return "ahead", f"{c['version']} is newer than the server -- never downgraded"
    if c["state"] == "unknown":
        return "unknown_version", "no version reported -- Refresh client info first"
    if c["os"] not in OS_UPGRADE:
        return "unsupported_os", f"{c['os'] or 'unknown OS'} -- only Windows and Linux are upgraded from here"
    if c["os"] == "windows":
        ok, why = windows_can_run_current(c.get("release"))
        if not ok:
            return ("unknown_release" if not (c.get("release") or "").strip() else "old_windows"), why
    return None, ""


def summarize(status):
    """Everything the tab shows above the table, computed here (one pass)."""
    by_version, by_os, groups = {}, {}, {}
    eligible = eligible_online = 0
    for c in status["clients"]:
        if c["state"] == "imported":
            continue                      # not part of the fleet: counted apart
        by_version[c["version"] or ""] = by_version.get(c["version"] or "", 0) + 1
        by_os[c["os"] or ""] = by_os.get(c["os"] or "", 0) + 1
        key, _ = eligibility(c)
        if key is None:
            eligible += 1
            eligible_online += c["online"]
        elif key in NOT_UPGRADABLE:
            groups[key] = groups.get(key, 0) + 1
    versions = sorted(by_version.items(), key=lambda kv: (version_key(kv[0]) or (-1,)), reverse=True)
    imported = status["counts"].get("imported", 0)
    return {"server_version": status["server_version"], "total": status["total"], "counts": status["counts"],
            "agents": status["total"] - imported, "imported": imported,
            "blocked": sum(groups.values()),
            "by_version": [{"version": v, "n": n} for v, n in versions],
            "by_os": [{"os": o, "n": n} for o, n in sorted(by_os.items(), key=lambda kv: -kv[1])],
            "eligible": eligible, "eligible_online": eligible_online,
            "not_upgradable": [{"key": k, "label": NOT_UPGRADABLE[k], "n": groups[k]}
                               for k in NOT_UPGRADABLE if groups.get(k)]}


def filter_clients(status, state=None, os=None, version=None, online=None, q=None, reason=None):
    """Server-side filter for the paged table. reason: 'eligible', 'blocked' (any
    reason it cannot be upgraded from here) or a NOT_UPGRADABLE key. Imports are
    left out unless asked for (state='imported')."""
    q = (q or "").strip().lower()
    out = []
    for c in status["clients"]:
        if c["state"] == "imported" and state != "imported":
            continue
        if state and c["state"] != state:
            continue
        if os and c["os"] != os:
            continue
        if version is not None and version != "__any__" and (c["version"] or "") != version:
            continue
        if online is not None and c["online"] != online:
            continue
        if q and q not in c["hostname"].lower() and q not in c["client_id"].lower():
            continue
        if reason:
            key, _ = eligibility(c)
            if reason == "eligible":
                if key is not None:
                    continue
            elif reason == "blocked":
                if key not in NOT_UPGRADABLE:
                    continue
            elif key != reason:
                continue
        out.append(c)
    return out


def pilot_candidates(status, q="", limit=20):
    """Online clients the pilot may use, matching q (host or client id)."""
    rows = [c for c in filter_clients(status, online=True, q=q, reason="eligible")]
    return rows[:limit]


def upgrade_targets(status, stage, client_ids=None, label=None, limit=None):
    """(targets, refusals). Explicit client_ids are each checked (refusals say why);
    otherwise every eligible client -- online only for a pilot, which takes one --
    narrowed to a Velociraptor label and capped at `limit` (a wave), online first.
    Never current, never newer (no downgrade), never unknown, never a Windows too
    old for the current build, never macOS."""
    by_id = {c["client_id"]: c for c in status["clients"]}
    if client_ids:
        targets, refused = [], []
        for cid in client_ids:
            c = by_id.get(cid)
            key, why = eligibility(c) if c else ("missing", "not a known client")
            if key is None and stage == "pilot" and not c["online"]:
                key, why = "offline", "offline -- a pilot must be online to be checked"
            if key is None:
                targets.append(c)
            else:
                refused.append(f"{c['hostname'] if c else cid}: {why}")
        return targets, refused
    pool = [c for c in status["clients"] if eligibility(c)[0] is None
            and (stage != "pilot" or c["online"]) and (not label or label in c["labels"])]
    pool.sort(key=lambda c: (not c["online"], c["hostname"].lower()))
    if stage == "pilot":
        pool = pool[:1]
    elif limit:
        pool = pool[:int(limit)]
    return pool, []


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


def start_upgrade(stage, client_ids=None, label=None, limit=None):
    """Preflight, then start the run. Returns run_id; raises ValueError (the
    operator's reason) when it must not start."""
    import threading
    import time
    from services.workflow_service import create_automation_run, add_log_to_run, update_run_status
    if stage not in WATCH:
        raise ValueError("stage must be pilot or rest")
    if label and not _LABEL_RE.match(label):
        raise ValueError("a label is letters, digits and . _ : - (at most 64)")
    if limit is not None:
        try:
            limit = int(limit)
        except (TypeError, ValueError):
            raise ValueError("the wave size must be a number")
        if limit < 1:
            raise ValueError("the wave size must be at least 1")
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
    targets, refused = upgrade_targets(status, stage, client_ids, label=label, limit=limit)
    if not targets:
        why = "; ".join(refused[:5]) if refused else (
            f"no eligible client{' labelled ' + label if label else ''} -- see 'Not upgraded from here'")
        raise ValueError("no client to upgrade: " + why)
    run_label = f"intact-upgrade-{pkg['package_id'][:8]}-{stage}"
    scope = (f" labelled {label}" if label else "") + (f", wave of {limit}" if limit else "")
    run_id = create_automation_run(
        RUN_TYPE, f"Upgrade Velociraptor clients to {server} ({stage}: {len(targets)}{scope})",
        details={"stage": stage, "package_version": server, "package_id": pkg["package_id"], "label": run_label,
                 "scope": {"label": label, "limit": limit},
                 "targets": [{"client_id": c["client_id"], "hostname": c["hostname"], "os": c["os"],
                              "from": c["version"]} for c in targets],
                 "watch_until": time.time() + WATCH[stage]["seconds"],
                 "upgraded": [], "failed": [], "pending": [c["client_id"] for c in targets]})
    for why in refused[:20]:
        add_log_to_run(run_id, f"Skipped {why}", "warning")
    if len(refused) > 20:
        add_log_to_run(run_id, f"... and {len(refused) - 20} more skipped", "warning")
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
    """A hunt's flow on each client: H.XYZ -> F.XYZ.H."""
    return "F." + hunt_id.split(".", 1)[-1] + ".H"


WINDOWS_IDLE_SECONDS = 300      # msiexec codes in, all non-zero, no activity since: it failed


def outcomes(flows, results, os_name, now=None):
    """{client_id: why it failed} for a hunt, from ONE hunt_flows() and ONE
    hunt_results() query -- not two queries per client (a fleet of thousands).
    Only failures; a success shows up as the client reporting the new version.

    Seen live: the Windows flow of a failed MSI stayed IN_PROGRESS for hours after
    msiexec returned 1603 twice, so "finished" is never required -- results with
    no zero and no activity for WINDOWS_IDLE_SECONDS is a failure. Linux: the
    artifact's FAIL: line; or OK and, ROLLBACK_SECONDS on, the client still old
    (the caller only asks about clients still on the old version) = rolled back."""
    import time
    now = time.time() if now is None else now
    by_client = {}
    for r in results:
        by_client.setdefault(r.get("ClientId"), []).append(r)
    out = {}
    for f in flows:
        cid = f.get("ClientId")
        flow = f.get("Flow") or {}
        rows = by_client.get(cid) or []
        codes = [r.get("ReturnCode") for r in rows]
        idle = now - (flow.get("active_time") or 0) / 1e6
        state = flow.get("state") or ""
        if not codes:
            if state == "ERROR":
                out[cid] = f"the upgrade did not run: {(flow.get('status') or 'flow error')[:200]}"
            continue
        if os_name == "linux":
            if 0 in codes:
                if idle > ROLLBACK_SECONDS:
                    out[cid] = ("installed, but the new version did not stay up -- the old binary was put "
                                "back (see `journalctl -u velociraptor_client` on that host)")
                continue
            said = next((str(r.get("Stdout") or "").strip() for r in rows if r.get("Stdout")), "")
            out[cid] = said or f"the upgrade returned {codes[0]}"
            continue
        if 0 in codes or (state != "FINISHED" and idle <= WINDOWS_IDLE_SECONDS):
            continue
        hint = (" (Windows Installer failed; 1603 when the same version is already installed from an "
                "installer file that no longer exists -- see the MsiInstaller events on that host)"
                if 1603 in codes else "")
        out[cid] = f"msiexec returned {', '.join(str(c) for c in codes)}{hint}"
    return out


def _hunt_failures(hunt_id, os_name):
    art = OS_UPGRADE[os_name]["artifact"]
    return outcomes(_query(f"SELECT ClientId, Flow FROM hunt_flows(hunt_id='{hunt_id}')"),
                    _query(f"SELECT ClientId, ReturnCode, Stdout FROM hunt_results(hunt_id='{hunt_id}', "
                           f"artifact='{art}')"), os_name)


def _label_clients(ids, label, op):
    """One VQL per 200 clients, not one per client."""
    from services.vql_safety import is_valid_client_id
    ids = [i for i in ids if is_valid_client_id(i)]
    for i in range(0, len(ids), 200):
        arr = "[" + ",".join(f"'{c}'" for c in ids[i:i + 200]) + "]"
        _query(f"SELECT label(client_id=_value, labels=['{label}'], op='{op}') AS r FROM foreach(row={arr})")


def spread_seconds(n):
    """The random delay before each client downloads: 2 s per client, at least 10
    min, at most 4 h -- 1,000 clients x a 27 MB MSI over 10 min was ~45 MB/s off
    the Velociraptor server."""
    return min(4 * 3600, max(600, 2 * n))


def _names(rows, n=3):
    hosts = [r["hostname"] for r in rows[:n]]
    return ", ".join(hosts) + (f" and {len(rows) - n} more" if len(rows) > n else "")


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
            _label_clients(list(by_id), label, "set")
            sleep = w["sleep"] if stage == "pilot" else spread_seconds(total)
            for os_name in sorted({t["os"] for t in by_id.values()}):
                art = OS_UPGRADE[os_name]["artifact"]
                hunt = (_query(
                    "LET h = hunt(description='Settings → Velociraptor: upgrade clients to " + server
                    + f" ({stage}, {os_name})', artifacts='{art}', "
                    f"spec=dict(`{art}`=dict(SleepDuration='{sleep}')), include_labels=['{label}'], "
                    # the per-client timeout covers the random wait plus the install
                    f"expires=now() + {w['open_days'] * 86400}, timeout={sleep + 900}, cpu_limit=50) "
                    "SELECT HuntId FROM h") or [{}])[0].get("HuntId")
                if not hunt:
                    raise RuntimeError(f"Velociraptor did not create the {os_name} upgrade hunt")
                hunts[os_name] = hunt
                log(f"Hunt {hunt}: {art} on {sum(t['os'] == os_name for t in by_id.values())} {os_name} "
                    f"client(s) labelled {label}; downloads spread over {sleep // 60} min; open "
                    f"{w['open_days']} day(s) (offline clients upgrade when next seen)")
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
            new_done = [cid for cid in pending() if (rows.get(cid) or {}).get("version")
                        and version_key(rows[cid]["version"]) == version_key(server)]
            done.update(new_done)
            if new_done:
                _label_clients(new_done, label, "remove")
                if stage == "pilot" or len(new_done) <= 5:
                    for cid in new_done:
                        t = by_id[cid]
                        log(f"{t['hostname']} ({t['os']}): upgraded {t['from']} → {rows[cid]['version']}", "success")
                else:
                    log(f"+{len(new_done)} upgraded: {_names([by_id[c] for c in new_done])}", "success")
            new_failed, pend = {}, set(pending())
            for os_name, hunt in hunts.items():
                for cid, why in _hunt_failures(hunt, os_name).items():
                    if cid in pend:
                        new_failed[cid] = why
            failed.update(new_failed)
            for i, (cid, why) in enumerate(new_failed.items()):
                if i == 20:
                    log(f"... and {len(new_failed) - 20} more failed (all listed in this run's details)", "error")
                    break
                log(f"{by_id[cid]['hostname']} ({by_id[cid]['os']}): {why}", "error")
            if stage == "pilot":
                for cid in pending():
                    if (rows.get(cid) or {}).get("online") and time.time() - asked.get(cid, 0) > 120:
                        # the server may keep the old version on record after a restart
                        _query(f"SELECT collect_client(client_id='{cid}', artifacts='Generic.Client.Info') FROM scope()")
                        asked[cid] = time.time()
            left = pending()
            offline = [cid for cid in left if not (rows.get(cid) or {}).get("online")]
            update_run_status(run_id, "running", progress=5 + int(90 * (len(done) + len(failed)) / total),
                              details={"upgraded": sorted(done), "failed": sorted(failed), "pending": left,
                                       "failures": {**(d.get("failures") or {}), **new_failed}})
            d["failures"] = {**(d.get("failures") or {}), **new_failed}
            if stage == "rest":       # the hourly line the operator follows
                log(f"Hour {checks}: {len(done)} of {total} upgraded, {len(left)} pending "
                    f"({len(offline)} offline), {len(failed)} failed")

        if cancel.is_set():
            # Stopped by the operator (request_stop already marked the run cancelled):
            # stop the hunts and unlabel who is left, so nothing else is upgraded.
            for hunt in hunts.values():
                _query(f"SELECT hunt_update(hunt_id='{hunt}', stop=TRUE) FROM scope()")
            _label_clients(pending(), label, "remove")
            # force: the run is already 'cancelled', and this IS the work the stop did
            add_log_to_run(run_id, f"Stopped: {len(done)} of {total} upgraded, {len(failed)} failed; hunts "
                                   f"stopped -- the {len(pending())} not upgraded yet will not be",
                           "warning", force=True)
            return
        rows = {r["client_id"]: r for r in client_versions()["clients"]}
        left = pending()
        offline = [cid for cid in left if not (rows.get(cid) or {}).get("online")]
        stuck = [cid for cid in left if cid not in offline]
        if offline:
            log(f"{len(offline)} offline ({_names([by_id[c] for c in offline])}) -- they still upgrade when "
                f"next seen, while the hunt is open ({w['open_days']} day(s))", "warning")
        for cid in stuck[:20]:
            log(f"{by_id[cid]['hostname']}: still {by_id[cid]['from']} -- check the upgrade hunt's flow on "
                "that client in Velociraptor", "error")
        if len(stuck) > 20:
            log(f"... and {len(stuck) - 20} more still on the old version", "error")
        bad = sorted(failed | set(stuck))
        _label_clients(bad, label, "remove")   # offline ones keep it: the open hunt reaches them through it
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


# ---------------------------------------------------------------------------
# Step 4 -- after a server upgrade the packages are rebuilt by themselves; the
# CLIENTS are not: nothing is pushed without the operator ("we notify, never
# auto-act"). Checked here, not in the host-side upgrade engine, so it holds
# however the server got its new version. Switch: Settings → Velociraptor
# ("Rebuild packages automatically", frontend_config velociraptor.auto_prepare_packages).
# ---------------------------------------------------------------------------
PACKAGE_RUN_TYPE = "velociraptor_client_package"
AUTO_FIRST_SECONDS = 60
AUTO_EVERY_SECONDS = 600
AUTO_RETRY_SECONDS = 6 * 3600
_auto = {"started": False, "tried": {}}        # server version -> last automatic attempt


def auto_prepare_enabled():
    try:
        from services.storage.config_store import load_frontend_config
        return bool(((load_frontend_config() or {}).get("velociraptor") or {}).get("auto_prepare_packages", True))
    except Exception:  # noqa: BLE001 -- unreadable settings: keep the default
        return True


def set_auto_prepare(enabled):
    from services.storage.config_store import load_frontend_config, save_frontend_config
    v = dict((load_frontend_config() or {}).get("velociraptor") or {})
    v["auto_prepare_packages"] = bool(enabled)
    save_frontend_config({"velociraptor": v})


def preparing():
    """The package run in progress, if any."""
    from services.workflow_service import get_automation_runs_by_case, _system_case_id
    return next((r for r in get_automation_runs_by_case(_system_case_id()) or []
                 if r.get("automation_type") == PACKAGE_RUN_TYPE and r.get("status") in ("running", "pending")), None)


def last_package_run():
    from services.workflow_service import get_automation_runs_by_case, _system_case_id
    runs = [r for r in get_automation_runs_by_case(_system_case_id()) or []
            if r.get("automation_type") == PACKAGE_RUN_TYPE]
    return max(runs, key=lambda r: r.get("created_at") or "", default=None)


def start_prepare_run(reason=None):
    """Prepare packages as a System action (Settings → Actions). Returns run_id;
    ValueError when one must not start now."""
    import threading
    from services.workflow_service import create_automation_run, add_log_to_run, update_run_status
    busy = running_upgrade()
    if busy:
        raise ValueError(f"an upgrade is still being followed ({busy.get('name')}) -- prepare once it has finished")
    if preparing():
        raise ValueError("the packages are already being prepared")
    run_id = create_automation_run(PACKAGE_RUN_TYPE, "Prepare the Velociraptor client packages"
                                   + (f" ({reason})" if reason else ""))
    update_run_status(run_id, "running", progress=5)

    def _work():
        try:
            pkg = prepare_packages(log=lambda m: add_log_to_run(run_id, m))
            update_run_status(run_id, "completed", progress=100, details={"package": pkg})
            add_log_to_run(run_id, f"Ready for {pkg['version']}: {pkg['windows']['filename']}, "
                                   f"{pkg['linux']['filename']} -- upgrade the clients from Settings → "
                                   "Velociraptor (pilot first)", "success")
        except Exception as e:  # noqa: BLE001 -- the reason is the result
            add_log_to_run(run_id, f"Not prepared: {e}", "error")
            update_run_status(run_id, "failed", progress=100, error=str(e)[:300])
    threading.Thread(target=_work, daemon=True, name=f"velo-package-{run_id}").start()
    return run_id


def auto_prepare_check(now=None):
    """Rebuild the packages when the server's version moved past them. Returns
    the run_id it started, or None. Never upgrades a client."""
    import time
    now = time.time() if now is None else now
    if not auto_prepare_enabled():
        return None
    server = (_query("SELECT version.version AS v FROM config") or [{}])[0].get("v") or ""
    if not server or package_state().get("version") == server:
        return None
    if running_upgrade() or preparing():
        return None
    last = _auto["tried"].get(server)
    if last is not None and now - last < AUTO_RETRY_SECONDS:       # tried (and failed) recently
        return None
    _auto["tried"][server] = now
    have = package_state().get("version")
    return start_prepare_run(f"automatic: server is {server}" + (f", packages were {have}" if have else ""))


def start_auto_prepare():
    """At boot: check once after AUTO_FIRST_SECONDS, then every AUTO_EVERY_SECONDS."""
    import threading
    import time
    if _auto["started"]:
        return
    _auto["started"] = True

    def _loop():
        time.sleep(AUTO_FIRST_SECONDS)
        while True:
            try:
                auto_prepare_check()
            except Exception as e:  # noqa: BLE001 -- Velociraptor down, etc.: try again later
                print(f"[VELO-PACKAGES] automatic check skipped: {e}", flush=True)
            time.sleep(AUTO_EVERY_SECONDS)
    threading.Thread(target=_loop, daemon=True, name="velo-auto-prepare").start()
