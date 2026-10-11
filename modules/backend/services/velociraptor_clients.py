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
