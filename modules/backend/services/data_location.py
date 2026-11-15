"""Data location: where Intact keeps its data (config.yaml `data_path`).

Empty (the default) is the system disk. A folder -- usually on another drive --
holds Docker's data root (every module's volumes and the images) and the
install's data/ folder. scripts/move-data.sh does the move. It must run ON THE
HOST, outside Docker, because it stops Docker -- and this backend with it -- so
it is started as a transient systemd unit, through a one-shot privileged helper
container that enters the host's PID 1 namespaces. That grants nothing new: this
backend already holds docker.sock, which is root on the host, and the upgrade
helper (services/upgrade_launcher.py) runs host work the same way.

The script writes <install>/data-move-status.json as it goes, and config.yaml's
data_path only once the move succeeded; Settings reads both, including after the
backend comes back up on the new location.
"""
import json
import os
import re
import shutil
import subprocess
import time

from services.proc import HOST_PATH

SCRIPT = f"{HOST_PATH}/scripts/move-data.sh"
STATUS_FILE = os.path.join(HOST_PATH, "data-move-status.json")
_PATH_RE = re.compile(r"^/[A-Za-z0-9._/-]{1,200}$")
# A move stops every service: never under one of these, which swap containers.
_BLOCKING_TYPES = {"upgrade", "upgrade_package_upload", "velociraptor_client_upgrade"}
WARN_PCT, CRIT_PCT = 80, 90


def clean_path(path):
    """'' for the system disk, else a safe absolute folder path; ValueError."""
    path = (path or "").strip()
    if path in ("", "default", "system"):
        return ""
    path = path.rstrip("/")
    if not _PATH_RE.match(path) or ".." in path:
        raise ValueError("Use an absolute folder path of letters, digits and . _ - / (e.g. /mnt/intact-data)")
    return path


def read_setting():
    from services.auth_service import config_path
    import yaml
    try:
        with open(config_path(), encoding="utf-8") as fh:
            return ((yaml.safe_load(fh) or {}).get("data_path") or "").strip()
    except Exception:  # noqa: BLE001 -- no or unreadable config: the default
        return ""


def _own_image():
    r = subprocess.run(["docker", "inspect", "-f", "{{.Config.Image}}", "intact_backend"],
                       capture_output=True, text=True, timeout=20)
    return r.stdout.strip() or "intact-backend:latest"


def host_run(argv, timeout=120):
    """Run argv on the HOST, as root in its namespaces: (rc, stdout, stderr)."""
    cmd = ["docker", "run", "--rm", "--privileged", "--pid=host", "--network", "none",
           "--entrypoint", "nsenter", _own_image(),
           "--target", "1", "--mount", "--uts", "--ipc", "--net", "--pid", "--", *argv]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return r.returncode, r.stdout, r.stderr


def check(path):
    """What the move script says about moving to `path` ('' = the system disk)."""
    rc, out, err = host_run(["bash", SCRIPT, "--check", path], timeout=600)
    try:
        return json.loads(out.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return {"ok": False, "reason": (err or out or f"the check failed (rc {rc})").strip()[:300]}


def status():
    try:
        with open(STATUS_FILE) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {"state": "none"}


def disk():
    """Usage of the disk the data is on (data/ moves together with Docker's
    data root, so its filesystem is the data's): {total, used, free, pct, level}."""
    try:
        u = shutil.disk_usage(os.path.join(HOST_PATH, "data"))
    except OSError:
        return None
    pct = round(100 * u.used / u.total) if u.total else 0
    level = "critical" if pct >= CRIT_PCT else "warning" if pct >= WARN_PCT else "ok"
    return {"total": u.total, "used": u.used, "free": u.free, "pct": pct, "level": level}


# Every case keeps a record of type "case" (and a baseline) that stays
# "running" for the case's whole life: bookkeeping, not work a move cuts off.
# Counting them made Move ask "2 runs are still going" on every box.
_BOOKKEEPING_TYPES = {"case", "fusion_baseline"}


def active_runs():
    from services.workflow_service import get_all_automation_runs
    return [r for r in get_all_automation_runs() or []
            if r.get("status") in ("running", "pending") and r.get("automation_type") not in _BOOKKEEPING_TYPES]


def _refuse_if_busy(force):
    """Raise ValueError when a move or an undo must not start now: both stop every service."""
    if status().get("state") == "running":
        raise ValueError("A data move is already running.")
    busy = active_runs()
    blocking = [r for r in busy if r.get("automation_type") in _BLOCKING_TYPES]
    if blocking:
        raise ValueError(f"Wait for {blocking[0].get('name') or 'the upgrade'} to finish: "
                         "a data move stops every service.")
    if busy and not force:
        names = ", ".join((r.get("name") or r.get("run_id") or "?") for r in busy[:5])
        raise ValueError(f"{len(busy)} run(s) are still going ({names}). The move stops every service and "
                         "would cut them off -- wait for them, or confirm to move anyway.")


def start_move(path, force=False):
    """Check, then start the move on the host. Returns what to show; raises
    ValueError with the operator's reason, RuntimeError when the host refused."""
    path = clean_path(path)
    _refuse_if_busy(force)
    chk = check(path)
    if not chk.get("ok"):
        raise ValueError(chk.get("reason") or "That location cannot be used.")
    unit = f"intact-data-move-{int(time.time())}"
    rc, out, err = host_run(["systemd-run", f"--unit={unit}", "--collect",
                             "bash", SCRIPT, path or "--default", "--yes"], timeout=60)
    if rc != 0:
        raise RuntimeError(f"Could not start the move on the host: {(err or out).strip()[:300]}")
    return {"state": "starting", "unit": unit, "copy_bytes": chk.get("used_bytes"),
            "message": f"Moving the data to {path or 'the system disk'}. Every service stops while it "
                       "copies; this page reconnects when Intact is back."}


def start_undo(force=False):
    """Switch back to the backup the last move kept (move-data.sh --undo): no
    copy, and anything written since the move is not there."""
    st = status()
    if st.get("state") != "done" or not st.get("undo_root_backup"):
        raise ValueError("There is no move to undo.")
    _refuse_if_busy(force)
    unit = f"intact-data-undo-{int(time.time())}"
    rc, out, err = host_run(["systemd-run", f"--unit={unit}", "--collect", "bash", SCRIPT, "--undo"], timeout=60)
    if rc != 0:
        raise RuntimeError(f"Could not start the undo on the host: {(err or out).strip()[:300]}")
    return {"state": "starting", "unit": unit,
            "message": "Switching back to where the data was before the move; this page reconnects when Intact is back."}


def start_cleanup():
    st = status()
    if st.get("state") != "done" or not st.get("old_copies"):
        raise ValueError("There is no old copy to delete.")
    rc, out, err = host_run(["systemd-run", f"--unit=intact-data-cleanup-{int(time.time())}", "--collect",
                             "bash", SCRIPT, "--cleanup"], timeout=60)
    if rc != 0:
        raise RuntimeError(f"Could not start the cleanup: {(err or out).strip()[:300]}")
    return {"started": True, "old_copies": st.get("old_copies")}


def disks():
    """Mounted disks the data could move to, for the Settings picker:
    [{path, size, free, device}]. The system disk (/) is the picker's own
    "System disk" entry; bind mounts (data/ itself), /boot and folders inside
    the install are left out. Only filesystems Docker can run on."""
    _rc, out, _err = host_run(["findmnt", "-rn", "-b", "-o", "TARGET,FSTYPE,SIZE,AVAIL,SOURCE",
                               "-t", "ext4,xfs,btrfs"], timeout=60)
    found = []
    for line in (out or "").splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        target, _fs, size, avail, source = parts[:5]
        if (target == "/" or target.startswith("/boot") or "[" in source
                or target.startswith(HOST_PATH.rstrip("/") + "/") or not _PATH_RE.match(target)):
            continue
        found.append({"path": target, "size": int(size), "free": int(avail), "device": source})
    return found


def overview():
    setting = read_setting()
    return {"data_path": setting, "location": setting or "system disk",
            "status": status(), "disk": disk()}
