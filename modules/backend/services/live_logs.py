"""Settings -> Logs: each intact_* container's log, viewable live in the UI.

The containers' own output (`docker logs`), as a support bundle collects it and
with the same secret redaction -- IRIS prints its admin password on first boot,
and a bundle once shipped it. Only the general per-container logs: not the files
inside containers or the upgrade engine's ("no need for all the support bundle").

Nothing here runs in the background. The list is read when Settings -> Logs is
opened, and a log only while its viewer is open, which asks for the NEW lines
since its cursor (`docker logs --since`, ~30 ms on the appliance).
"""
import re
import subprocess

from services import support_bundle as sb

VIEW_LINES = 1000                                  # first open: the last N lines
DOWNLOAD_LINES = sb.CONTAINER_LOG_TAIL_LINES       # Download Log = what a bundle holds
POLL_MS = 1000

_TS = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?Z\s?")
_ERR = re.compile(r"\b(error|exception|traceback|fatal|critical|failed)\b", re.I)
_WARN = re.compile(r"\b(warn|warning)\b", re.I)


def sources():
    """Every intact_* container, stopped ones too (a crashed one is often the
    interesting one). read() accepts only names from this list."""
    r = subprocess.run(["docker", "ps", "-a", "--filter", "name=intact_",
                        "--format", "{{.Names}}\t{{.State}}\t{{.Status}}"],
                       capture_output=True, text=True, timeout=15)
    out = []
    for line in r.stdout.splitlines():
        name, state, status = (line.split("\t") + ["", ""])[:3]
        if name.strip():
            out.append({"id": name.strip(), "name": name.strip(), "state": state or "unknown", "status": status})
    return sorted(out, key=lambda s: s["name"])


def _find(name):
    return next((s for s in sources() if s["id"] == name), None)


def _clean(line):
    line = sb._ANSI.sub("", line.rstrip("\r\n"))
    for pat, rep in sb._SECRET_PATTERNS:
        line = pat.sub(rep, line)
    return line


def _level(msg):
    return "error" if _ERR.search(msg) else "warning" if _WARN.search(msg) else "info"


def _norm_ts(sec, frac):
    """docker trims trailing zeros (RFC3339Nano), so '...24.1Z' and '...24.123Z'
    do not compare as strings. Nine digits always."""
    return "%s.%sZ" % (sec, (frac or "").ljust(9, "0")[:9])


def parse(text, cursor=None):
    """`docker logs --timestamps` output -> (entries, cursor of the last one)."""
    logs, last = [], cursor
    for raw in text.splitlines():
        m = _TS.match(raw)
        if not m:
            continue
        ts = _norm_ts(m.group(1), m.group(2))
        # --since is inclusive: the line the cursor points at comes back again.
        # ponytail: two lines in the same nanosecond across a poll would lose the second; never seen.
        if cursor and ts <= cursor:
            continue
        msg = _clean(raw[m.end():])
        logs.append({"timestamp": ts, "level": _level(msg), "message": msg})
        last = ts
    return logs, last


def read(name, cursor=None):
    """One poll of a container's log, in the shape of a workflow run so the
    dashboard's log viewer renders it as is, plus the cursor for the next poll."""
    s = _find(name)
    if s is None:
        return None
    cmd = ["docker", "logs", "--timestamps", "--tail", str(VIEW_LINES)]
    if cursor:
        cmd += ["--since", cursor]
    r = subprocess.run(cmd + [name], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=20)
    logs, nxt = parse(r.stdout.decode("utf-8", "replace"), cursor or None)
    return {"id": name, "name": name, "type": "container log", "status": s["state"],
            "is_system_log": True, "logs": logs, "cursor": nxt, "poll_ms": POLL_MS}


def download(name):
    """(file name, generator of redacted lines): the tail a bundle takes."""
    if _find(name) is None:
        return None

    def gen():
        p = subprocess.Popen(["docker", "logs", "--timestamps", "--tail", str(DOWNLOAD_LINES), name],
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        try:
            for raw in p.stdout:
                yield _clean(raw.decode("utf-8", "replace")) + "\n"
        finally:
            p.kill()
            p.wait()
    return name + ".log", gen()
