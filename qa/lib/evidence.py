"""Package real host evidence into the shape the ingest pipeline accepts.

The Timesketch pipeline takes a ZIP, and `detect_kape_format` decides what it is
by LAYOUT alone -- `client_info.json` or any member path containing `uploads/`
means "velociraptor", a `C/` prefix means "kape", anything else is rejected
outright. It never looks for `.evtx`, never reads `client_info.json`, and never
checks an OS. That is what makes a Linux ingest possible with no code change:
put real Linux logs under `uploads/` and the pipeline treats them as a
collection, because as far as it is concerned they are one.

The evidence itself is real. A CI runner has hundreds of kilobytes of
`/var/log/auth.log` and a few hundred megabytes of journal, written by the same
sshd and systemd a customer's box runs. Nothing here is synthesised, which is the
whole point -- a fixture proves the parser still parses the fixture.

Sizes are capped per file. The pipeline's archive guard rejects an expansion
ratio above 500x once a member passes 32 MiB, and log files compress far better
than that, so an uncapped journal export is a genuine way to have the upload
refused for looking like a zip bomb.
"""

import os
import subprocess
import zipfile

# Real Linux forensic sources, in the order plaso finds them most useful. Paths
# that do not exist on a given box are skipped, not failed -- a container-based
# distro may have journald and no syslog, and that is not an error.
LINUX_SOURCES = [
    ("/var/log/auth.log", "var/log/auth.log"),
    ("/var/log/syslog", "var/log/syslog"),
    ("/var/log/secure", "var/log/secure"),
    ("/var/log/wtmp", "var/log/wtmp"),
    ("/var/log/btmp", "var/log/btmp"),
    ("/var/log/lastlog", "var/log/lastlog"),
    ("/var/log/dpkg.log", "var/log/dpkg.log"),
    ("/root/.bash_history", "root/.bash_history"),
]

# 24 MiB per member. Above the guard's 32 MiB ratio-check threshold a highly
# compressible log can trip the 500x bomb heuristic; below it the check is not
# applied at all.
MAX_MEMBER_BYTES = 24 * 2**20


def build_linux_evidence_zip(dest_path, hostname, extra_sources=(), sudo=None):
    """Write a `uploads/`-shaped ZIP of this host's real logs.

    Returns {"path", "members", "bytes"}; members is the list actually included,
    so a caller can report what the evidence really contained rather than what it
    hoped for.

    `sudo` is a callable(argv) -> text used to read root-only files (auth.log is
    0640 root:adm). When absent, unreadable sources are skipped.
    """
    included, total = [], 0
    os.makedirs(os.path.dirname(os.path.abspath(dest_path)) or ".", exist_ok=True)

    with zipfile.ZipFile(dest_path, "w", zipfile.ZIP_DEFLATED) as zf:
        # client_info.json is not required -- `uploads/` alone is enough -- but
        # the pipeline reads os_info.hostname from it to name the .plaso file,
        # and a name it derives from the filename instead is far less obvious in
        # a report.
        zf.writestr("client_info.json",
                    '{"os_info": {"hostname": "%s", "system": "linux"}}' % hostname)

        for src, arcname in list(LINUX_SOURCES) + list(extra_sources):
            data = _read_capped(src, sudo)
            if not data:
                continue
            zf.writestr(f"uploads/{arcname}", data)
            included.append(arcname)
            total += len(data)

        # journald holds what a modern box actually logs, and it is not a file
        # plaso can read in place -- export it to text so the syslog parser can.
        journal = _journal_text(sudo)
        if journal:
            zf.writestr("uploads/var/log/journal-export.log", journal)
            included.append("var/log/journal-export.log")
            total += len(journal)

    return {"path": dest_path, "members": included, "bytes": total}


def _read_capped(path, sudo):
    """The last MAX_MEMBER_BYTES of a file, or b"" if unreadable.

    The TAIL, not the head: recent entries are the ones that describe this run,
    and a truncated-from-the-front log is still valid input to every parser.
    """
    try:
        if os.access(path, os.R_OK):
            with open(path, "rb") as fh:
                fh.seek(0, os.SEEK_END)
                size = fh.tell()
                fh.seek(max(0, size - MAX_MEMBER_BYTES))
                return fh.read()
    except OSError:
        pass

    if sudo is None:
        return b""
    try:
        out = sudo(["tail", "-c", str(MAX_MEMBER_BYTES), path])
        return out.encode("utf-8", "replace") if isinstance(out, str) else (out or b"")
    except Exception:                                         # noqa: BLE001
        return b""


def _journal_text(sudo):
    """A short syslog-formatted journal export, or b"".

    `-o short` deliberately: it is the classic syslog line shape, which is what
    plaso's syslog parser expects. The JSON export would need a different parser
    and buys nothing here.
    """
    argv = ["journalctl", "--no-pager", "-o", "short", "-n", "20000"]
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=120)
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.encode("utf-8", "replace")[-MAX_MEMBER_BYTES:]
    except Exception:                                         # noqa: BLE001
        pass
    if sudo is None:
        return b""
    try:
        out = sudo(argv)
        data = out.encode("utf-8", "replace") if isinstance(out, str) else (out or b"")
        return data[-MAX_MEMBER_BYTES:]
    except Exception:                                         # noqa: BLE001
        return b""
