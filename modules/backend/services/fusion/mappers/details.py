"""Parser for the Hayabusa/SIGMA ``Details`` field — a ` ¦ `-delimited key:value
string carrying the process/account/network/hash context of each detection.

Pure (imports nothing from fusion), so it's reusable and cycle-free like keys.py.
NEVER raises — malformed input yields an empty/partial dict (the fuzz suite feeds junk).

Real shapes (from committed fixtures):
  EID 1 (Sysmon process create):
    Cmdline: "..." ¦ Proc: C:\\Windows\\System32\\cmd.exe ¦ User: NT AUTHORITY\\SYSTEM ¦
    ParentCmdline: ... ¦ PID: 5064 ¦ ParentPID: 1472 ¦ Hashes: MD5=..,SHA256=..,IMPHASH=..
  EID 3 (Sysmon netconn):
    Initiated: true ¦ Proto: tcp ¦ SrcIP: .. ¦ TgtIP: 20.42.65.89 ¦ TgtPort: 443 ¦
    User: HOST\\user ¦ Proc: ...OneDrive.exe ¦ PID: 4684
  Defender variant: Time: ".." ¦ User: SYSTEM   (no Proc/PID — handled by None returns)
"""

from __future__ import annotations

_DELIM = " ¦ "


def parse_details(s) -> dict:
    """Split a Details string into a lowercased key->value dict (last value wins).
    Splits on ` ¦ ` then the FIRST `: ` (values contain ':' — paths, URLs, times)."""
    out: dict = {}
    if not isinstance(s, str) or not s:
        return out
    for tok in s.split(_DELIM):
        if ": " in tok:
            k, v = tok.split(": ", 1)
        elif ":" in tok:
            k, v = tok.split(":", 1)
        else:
            continue
        k = k.strip().lower()
        if k:
            out[k] = v.strip()
    return out


def _intish(v):
    try:
        return str(int(str(v).strip()))
    except (TypeError, ValueError):
        return None


def pid(d: dict):
    return _intish(d.get("pid"))


def parentpid(d: dict):
    return _intish(d.get("parentpid") or d.get("ppid"))


def proc(d: dict):
    return d.get("proc") or None


def cmdline(d: dict):
    return d.get("cmdline") or None


def user(d: dict):
    """Returns (domain, user) split on the first backslash, or (None, user)."""
    raw = d.get("user")
    if not raw or raw in ("-", "N/A"):
        return None, None
    if "\\" in raw:
        dom, usr = raw.split("\\", 1)
        return dom.strip() or None, usr.strip() or None
    return None, raw.strip() or None


def tgtip(d: dict):
    return d.get("tgtip") or None


def srcip(d: dict):
    return d.get("srcip") or None


def hashes(d: dict) -> dict:
    """Parse `MD5=..,SHA256=..,IMPHASH=..` into {md5, sha256, imphash} (lowercased)."""
    raw = d.get("hashes")
    out: dict = {}
    if not isinstance(raw, str):
        return out
    for part in raw.split(","):
        if "=" in part:
            a, b = part.split("=", 1)
            a, b = a.strip().lower(), b.strip().lower()
            if a and b:
                out[a] = b
    return out
