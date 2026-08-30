"""Natural-key generation — deterministic ids so the SAME real-world thing
collapses on upsert regardless of which module/artifact emitted it.

Imported by BOTH the mappers and correlate (which is why it lives in its
own module with no intra-fusion imports — avoids a cycle).

The asset anchor is the Velociraptor ``client_id`` (stable, collector-
injected), NEVER a per-artifact hostname column. Cloud assets (future)
key on provider+account/resource with the same shape.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import re

# A bare number = Unix epoch (seconds or ms), integer or float. Anchored so a
# dashed date ("2026-08-30") never matches and get treated as an epoch.
_EPOCH_RE = re.compile(r"-?\d+(?:\.\d+)?$")

_HEXISH = re.compile(r"^[0-9a-fA-F.:-]+$")


def _h(s: str, n: int = 10) -> str:
    return hashlib.sha1(s.encode("utf-8", "ignore")).hexdigest()[:n]


def norm_host(name) -> str:
    s = (str(name) if name is not None else "").strip().lower()
    s = s.split(".")[0]          # strip DNS suffix
    s = s.rstrip("$")            # machine-account trailing $
    return s


def norm_path(p) -> str:
    s = (str(p) if p is not None else "").strip().lower().replace("\\", "/")
    s = s.replace("%systemroot%", "c:/windows").replace("%windir%", "c:/windows")
    return s


def norm_ts(v) -> str | None:
    """Best-effort normalise a timestamp to 'YYYY-MM-DDTHH:MM:SS'."""
    if v in (None, ""):
        return None
    s = str(v).strip()
    # epoch (s or ms)?
    if s.isdigit():
        try:
            n = int(s)
            if n > 1_000_000_000_000:      # ms
                n //= 1000
            import datetime as _dt
            return _dt.datetime.utcfromtimestamp(n).strftime("%Y-%m-%dT%H:%M:%S")
        except Exception:
            return s
    if "T" in s:
        return s[:19]                       # ISO -> second precision
    if " " in s and "-" in s:
        return s.replace(" ", "T")[:19]
    return s[:19]


def to_utc_dt(v):
    """Parse an ISO-ish / epoch timestamp to a tz-aware UTC datetime.

    Naive values (no offset) are assumed UTC. Returns None if empty/unparseable.

    This is the comparison primitive for the case time window: bounds and event
    times must be judged in ONE frame. Before this, `in_window` string-compared a
    local-wall-clock picker bound against UTC `first_seen` values that carried a
    trailing 'Z' / fractional seconds — so a row at the window edge sorted as
    "after end" and freshly-collected data got dropped. Parsing both sides fixes
    the frame mismatch and the 'Z'/precision sort hazard at once.
    """
    if v in (None, ""):
        return None
    s = str(v).strip()
    if not s:
        return None
    if _EPOCH_RE.match(s):                   # epoch seconds or ms, int OR float
        # Linux/Velociraptor pass some raw times through as Unix seconds, and a
        # few as a FLOAT ("1788079621.57" from stat Mtime); `.isdigit()` rejected
        # the float and it fell through to None -> kept-unfiltered. Accept both.
        try:
            n = float(s)
            if n > 1_000_000_000_000:        # milliseconds -> seconds
                n /= 1000.0
            return _dt.datetime.fromtimestamp(n, tz=_dt.timezone.utc)
        except (ValueError, OSError, OverflowError):
            return None
    t = s.replace(" ", "T")
    try:
        dt = _dt.datetime.fromisoformat(t)  # 3.11+ handles 'Z', offsets, fractions
    except Exception:
        try:
            dt = _dt.datetime.strptime(t[:19], "%Y-%m-%dT%H:%M:%S")
        except Exception:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=_dt.timezone.utc)
    return dt.astimezone(_dt.timezone.utc)


# -- asset ----------------------------------------------------------------
def asset_id(client_id) -> str:
    return f"asset:endpoint:{str(client_id).strip()}"


def asset_id_from_host(hostname) -> str:
    return f"asset:endpoint:host={norm_host(hostname)}"




# -- process (the headline cross-module merge) ----------------------------
def ct_bucket(createtime) -> str:
    t = norm_ts(createtime)
    return t or "?"


def process_id(asset: str, pid, createtime=None, image=None) -> str:
    pid = str(pid)
    ct = ct_bucket(createtime)
    if ct != "?":
        return f"process:{asset}:{pid}:{ct}"
    if image:
        return f"process:{asset}:{pid}:img={norm_path(image).split('/')[-1]}"
    return f"process:{asset}:{pid}:?"


# -- host-independent indicators ------------------------------------------
def ioc_id(kind: str, value) -> str:
    return f"ioc:{kind}:{str(value).strip().lower()}"


_FILE_EXT = {"exe", "dll", "sys", "txt", "log", "dat", "tmp", "bin", "ini", "xml",
             "json", "db", "lnk", "bat", "ps1", "vbs", "js", "msi", "cab", "zip",
             "png", "jpg", "jpeg", "ico", "mui", "config", "manifest", "etl",
             "evtx", "pf", "old", "bak", "rs", "py", "html", "css", "node"}
_BENIGN_DOM = {"microsoft.com", "windows.com", "msftncsi.com", "windowsupdate.com",
               "office.com", "live.com", "msn.com", "bing.com", "google.com",
               "gstatic.com", "office365.com", "azureedge.net", "akamaized.net"}


def classify_indicator(value) -> str | None:
    """Return 'ip' | 'domain' | 'hash' for a *useful* IOC, else None.

    Excludes filenames (evil.exe is not a domain), benign update domains, and
    private/loopback/link-local/multicast IPs (noise, not C2 infrastructure)."""
    s = str(value).strip().lower()
    if not s:
        return None
    m = re.match(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$", s)
    if m:
        o = [int(x) for x in m.groups()]
        if any(x > 255 for x in o):
            return None
        if (o[0] in (0, 127, 255, 10) or o[0] >= 224
                or (o[0] == 192 and o[1] == 168) or (o[0] == 172 and 16 <= o[1] <= 31)
                or (o[0] == 169 and o[1] == 254)):
            return None                       # private / loopback / link-local / multicast
        return "ip"
    if re.match(r"^[0-9a-f]{32}$|^[0-9a-f]{40}$|^[0-9a-f]{64}$", s):
        return "hash"
    if re.match(r"^([a-z0-9-]+\.)+[a-z]{2,24}$", s):
        last = s.rsplit(".", 1)[-1]
        if last in _FILE_EXT or s in _BENIGN_DOM:
            return None                       # filename or benign-update domain
        return "domain"
    return None


# -- asset-scoped entities ------------------------------------------------
# Windows hands the same account back in two shapes depending on the artifact:
# a parsed pair (domain="adatumlab", user="noda") or one qualified string
# (user="adatumlab\\noda", no domain at all). The account key branches on whether
# a domain is present, so the second shape never reached the domain branch and
# minted a SECOND, host-scoped entity for an account that already existed
# globally:
#
#   account:domain:adatumlab\noda                        (parsed pair)
#   account:asset:endpoint:C.d1a336242178d27f:adatumlab\noda   (qualified string)
#
# Same person, same host, two rows in the Identities tab — reported from the
# field, reproduced here on every user in a real case.
#
# Deliberately backslash only. `user@domain` is NOT split: an `@` also appears
# in perfectly ordinary local account names and in cloud principals, and
# mappers/cloud.py already has its own UPN handling that knows the provider
# context this function does not.
def split_domain_user(user, domain=None) -> tuple:
    """(domain, user), pulling a `DOMAIN\\user` apart only when no domain was given.

    Never raises: a fuse must not fail over a malformed account string, so any
    surprise falls back to the input unchanged.
    """
    try:
        d = (str(domain) if domain is not None else "").strip().lower()
        u = (str(user) if user is not None else "").strip().lower()
        if d or not u or "\\" not in u:
            return d, u
        head, _, tail = u.rpartition("\\")
        head, tail = head.strip(), tail.strip()
        # "\user", "domain\" and ".\user" (the Windows local form) carry no
        # usable domain — leave the caller on its local-account path.
        if not head or not tail or head == ".":
            return d, u
        return head, tail
    except Exception:                                   # noqa: BLE001
        # Empty, NOT the inputs re-stringified: whatever raised above will
        # raise again on the way out, and this function's whole contract is
        # that it cannot be the thing that breaks a fuse. An empty user makes
        # the caller skip the account, which is the right answer for a value
        # nothing can read.
        return "", ""


def account_id(asset: str, domain, user) -> str:
    d = (str(domain) if domain else "").strip().lower()
    u = (str(user) if user else "").strip().lower()
    return f"account:{asset}:{d}\\{u}" if d else f"account:{asset}:{u}"


def file_id(asset: str, path) -> str:
    return f"file:{asset}:{norm_path(path)}"


def module_id(asset: str, path) -> str:
    return f"module:{asset}:{norm_path(path)}"


def service_id(asset: str, name) -> str:
    return f"service:{asset}:{str(name).strip().lower()}"




def netconn_id(asset: str, laddr, lport, raddr, rport) -> str:
    return f"netconn:{asset}:{laddr}:{lport}->{raddr}:{rport}"


def yarahit_id(asset: str, rule, pid="") -> str:
    return f"yarahit:{asset}:{str(rule).strip()}:{pid}"




def event_key(asset: str, *parts) -> str:
    """Identity for an event whose distinguishing content — not its time — is what
    makes it unique: a file path, a DLL name, a service name.

    WHY THIS EXISTS. `event_id`'s second parameter is a TIMESTAMP: it runs the
    value through norm_ts(), which ends in `if "T" in s: return s[:19]`. Twenty
    mapper call sites were passing `f"{asset}:{path}"` there to make the id
    unique. Every one of those strings contains a "T" (in "asset:endpoinT"), so
    norm_ts took the ISO branch and truncated it to a 19-character constant — the
    asset prefix — silently deleting the path from the identity. Measured on a
    real case: DetectRaptor MFT collapsed 516 detections into 69 nodes (86.6%
    lost), one of them fusing AdFind.exe, PingCastle.exe, ADRecon.ps1 and
    Everything.exe across 12 months into a single dated point; BinaryRename
    merged a $Recycle.Bin copy of AdFind into a benign one.

    Here the discriminating parts are explicit and variadic, so nothing can be
    smuggled into a timestamp slot. No time is embedded — for these events the
    time is a property, not part of who they are, and the previous ids carried a
    truncated asset prefix in that position anyway, so none is lost.
    """
    blob = ":".join(str(p) for p in parts if p is not None and str(p) != "")
    return f"event:{asset}:{_h(blob, 16)}"


def event_id(asset: str, ts, msg) -> str:
    """Identity for an observed event — like every other key here it anchors on
    the ASSET (identity) plus the event's own (normalised) timestamp and a hash
    of its discriminating content. It deliberately EXCLUDES the collection run /
    collection time, so re-collecting the same event on a host collapses to one
    node (only the artifact's run time changed), while the same event on a
    DIFFERENT asset stays a separate node. Generic — every mapper uses this one
    function for every artifact/module."""
    return f"event:{asset}:{norm_ts(ts) or '?'}:{_h(str(msg), 10)}"
