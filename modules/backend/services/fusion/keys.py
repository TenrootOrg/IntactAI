"""Natural-key generation — deterministic ids so the SAME real-world thing
collapses on upsert regardless of which module/artifact emitted it.

Imported by BOTH the mappers and correlate (which is why it lives in its
own module with no intra-fusion imports — avoids a cycle).

The asset anchor is the Velociraptor ``client_id`` (stable, collector-
injected), NEVER a per-artifact hostname column. Cloud assets (future)
key on provider+account/resource with the same shape.
"""

from __future__ import annotations

import hashlib
import re

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
             "evtx", "pf", "old", "bak", "rs", "py", "html", "css", "node",
             # Data/report extensions that show up constantly in Windows event
             # text. A real miss: "WER.dbfb444b-….tmp.csv" was classified as a
             # DOMAIN and entered a case graph as an IOC, because only the LAST
             # component is checked and "csv" was not listed.
             "csv", "tsv", "jsonl", "yaml", "yml", "toml", "md", "sqlite",
             "eml", "msg", "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
             "rtf", "gz", "7z", "rar", "iso", "vhd", "vhdx", "url", "lock",
             "pid", "swp", "plist", "reg", "wer", "dmp", "sqlite3"}
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
        if last in _FILE_EXT:
            return None                       # filename, not a domain
        # Benign-update infrastructure, matched on the REGISTRABLE domain rather
        # than the exact string: "microsoft.com" was listed but "fs.microsoft.com"
        # still became an IOC, and update/telemetry traffic is overwhelmingly
        # subdomains. Every module's IOC extraction gets quieter for this.
        if s in _BENIGN_DOM or any(s.endswith("." + b) for b in _BENIGN_DOM):
            return None
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




def event_id(asset: str, ts, msg) -> str:
    """Identity for an observed event — like every other key here it anchors on
    the ASSET (identity) plus the event's own (normalised) timestamp and a hash
    of its discriminating content. It deliberately EXCLUDES the collection run /
    collection time, so re-collecting the same event on a host collapses to one
    node (only the artifact's run time changed), while the same event on a
    DIFFERENT asset stays a separate node. Generic — every mapper uses this one
    function for every artifact/module."""
    return f"event:{asset}:{norm_ts(ts) or '?'}:{_h(str(msg), 10)}"
