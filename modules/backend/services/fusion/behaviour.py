"""Behaviour rules: what only MANY rows of a pure log show.

A vendor verdict or a Sigma rule judges one row. A firewall flow log, an IdP
sign-in log or an auth.log is mostly rows that are each harmless: the attack is
the pattern -- forty failed logins then a success, one address trying a hundred
accounts, a host touching every port, a connection every 60 seconds to the same
place. These rules count those patterns over the normalized rows (so every
vendor's export works the same) and turn each occurrence into ONE detection row
with its counts, time span and example rows. Thresholds live in the `behaviour:`
section of config/external_log_rules.yaml.

Deterministic: a fixed threshold over a sliding time window, nothing inferred.
"""
from __future__ import annotations

import math
import ipaddress
import re
import statistics

from . import keys

DEFAULTS = {
    "brute-force": {"failures": 10, "window_s": 600, "success_within_s": 1800,
                    "severity": "medium", "severity_with_success": "high"},
    "password-spray": {"users": 10, "window_s": 1800, "severity": "high"},
    "distributed-spray": {"users": 20, "sources": 3, "window_s": 3600, "recover_s": 1800, "severity": "high"},
    "mfa-fatigue": {"denials": 5, "window_s": 900, "severity": "medium", "severity_with_success": "high"},
    "port-scan": {"ports": 25, "window_s": 300, "severity": "medium"},
    "host-sweep": {"hosts": 25, "window_s": 300, "severity": "medium"},
    # max_interval_s: a fixed hourly check-in with zero jitter is what update and
    # IoT telemetry look like (a Hue bridge, every 3,600 s, in the IoT-23 benign
    # capture); C2 beacons run seconds to minutes. Slower beacons are the trade.
    "beaconing": {"connections": 20, "min_span_s": 1800, "max_jitter": 0.2, "min_interval_s": 10,
                  "max_interval_s": 1800, "severity": "medium"},
    # SSH (22) is left out: jump hosts take it from the internet by design.
    "inbound-remote-admin": {"ports": [3389, 5900, 5985, 5986, 445, 135, 139, 23], "severity": "medium"},
    "outbound-flood": {"connections": 1000, "window_s": 60, "severity": "high"},
    "c2-retry": {"attempts": 200, "window_s": 3600, "failed_share": 0.5, "severity": "medium"},
    "web-scan": {"paths": 50, "window_s": 600, "severity": "medium"},
    "web-login-brute-force": {"posts": 20, "window_s": 600, "severity": "medium"},
    "dns-ptr-sweep": {"lookups": 100, "window_s": 600, "severity": "medium"},
    # Splunk-style risk adding: low "anomaly" signals (whoami, a cron edit, a hidden
    # file) are noise alone; several DIFFERENT ones on one host within the hour are an
    # operator working the box.
    "suspicious-burst": {"distinct": 3, "window_s": 3600, "severity": "medium"},
    "ad-acl-change": {"severity": "medium"},
    "kerberos-ticket-burst": {"services": 10, "window_s": 600, "severity": "medium"},
    "kerberos-user-enum": {"names": 10, "window_s": 600, "severity": "medium"},
    "dns-tunnel": {"subdomains": 100, "window_s": 3600, "long_label": 40, "long_queries": 20,
                   "severity": "medium"},
}

_FAIL = re.compile(r"\b(fail(ed|ure|s)?|denied|deny|invalid|reject(ed)?|bad (password|credentials)|wrong|"
                   r"incorrect|unauthori[sz]ed|locked|lockout|not authenticated|authentication error|"
                   r"invalid_credentials|verification_error|fraud|timeout|timed out|4625|4771|4776|50126|50053|"
                   r"50055|50057|50074|50076|50079|50158|500121)\b", re.I)
_OK = re.compile(r"\b(success(ful(ly)?)?|succeeded|accepted|granted|approved|allowed|logged on|logon success|"
                 r"4624|session opened)\b", re.I)
_MFA = re.compile(r"\b(mfa|2fa|multi.?factor|push|verify|verification|duo|authenticator|otp|factor)\b", re.I)
_AUTH = re.compile(r"\b(log ?(in|on)|sign.?in|auth|authenticat\w*|password|session[ .]start|credential|sso|"
                   r"mfa|4624|4625|4771|4776)\b", re.I)
# MFA wording is a sign-in signal too -- but only these phrases: a bare "push"
# is also "git push".
_MFA_AUTH = re.compile(r"\b(mfa|2fa|multi.?factor|factor|push verification|verify push|verification push|"
                       r"otp|authenticator|duo push)\b", re.I)
_TEXT_AUTH = re.compile(r"(?:for|user)\s+(?:invalid user\s+)?([A-Za-z0-9._@\\$-]{1,64})\s+from\s+"
                        r"((?:\d{1,3}\.){3}\d{1,3})", re.I)
# Cisco ASA 113005 / 113004: "AAA user authentication Rejected : ... : user = jdoe : user IP = 1.2.3.4"
_TEXT_AAA = re.compile(r"user\s*=\s*([A-Za-z0-9._@\\$-]{1,64})\s*:\s*user IP\s*=\s*((?:\d{1,3}\.){3}\d{1,3})", re.I)
# PAM: "authentication failure; logname= uid=0 ... rhost=1.2.3.4  user=root"
_TEXT_PAM = re.compile(r"rhost=((?:\d{1,3}\.){3}\d{1,3})(?:\s+user=([A-Za-z0-9._@\\$-]{1,64}))?", re.I)
_IPV4 = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")
_OUTCOME_KEYS = ("outcome", "result", "status", "resulttype", "errorcode", "action", "disposition",
                 "reason", "eventid", "eventtype", "type", "message", "displaymessage")


_OUTCOME_COLS: dict = {}


def _outcome_cols(keys_):
    """Which columns of a row shape can say success / failure (cached per shape)."""
    got = _OUTCOME_COLS.get(keys_)
    if got is None:
        got = _OUTCOME_COLS[keys_] = [k for k in keys_ if any(
            re.sub(r"[^a-z]", "", str(k).lower()).endswith(o) for o in _OUTCOME_KEYS)]
    return got


def _outcome_text(n, raw) -> str:
    bits = [str(n.get(k) or "") for k in ("action", "rule", "message")]
    if isinstance(raw, dict):
        for k in _outcome_cols(tuple(raw)):
            v = raw.get(k)
            if not isinstance(v, (dict, list)):
                bits.append(f"{k}={v}")
        if "text" in raw or "_line" in raw:
            bits.append(str(raw.get("text") or raw.get("_line")))
    # "login_failure", "user.session.start": separators, or \b never sees the words
    return re.sub(r"[_.]", " ", " ".join(bits))


def _entra_outcome(raw):
    """Entra / Azure AD: errorCode / ResultType 0 = success, anything else failure."""
    if not isinstance(raw, dict):
        return None
    for k, v in raw.items():
        lk = re.sub(r"[^a-z]", "", str(k).lower())
        if lk.endswith("errorcode") or lk == "resulttype":
            s = str(v).strip()
            if s.isdigit():
                return "ok" if s == "0" else "fail"
    return None


# Windows events say what they are by ID. Read by words, a Sysmon registry write
# from mmc.exe and an Event 69 "failed" were brute forces on a benign DC.
_WIN_LOGON = {"4624": "ok", "4625": "fail", "4648": "ok", "4768": None, "4771": "fail", "4776": None,
              "528": "ok", "529": "fail", "530": "fail", "531": "fail", "532": "fail", "533": "fail",
              "534": "fail", "535": "fail", "536": "fail", "537": "fail", "539": "fail", "540": "ok"}


def _windows_event(raw):
    return isinstance(raw, dict) and raw.get("EventID") not in (None, "") and \
        any(raw.get(k) for k in ("Channel", "Provider", "SourceName", "ProviderName"))


def auth_event(r):
    """(ts, user, src_ip, outcome, mfa) when the row is an authentication, else None."""
    n, raw = r.get("n") or {}, r.get("raw") or {}
    ts = n.get("ts")
    if not ts:
        return None
    if _windows_event(raw):
        eid = str(raw.get("EventID")).strip()
        if eid not in _WIN_LOGON:
            return None
        user = raw.get("TargetUserName") or n.get("user")
        if not user or str(user).endswith("$"):          # a machine account's logon
            return None
        outcome = _WIN_LOGON[eid]
        if eid in ("4768", "4771", "4776"):              # the status says -- and only a WRONG
            st = str(raw.get("Status") or raw.get("ResultCode") or "0x0").lower()   # PASSWORD is a failure
            if st in ("0x0", "0", ""):
                outcome = "ok" if eid != "4771" else None
            elif st in ("0x18", "0xc000006a"):
                outcome = "fail"
            else:                                        # 0x6 / 0xc0000064: no such account --
                return None                              # enumeration (kerberos-user-enum), not a guess
            if outcome is None:
                return None
        src = n.get("src_ip") or raw.get("IpAddress")
        src = None if str(src) in ("-", "::1", "127.0.0.1", "") else src
        return ts, str(user).lower(), src, outcome, False
    user, src = n.get("user") or (n.get("users") or [None])[0], n.get("src_ip")
    text = _outcome_text(n, raw)
    phrase = False                     # user + source read from a sign-in phrase in free text
    if (not user or not src) and isinstance(raw, dict) and (raw.get("text") or raw.get("_line")):
        line = str(raw.get("text") or raw.get("_line"))
        m = _TEXT_AUTH.search(line) or _TEXT_AAA.search(line)
        if m:
            user, src, phrase = user or m.group(1), src or m.group(2), True
        else:
            m = _TEXT_PAM.search(line)
            if m:
                src, user, phrase = src or m.group(1), user or m.group(2) or "(unknown)", True
    if not user and isinstance(raw, dict) and str(raw.get("status", "")).lower() in ("success", "failure") \
            and any(str(raw.get(k, "")).startswith("SSH-") for k in ("client", "server")):
        user, phrase = "(any account)", True       # Zeek ssh.log: the outcome, never the account
    if not user:
        return None
    outcome = _entra_outcome(raw)
    if outcome is None:
        if _FAIL.search(text):
            outcome = "fail"
        elif _OK.search(text):
            outcome = "ok"
        else:
            return None
    # A sign-in has to SAY it is one. A user, a failure word and an address are
    # not enough: a proxy line "TCP_DENIED/407 ... someone@hotmail.com" is a
    # normal authentication challenge, and 36 of them read as a brute force.
    if not (phrase or _AUTH.search(text) or _MFA_AUTH.search(text) or _entra_outcome(raw) is not None):
        return None
    return ts, str(user).lower(), src, outcome, bool(_MFA.search(text))


def _t(ts):
    d = keys.to_utc_dt(ts)
    return d.timestamp() if d else None


def _row(rule_id, title, sev, members, n_extra, summary):
    """One detection row standing for many raw rows."""
    tss = sorted(m[0] for m in members if m[0])
    first, last = (tss[0], tss[-1]) if tss else (None, None)
    n = {"ts": first, "severity": sev, "rule": title, "detected_by": [f"behaviour: {rule_id}"],
         "message": summary, **{k: v for k, v in n_extra.items() if v}}
    raw = {"behaviour": rule_id, "summary": summary, "first": first, "last": last, "count": len(members),
           "example_rows": sorted({m[-1] for m in members})[:10]}
    return {"n": n, "raw": raw}


def _windows(items, window_s):
    """[(t, item)] -> the densest window of each episode. An episode ends where
    nothing happens for longer than the window, so one attack is one detection,
    and the same pattern a day later is another."""
    items = sorted(items, key=lambda x: x[0])
    eps, cur = [], []
    for it in items:
        if cur and it[0] - cur[-1][0] > window_s:
            eps.append(cur)
            cur = []
        cur.append(it)
    if cur:
        eps.append(cur)
    out = []
    for ep in eps:
        start, best = 0, (0, 0)
        for end in range(len(ep)):
            while ep[end][0] - ep[start][0] > window_s:
                start += 1
            if end - start + 1 > best[1] - best[0]:
                best = (start, end + 1)
        out.append(ep[best[0]:best[1]])
    return out


def _densest(items, window_s, key, need):
    """(distinct, window) -- the time window (<= window_s) holding the most
    DISTINCT key(item) values, if it reaches `need`; else None. Incremental
    counts as the window slides: linear. (Rebuilding a set at every step was
    quadratic -- a scanner's 50k requests took minutes.)"""
    items = sorted(items, key=lambda x: x[0])
    counts: dict = {}
    start, best = 0, None
    for end, it in enumerate(items):
        k = key(it)
        counts[k] = counts.get(k, 0) + 1
        while it[0] - items[start][0] > window_s:
            old = key(items[start])
            counts[old] -= 1
            if not counts[old]:
                del counts[old]
            start += 1
        if len(counts) >= need and (best is None or len(counts) > best[0]):
            best = (len(counts), items[start:end + 1])
    return best


# -- the rules ------------------------------------------------------------------------
def brute_force(auth, p, spray_srcs=()):
    """Many failures for one account from one source; worse when a success follows.
    A source already named in a password spray raises no PLAIN brute force (the
    same burst, counted once) -- but always a brute force that ended in a success."""
    out = []
    groups: dict = {}
    for a in auth:
        groups.setdefault((a[1], a[2]), []).append(a)
    for (user, src), evs in groups.items():
        fails = [(_t(e[0]), e) for e in evs if e[3] == "fail" and _t(e[0]) is not None]
        oks = sorted(_t(e[0]) for e in evs if e[3] == "ok" and _t(e[0]) is not None)
        for win in _windows(fails, p["window_s"]):
            if len(win) < p["failures"]:
                continue
            end = win[-1][0]
            won = next((t for t in oks if end - p["window_s"] <= t <= end + p["success_within_s"]
                        and t >= win[0][0]), None)
            if won is None and src in spray_srcs:
                continue
            members = [w[1] for w in win]
            who = f"{user}" + (f" from {src}" if src else "")
            if won is not None:
                title, sev = "Brute force then success", p["severity_with_success"]
            else:
                title, sev = "Brute force", p["severity"]
            out.append(_row("brute-force", title, sev, members, {"user": user, "src_ip": src},
                            f"{len(members)} failed sign-ins for {who}"
                            + (" followed by a successful one" if won is not None else "")))
    return out


def password_spray(auth, p):
    """One source failing against many different accounts."""
    out = []
    groups: dict = {}
    for a in auth:
        if a[2] and a[3] == "fail" and _t(a[0]) is not None:
            groups.setdefault(a[2], []).append((_t(a[0]), a))
    for src, items in groups.items():
        best = _densest(items, p["window_s"], lambda i: i[1][1], p["users"])
        if best:
            members = [i[1] for i in best[1]]
            out.append(_row("password-spray", "Password spray", p["severity"], members,
                            {"src_ip": src, "users": sorted({m[1] for m in members})[:50]},
                            f"{src} failed against {best[0]} different accounts"))
    return out


def distributed_spray(auth, p, spray_srcs=()):
    """A spray spread over many addresses (one guess per account per IP), which the
    per-source rule cannot see. Counted are only UNRECOVERED failures -- an account
    whose failure is not followed by its own success -- so a busy morning of typos,
    each followed by a good login, stays quiet."""
    oks: dict = {}
    for a in auth:
        if a[3] == "ok" and _t(a[0]) is not None:
            oks.setdefault(a[1], []).append(_t(a[0]))
    fails = []
    for a in auth:
        t = _t(a[0])
        if a[3] != "fail" or t is None or a[2] in spray_srcs:
            continue
        if any(t <= o <= t + p["recover_s"] for o in oks.get(a[1], ())):
            continue                                       # the owner got in: a typo
        fails.append((t, a))
    out = []
    for win in _windows(fails, p["window_s"]):
        users = {w[1][1] for w in win}
        srcs = {w[1][2] for w in win if w[1][2]}
        if len(users) >= p["users"] and len(srcs) >= p["sources"]:
            members = [w[1] for w in win]
            out.append(_row("distributed-spray", "Distributed password spray", p["severity"], members,
                            {"users": sorted(users)[:50], "ips": sorted(srcs)[:50]},
                            f"{len(users)} accounts failed without a later success, from {len(srcs)} addresses"))
    return out


def mfa_fatigue(auth, p):
    """Repeated MFA prompts denied or left to time out for one account."""
    out = []
    groups: dict = {}
    for a in auth:
        if a[4]:
            groups.setdefault(a[1], []).append(a)
    for user, evs in groups.items():
        den = [(_t(e[0]), e) for e in evs if e[3] == "fail" and _t(e[0]) is not None]
        oks = sorted(_t(e[0]) for e in evs if e[3] == "ok" and _t(e[0]) is not None)
        for win in _windows(den, p["window_s"]):
            if len(win) < p["denials"]:
                continue
            won = next((t for t in oks if win[0][0] <= t <= win[-1][0] + p["window_s"]), None)
            members = [w[1] for w in win]
            out.append(_row("mfa-fatigue", "MFA fatigue" + (" then approved" if won else ""),
                            p["severity_with_success"] if won else p["severity"], members, {"user": user},
                            f"{len(members)} MFA prompts denied or unanswered for {user}"
                            + (", then one approved" if won else "")))
    return out


_FAILED_STATE = re.compile(r"^(S0|REJ|RSTOS0|RSTRH|SH|SHR|OTH)$")      # Zeek conn_state: never answered
# Letter boundaries, not \b: iptables prefixes read "DROP_INPUT" / "REJECT_FWD".
_FAILED_ACTION = re.compile(r"(?<![a-z])(deny|denied|drop(ped)?|reject(ed)?|block(ed)?|reset)(?![a-z])", re.I)


def _failed(n, raw):
    """A connection that never got through (unanswered, refused, dropped)."""
    st = str((raw or {}).get("conn_state") or "")
    if st:
        return bool(_FAILED_STATE.match(st))
    # No action column: an iptables/netfilter line says it in its log prefix.
    act = n.get("action") or (raw or {}).get("syslog_header") or ""
    return bool(_FAILED_ACTION.search(str(act)))


def _no_peer(ip):
    """Multicast / broadcast / unspecified: no host on the other end (LLMNR from
    224.0.0.252 to svchost read as a port scan on a benign DC)."""
    try:
        a = ipaddress.ip_address(str(ip).strip())
        return a.is_multicast or a.is_unspecified or str(a) == "255.255.255.255"
    except ValueError:
        return False


def _flows(rows):
    for i, r in enumerate(rows):
        n = r.get("n") or {}
        t = _t(n.get("ts"))
        if t is not None and n.get("src_ip") and (n.get("dst_ip") or n.get("domain")) \
                and n.get("src_ip") != n.get("dst_ip") and not _no_peer(n.get("src_ip")) \
                and not _no_peer(n.get("dst_ip")):
            yield t, n.get("src_ip"), n.get("dst_ip"), n.get("dst_port"), n.get("domain"), n.get("ts"), i, \
                _failed(n, r.get("raw"))


def _public(ip):
    return bool(ip) and keys.classify_indicator(ip) == "ip"


def outbound_flood(flows, p):
    """One source hammering one destination across the network edge: a host in
    a DDoS (or the victim of one). Internal-to-internal is left out -- a proxy
    or load balancer talks to its backends that way all day."""
    groups: dict = {}
    for f in flows:
        if f[2] and (_public(f[1]) != _public(f[2])):
            groups.setdefault((f[1], f[2]), []).append(f)
    out = []
    for (src, dst), items in groups.items():
        if len(items) < p["connections"]:
            continue
        win = max(_windows([(i[0], i) for i in items], p["window_s"]), key=len)
        if len(win) >= p["connections"]:
            members = [(w[1][5], w[1][6]) for w in win]
            out.append(_row("outbound-flood", "Connection flood", p["severity"], members,
                            {"src_ip": src, "dst_ip": dst},
                            f"{src} opened {len(win):,} connections to {dst} within {p['window_s']}s"))
    return out


def c2_retry(flows, p, flood_pairs=()):
    """A host trying the same outside address and port again and again, mostly
    without an answer: malware retrying its command server."""
    groups: dict = {}
    for f in flows:
        if f[2] and f[3] and _public(f[2]) and not _public(f[1]):
            groups.setdefault((f[1], f[2], f[3]), []).append(f)
    out = []
    for (src, dst, port), items in groups.items():
        if len(items) < p["attempts"] or (src, dst) in flood_pairs:    # a flood is not a retry
            continue
        win = max(_windows([(i[0], i) for i in items], p["window_s"]), key=len)
        failed = sum(1 for w in win if w[1][7])
        if len(win) >= p["attempts"] and failed >= p["failed_share"] * len(win):
            members = [(w[1][5], w[1][6]) for w in win]
            out.append(_row("c2-retry", "Repeated failed connections to an outside host", p["severity"], members,
                            {"src_ip": src, "dst_ip": dst, "dst_port": port},
                            f"{src} tried {dst}:{port} {len(win):,} times within {p['window_s'] // 60} min, "
                            f"{failed:,} without an answer"))
    return out


def inbound_remote_admin(flows, p):
    """An outside address getting an answer from RDP / SMB / WinRM / VNC / RPC /
    Telnet on an internal host. One row per exposed service, not per source, so
    internet-wide scanning of it reads as one finding."""
    ports = {int(x) for x in p["ports"]}
    groups: dict = {}
    for f in flows:
        try:
            port = int(f[3])
        except (TypeError, ValueError):
            continue
        if port in ports and not f[7] and _public(f[1]) and f[2] and not _public(f[2]) \
                and _IPV4.fullmatch(str(f[2])):
            groups.setdefault((f[2], port), []).append(f)
    out = []
    for (dst, port), items in groups.items():
        srcs = sorted({i[1] for i in items})
        members = [(i[5], i[6]) for i in items]
        out.append(_row("inbound-remote-admin", "Remote admin service reached from the internet", p["severity"],
                        members, {"src_ip": srcs[0] if len(srcs) == 1 else None, "dst_ip": dst, "dst_port": port,
                                  "ips": srcs[:20]},
                        f"{dst}:{port} answered {len(items):,} connection(s) from {len(srcs)} outside "
                        f"address(es): {', '.join(srcs[:5])}{' …' if len(srcs) > 5 else ''}"))
    return out


def port_scan(flows, p):
    out = []
    groups: dict = {}
    for f in flows:
        if f[2] and f[3]:
            groups.setdefault((f[1], f[2]), []).append(f)
    for (src, dst), items in groups.items():
        best = _densest(items, p["window_s"], lambda i: i[3], p["ports"])
        if best:
            members = [(i[5], i[6]) for i in best[1]]
            out.append(_row("port-scan", "Port scan", p["severity"], members,
                            {"src_ip": src, "dst_ip": dst}, f"{src} reached {best[0]} different ports on {dst}"))
    return out


def host_sweep(flows, p):
    out = []
    groups: dict = {}
    for f in flows:
        # Lateral only: one workstation reaches dozens of PUBLIC addresses on 443
        # in minutes just by browsing; sweeping the internal network is the signal.
        if f[2] and f[3] and keys.classify_indicator(f[2]) != "ip" and _IPV4.fullmatch(str(f[2])):
            groups.setdefault((f[1], f[3]), []).append(f)
    for (src, port), items in groups.items():
        best = _densest(items, p["window_s"], lambda i: i[2], p["hosts"])
        if best:
            members = [(i[5], i[6]) for i in best[1]]
            out.append(_row("host-sweep", "Host sweep", p["severity"], members,
                            {"src_ip": src, "dst_port": port}, f"{src} reached {best[0]} different hosts on port {port}"))
    return out


def beaconing(flows, p):
    """Regular connections to one PUBLIC destination: the interval between them
    barely varies (jitter = stdev / mean)."""
    out = []
    groups: dict = {}
    for f in flows:
        dest = f[4] if f[4] and keys.classify_indicator(f[4]) == "domain" else \
            f[2] if f[2] and keys.classify_indicator(f[2]) == "ip" else None
        if dest:
            groups.setdefault((f[1], dest), []).append(f)
    for (src, dest), items in groups.items():
        if len(items) < p["connections"]:
            continue
        ts = sorted({i[0] for i in items})
        if len(ts) < p["connections"] or ts[-1] - ts[0] < p["min_span_s"]:
            continue
        gaps = [b - a for a, b in zip(ts, ts[1:])]
        mean = statistics.mean(gaps)
        if not (p["min_interval_s"] <= mean <= p["max_interval_s"]):
            continue
        jitter = statistics.pstdev(gaps) / mean if mean else 1
        if jitter > p["max_jitter"]:
            continue
        members = [(i[5], i[6]) for i in items]
        out.append(_row("beaconing", "Beaconing", p["severity"], members,
                        {"src_ip": src, "dst_ip": dest if keys.classify_indicator(dest) == "ip" else None,
                         "domain": dest if keys.classify_indicator(dest) == "domain" else None},
                        f"{len(ts)} connections from {src} to {dest} every ~{mean:.0f}s (jitter {jitter:.2f}) "
                        f"over {(ts[-1] - ts[0]) / 60:.0f} min"))
    return out


_LOGIN_PATH = re.compile(r"(log[_-]?in|log[_-]?on|sign[_-]?in|wp-login\.php|xmlrpc\.php|/auth\b|/session|"
                         r"/token\b|j_security_check|owa/auth|/api/v\d+/login|/user/login|/account/login)", re.I)


def _web(rows):
    for i, r in enumerate(rows):
        n = r.get("n") or {}
        t = _t(n.get("ts"))
        if t is not None and n.get("src_ip") and n.get("url") and n.get("http_status"):
            yield t, n.get("src_ip"), str(n["url"]).split("?")[0], str(n.get("http_method") or "").upper(), \
                str(n["http_status"]), n.get("ts"), i


def web_scan(rows, p):
    """One source asking for many different paths that do not exist (4xx): a
    scanner walking a wordlist, not a visitor."""
    out, groups = [], {}
    for w in _web(rows):
        if w[4].startswith("4"):
            groups.setdefault(w[1], []).append(w)
    for src, items in groups.items():
        best = _densest(items, p["window_s"], lambda i: i[2], p["paths"])
        if best:
            out.append(_row("web-scan", "Web scanning", p["severity"], [(i[5], i[6]) for i in best[1]],
                            {"src_ip": src}, f"{src} asked for {best[0]} different paths that returned 4xx"))
    return out


def web_login_brute_force(rows, p):
    """One source posting to a login page over and over."""
    out, groups = [], {}
    for w in _web(rows):
        if w[3] == "POST" and _LOGIN_PATH.search(w[2]):
            groups.setdefault(w[1], []).append((w[0], w))
    for src, items in groups.items():
        for win in _windows(items, p["window_s"]):
            if len(win) >= p["posts"]:
                paths = sorted({w[1][2] for w in win})
                out.append(_row("web-login-brute-force", "Web login brute force", p["severity"],
                                [(w[1][5], w[1][6]) for w in win], {"src_ip": src, "url": paths[0]},
                                f"{src} posted {len(win)} times to {', '.join(paths[:3])}"))
    return out


def _entropy(s):
    if not s:
        return 0.0
    counts = {c: s.count(c) for c in set(s)}
    return -sum(v / len(s) * math.log2(v / len(s)) for v in counts.values())


def dns_tunnel(rows, p):
    """Many distinct subdomains, or long random-looking labels, under one domain."""
    out = []
    groups: dict = {}
    for i, r in enumerate(rows):
        n = r.get("n") or {}
        names = [n.get("domain")] + list(n.get("domains") or [])
        t = _t(n.get("ts"))
        for d in names:
            if not d or t is None or d.count(".") < 2 or d.lower().rstrip(".").endswith(".arpa"):
                continue                           # reverse lookups are dns-ptr-sweep's, never a tunnel
            labels = d.lower().rstrip(".").split(".")
            base = ".".join(labels[-2:])
            groups.setdefault(base, []).append((t, labels[0], n.get("ts"), i, n.get("src_ip")))
    for base, items in groups.items():
        best = _densest(items, p["window_s"], lambda i: i[1], p["subdomains"])
        long_q = [i for i in items if len(i[1]) >= p["long_label"] and _entropy(i[1]) >= 3.5]
        if best or len(long_q) >= p["long_queries"]:
            members = [(i[2], i[3]) for i in (best[1] if best else long_q)]
            src = next((i[4] for i in items if i[4]), None)
            why = (f"{best[0]} different subdomains of {base}" if best else
                   f"{len(long_q)} queries with long random labels under {base}")
            out.append(_row("dns-tunnel", "Possible DNS tunnelling", p["severity"], members,
                            {"domain": base, "src_ip": src}, why))
    return out


def dns_ptr_sweep(rows, p):
    """One source resolving many different addresses back to names: mapping the
    network (reconnaissance), not a client resolving what it talks to."""
    groups: dict = {}
    for i, r in enumerate(rows):
        n = r.get("n") or {}
        t = _t(n.get("ts"))
        for d in [n.get("domain")] + list(n.get("domains") or []):
            if d and t is not None and str(d).lower().rstrip(".").endswith((".in-addr.arpa", ".ip6.arpa")):
                groups.setdefault(n.get("src_ip") or "?", []).append((t, str(d).lower(), n.get("ts"), i))
    out = []
    for src, items in groups.items():
        best = _densest(items, p["window_s"], lambda i: i[1], p["lookups"])
        if best:
            out.append(_row("dns-ptr-sweep", "Reverse DNS sweep", p["severity"], [(i[2], i[3]) for i in best[1]],
                            {"src_ip": None if src == "?" else src},
                            f"{src} resolved {best[0]} different addresses back to names"))
    return out


# -- Active Directory permission changes (Security 5136 on nTSecurityDescriptor) --------
# A change logs the old descriptor (%%14675, value deleted) and the new (%%14674,
# value added) under one OpCorrelationID; what the attacker ADDED is the diff.
_ACE = re.compile(r"\(([^()]*)\)")
_CONTROL = re.compile(r"GA|WD|WO")                       # full control / write DACL / write owner
_ADMIN_SIDS = {"DA", "EA", "BA", "SY", "AO", "SO", "PO", "CA", "ED", "DD", "RS", "ER", "CO", "PS", "RU",
               "NO", "BO", "SA"}


def _trustee_is_admin(sid):
    s = str(sid).upper()
    if s in _ADMIN_SIDS or s.startswith("S-1-5-32-") or s in ("S-1-5-18", "S-1-5-9"):
        return True
    m = re.search(r"-(\d+)$", s)
    return bool(s.startswith("S-1-5-21-") and m and int(m.group(1)) < 1000)   # 500 admin, 512 DA, 519 EA...


def ad_acl_change(rows, p):
    pairs: dict = {}
    for i, r in enumerate(rows):
        raw = r.get("raw") or {}
        if str(raw.get("EventID")) != "5136" or str(raw.get("AttributeLDAPDisplayName") or "").lower() \
                != "ntsecuritydescriptor":
            continue
        k = raw.get("OpCorrelationID") or f"row{i}"
        pairs.setdefault(k, {})[str(raw.get("OperationType"))] = (i, raw)
    out = []
    for k, ops in pairs.items():
        if "%%14674" not in ops:
            continue
        i, new = ops["%%14674"]
        old = ops.get("%%14675", (None, {}))[1]
        added = set(_ACE.findall(str(new.get("AttributeValue") or ""))) - set(
            _ACE.findall(str(old.get("AttributeValue") or "")))
        if "%%14675" not in ops:                             # nothing to diff against: too noisy to read
            continue
        dn = str(new.get("ObjectDN") or "")
        hits = []
        for ace in added:
            part = ace.split(";")
            if len(part) < 6 or "ID" in part[1]:             # inherited: comes from the parent, not this change
                continue
            kind, rights, who = part[0], part[2], part[5]
            if kind in ("A", "OA") and _CONTROL.search(rights) and not _trustee_is_admin(who):
                hits.append(f"control ({rights}) granted to {who}")
            elif kind == "D" and who in ("WD", "AU") and "LC" in rights:
                hits.append("hidden from everyone (deny list contents)")
        adminsd = "cn=adminsdholder" in dn.lower()
        if not hits and not (adminsd and added):
            continue
        n = rows[i].get("n") or {}
        sev = "high" if adminsd else p["severity"]
        title = ("AdminSDHolder permissions changed" if adminsd else
                 "AD object hidden" if all(h.startswith("hidden") for h in hits) else
                 "AD object permissions granted to an account")
        out.append(_row("ad-acl-change", title, sev, [(n.get("ts"), i)],
                        {"user": new.get("SubjectUserName"), "host": new.get("Computer")},
                        f"{new.get('SubjectUserName')} changed the permissions of {dn}: "
                        + ("; ".join(hits) if hits else "AdminSDHolder is copied onto every admin account")))
    return out


# -- Kerberos (Security 4768 / 4769) -----------------------------------------------------
def _krb_user(v):
    return str(v or "").split("@", 1)[0].strip().lower()


def kerberos_ticket_burst(rows, p):
    """One account asking for service tickets to many DIFFERENT services in a short
    window: Kerberoasting (RC4 tickets) or a sweep of computer accounts (discovery)."""
    groups: dict = {}
    for i, r in enumerate(rows):
        raw = r.get("raw") or {}
        if str(raw.get("EventID")) != "4769" or str(raw.get("Status") or "0x0").lower() not in ("0x0", "0"):
            continue
        svc = str(raw.get("ServiceName") or "").strip()
        t = _t((r.get("n") or {}).get("ts"))
        if not svc or svc.lower().startswith("krbtgt") or t is None:
            continue
        groups.setdefault(_krb_user(raw.get("TargetUserName")), []).append(
            (t, svc.lower(), str(raw.get("TicketEncryptionType") or "").lower(), (r.get("n") or {}).get("ts"), i))
    out = []
    for user, items in groups.items():
        best = _densest(items, p["window_s"], lambda x: x[1], p["services"])
        if not best:
            continue
        svcs = {x[1] for x in best[1]}
        rc4 = sum(1 for x in best[1] if x[2] in ("0x17", "0x18"))
        computers = sum(1 for s_ in svcs if s_.endswith("$"))
        if rc4:
            title, sev = "Possible Kerberoasting (RC4 service tickets)", "high"
        elif computers >= 0.8 * len(svcs):
            title, sev = "Kerberos tickets for many computers", p["severity"]
        else:
            title, sev = "Unusual number of Kerberos service tickets", p["severity"]
        out.append(_row("kerberos-ticket-burst", title, sev, [(x[3], x[4]) for x in best[1]], {"user": user},
                        f"{user} requested tickets for {len(svcs)} different services within "
                        f"{p['window_s'] // 60} min" + (f", {rc4} of them RC4" if rc4 else "")))
    return out


def kerberos_user_enum(rows, p):
    """Pre-authentication for many names that do not exist (4768, 0x6) from one address."""
    groups: dict = {}
    for i, r in enumerate(rows):
        raw = r.get("raw") or {}
        if str(raw.get("EventID")) != "4768" or str(raw.get("Status") or "").lower() != "0x6":
            continue
        t = _t((r.get("n") or {}).get("ts"))
        if t is None:
            continue
        src = str(raw.get("IpAddress") or "").replace("::ffff:", "")
        groups.setdefault(src, []).append((t, _krb_user(raw.get("TargetUserName")), (r.get("n") or {}).get("ts"), i))
    out = []
    for src, items in groups.items():
        best = _densest(items, p["window_s"], lambda x: x[1], p["names"])
        if best:
            out.append(_row("kerberos-user-enum", "Kerberos user enumeration", p["severity"],
                            [(x[2], x[3]) for x in best[1]], {"src_ip": src or None},
                            f"{src or 'one address'} tried {best[0]} account names that do not exist "
                            f"within {p['window_s'] // 60} min"))
    return out


def suspicious_burst(rows, p):
    """Several different low-level Sigma signals on one host within a window."""
    groups: dict = {}
    for i, r in enumerate(rows):
        n = r.get("n") or {}
        if n.get("severity") != "low" or not any(str(d).startswith("sigma:") for d in n.get("detected_by") or []):
            continue
        t = _t(n.get("ts"))
        if t is None:
            continue
        host = str(n.get("host") or "").strip().lower()
        groups.setdefault(host, []).append((t, n.get("rule"), n.get("ts"), i))
    out = []
    for host, items in groups.items():
        best = _densest(items, p["window_s"], lambda x: x[1], p["distinct"])
        if best:
            members = [(x[2], x[3]) for x in best[1]]
            titles = sorted({x[1] for x in best[1]})
            out.append(_row("suspicious-burst", "Burst of suspicious activity", p["severity"], members,
                            {"host": host or None},
                            f"{len(titles)} different suspicious signals within {p['window_s'] // 60} min"
                            + (f" on {host}" if host else "") + ": " + "; ".join(titles[:8])))
    return out


def run(rows, params=None, log=None) -> list:
    """Every behaviour rule over the normalized rows -> detection rows to append."""
    log = log or (lambda m, l="info": None)
    ps = {k: {**v, **((params or {}).get(k) or {})} for k, v in DEFAULTS.items()}
    off = {k for k, v in ((params or {}).items()) if isinstance(v, dict) and v.get("enabled") is False}
    auth = []
    for i, r in enumerate(rows):
        a = auth_event(r)
        if a:
            auth.append((*a, i))
    flows = list(_flows(rows))
    found, spray_srcs = [], set()
    if "password-spray" not in off:
        try:
            sprays = password_spray(auth, ps["password-spray"])
            found += sprays
            spray_srcs = {f["n"].get("src_ip") for f in sprays}
        except Exception as e:                             # noqa: BLE001
            log(f"behaviour rule password-spray failed: {e}", "warning")
    for name, fn, data in (("brute-force", lambda a, p: brute_force(a, p, spray_srcs), auth),
                           ("distributed-spray", lambda a, p: distributed_spray(a, p, spray_srcs), auth),
                           ("mfa-fatigue", mfa_fatigue, auth), ("port-scan", port_scan, flows),
                           ("host-sweep", host_sweep, flows), ("beaconing", beaconing, flows),
                           ("outbound-flood", outbound_flood, flows),
                           ("inbound-remote-admin", inbound_remote_admin, flows),
                           ("c2-retry", lambda f, p: c2_retry(f, p, {(x["n"].get("src_ip"), x["n"].get("dst_ip"))
                                                                     for x in found if x["raw"]["behaviour"] ==
                                                                     "outbound-flood"}), flows),
                           ("web-scan", web_scan, rows), ("web-login-brute-force", web_login_brute_force, rows),
                           ("dns-ptr-sweep", dns_ptr_sweep, rows),
                           ("suspicious-burst", suspicious_burst, rows),
                           ("ad-acl-change", ad_acl_change, rows),
                           ("kerberos-ticket-burst", kerberos_ticket_burst, rows),
                           ("kerberos-user-enum", kerberos_user_enum, rows),
                           ("dns-tunnel", dns_tunnel, rows)):
        if name in off:
            continue
        try:
            got = fn(data, ps[name])
        except Exception as e:                             # noqa: BLE001 -- one rule, never the file
            log(f"behaviour rule {name} failed: {e}", "warning")
            continue
        found += got
    log(f"behaviour: {len(auth):,} sign-in row(s), {len(flows):,} connection row(s) checked — "
        f"{len(found)} pattern(s) found" + (": " + "; ".join(f["n"]["rule"] for f in found[:5]) if found else ""),
        "info")
    return found
