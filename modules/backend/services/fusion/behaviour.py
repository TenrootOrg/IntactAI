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
    "beaconing": {"connections": 20, "min_span_s": 1800, "max_jitter": 0.2, "min_interval_s": 10,
                  "max_interval_s": 3600, "severity": "medium"},
    "web-scan": {"paths": 50, "window_s": 600, "severity": "medium"},
    "web-login-brute-force": {"posts": 20, "window_s": 600, "severity": "medium"},
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
_AUTH = re.compile(r"\b(log ?(in|on)|sign.?in|auth|authenticat\w*|password|session\.start|credential|sso|"
                   r"4624|4625|4771|4776)\b", re.I)
_TEXT_AUTH = re.compile(r"(?:for|user)\s+(?:invalid user\s+)?([A-Za-z0-9._@\\$-]{1,64})\s+from\s+"
                        r"((?:\d{1,3}\.){3}\d{1,3})", re.I)
# PAM: "authentication failure; logname= uid=0 ... rhost=1.2.3.4  user=root"
_TEXT_PAM = re.compile(r"rhost=((?:\d{1,3}\.){3}\d{1,3})(?:\s+user=([A-Za-z0-9._@\\$-]{1,64}))?", re.I)
_IPV4 = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")
_OUTCOME_KEYS = ("outcome", "result", "status", "resulttype", "errorcode", "action", "disposition",
                 "reason", "eventid", "eventtype", "type", "message", "displaymessage")


def _outcome_text(n, raw) -> str:
    bits = [str(n.get(k) or "") for k in ("action", "rule", "message")]
    if isinstance(raw, dict):
        for k, v in raw.items():
            lk = re.sub(r"[^a-z]", "", str(k).lower())
            if any(lk.endswith(o) for o in _OUTCOME_KEYS) and not isinstance(v, (dict, list)):
                bits.append(f"{k}={v}")
        if "text" in raw:
            bits.append(str(raw["text"]))
    return " ".join(bits)


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


def auth_event(r):
    """(ts, user, src_ip, outcome, mfa) when the row is an authentication, else None."""
    n, raw = r.get("n") or {}, r.get("raw") or {}
    ts = n.get("ts")
    if not ts:
        return None
    user, src = n.get("user") or (n.get("users") or [None])[0], n.get("src_ip")
    text = _outcome_text(n, raw)
    phrase = False                     # user + source read from a sign-in phrase in free text
    if (not user or not src) and isinstance(raw, dict) and raw.get("text"):
        line = str(raw["text"])
        m = _TEXT_AUTH.search(line)
        if m:
            user, src, phrase = user or m.group(1), src or m.group(2), True
        else:
            m = _TEXT_PAM.search(line)
            if m:
                src, user, phrase = src or m.group(1), user or m.group(2) or "(unknown)", True
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
    if not (phrase or _AUTH.search(text) or _entra_outcome(raw) is not None or n.get("src_ip")):
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
        items.sort(key=lambda x: x[0])
        start, best = 0, None
        for end in range(len(items)):
            while items[end][0] - items[start][0] > p["window_s"]:
                start += 1
            users = {i[1][1] for i in items[start:end + 1]}
            if len(users) >= p["users"] and (best is None or len(users) > best[0]):
                best = (len(users), items[start:end + 1])
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


def _flows(rows):
    for i, r in enumerate(rows):
        n = r.get("n") or {}
        t = _t(n.get("ts"))
        if t is not None and n.get("src_ip") and (n.get("dst_ip") or n.get("domain")):
            yield t, n.get("src_ip"), n.get("dst_ip"), n.get("dst_port"), n.get("domain"), n.get("ts"), i


def port_scan(flows, p):
    out = []
    groups: dict = {}
    for f in flows:
        if f[2] and f[3]:
            groups.setdefault((f[1], f[2]), []).append(f)
    for (src, dst), items in groups.items():
        items.sort(key=lambda x: x[0])
        start, best = 0, None
        for end in range(len(items)):
            while items[end][0] - items[start][0] > p["window_s"]:
                start += 1
            ports = {i[3] for i in items[start:end + 1]}
            if len(ports) >= p["ports"] and (best is None or len(ports) > best[0]):
                best = (len(ports), items[start:end + 1])
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
        items.sort(key=lambda x: x[0])
        start, best = 0, None
        for end in range(len(items)):
            while items[end][0] - items[start][0] > p["window_s"]:
                start += 1
            hosts = {i[2] for i in items[start:end + 1]}
            if len(hosts) >= p["hosts"] and (best is None or len(hosts) > best[0]):
                best = (len(hosts), items[start:end + 1])
        if best:
            members = [(i[5], i[6]) for i in best[1]]
            out.append(_row("host-sweep", f"Host sweep on port {port}", p["severity"], members,
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
        items.sort(key=lambda x: x[0])
        start, best = 0, None
        for end in range(len(items)):
            while items[end][0] - items[start][0] > p["window_s"]:
                start += 1
            paths = {i[2] for i in items[start:end + 1]}
            if len(paths) >= p["paths"] and (best is None or len(paths) > best[0]):
                best = (len(paths), items[start:end + 1])
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
            if not d or t is None or d.count(".") < 2:
                continue
            labels = d.lower().rstrip(".").split(".")
            base = ".".join(labels[-2:])
            groups.setdefault(base, []).append((t, labels[0], n.get("ts"), i, n.get("src_ip")))
    for base, items in groups.items():
        items.sort(key=lambda x: x[0])
        start, best = 0, None
        for end in range(len(items)):
            while items[end][0] - items[start][0] > p["window_s"]:
                start += 1
            subs = {i[1] for i in items[start:end + 1]}
            if len(subs) >= p["subdomains"] and (best is None or len(subs) > best[0]):
                best = (len(subs), items[start:end + 1])
        long_q = [i for i in items if len(i[1]) >= p["long_label"] and _entropy(i[1]) >= 3.5]
        if best or len(long_q) >= p["long_queries"]:
            members = [(i[2], i[3]) for i in (best[1] if best else long_q)]
            src = next((i[4] for i in items if i[4]), None)
            why = (f"{best[0]} different subdomains of {base}" if best else
                   f"{len(long_q)} queries with long random labels under {base}")
            out.append(_row("dns-tunnel", "Possible DNS tunnelling", p["severity"], members,
                            {"domain": base, "src_ip": src}, why))
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
                           ("web-scan", web_scan, rows), ("web-login-brute-force", web_login_brute_force, rows),
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
