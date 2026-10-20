"""Sigma rules, evaluated directly against log rows -- the community detection set
(SigmaHQ, /opt/sigma-rules) run over attached log data, the way Hayabusa runs it
over endpoint event logs.

One rule = a logsource (which rows it is about) + a detection (named searches and
a condition). A row is a flat dict (dotted keys for nested JSON). Matching follows
the Sigma specification: values are case-insensitive whole-value matches with
`*` / `?` wildcards unless a modifier says otherwise; a list of values is OR
(AND with `|all`); a list of maps is OR; a plain list of strings is a keyword
search over every value; the condition combines searches with and / or / not,
parentheses, "1 of x*", "all of x*", "1 of them".

Which rules run on a row is decided by the row's own shape (`profiles`): a proxy
rule only on proxy rows, an Okta rule only on Okta rows, a Windows process
creation rule only on process-creation events -- a coincidental field name in
another product's log must never fire it. A rule this engine cannot evaluate
exactly (a placeholder, an aggregation, an unknown modifier) is skipped, never
guessed at.
"""
from __future__ import annotations

import base64
import ipaddress
import os
import re

_APP = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
# Splunk Security Content detections translated to Sigma and proved on their own
# attack_data recordings (scripts/dev/escu_to_sigma.py, escu_prove.py). Bundled in
# the image, so they run where /opt/sigma-rules is not installed too.
BUNDLED = os.path.join(_APP, "config", "sigma-escu")
# SigmaHQ: the copy baked into the image (SIGMA_RULES_DIR, pinned with the release,
# there offline too), else an older box's /opt/sigma-rules clone.
SIGMAHQ = next((d for d in (os.getenv("SIGMA_RULES_DIR"), "/opt/sigma-rules")
                if d and os.path.isdir(os.path.join(d, "rules"))), "/opt/sigma-rules")
RULE_DIRS = (os.path.join(SIGMAHQ, "rules"), os.path.join(SIGMAHQ, "rules-emerging-threats"), BUNDLED)
DEMOTE = os.path.join(os.path.dirname(BUNDLED), "sigma_demote.yaml")   # SigmaHQ rules noisy on benign data
LEVELS = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
MIN_LEVEL = "medium"                 # below it a rule is context, never a detection
_CACHE = {"key": None, "rules": [], "skipped": {}, "correlations": []}


# -- values -----------------------------------------------------------------------
def _wild(pat: str, cased=False, pre=False, post=False):
    """A Sigma value with * / ? wildcards (backslash escapes them) -> compiled regex.
    `pre` / `post` are the wildcards a modifier adds (contains / endswith /
    startswith): they go OUTSIDE the value, never textually after it -- a value
    ending in a backslash ("\\sysvol\\") would otherwise escape the added "*"."""
    out, i = [".*"] if pre else [], 0
    while i < len(pat):
        c = pat[i]
        if c == "\\" and i + 1 < len(pat) and pat[i + 1] in "*?\\":
            out.append(re.escape(pat[i + 1]))
            i += 2
            continue
        out.append(".*" if c == "*" else "." if c == "?" else re.escape(c))
        i += 1
    if post:
        out.append(".*")
    return re.compile("".join(out), 0 if cased else re.I | re.S)


def _has_wild(s: str) -> bool:
    # Read escapes in pairs, as _wild() does: USBSTOR\\* is a backslash and THEN a
    # wildcard (a look-behind took the star for escaped and matched it literally).
    return bool(re.search(r"[*?]", re.sub(r"\\[*?\\]", "", s)))


def _unescape(s: str) -> str:
    return re.sub(r"\\([*?\\])", r"\1", s)


def _windash(v: str) -> list:
    """`-x` also as `/x`, en/em dash and horizontal bar (Windows accepts them all)."""
    out = {v}
    for a in ("-", "/", "–", "—", "―"):
        out.add(re.sub(r"(?<=\s)-|^-", a, v))
        out.add(re.sub(r"(?<=\s)/|^/", a, v))
    return sorted(out)


def _b64offset(v: bytes) -> list:
    """The three base64 encodings of `v` at offsets 0/1/2 inside a larger blob."""
    out = []
    for i in range(3):
        enc = base64.b64encode(b"\x00" * i + v).decode()
        start = (0, 2, 3)[i]
        end = len(enc) - (0, 3, 2)[(len(v) + i) % 3] if (len(v) + i) % 3 else len(enc)
        out.append(enc[start:end])
    return out


class Unsupported(Exception):
    pass


def _matcher(mods, value):
    """(callable(field_value) -> bool) for one value under a modifier chain."""
    cased = "cased" in mods
    if "exists" in mods:
        want = str(value).lower() in ("true", "yes", "1")
        return ("exists", want)
    if value is None:
        return lambda v: v in (None, "")
    if any(m in mods for m in ("gt", "gte", "lt", "lte")):
        n = float(value)
        op = next(m for m in mods if m in ("gt", "gte", "lt", "lte"))

        def num(v, n=n, op=op):
            try:
                x = float(v)
            except (TypeError, ValueError):
                return False
            return {"gt": x > n, "gte": x >= n, "lt": x < n, "lte": x <= n}[op]
        return num
    if "cidr" in mods:
        net = ipaddress.ip_network(str(value), strict=False)

        def incidr(v, net=net):
            try:
                return ipaddress.ip_address(str(v).strip()) in net
            except ValueError:
                return False
        return incidr
    if isinstance(value, bool):
        value = "true" if value else "false"
    s = str(value)
    if "re" in mods:
        flags = 0
        flags |= re.I if "i" in mods else 0
        flags |= re.M if "m" in mods else 0
        flags |= re.S if "s" in mods else 0
        rx = re.compile(s, flags)
        return lambda v, rx=rx: v is not None and rx.search(str(v)) is not None
    variants = _windash(s) if "windash" in mods else [s]
    if any(m in mods for m in ("wide", "utf16le", "utf16be", "utf16", "base64", "base64offset")):
        raw = []
        for x in variants:
            b = _unescape(x).encode()
            if "wide" in mods or "utf16le" in mods:
                b = _unescape(x).encode("utf-16-le")
            elif "utf16be" in mods:
                b = _unescape(x).encode("utf-16-be")
            elif "utf16" in mods:
                b = _unescape(x).encode("utf-16")
            if "base64offset" in mods:
                raw.extend(_b64offset(b))
            elif "base64" in mods:
                raw.append(base64.b64encode(b).decode())
            else:
                raw.append(b.decode("latin-1"))
        variants = [re.sub(r"([*?\\])", r"\\\1", x) for x in raw]
        cased = True                                       # an encoding is exact
    pre = "contains" in mods or "endswith" in mods
    post = "contains" in mods or "startswith" in mods
    tests = []
    for x in variants:
        if _has_wild(x):
            rx = _wild(x, cased, pre, post)
            tests.append(lambda v, rx=rx: rx.fullmatch(v) is not None)
            continue
        # No wildcard of its own (nearly every Sigma value): plain string checks,
        # not a regex -- same meaning, a fraction of the cost on big exports.
        lit = _unescape(x) if cased else _unescape(x).lower()
        low = (lambda v: v) if cased else str.lower
        if pre and post:
            tests.append(lambda v, lit=lit, low=low: lit in low(v))
        elif pre:
            tests.append(lambda v, lit=lit, low=low: low(v).endswith(lit))
        elif post:
            tests.append(lambda v, lit=lit, low=low: low(v).startswith(lit))
        else:
            tests.append(lambda v, lit=lit, low=low: low(v) == lit)

    def test(v):
        if v is None:
            return False
        sv = str(v) if not isinstance(v, bool) else ("true" if v else "false")
        return any(t(sv) for t in tests)
    return test


_KNOWN_MODS = {"contains", "startswith", "endswith", "all", "re", "i", "m", "s", "base64", "base64offset",
               "wide", "utf16le", "utf16be", "utf16", "windash", "cidr", "exists", "gt", "gte", "lt", "lte",
               "cased", "fieldref"}


_PLAIN_MODS = {"contains", "startswith", "endswith", "cased"}


def _fast_list(mods, vals):
    """ONE test for a list of plain values (no wildcard, no encoding, not |all) --
    the common case, and the costly one: a user-agent rule lists hundreds of
    strings. equals = a set lookup, startswith / endswith = one call with a
    tuple, contains = one combined regex. Same meaning as testing them one by
    one; None when the list is not of that kind."""
    if len(vals) < 2 or any(m not in _PLAIN_MODS for m in mods):
        return None
    if any(not isinstance(v, (str, int)) or isinstance(v, bool) or _has_wild(str(v)) for v in vals):
        return None
    cased = "cased" in mods
    lits = [_unescape(str(v)) if cased else _unescape(str(v)).lower() for v in vals]
    low = (lambda v: str(v)) if cased else (lambda v: str(v).lower())
    if "contains" in mods:
        rx = re.compile("|".join(re.escape(x) for x in sorted(set(lits), key=len, reverse=True)))
        return lambda v, rx=rx, low=low: rx.search(low(v)) is not None
    if "startswith" in mods:
        t = tuple(lits)
        return lambda v, t=t, low=low: low(v).startswith(t)
    if "endswith" in mods:
        t = tuple(lits)
        return lambda v, t=t, low=low: low(v).endswith(t)
    fs = frozenset(lits)
    return lambda v, fs=fs, low=low: low(v) in fs


def _field_cond(spec, values):
    """One `field|mods: values` entry -> callable(event) -> bool."""
    parts = str(spec).split("|")
    field, mods = parts[0], [m.lower() for m in parts[1:]]
    if any(m not in _KNOWN_MODS for m in mods) or "expand" in mods:
        raise Unsupported(f"modifier {mods}")
    vals = values if isinstance(values, list) else [values]
    if "fieldref" in mods:
        refs = [str(v) for v in vals]

        def fr(ev, field=field, refs=refs):
            a = ev.get(field)
            return a is not None and any(str(ev.get(r)) == str(a) for r in refs)
        return fr
    fast = _fast_list(mods, vals)
    if fast is not None:
        def cond_fast(ev, field=field, fast=fast):
            v = ev.get(field)
            if isinstance(v, list):
                return any(fast(x) for x in v if x is not None)
            return v is not None and fast(v)
        return cond_fast
    tests = [_matcher(mods, v) for v in vals]
    if tests and isinstance(tests[0], tuple):
        want = tests[0][1]
        return lambda ev, field=field, want=want: (ev.get(field) not in (None, "")) == want
    every = "all" in mods

    def cond(ev, field=field, tests=tests, every=every):
        v = ev.get(field)
        if isinstance(v, list):
            return any((all if every else any)(t(x) for t in tests) for x in v)
        return (all if every else any)(t(v) for t in tests)
    return cond


def _search(body):
    """A named search -> callable(event) -> bool."""
    if isinstance(body, dict):
        conds = [_field_cond(k, v) for k, v in body.items()]
        return lambda ev, conds=conds: all(c(ev) for c in conds)
    if isinstance(body, list) and body and all(isinstance(x, dict) for x in body):
        maps = [_search(x) for x in body]
        return lambda ev, maps=maps: any(m(ev) for m in maps)
    if isinstance(body, (list, str, int)):                  # keywords: anywhere in the event
        kws = body if isinstance(body, list) else [body]
        if any(isinstance(k, (dict, list)) for k in kws):
            raise Unsupported("mixed keyword list")
        lits = [_unescape(str(k)).lower() for k in kws if not _has_wild(str(k))]
        wild = [_wild(str(k), pre=True, post=True).pattern for k in kws if _has_wild(str(k))]
        rx = re.compile("|".join(f"(?:{w})" for w in wild), re.I | re.S) if wild else None

        def kw(ev, lits=lits, rx=rx):
            for t in ev.texts_lower():
                if any(k in t for k in lits) or (rx is not None and rx.fullmatch(t)):
                    return True
            return False
        return kw
    raise Unsupported("empty search")


# -- condition ----------------------------------------------------------------------
_TOK = re.compile(r"\s*(\(|\)|[A-Za-z0-9_*]+)")


def _condition(text, names):
    """Parse a condition string over the rule's search names -> callable(results)."""
    if "|" in text:
        raise Unsupported("aggregation")
    toks = _TOK.findall(text)
    if "".join(toks).replace(" ", "") != re.sub(r"\s+", "", text):
        raise Unsupported(f"condition {text!r}")
    pos = [0]

    def peek():
        return toks[pos[0]].lower() if pos[0] < len(toks) else None

    def take():
        pos[0] += 1
        return toks[pos[0] - 1]

    def group(pat):
        if pat.lower() == "them":
            return list(names)
        rx = _wild(pat, cased=True)
        got = [n for n in names if rx.fullmatch(n)]
        if not got:
            raise Unsupported(f"no search matches {pat}")
        return got

    def atom():
        t = peek()
        if t == "(":
            take()
            node = expr()
            if take() != ")":
                raise Unsupported("unbalanced")
            return node
        if t == "not":
            take()
            inner = atom()
            return lambda r, inner=inner: not inner(r)
        if t in ("1", "any", "all") and pos[0] + 2 < len(toks) + 1 and len(toks) > pos[0] + 2 \
                and toks[pos[0] + 1].lower() == "of":
            q = take().lower()
            take()
            members = group(take())
            if q == "all":
                return lambda r, m=members: all(r[x] for x in m)
            return lambda r, m=members: any(r[x] for x in m)
        name = take()
        if name not in names:
            raise Unsupported(f"unknown search {name}")
        return lambda r, name=name: r[name]

    def conj():
        node = atom()
        while peek() == "and":
            take()
            rhs = atom()
            node = (lambda r, a=node, b=rhs: a(r) and b(r))
        return node

    def expr():
        node = conj()
        while peek() == "or":
            take()
            rhs = conj()
            node = (lambda r, a=node, b=rhs: a(r) or b(r))
        return node
    node = expr()
    if pos[0] != len(toks):
        raise Unsupported(f"trailing {toks[pos[0]:]}")
    return node


def compile_rule(doc):
    """A parsed rule YAML -> compiled rule dict, or raise Unsupported."""
    det = doc.get("detection") or {}
    cond = det.get("condition")
    if not cond:
        raise Unsupported("no condition")
    conds = cond if isinstance(cond, list) else [cond]
    searches = {k: _search(v) for k, v in det.items() if k not in ("condition", "timeframe")}
    trees = [_condition(str(c), searches) for c in conds]
    ls = doc.get("logsource") or {}
    tags = [str(t) for t in doc.get("tags") or []]
    return {"id": str(doc.get("id") or doc.get("title")), "title": str(doc.get("title") or "Sigma rule"),
            "level": str(doc.get("level") or "medium").lower(),
            "product": (ls.get("product") or "").lower() or None,
            "category": (ls.get("category") or "").lower() or None,
            "service": (ls.get("service") or "").lower() or None,
            "mitre": sorted({t.split(".", 1)[1].upper() for t in tags if re.match(r"attack\.t\d{4}", t)}),
            "searches": searches, "trees": trees,
            # False: a low signal normal systems also raise -- context only, never
            # counted toward a "burst of suspicious activity" (behaviour.py).
            "burst": doc.get("x-intact-burst") is not False}


def load(dirs=RULE_DIRS, min_level=MIN_LEVEL) -> dict:
    """All usable rules (cached until a rule directory changes). Returns
    {"rules": [...], "correlations": [...], "skipped": {reason: count}, "dirs": [...]}.
    A file may hold several YAML documents: a correlation rule ships beside the
    base rule it counts."""
    import yaml
    present = [d for d in dirs if os.path.isdir(d)]
    key = tuple((d, os.path.getmtime(d)) for d in present)
    if key == _CACHE["key"]:
        return _CACHE
    rules, skipped, pending, refs = [], {}, [], {}
    try:
        with open(DEMOTE) as fh:
            demote = set((yaml.safe_load(fh) or {}).keys())
    except Exception:                                      # noqa: BLE001 -- no list = nothing demoted
        demote = set()
    for d in present:
        # The bundled set also ships LOW rules (Splunk "Anomaly" signals): context on
        # their own, and what the suspicious-activity burst rule counts per host.
        floor = min(LEVELS[min_level], LEVELS["low"]) if d == BUNDLED else LEVELS[min_level]
        for root, _dirs, files in os.walk(d):
            for fn in files:
                if not fn.endswith((".yml", ".yaml")):
                    continue
                try:
                    with open(os.path.join(root, fn)) as fh:
                        docs = [x for x in yaml.safe_load_all(fh) if isinstance(x, dict)]
                except Exception:                          # noqa: BLE001
                    skipped["unreadable"] = skipped.get("unreadable", 0) + 1
                    continue
                for doc in docs:
                    if "correlation" in doc:
                        pending.append((doc, floor))
                    elif "detection" in doc:
                        for ref in (doc.get("name"), doc.get("id")):
                            if ref:
                                refs[str(ref)] = doc
                for doc in docs:
                    if "detection" not in doc:
                        continue
                    if str(doc.get("status") or "").lower() in ("deprecated", "unsupported"):
                        skipped["deprecated"] = skipped.get("deprecated", 0) + 1
                        continue
                    if LEVELS.get(str(doc.get("level") or "").lower(), 0) < floor:
                        skipped["below level"] = skipped.get("below level", 0) + 1
                        continue
                    try:
                        rule = compile_rule(doc)
                        if rule["id"] in demote:              # noisy on normal systems: context only
                            rule.update(level="low", burst=False)
                        rules.append(rule)
                    except Unsupported as e:
                        k = str(e).split(" ")[0]
                        skipped[k] = skipped.get(k, 0) + 1
                    except Exception:                          # noqa: BLE001
                        skipped["invalid"] = skipped.get("invalid", 0) + 1
    correlations, bases = [], set()
    for doc, floor in pending:
        try:
            if LEVELS.get(str(doc.get("level") or "").lower(), 0) < floor:
                skipped["below level"] = skipped.get("below level", 0) + 1
                continue
            c = compile_correlation(doc, refs)
        except Unsupported as e:
            k = str(e).split(" ")[0]
            skipped[k] = skipped.get(k, 0) + 1
            continue
        except Exception:                                  # noqa: BLE001
            skipped["invalid"] = skipped.get("invalid", 0) + 1
            continue
        correlations.append(c)
        if not c["generate"]:
            bases |= {b["id"] for b in c["bases"]}
    # A base rule counts toward its correlation; on its own one failed sign-in is
    # not a detection (Sigma's `generate: false`, the default).
    rules = [r for r in rules if r["id"] not in bases]
    _CACHE.update(key=key, rules=rules, skipped=skipped, dirs=present, correlations=correlations)
    return _CACHE


# -- correlation rules: a count over a time window -----------------------------------
# Sigma's correlation spec (event_count / value_count): rows matching a base rule,
# grouped by fields, counted -- or their distinct values of one field counted --
# within a sliding timespan. About 190 Splunk detections are of this shape ("stats
# count by user | where count > 10"): password spray, MFA floods, mass share access.
_SPAN = re.compile(r"^\s*(\d+)\s*([smhdw])\s*$", re.I)
_SPAN_S = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
_OPS = {"gte": lambda a, b: a >= b, "gt": lambda a, b: a > b}


def _span_seconds(text) -> int:
    m = _SPAN.match(str(text or ""))
    if not m:
        raise Unsupported(f"timespan {text!r}")
    return int(m.group(1)) * _SPAN_S[m.group(2).lower()]


def compile_correlation(doc, refs) -> dict:
    """A correlation YAML -> compiled dict, or raise Unsupported. `refs` maps a base
    rule's name / id to its YAML document."""
    c = doc.get("correlation") or {}
    typ = c.get("type")
    if typ not in ("event_count", "value_count"):
        raise Unsupported(f"correlation-{typ}")          # temporal: several rules in order
    cond = c.get("condition") or {}
    op = next((k for k in _OPS if k in cond), None)
    if op is None:
        raise Unsupported("correlation-condition")       # lt / lte / eq: "too few" is not an attack
    field = cond.get("field") if typ == "value_count" else None
    if typ == "value_count" and not field:
        raise Unsupported("correlation-field")
    names = c.get("rules") or []
    names = [names] if isinstance(names, str) else names
    try:
        bases = [compile_rule(refs[str(n)]) for n in names]
    except KeyError as e:
        raise Unsupported(f"correlation-base-missing {e}") from None
    if not bases:
        raise Unsupported("correlation-no-base")
    tags = [str(t) for t in doc.get("tags") or []] + [str(t) for b in names for t in (refs[str(b)].get("tags") or [])]
    gb = c.get("group-by") or []
    return {"id": str(doc.get("id") or doc.get("name") or doc.get("title")),
            "title": str(doc.get("title") or "Sigma correlation"),
            "level": str(doc.get("level") or "medium").lower(),
            "mitre": sorted({t.split(".", 1)[1].upper() for t in tags if re.match(r"attack\.t\d{4}", t)}),
            "type": typ, "op": op, "n": int(cond[op]), "field": field,
            "group_by": [gb] if isinstance(gb, str) else list(gb),
            "timespan": _span_seconds(c.get("timespan")),
            "bases": bases, "generate": bool(doc.get("generate") or c.get("generate")),
            "burst": doc.get("x-intact-burst") is not False}


def _base_match(rule, ev, profs) -> bool:
    if not _applies(rule, profs):
        return False
    try:
        res = _Lazy(rule["searches"], ev)
        return any(t(res) for t in rule["trees"])
    except Exception:                                      # noqa: BLE001 -- one odd value
        return False


def correlate(items, correlations=None, max_members=50) -> list:
    """items: (epoch_seconds, row) pairs. One hit per correlation and group: its
    densest window, if that window meets the condition. A hit is {"rule", "group",
    "count", "first", "last", "members" (item indexes, first `max_members`)}.
    ponytail: one episode per group -- two separate floods by the same source read
    as one hit with the larger count; split by gap if an analyst needs both."""
    correlations = load()["correlations"] if correlations is None else correlations
    if not correlations:
        return []
    events = []
    for i, (t, row) in enumerate(items):
        if t is None:
            continue
        ev = Event(row)
        profs = _profiles_cached(ev)
        if profs:
            events.append((t, i, ev, profs))
    events.sort(key=lambda e: e[0])
    hits = []
    for c in correlations:
        groups: dict = {}
        for t, i, ev, profs in events:
            if not any(_base_match(b, ev, profs) for b in c["bases"]):
                continue
            key = tuple(str(ev.get(f) if ev.get(f) is not None else "") for f in c["group_by"])
            val = None
            if c["field"]:
                val = ev.get(c["field"])
                if val in (None, "", "-"):
                    continue
                val = str(val).lower()
            groups.setdefault(key, []).append((t, i, val))
        for key, seq in groups.items():
            best = _densest_window(seq, c["timespan"], c["type"] == "value_count")
            if best and _OPS[c["op"]](best[0], c["n"]):
                n, lo, hi = best
                hits.append({"rule": c, "group": dict(zip(c["group_by"], key)), "count": n,
                             "first": seq[lo][0], "last": seq[hi][0],
                             "members": [seq[j][1] for j in range(lo, hi + 1)][:max_members]})
    return hits


def _densest_window(seq, span, distinct):
    """(metric, lo, hi) of the window of `span` seconds with the most events -- or,
    with `distinct`, the most distinct values -- over time-sorted (t, i, value)."""
    best, lo, vals = None, 0, {}
    for hi, (t, _i, v) in enumerate(seq):
        if distinct:
            vals[v] = vals.get(v, 0) + 1
        while t - seq[lo][0] > span:
            if distinct:
                ov = seq[lo][2]
                vals[ov] -= 1
                if not vals[ov]:
                    del vals[ov]
            lo += 1
        metric = len(vals) if distinct else hi - lo + 1
        if best is None or metric > best[0]:
            best = (metric, lo, hi)
    return best


# -- events: a row seen the way Sigma rules name fields ------------------------------
# Taxonomy field -> where other products keep it. Sigma rules use the Sysmon / CIM
# style names; a Security 4688 event, a proxy export or a DNS log spells them
# otherwise (the role pySigma's processing pipelines play).
# The threat name an AV / EDR product gave a detection -- the field Sigma's antivirus
# rules call Signature ("HackTool:Win32/Mimikatz"). Not a bare "signature" column:
# Suricata and other IDS logs use that for their own rule names.
_THREAT_NAMES = ("threatname", "threat_name", "virusname", "virus_name", "malwarename", "malware_name",
                 "risk_name", "riskname", "detectionname", "detection_name", "infectionname", "infection_name",
                 "threat", "virus", "malware")

ALIASES = {
    # Sigma's antivirus rules (password dumpers, ransomware, web shells: mostly
    # CRITICAL) read Signature and Filename; each AV / EDR product names them its way.
    "signature": list(_THREAT_NAMES),
    "filename": ["file_name", "filepath", "file_path", "targetfilename", "path", "file.path", "file.name",
                 "objectname", "infectedfile", "infected_file"],
    # 86 SigmaHQ rules name the event provider Provider_Name (the EVTX-to-JSON name);
    # Windows event XML, NXLog and Winlogbeat call it Provider / SourceName / provider_name.
    "provider_name": ["provider", "sourcename", "providername", "winlog.provider_name"],
    # CloudTrail in OCSF (AWS Security Lake): the CloudTrail names Sigma rules use
    "eventname": ["api.operation"], "eventsource": ["api.service.name"],
    "errorcode": ["api.response.error"], "errormessage": ["api.response.message"],
    "useragent": ["http_request.user_agent"], "sourceipaddress": ["src_endpoint.ip"],
    "useridentity.type": ["actor.user.type"], "useridentity.arn": ["actor.user.uid"],
    "useridentity.accountid": ["actor.user.account.uid"], "recipientaccountid": ["cloud.account.uid"],
    "requestparameters": ["api.request.data"], "responseelements": ["api.response.data"],
    "awsregion": ["cloud.region"],
    # process telemetry: Security 4688, Defender XDR, CrowdStrike FDR, Elastic, generic
    "image": ["newprocessname", "folderpath", "imagefilename", "process.executable", "processpath",
              "actor_process_image_path", "exe", "columns.path", "processname"],
    "parentimage": ["parentprocessname", "initiatingprocessfolderpath", "process.parent.executable",
                    "parentimagefilename", "causality_actor_process_image_path"],
    "commandline": ["processcommandline", "process.command_line", "actor_process_command_line", "cmdline"],
    "parentcommandline": ["initiatingprocesscommandline", "process.parent.command_line",
                          "parentcommandline"],
    "user": ["subjectusername", "targetusername", "accountname", "user.name", "username"],
    "originalfilename": ["processversioninfooriginalfilename", "process.pe.original_file_name"],
    "c-uri": ["url", "uri", "requesturl", "url.full", "url.original", "clientrequesturi"],
    "c-uri-query": ["cs-uri-query", "url.query", "query_string", "uri_query"],
    "c-uri-stem": ["cs-uri-stem", "url.path", "uri_path"],
    # Network HTTP (Suricata http.url, Zeek uri) keeps path and query in ONE field;
    # the web server rules that look at either are contains-style, so it serves both.
    "cs-uri-query": ["c-uri-query", "url.query", "query_string", "uri_query", "url", "uri"],
    "cs-uri-stem": ["c-uri-stem", "url.path", "uri_path", "uri", "clientrequesturi", "url"],
    "c-useragent": ["useragent", "user_agent", "http_user_agent", "cs(user-agent)", "user_agent.original",
                    "http.user_agent",
                    "clientrequestuseragent", "cs-user-agent", "c-user-agent"],
    "cs-user-agent": ["c-useragent", "useragent", "user_agent", "cs(user-agent)", "user_agent.original"],
    "cs-host": ["host", "domain", "url.domain", "clientrequesthost", "cs(host)", "hostname"],
    "cs-method": ["method", "http_method", "http.request.method", "clientrequestmethod", "request_method"],
    "sc-status": ["status", "http.response.status_code", "edgeresponsestatus", "status_code"],
    "cs-referrer": ["referer", "referrer", "cs(referer)", "http.request.referrer"],
    "c-ip": ["clientip", "src_ip", "source.ip", "srcip"],
    "query": ["dns.question.name", "queryname", "qname", "domain"],
    "dst_ip": ["dstip", "destination.ip", "dest_ip", "id.resp_h", "dst"],
    "src_ip": ["srcip", "source.ip", "id.orig_h", "src"],
    "dst_port": ["dstport", "destination.port", "dest_port", "id.resp_p", "dpt"],
    "src_port": ["srcport", "source.port", "id.orig_p", "spt"],
}


class Event:
    """A row with Sigma's field lookup: exact name, case-insensitive name, dotted
    suffix ("Image" finds "Event.EventData.Image"), then the taxonomy aliases."""
    __slots__ = ("row", "_low", "_last", "_texts", "_ltexts")

    def __init__(self, row):
        self.row = row
        self._low = None
        self._last = None
        self._texts = None
        self._ltexts = None

    def _index(self):
        self._low, self._last = {}, {}
        for k, v in self.row.items():
            # Defender writes "Threat Name", the rules say ThreatName: spaces never count.
            lk = str(k).lower().replace(" ", "")
            self._low.setdefault(lk, v)
            parts = lk.split(".")
            for i in range(1, len(parts)):
                self._last.setdefault(".".join(parts[i:]), v)

    def get(self, field):
        if field in self.row:
            return self.row[field]
        if self._low is None:
            self._index()
        f = str(field).lower().replace(" ", "")
        for name in [f] + ALIASES.get(f, []):
            if name in self._low:
                return self._low[name]
            if name in self._last:
                return self._last[name]
        if f == "targetobject" and "ObjectValueName" in self.row:
            # Security 4657: \REGISTRY\MACHINE\...\Lsa + "Security Packages", as Sysmon writes it
            # (HKLM\...\Lsa\Security Packages) for the registry rules.
            key = re.sub(r"^\\REGISTRY\\MACHINE", "HKLM", str(self.row.get("ObjectName") or ""), flags=re.I)
            key = re.sub(r"^\\REGISTRY\\USER", "HKU", key, flags=re.I)
            return f"{key}\\{self.row['ObjectValueName']}"
        if f == "details" and "NewValue" in self.row:
            return self.row["NewValue"]
        if f == "c-uri":
            # IIS / W3C and nginx keep path and query apart ("/shell.jsp", "cmd=id");
            # a rule on the whole URL ("*.jsp?cmd=*") reads them joined, as a proxy writes it.
            path, query = self.get("c-uri-stem"), self.get("c-uri-query")
            if path not in (None, "", "-"):
                return f"{path}?{query}" if query not in (None, "", "-") else path
        return None

    def texts_lower(self):
        if self._ltexts is None:
            self._ltexts = [t.lower() for t in self.texts()]
        return self._ltexts

    def texts(self):
        if self._texts is None:
            self._texts = [str(v) for v in self.row.values() if v not in (None, "") and not isinstance(v, (dict, list))]
        return self._texts


# -- which rules a row is about -------------------------------------------------------
# Windows event -> Sigma category, by provider + EventID (the Sysmon / Security
# mapping every Sigma backend uses).
_SYSMON = {1: "process_creation", 2: "file_change", 3: "network_connection", 4: "sysmon_status",
           5: "process_termination",
           6: "driver_load", 7: "image_load", 8: "create_remote_thread", 9: "raw_access_thread",
           10: "process_access", 11: "file_event", 12: "registry_add", 13: "registry_set",
           14: "registry_rename", 15: "create_stream_hash", 17: "pipe_created", 18: "pipe_created",
           19: "wmi_event", 20: "wmi_event", 21: "wmi_event", 22: "dns_query", 23: "file_delete",
           24: "clipboard_capture", 25: "process_tampering", 26: "file_delete_detected",
           16: "sysmon_status", 255: "sysmon_error"}
_REGISTRY = {"registry_add", "registry_set", "registry_rename", "registry_delete"}
_CHANNELS = {"security": "security", "system": "system", "application": "application",
             # SigmaHQ services with no channel here until the 2026-10-20 severity audit
             # (PrintNightmare is critical): SigmaHQ's own service -> channel names.
             "microsoft-windows-printservice/operational": "printservice-operational",
             "microsoft-windows-printservice/admin": "printservice-admin",
             "microsoft-windows-dns-server/analytical": "dns-server-analytic",
             "microsoft-windows-certificateservicesclient-lifecycle-system/operational":
                 "certificateservicesclient-lifecycle-system",
             "microsoft-windows-smbclient/connectivity": "smbclient-connectivity",
             "microsoft-windows-powershell/operational": "powershell",
             "windows powershell": "powershell-classic", "microsoft-windows-sysmon/operational": "sysmon",
             "microsoft-windows-windows defender/operational": "windefend",
             "microsoft-windows-taskscheduler/operational": "taskscheduler",
             "microsoft-windows-bits-client/operational": "bits-client",
             "microsoft-windows-dns-client/operational": "dns-client",
             "microsoft-windows-wmi-activity/operational": "wmi",
             "microsoft-windows-terminalservices-localsessionmanager/operational": "terminalservices-localsessionmanager",
             "microsoft-windows-codeintegrity/operational": "codeintegrity-operational",
             "microsoft-windows-applocker/exe and dll": "applocker",
             "microsoft-windows-smbclient/security": "smbclient-security",
             "microsoft-windows-ntlm/operational": "ntlm", "directory service": "directory-service",
             "dns server": "dns-server", "microsoft-windows-firewall-with-advanced-security/firewall": "firewall-as",
             # the rest of SigmaHQ's Windows services (sigma's windows pipeline names these channels)
             "microsoft-windows-appxdeploymentserver/operational": "appxdeployment-server",
             "msexchange management": "msexchange-management",
             "microsoft-iis-configuration/operational": "iis-configuration",
             "microsoft-windows-security-mitigations/kernelmode": "security-mitigations",
             "microsoft-windows-security-mitigations/usermode": "security-mitigations",
             "microsoft-windows-shell-core/operational": "shell-core",
             "microsoft-windows-driverframeworks-usermode/operational": "driver-framework",
             "openssh/operational": "openssh",
             "microsoft-windows-appxpackaging/operational": "appxpackaging-om",
             "microsoft-windows-appmodel-runtime/admin": "appmodel-runtime",
             "microsoft-windows-capi2/operational": "capi2",
             "microsoft-servicebus-client": "microsoft-servicebus-client",
             "microsoft-windows-diagnosis-scripted/operational": "diagnosis-scripted",
             "microsoft-windows-ldap-client/debug": "ldap",
             "microsoft-windows-lsa/operational": "lsa-server",
             "microsoft-windows-certificateservicesclient-lifecycle-system/operational":
                 "certificateservicesclient-lifecycle-system",
             "microsoft-windows-smbserver/connectivity": "smbserver-connectivity"}


def _has(ev, *names):
    """Has one of these fields under its OWN name (exact, case-insensitive or dotted
    suffix) -- never via the taxonomy aliases: a row's shape is judged on what the
    product wrote, or a web server's cs-uri-stem would make it a proxy log."""
    if ev._low is None:
        ev._index()
    for n in names:
        if n in ev.row and ev.row[n] not in (None, ""):
            return True
        f = str(n).lower().replace(" ", "")
        v = ev._low.get(f, ev._last.get(f))
        if v not in (None, ""):
            return True
    return False


def profiles(row) -> set:
    """{(product, category, service)} this row is evidence for. Unknown parts are
    None; a rule matches when every part it names is in one of the tuples."""
    ev = row if isinstance(row, Event) else Event(row)
    out = set()
    eid = ev.get("EventID") or ev.get("EventCode") or (ev.get("Id") if _has(ev, "LogName", "ProviderName") else None)
    chan = str(ev.get("Channel") or ev.get("LogName") or ev.get("log_name") or "").lower()
    prov = str(ev.get("Provider") or ev.get("Provider.#attributes.Name") or ev.get("Provider_Name")
               or ev.get("SourceName") or ev.get("ProviderName") or ev.get("provider_name")
               or "").lower()                         # NXLog, PowerShell, Winlogbeat names for the provider
    if eid not in (None, "") and (chan or prov):
        try:
            eid = int(str(eid).strip())
        except ValueError:
            eid = None
        # Sysmon for Linux shares the event IDs, on channel "Linux-Sysmon/Operational":
        # profiled as Windows, no Linux Sigma rule ever ran on it (2026-10-15).
        lin = "linux-sysmon" in chan or "linux-sysmon" in prov
        osname = "linux" if lin else "windows"
        svc = _CHANNELS.get(chan)
        if not lin:
            out.add(("windows", None, svc))
        if "sysmon" in chan or "sysmon" in prov:
            cat = _SYSMON.get(eid)
            if cat:
                out.add((osname, cat, "sysmon"))
                if cat in _REGISTRY:
                    out.add(("windows", "registry_event", "sysmon"))
                if eid == 12:                          # Sysmon 12 = a key or value added OR deleted
                    out.add(("windows", "registry_delete", "sysmon"))
                if cat == "dns_query":                 # a DNS query: the generic DNS rules apply too
                    out.add((None, "dns", None))
        if eid == 4688:
            out.add(("windows", "process_creation", "security"))
        if eid == 4657 and chan == "security":                 # registry value modified (object auditing)
            out.add(("windows", "registry_set", "security"))
            out.add(("windows", "registry_event", "security"))
        if eid in (4104, 4103) and "powershell" in chan:
            out.add(("windows", "ps_script" if eid == 4104 else "ps_module", "powershell"))
        if eid in (400, 403, 600, 800) and chan == "windows powershell":
            out.add(("windows", "ps_classic_start" if eid == 400 else "ps_classic_provider_start", "powershell-classic"))
        if _has(ev, *_THREAT_NAMES):                       # Defender 1116 / 1117: the threat it named
            out.add((None, "antivirus", None))
        return out
    # Process telemetry from an EDR export (no Windows event envelope): a command
    # line next to an image path is a process creation, on Windows when the path is.
    cmd = ev.get("CommandLine")
    proc = ev.get("Image") or ev.get("FileName") or ev.get("process.name") or ev.get("ProcessName")
    if cmd not in (None, "") and proc not in (None, ""):
        win = "\\" in str(proc) or str(proc).lower().endswith(".exe") or ".exe" in str(cmd).lower()
        out.add(("windows" if win else "linux", "process_creation", None))
    # osquery process events: macOS EndpointSecurity (es_process_events) or the Linux
    # audit / eBPF tables. Profiles are cached per row SHAPE, so this must not turn on a
    # value: exec, fork and exit rows share one shape (an exit row only repeats the path).
    oq = str(ev.get("name") or "")
    if oq in ("es_process_events", "process_events", "bpf_process_events") and _has(ev, "columns.path"):
        out.add(("macos" if oq.startswith("es_") else "linux", "process_creation", None))
    if _has(ev, "eventType") and _has(ev, "actor.alternateId", "actor.id", "displayMessage"):
        out.add(("okta", None, "okta"))
    if _has(ev, "userPrincipalName") and _has(ev, "appDisplayName", "ResultType", "resultType", "status.errorCode",
                                              "conditionalAccessStatus", "ConditionalAccessStatus"):
        out.add(("azure", None, "signinlogs"))
    if _has(ev, "activityDisplayName", "ActivityDisplayName", "OperationName") and _has(
            ev, "targetResources", "TargetResources", "initiatedBy", "InitiatedBy", "LoggedByService", "Category"):
        out.add(("azure", None, "auditlogs"))
    if _has(ev, "operationName") and _has(ev, "resourceId", "ResourceId", "properties.eventCategory"):
        out.add(("azure", None, "activitylogs"))
    if _has(ev, "riskEventType"):
        out.add(("azure", None, "riskdetection"))
    # O365 Management Activity: Workload, or (a field-trimmed export) RecordType /
    # the organisation next to Operation and UserId.
    if _has(ev, "Operation") and (_has(ev, "Workload") or (_has(ev, "UserId") and _has(
            ev, "RecordType", "OrganizationId", "OrganizationName"))):
        out.add(("m365", None, "threat_management"))
        out.add(("m365", None, "audit"))
    if _has(ev, "protoPayload.methodName", "protoPayload.serviceName"):
        out.add(("gcp", None, "gcp.audit"))
    if _has(ev, "id.applicationName") or (_has(ev, "events") and _has(ev, "actor.email")):
        out.add(("gcp", None, "google_workspace.admin"))
        out.add(("google_workspace", None, "google_workspace.admin"))
    if _has(ev, "eventSource") and _has(ev, "eventName") and _has(ev, "awsRegion", "userIdentity.type",
                                                                   "recipientAccountId"):
        out.add(("aws", None, "cloudtrail"))
    if _has(ev, "api.operation") and str(ev.get("metadata.product.name") or "").lower() == "cloudtrail":
        out.add(("aws", None, "cloudtrail"))                # the same log as OCSF (AWS Security Lake)
    if _has(ev, "action") and _has(ev, "actor", "actor_id") and _has(ev, "org", "repo", "business", "@timestamp"):
        out.add(("github", None, "audit"))
    if _has(ev, "action") and _has(ev, "actionlabel") and _has(ev, "isotimestamp", "timestamp"):
        out.add(("cisco", None, "duo"))                     # Duo Admin API administrator log
    if _has(ev, "EventType") and _has(ev, "InitiatorIP") and _has(ev, "DeviceUUID", "ConnectionID"):
        out.add(("cisco", None, "secure_firewall"))         # FTD / FMC eStreamer record
    if _has(ev, "verb") and _has(ev, "objectRef.resource") and _has(ev, "auditID"):
        out.add(("kubernetes", None, "audit"))              # API server audit event (audit.k8s.io)
    if _has(ev, "type") and re.match(r"audit\(", str(ev.get("msg") or "")):
        out.add(("linux", None, "auditd"))
    if _has(ev, "id.orig_h"):
        if _has(ev, "query", "qtype_name"):
            out.add(("zeek", None, "dns"))
        elif _has(ev, "method") and _has(ev, "uri"):
            out.add(("zeek", None, "http"))
        elif _has(ev, "request_type", "client") and _has(ev, "service", "cipher"):
            out.add(("zeek", None, "kerberos"))
        elif _has(ev, "endpoint") and _has(ev, "operation"):
            out.add(("zeek", None, "dce_rpc"))
        elif _has(ev, "path", "name") and _has(ev, "action") and "smb" in str(ev.row).lower()[:4000]:
            out.add(("zeek", None, "smb_files"))
        else:
            out.add(("zeek", None, "conn"))
    # A proxy log names the full destination (scheme://host/... or cs-host); a web
    # server log only the path it served. Sigma keeps them apart (a crawler is
    # normal on a web server and odd leaving a workstation).
    urls = [str(ev.get(n) or "") for n in ("c-uri", "url", "requesturl", "url.full", "url.original")]
    full_url = any("://" in u[:12] for u in urls)
    # A firewall URL log writes "host/path" without a scheme; next to the two
    # addresses of the connection it is the same request a proxy logs.
    host_path = any(re.match(r"[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+(:\d+)?/", u) for u in urls)
    if ((full_url or _has(ev, "cs-host", "c-uri")) and _has(ev, "c-useragent", "cs-host", "cs-method", "useragent",
                                                            "user_agent", "method", "http.request.method")) \
            or (host_path and _has(ev, "dst_ip", "dstip", "destination.ip", "dst")) \
            or (_has(ev, "url", "c-uri") and _has(ev, "urlcategory", "url_category", "urlclass", "urlsupercategory")):
        # (A URL with its category: only a secure web gateway / URL filter writes one --
        # Zscaler NSS logs "host" without a path and the server as "serverip".)
        out.add((None, "proxy", None))
    # HTTP seen on the wire (Suricata http / fileinfo, Zeek http.log): both ends of
    # the request are in it, so the proxy AND web server rules are about it.
    if _has(ev, "http.url", "uri") and _has(ev, "http.http_user_agent", "http.hostname", "user_agent", "host") \
            and _has(ev, "http.http_method", "method", "http.status", "status_code"):
        out.add((None, "proxy", None))
        out.add((None, "webserver", None))
    if _has(ev, "cs-uri-stem", "cs-uri-query", "request", "uri_path", "url.path", "clientrequesturi") and \
            _has(ev, "sc-status", "status", "http.response.status_code", "edgeresponsestatus"):
        out.add((None, "webserver", None))
    if _has(ev, "query", "dns.question.name", "queryname", "qname") and not _has(ev, "c-uri", "url"):
        out.add((None, "dns", None))
    if _has(ev, "src_ip", "srcip", "source.ip", "src", "sourceaddress", "source address", "srcaddr") \
            and _has(ev, "dst_ip", "dstip", "destination.ip", "dst", "destinationaddress", "destination address",
                     "dstaddr") \
            and _has(ev, "dst_port", "dstport", "destination.port", "dpt", "action", "destination port", "dstport"):
        out.add((None, "firewall", None))
    if _has(ev, "_text") and not out:
        # A free-text line: the keyword rules of the syslog services it may come from.
        for svc in (None, "auth", "sshd", "syslog", "sudo", "cron", "vsftpd", "guacamole", "clamav"):
            out.add(("linux", None, svc))
        # ESXi syslog too. Not decided by the line's content: profiles are cached per
        # row SHAPE and every free-text row has one shape. The ESXi rules match
        # ESXi-only text (esxcli ..., vob.user.ssh.enabled), so other lines stay quiet.
        out.add(("esxi", None, None))
    if _has(ev, "auditType.category") and _has(ev, "auditType.action"):
        # Atlassian Data Center audit log (Bitbucket's log/audit/*.audit.log, the REST
        # /rest/auditing events): Sigma's Bitbucket rules -- 2 CRITICAL (unauthorized
        # access, unauthorized full data export) -- had no row to run on.
        out.add(("bitbucket", None, "audit"))
    if _has(ev, *_THREAT_NAMES):
        # An AV / EDR detection: the product named the threat. Sigma's antivirus rules
        # match that name whichever product wrote it (2026-10-20: 6 critical and 3 high
        # rules could never fire -- no row was ever an antivirus row).
        out.add((None, "antivirus", None))
    if _has(ev, "_text") and _has(ev, "message_id") and re.search(r"%(ASA|FTD)-\d-", str(ev.get("_text"))):
        out.add(("cisco", None, "asa"))                     # ASA / FTD syslog (fields from sigma_event)
    return out


class _Lazy(dict):
    """Search results computed on first use: "selection and not filter" never runs
    the filter when the selection already failed."""
    __slots__ = ("_s", "_ev")

    def __init__(self, searches, ev):
        super().__init__()
        self._s, self._ev = searches, ev

    def __missing__(self, name):
        v = self[name] = self._s[name](self._ev)
        return v


def _applies(rule, profs) -> bool:
    for p, c, s in profs:
        # "web" is Splunk's Web data model (rules from sigma-escu): any HTTP record, a
        # proxy's or firewall's URL log as much as a web server's access log.
        cat_ok = rule["category"] in (None, c) or (rule["category"] == "web" and c in ("proxy", "webserver"))
        if (rule["product"] in (None, p) and cat_ok and rule["service"] in (None, s)
                and (rule["product"] or rule["category"] or rule["service"])):
            return True
    return False


_PROF_CACHE: dict = {}


def _profiles_cached(ev):
    """profiles() depends on which columns a row has, plus a few values (the
    Windows event id / channel / provider and the URL's form): rows of one export
    share the answer, so it is worked out once per such signature."""
    row = ev.row
    urls = tuple(str(ev.get(n) or "")[:12].find("://") >= 0 for n in ("c-uri", "url"))
    sig = (tuple(row), ev.get("EventID"), ev.get("EventCode"), ev.get("Channel"), ev.get("LogName"),
           ev.get("Provider"), ev.get("SourceName"), urls,
           bool(re.match(r"[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+(:\d+)?/", str(ev.get("url") or ""))),
           str(ev.get("Image") or ev.get("FileName") or "")[-4:].lower() == ".exe")
    got = _PROF_CACHE.get(sig)
    if got is None:
        if len(_PROF_CACHE) > 20000:
            _PROF_CACHE.clear()
        got = _PROF_CACHE[sig] = profiles(ev)
    return got


def evaluate(row, rules=None, _cache=None) -> list:
    """The rules (level >= medium) that match one row, best first."""
    rules = load()["rules"] if rules is None else rules
    ev = Event(row)
    profs = _profiles_cached(ev)
    if not profs:
        return []
    key = tuple(sorted(map(str, profs)))
    cache = _cache if _cache is not None else {}
    todo = cache.get(key)
    if todo is None:
        todo = cache[key] = [r for r in rules if _applies(r, profs)]
    hits = []
    for r in todo:
        try:
            res = _Lazy(r["searches"], ev)          # a search runs only if the condition asks
            if any(t(res) for t in r["trees"]):
                hits.append(r)
        except Exception:                                  # noqa: BLE001 -- one odd value, not the file
            continue
    return sorted(hits, key=lambda r: -LEVELS.get(r["level"], 0))
