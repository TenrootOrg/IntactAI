"""Cross-infrastructure identity correlation (candidate generation).

The fused graph merges identities only on an EXACT normalized key (domain/UPN forms),
so the same person under different names across infrastructures — AWS `alon`, endpoint
`AlonM`, `AlonM@gmail.com` — and user->host ownership (`alon` -> `ALON-PC`) are invisible.
This module proposes CANDIDATE links for analyst review; nothing here mutates the graph.
The store layer persists analyst decisions and applies confirmed links as edges on fuse.

Design: docs/PLAN_identity_correlation.md. Two link kinds, never merges:
  * same_identity  (account <-> account, across infrastructure buckets)
  * operates       (account <-> asset host whose name embeds the user)

Everything here is best-effort and side-effect-free: a failure must never break a fuse.
"""

from __future__ import annotations

import hashlib
import re
from difflib import SequenceMatcher

try:
    from .llm_sim import _MASK_STOPWORDS as _STOP     # reuse the generic-word filter
except Exception:                                     # pragma: no cover - defensive
    _STOP = frozenset()
try:
    from services.data_anonymizer import SYSTEM_ACCOUNTS as _SYS
except Exception:                                     # pragma: no cover - defensive
    _SYS = set()

# Windows built-in / service accounts that are NOT people — they'd otherwise show up as
# "identities" and pollute the page (network service, defaultaccount, dwm-1, ...).
_NON_PERSON = frozenset({
    "defaultaccount", "wdagutilityaccount", "guest", "administrator", "system",
    "localsystem", "networkservice", "localservice", "network service", "local service",
    "anonymous", "anonymous logon", "nt authority", "nt service", "dwm", "umfd",
    "font driver host", "window manager", "iusr", "healthmailbox",
    "interactive", "batch", "service", "self", "owner rights", "creator owner",
    "console logon", "restricted", "everyone", "authenticated users",
})


def _norm_user(label) -> str:
    """Bare username stem: strip DOMAIN\\ / @domain / trailing $, lowercase."""
    s = (label or "").strip().lower()
    if "\\" in s:
        s = s.split("\\", 1)[1]
    if "@" in s:
        s = s.split("@", 1)[0]
    return s.rstrip("$").strip()


# Cloud/service domain suffixes that don't identify an org tenant (so azuread\\u@corp
# and NT corp\\u share root "corp", not "onmicrosoft").
_DOMAIN_SUFFIX_SKIP = {"onmicrosoft", "com", "net", "org", "io", "local", "internal", "lan"}




def _is_person(label) -> bool:
    """A real user identity worth clustering — excludes machine accounts (HOST$),
    generic words, and Windows built-in / service accounts (SYSTEM, DWM-1, …)."""
    s = (label or "").strip()
    if not s or s.endswith("$"):
        return False
    n = _norm_user(s)
    if not n or len(n) < 3 or n in _STOP or n in _NON_PERSON:
        return False
    up = s.upper()
    if any(sa.upper() in up for sa in _SYS):          # SYSTEM / NETWORK SERVICE / DWM / UMFD …
        return False
    import re as _re
    if _re.match(r"^(dwm|umfd|cdpuser)-?\d*$", n):     # session pseudo-accounts
        return False
    if n.startswith("%") and n.endswith("%"):          # template/WMI placeholders (%wmi-userdatauser%)
        return False
    if _re.match(r"^defaultuser\d+$", n):              # Windows OOBE default profiles
        return False
    # well-known system SIDs (SYSTEM/LOCAL SERVICE/NETWORK SERVICE/built-in groups/service SIDs)
    if _re.match(r"^s-1-5-(18|19|20)$", n) or _re.match(r"^s-1-5-(32|80|82|83|90|96)-", n):
        return False
    return True

# Infrastructure buckets. Velociraptor + Memory + TimeSketch all hang off the same
# Velociraptor host/client_id, so they are ONE machine bucket ("endpoint"); AWS and
# Azure are their own. Cross-infra correlation only matters BETWEEN buckets.
_ENDPOINT_SOURCES = {"agentic", "velociraptor", "memory", "timesketch"}


def _email(label) -> str | None:
    s = (label or "").strip().lower()
    return s if "@" in s and "." in s.split("@", 1)[1] else None


def link_id(a_id: str, b_id: str, kind: str) -> str:
    """Stable id for a link, independent of endpoint order — so an analyst decision
    binds across re-fuses no matter which side the candidate pass emits first."""
    lo, hi = sorted([a_id or "", b_id or ""])
    return "idl_" + hashlib.sha1(f"{kind}|{lo}|{hi}".encode()).hexdigest()[:14]


def _context(e, graph) -> str:
    """Human context for a candidate side so identical labels are distinguishable in the
    UI: the endpoint HOST for an endpoint account, the provider for a cloud account."""
    for aid in (e.assets() or []):
        b = _bucket_of_asset(aid)
        if b == "endpoint":
            a = graph.entities.get(aid)
            if a is not None and a.label:
                return a.label
        elif b in ("aws", "azure"):
            return b
    srcs = set(getattr(e, "sources", []) or [])
    if "cloud" in srcs:
        return (e.attrs or {}).get("provider") or "cloud"
    return ""


def _bucket_of_asset(asset_id: str) -> str | None:
    if not asset_id:
        return None
    if "cloud_account:aws" in asset_id:
        return "aws"
    if "cloud_account:azure" in asset_id:
        return "azure"
    if asset_id.startswith("asset:"):
        return "endpoint"
    return None


def _entity_buckets(e, graph) -> set:
    """Which infrastructure bucket(s) an entity belongs to (via its asset anchor +
    the source module, so a cloud account with no resolved asset still classifies)."""
    out = set()
    for aid in (e.assets() or []):
        b = _bucket_of_asset(aid)
        if b:
            out.add(b)
    srcs = set(getattr(e, "sources", []) or [])
    if srcs & _ENDPOINT_SOURCES:
        out.add("endpoint")
    if "cloud" in srcs and not (out & {"aws", "azure"}):
        prov = (e.attrs or {}).get("provider")
        if prov in ("aws", "azure"):
            out.add(prov)
    return out


def case_buckets(graph) -> list:
    """Distinct infra buckets present in the graph — drives whether cross-infra
    correlation is even offered (needs >= 2)."""
    out = set()
    for e in graph.entities.values():
        out |= _entity_buckets(e, graph)
    return sorted(out)


def _adjacency(graph):
    adj: dict[str, set] = {}
    for r in graph.relationships:
        adj.setdefault(r.src, set()).add(r.dst)
        adj.setdefault(r.dst, set()).add(r.src)
    return adj


def _account_ips(acc_id, graph, adj) -> set:
    """ioc:ip ids reachable from an account within 2 hops (account->event->ioc, or
    direct) — the strongest cross-bucket corroboration that two names are one person."""
    ips = set()
    seen = {acc_id}
    frontier = [acc_id]
    for _hop in range(2):
        nxt = []
        for n in frontier:
            for m in adj.get(n, ()):
                if m in seen:
                    continue
                seen.add(m)
                e = graph.entities.get(m)
                if e is not None and e.type == "ioc" and (e.attrs or {}).get("ioc_kind") == "ip":
                    ips.add(m)
                else:
                    nxt.append(m)
        frontier = nxt
    return ips


def _initials(n):
    """'john.smith' / 'john_smith' / 'john smith' -> 'jsmith' (first initial + last).
    Lets the two commonest org conventions for one person match."""
    parts = [p for p in re.split(r"[._\- ]+", n or "") if p]
    if len(parts) >= 2 and parts[0] and parts[-1]:
        return parts[0][0] + parts[-1]
    return None


def _match(a_label, b_label):
    """Return (score, reason, auto_eligible) for two usernames, or None if no match.
    auto_eligible = strong enough to auto-confirm IF the match is also unique."""
    ea, eb = _email(a_label), _email(b_label)
    na, nb = _norm_user(a_label), _norm_user(b_label)
    if not na or not nb or na in _STOP or nb in _STOP or len(na) < 3 or len(nb) < 3:
        return None
    # 100% strong identifier: identical email, or one's email local-part == the other's user
    if ea and eb and ea == eb:
        return (1.0, "identical email", True)
    if (ea and _norm_user(ea) == nb) or (eb and _norm_user(eb) == na):
        return (0.95, "email local-part == username", True)
    if na == nb:
        return (0.9, "exact username", True)
    # first.last <-> flast: the two commonest org username conventions for the same person
    # ("john.smith" <-> "jsmith"). Not auto on its own — needs corroboration (shared host/IP).
    ia, ib = _initials(na), _initials(nb)
    if (ia and ia == nb) or (ib and ib == na) or (ia and ib and ia == ib):
        return (0.65, "first.last / flast form", False)
    # prefix / containment at a token boundary (alon vs alonm)
    if (nb.startswith(na) or na.startswith(nb)) and abs(len(na) - len(nb)) <= 4:
        return (0.6, "username prefix", False)
    ratio = SequenceMatcher(None, na, nb).ratio()
    if ratio >= 0.85:
        return (round(ratio, 2), f"fuzzy {ratio:.2f}", False)   # fuzzy alone never auto
    return None


def resolve_identities(graph, merges=None, splits=None, host_excludes=None) -> list:
    """DETERMINISTIC identity resolution — the unified 'identity page'. Cluster accounts
    that are the SAME person by normalized username (collapses DOMAIN\\user, user@domain,
    and the same name seen across many hosts / clouds into ONE person), and attach the
    hosts they operate + the infra buckets they span. Exact-name resolution is automatic
    (mirrors UEBA/identity entity pages); fuzzy/uncertain links are separate SUGGESTIONS.

    Analyst overrides (all persisted, survive re-fusion):
      merges        = confirmed (name_a, name_b, score) same-person pairs -> union clusters.
      splits        = account ids the analyst removed ("not this person") -> isolate.
      host_excludes = (name, host_id) the analyst removed from a person's operated hosts.

    Each account carries a `conf` (1.0 exact-name; the merge score when folded in by a
    confirmed fuzzy link) so the card can show how sure the clustering is.
    """
    from collections import defaultdict
    splits = set(splits or [])
    host_excludes = set(host_excludes or [])
    accounts = [e for e in graph.entities.values()
                if e.type == "account" and _is_person(e.label)]
    idmap = {e.id: e for e in accounts}

    def _hostset(e):
        return {aid for aid in (e.assets() or []) if _bucket_of_asset(aid) == "endpoint"}

    # ---- connected-components resolution over SAFE edges (union-find on account ids) ----
    parent = {e.id: e.id for e in accounts}
    def _find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]; x = parent[x]
        return x
    def _union(a, b):
        if a in parent and b in parent:
            parent[_find(a)] = _find(b)

    merge_conf: dict = {}                               # account id -> score when joined via a fuzzy merge
    # DEFAULT resolution: the SAME normalized username is one person — this unites every
    # form (DOMAIN\u, u@domain, azuread\u@tenant, bare local u, cloud u) and the same name
    # across many hosts/clouds/domains into ONE person. In a single engagement (one org)
    # a username is one human; the RARE cross-org collision of an identical username is
    # handled by the analyst's Split action (never a silent, unfixable merge). DIFFERENT
    # names (alonm/alonn) stay separate and only link via corroborated suggestions below.
    bynorm = defaultdict(list)
    for e in accounts:
        bynorm[_norm_user(e.label)].append(e)
    for accs in bynorm.values():
        for e in accs[1:]:
            _union(e.id, accs[0].id)

    # cross-name corroborated / confirmed merges — SPECIFIC account pairs (a_id, b_id, score)
    for m in (merges or []):
        a, b = m[0], m[1]
        sc = m[2] if len(m) > 2 else 1.0
        if a in idmap and b in idmap:
            _union(a, b)
            merge_conf[a] = min(merge_conf.get(a, 1.0), sc)
            merge_conf[b] = min(merge_conf.get(b, 1.0), sc)

    # host index for operated-host attachment
    hosts = [e for e in graph.entities.values()
             if e.type == "asset" and "endpoint" in (_entity_buckets(e, graph) or set())
             and (e.label or "").strip()]
    hidx = defaultdict(list)
    for h in hosts:
        hn = (h.label or "").strip().lower()
        toks = hn.replace("-", " ").replace("_", " ").replace(".", " ").split()
        for ch in {hn[0]} | {t[0] for t in toks if t}:
            hidx[ch].append((h, hn, toks))

    def _build(key, accs):
        buckets, acct_out, seen_host_ids = set(), [], set()
        cnt = defaultdict(int)
        for e in accs:
            cnt[_norm_user(e.label)] += 1
        dominant = max(cnt, key=cnt.get) if cnt else key
        names = sorted(cnt)
        for e in accs:
            eb = _entity_buckets(e, graph)
            buckets |= eb
            conf = 1.0 if _norm_user(e.label) == dominant else merge_conf.get(e.id, 0.9)
            acct_out.append({"id": e.id, "label": e.label, "ctx": _context(e, graph),
                             "bucket": (sorted(eb)[0] if eb else ""), "conf": round(conf, 2)})
            seen_host_ids |= _hostset(e)
        hosts_out, added = [], set()
        for nm in names:
            for h, hn, htok in hidx.get(nm[0], ()):
                if h.id in added or (nm, h.id) in host_excludes:
                    continue
                if (nm in htok or hn.split("-")[0] == nm or hn.split(".")[0] == nm
                        or (len(nm) >= 4 and hn.startswith(nm) and len(hn) > len(nm) + 1)):
                    added.add(h.id)
                    hosts_out.append({"id": h.id, "label": h.label, "strong": h.id in seen_host_ids,
                                      "name": nm})
        confs = [a["conf"] for a in acct_out] or [1.0]
        return {"key": key, "name": (accs[0].label if len(accs) == 1 else dominant),
                "names": names, "buckets": sorted(buckets), "accounts": acct_out,
                "hosts": hosts_out, "confidence": round(sum(confs) / len(confs), 2)}

    comps = defaultdict(list)
    for e in accounts:
        comps[_find(e.id)].append(e)
    out = []
    for rep, accs in comps.items():
        keep = [e for e in accs if e.id not in splits]
        if keep:
            out.append(_build(rep, keep))
        for e in accs:                                 # split-out accounts -> own identity
            if e.id in splits:
                out.append(_build("split:" + e.id, [e]))
    out.sort(key=lambda x: (-len(x["buckets"]), -len(x["accounts"]), x["key"]))
    return out


def compute_candidates(graph) -> list:
    """Propose identity links from the graph. Pure — returns a list of candidate dicts;
    the caller decides/persists. auto=True only when the match is unambiguous (unique
    for BOTH sides) AND auto-eligible, OR a 100% strong-id; anything else needs a human."""
    buckets = case_buckets(graph)
    accounts = [e for e in graph.entities.values()
                if e.type == "account" and _is_person(e.label)]
    from collections import defaultdict
    adj = _adjacency(graph)
    cands = []
    # precompute buckets + normalized name once per account (avoid recompute in loops)
    info = [(e, _entity_buckets(e, graph), _norm_user(e.label)) for e in accounts]
    _ipc: dict = {}
    def _ips(aid):                                    # memoised 2-hop IP set per account
        if aid not in _ipc:
            _ipc[aid] = _account_ips(aid, graph, adj)
        return _ipc[aid]

    # host index (by token/name first char) — used for BOTH host corroboration and the
    # operates pass; keeps everything near-linear (a user only checks same-first-char hosts).
    hosts = [e for e in graph.entities.values()
             if e.type == "asset" and "endpoint" in (_entity_buckets(e, graph) or set())
             and (e.label or "").strip()]
    hidx = defaultdict(list)
    for h in hosts:
        hn = (h.label or "").strip().lower()
        toks = hn.replace("-", " ").replace("_", " ").replace(".", " ").split()
        for ch in {hn[0]} | {t[0] for t in toks if t}:
            hidx[ch].append((h, hn, toks))

    def _host_match(u, hn, htok):
        # host name embeds the username: whole token ("alon" in "ALON PC"), host stem
        # ("alon-pc"/"alon.corp"), or concatenated prefix ("nofl"->"noflaptop"). Prefix
        # needs a >=4-char username so "srv" doesn't match "srvexchange".
        return (u in htok or hn.split("-")[0] == u or hn.split(".")[0] == u
                or (len(u) >= 4 and hn.startswith(u) and len(hn) > len(u) + 1))

    _hc: dict = {}
    def _hostc(e):                                    # host ids linked to an account (resident + name-operated)
        if e.id in _hc:
            return _hc[e.id]
        hs = {aid for aid in (e.assets() or []) if _bucket_of_asset(aid) == "endpoint"}
        u = _norm_user(e.label)
        if len(u) >= 3:
            for h, hn, htok in hidx.get(u[0], ()):
                if _host_match(u, hn, htok):
                    hs.add(h.id)
        _hc[e.id] = hs
        return hs

    # ---- same_identity: account <-> account across DIFFERENT buckets ----
    # BLOCKING for scale: only compare accounts whose normalized name shares a first char
    # (exact/prefix/typo matches always do). auto-merge is EVIDENCE-led: a name match plus
    # a shared HOST/IP (or a strong id: email/SID) is auto; a bare name match is a suggestion.
    if len(buckets) >= 2:
        blocks = defaultdict(list)
        for tup in info:
            if tup[2]:
                blocks[tup[2][0]].append(tup)
        for blk in blocks.values():
            for i in range(len(blk)):
                ea, ba, _na = blk[i]
                for j in range(i + 1, len(blk)):
                    eb, bb, _nb = blk[j]
                    if ba and bb and ba == bb:        # same bucket -> keys already handle it
                        continue
                    m = _match(ea.label, eb.label)
                    if not m:
                        continue
                    score, reason, _ao = m
                    ev, corr, corroborated = [], 0.0, False
                    sh = _hostc(ea) & _hostc(eb)      # shared host = strong corroboration
                    if sh:
                        lbls = [graph.entities[x].label for x in list(sh)[:2] if x in graph.entities]
                        ev.append("shares host " + ", ".join(lbls)); corr = max(corr, 0.3); corroborated = True
                    sip = _ips(ea.id) & _ips(eb.id)
                    if sip:
                        lbls = [graph.entities[x].label for x in list(sip)[:2] if x in graph.entities]
                        ev.append("shares IP " + ", ".join(lbls)); corr = max(corr, 0.2); corroborated = True
                    strong = reason in ("identical email", "email local-part == username")
                    cands.append({
                        "kind": "same_identity", "a_id": ea.id, "a_label": ea.label,
                        "b_id": eb.id, "b_label": eb.label,
                        "a_ctx": _context(ea, graph), "b_ctx": _context(eb, graph),
                        "buckets": sorted(ba | bb), "score": min(1.0, score + corr),
                        "match": reason,
                        "reason": (reason + ((" · " + "; ".join(ev)) if ev else "")),
                        "evidence": ev, "corroborated": bool(corroborated or strong), "strong": strong,
                    })

    # ---- operates: account (user) <-> endpoint host whose NAME embeds the user ----
    for acc, ab, u in info:
        if len(u) < 3:
            continue
        seen_hosts = set()
        for h, hn, htok in hidx.get(u[0], ()):
            if h.id in seen_hosts or not _host_match(u, hn, htok):
                continue
            seen_hosts.add(h.id)
            seen_on = h.id in (acc.assets() or [])
            cands.append({
                "kind": "operates", "a_id": acc.id, "a_label": acc.label,
                "b_id": h.id, "b_label": h.label,
                "a_ctx": _context(acc, graph), "b_ctx": h.label,
                "buckets": sorted(ab | {"endpoint"}),
                "score": 0.9 if seen_on else 0.6,
                "reason": "host embeds username" + (" + user seen on host" if seen_on else ""),
                "evidence": (["user active on this host"] if seen_on else []),
                "auto_eligible": bool(seen_on),
            })

    # ---- stamp ids + ambiguity ----
    # Ambiguity is by DISTINCT partner NAME, not raw candidate count: `alon` matching
    # AlonM / AlonN / AlonT (3 distinct names) is ambiguous (likely different people ->
    # manual). The SAME name on several hosts (`nofl` on 5 endpoints) is NOT ambiguous —
    # it's one identity across machines -> auto. `operates` (one user -> many hosts) is a
    # legitimate one-to-many, never ambiguous.
    for c in cands:
        c["id"] = link_id(c["a_id"], c["b_id"], c["kind"])
    names_a: dict = {}
    names_b: dict = {}
    for c in cands:
        if c["kind"] != "same_identity":
            continue
        names_a.setdefault(c["a_id"], set()).add(_norm_user(c["b_label"]))
        names_b.setdefault(c["b_id"], set()).add(_norm_user(c["a_label"]))
    for c in cands:
        if c["kind"] == "same_identity":
            c["ambiguous"] = (len(names_a.get(c["a_id"], set())) > 1
                              or len(names_b.get(c["b_id"], set())) > 1)
            # Auto-merge when it's safe: an EXACT same name across infra, a strong id
            # (email/SID), or a name match backed by a shared host/IP. A bare PREFIX/FUZZY
            # name match with NO corroboration is only a SUGGESTION, never automatic — that
            # is where big-org name collisions (AlonM/AlonN/AlonT) live.
            c["auto"] = bool(c.get("corroborated") or c.get("match") == "exact username")
        else:                                          # operates: auto when the user is seen on the host
            c["ambiguous"] = False
            c["auto"] = bool(c.get("auto_eligible"))
    return cands
