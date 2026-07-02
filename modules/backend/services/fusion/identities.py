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
from difflib import SequenceMatcher

try:
    from .llm_sim import _MASK_STOPWORDS as _STOP     # reuse the generic-word filter
except Exception:                                     # pragma: no cover - defensive
    _STOP = frozenset()

# Infrastructure buckets. Velociraptor + Memory + TimeSketch all hang off the same
# Velociraptor host/client_id, so they are ONE machine bucket ("endpoint"); AWS and
# Azure are their own. Cross-infra correlation only matters BETWEEN buckets.
_ENDPOINT_SOURCES = {"agentic", "velociraptor", "memory", "timesketch"}


def _norm_user(label) -> str:
    """Bare username stem: strip DOMAIN\\ / @domain / trailing $, lowercase."""
    s = (label or "").strip().lower()
    if "\\" in s:
        s = s.split("\\", 1)[1]
    if "@" in s:
        s = s.split("@", 1)[0]
    return s.rstrip("$").strip()


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
    # prefix / containment at a token boundary (alon vs alonm) — unique-gated auto
    if (nb.startswith(na) or na.startswith(nb)) and abs(len(na) - len(nb)) <= 4:
        return (0.6, "username prefix", True)
    ratio = SequenceMatcher(None, na, nb).ratio()
    if ratio >= 0.85:
        return (round(ratio, 2), f"fuzzy {ratio:.2f}", False)   # fuzzy alone never auto
    return None


def compute_candidates(graph) -> list:
    """Propose identity links from the graph. Pure — returns a list of candidate dicts;
    the caller decides/persists. auto=True only when the match is unambiguous (unique
    for BOTH sides) AND auto-eligible, OR a 100% strong-id; anything else needs a human."""
    buckets = case_buckets(graph)
    accounts = [e for e in graph.entities.values()
                if e.type == "account" and (e.label or "").strip()
                and not (e.label or "").strip().endswith("$")   # machine acct (HOST$) = the host, not a person
                and _norm_user(e.label) not in _STOP and len(_norm_user(e.label)) >= 3]
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

    # ---- same_identity: account <-> account across DIFFERENT buckets ----
    # BLOCKING for scale: only compare accounts whose normalized name shares a first
    # char (exact/prefix/typo matches always do) — turns O(n^2) over all accounts into
    # O(sum of block^2), so 1000s of identities stay fast. (A rare first-char typo is
    # the accepted trade-off vs re-scanning every pair.)
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
                    score, reason, auto_ok = m
                    ev, corr = [], 0.0
                    shared = _ips(ea.id) & _ips(eb.id)
                    if shared:
                        lbls = [graph.entities[x].label for x in list(shared)[:3] if x in graph.entities]
                        ev.append("shares IP " + ", ".join(lbls))
                        corr = 0.2
                    cands.append({
                        "kind": "same_identity", "a_id": ea.id, "a_label": ea.label,
                        "b_id": eb.id, "b_label": eb.label,
                        "a_ctx": _context(ea, graph), "b_ctx": _context(eb, graph),
                        "buckets": sorted(ba | bb), "score": min(1.0, score + corr),
                        "reason": reason, "evidence": ev, "auto_eligible": auto_ok,
                    })

    # ---- operates: account (user) <-> endpoint host whose NAME embeds the user ----
    # Index hosts by the first char of each name token + the whole name, so a user only
    # checks hosts that could possibly match (prefix/token share a first char) — keeps
    # this near-linear instead of accounts x hosts.
    hosts = [e for e in graph.entities.values()
             if e.type == "asset" and "endpoint" in (_entity_buckets(e, graph) or set())
             and (e.label or "").strip()]
    hidx = defaultdict(list)
    for h in hosts:
        hn = (h.label or "").strip().lower()
        toks = hn.replace("-", " ").replace("_", " ").replace(".", " ").split()
        for ch in {hn[0]} | {t[0] for t in toks if t}:
            hidx[ch].append((h, hn, toks))
    for acc, ab, u in info:
        if len(u) < 3:
            continue
        seen_hosts = set()
        for h, hn, htok in hidx.get(u[0], ()):
            if h.id in seen_hosts:
                continue
            # host name embeds the username: a whole token ("alon" in "ALON PC"), the host
            # stem ("alon-pc"/"alon.corp"), or a concatenated prefix ("nofl"->"noflaptop").
            # Prefix rule needs a >=4-char username so "srv" doesn't match "srvexchange".
            if (u in htok or hn.split("-")[0] == u or hn.split(".")[0] == u
                    or (len(u) >= 4 and hn.startswith(u) and len(hn) > len(u) + 1)):
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
            amb = (len(names_a.get(c["a_id"], set())) > 1
                   or len(names_b.get(c["b_id"], set())) > 1)
        else:
            amb = False
        c["ambiguous"] = amb
        c["auto"] = bool(c["auto_eligible"] and not amb)
    return cands
