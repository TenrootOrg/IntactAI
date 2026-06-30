"""Chat entity resolution — turn a free-text question into the host/account it
actually means, safely.

Powers the chat retrieval pin (render.chat_subgraph) so "why is desktop-566
bad?" loads DESKTOP-566AT85's context instead of silently answering about the
whole fleet (or the wrong host — which would mislead an analyst).

Operator-agreed rules:
  * case-INsensitive;
  * partial / substring matching for HOSTS + ACCOUNTS only; IOCs/hashes/IPs
    need an exact token (a partial hash/IP is meaningless and dangerous);
  * resolve ONLY when a token maps to exactly ONE real entity; >1 -> ask which
    (offer all, allow "both"); 0-but-close -> ask "did you mean X?" (typo);
  * aliases (hostname / FQDN / Velociraptor client-id) all resolve to one host;
  * the guards live in the assistant's REPLY (a clarifying question), never as a
    gate on the user's input — an unambiguous or host-less question just answers.

`resolve()` is a pure function over (graph, question); everything is unit-tested
in tests/fusion/test_chat_resolve.py.
"""

from __future__ import annotations

import re

MIN_TOKEN_LEN = 3          # shorter tokens are too generic to pin on
FUZZY_MAX_EDITS = 2        # typo tolerance
FUZZY_MIN_LEN = 4          # don't fuzzy-match tiny tokens

# Common words that must never resolve to an entity even if they happen to be a
# substring of a label. Keeps "what host is worst" from matching a host.
_STOP = {
    "the", "this", "that", "what", "which", "who", "whom", "whose", "why", "how",
    "where", "when", "was", "were", "are", "is", "did", "does", "do", "has", "have",
    "and", "for", "with", "about", "from", "into", "any", "all", "more", "most",
    "host", "hosts", "machine", "machines", "client", "clients", "endpoint",
    "endpoints", "computer", "computers", "account", "accounts", "user", "users",
    "show", "list", "find", "tell", "give", "explain", "malicious", "suspicious",
    "activity", "finding", "findings", "severity", "risk", "critical", "high",
    "medium", "low", "happened", "happen", "happens", "going", "first", "second",
}

_TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9._\\-]*[a-z0-9$]|[a-z0-9]+")


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------
def _lev(a: str, b: str, maxd: int) -> int:
    """Levenshtein distance with early-exit once it exceeds maxd."""
    if abs(len(a) - len(b)) > maxd:
        return maxd + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        best = i
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
            best = min(best, cur[-1])
        if best > maxd:
            return maxd + 1
        prev = cur
    return prev[-1]


def _is_pure_numeric(t: str) -> bool:
    return t.isdigit()


def _name_like(t: str) -> bool:
    """Host-name-ish token (carries a digit or a hyphen) — only these are eligible
    for fuzzy 'did you mean', so plain words don't trigger typo prompts."""
    return any(c.isdigit() for c in t) or "-" in t


def _tokens(question: str) -> list:
    q = (question or "").lower()
    out, seen = [], set()
    for m in _TOKEN_RE.findall(q):
        t = m.strip(".-_")
        if len(t) < MIN_TOKEN_LEN or t in _STOP or t in seen:
            continue
        seen.add(t)
        out.append(t)
    return out


def _host_aliases(asset) -> set:
    al = set()
    if asset.label:
        al.add(asset.label.lower())
        al.add(asset.label.lower().split(".")[0])          # short name from an FQDN
    a = asset.attrs or {}
    for k in ("hostname", "fqdn", "netbios", "computer_name"):
        v = a.get(k)
        if v:
            al.add(str(v).lower())
            al.add(str(v).lower().split(".")[0])
    cid = asset.id.split(":")[-1]                            # Velociraptor client-id
    if cid:
        al.add(cid.lower())
    return {x for x in al if x}


def _acct_aliases(acct) -> set:
    al = set()
    if acct.label:
        lbl = acct.label.lower()
        al.add(lbl)
        if "\\" in lbl:
            al.add(lbl.split("\\", 1)[1])                   # bare username
        al.add(lbl.rstrip("$"))                             # machine acct w/o trailing $
    return {x for x in al if x}


def _build_index(graph):
    hosts, accounts, iocs = [], [], []
    for e in graph.entities.values():
        if e.type == "asset":
            hosts.append((e, _host_aliases(e)))
        elif e.type == "account":
            accounts.append((e, _acct_aliases(e)))
        elif e.type == "ioc":
            iocs.append((e, {(e.label or "").lower()}))
    return hosts, accounts, iocs


def _label(e) -> str:
    return e.label or e.id


# ---------------------------------------------------------------------------
# resolution
# ---------------------------------------------------------------------------
def resolve(graph, question: str) -> dict:
    """Map a question to the entities it names. Returns:
        {resolved:[entity], ambiguous:[{token, candidates:[entity]}],
         typos:[{token, suggestions:[entity]}]}
    `resolved` are unambiguous pins; the others need a clarifying question."""
    hosts, accounts, iocs = _build_index(graph)
    partial_pool = hosts + accounts                  # hosts+accounts: partial OK
    resolved, ambiguous, typos = {}, [], []

    for t in _tokens(question):
        # 1) EXACT against any alias (hosts, accounts, AND iocs/hashes/ips).
        exact = {e.id: e for (e, al) in (partial_pool + iocs) if t in al}
        if exact:
            resolved.update(exact)
            continue
        # 2) SUBSTRING (partial) — hosts + accounts ONLY, never iocs/hashes/ips,
        #    never pure-numeric tokens.
        if not _is_pure_numeric(t):
            subs = {e.id: e for (e, al) in partial_pool
                    if any(t in a or a in t for a in al)}
            if len(subs) == 1:
                resolved.update(subs)
                continue
            if len(subs) > 1:
                # A host token also matches its OWN local accounts/processes
                # (e.g. 'desktop-566' hits DESKTOP-566AT85 AND
                # desktop-566at85\vagrant). That's one machine, not real
                # ambiguity — collapse to the host so the user isn't blocked.
                coll = _collapse_same_host(list(subs.values()), graph)
                if coll:
                    resolved.update({e.id: e for e in coll})
                    continue
                ambiguous.append({"token": t, "candidates": list(subs.values())})
                continue
        # 3) FUZZY 'did you mean' — host-name-like tokens only, vs alias prefixes
        #    (so a typo'd PARTIAL like 'desktop-556' still suggests the host).
        if len(t) >= FUZZY_MIN_LEN and _name_like(t):
            fz = {}
            for (e, al) in partial_pool:
                for a in al:
                    if _lev(t, a[:len(t)], FUZZY_MAX_EDITS) <= FUZZY_MAX_EDITS \
                            or _lev(t, a, FUZZY_MAX_EDITS) <= FUZZY_MAX_EDITS:
                        fz[e.id] = e
                        break
            if fz:
                typos.append({"token": t, "suggestions": list(fz.values())})
        # else: token matches nothing — it's just a normal word, ignore it.

    return {"resolved": list(resolved.values()), "ambiguous": ambiguous, "typos": typos}


def _collapse_same_host(candidates, graph):
    """If every candidate belongs to ONE machine (a host plus accounts/processes
    seen on it), return [that host] so a host question isn't blocked by its own
    local identities. Returns None when candidates span >1 real machine (genuine
    ambiguity) or any candidate has no host anchor."""
    anchors = set()
    asset_by_id = {}
    for e in candidates:
        if e.type == "asset":
            anchors.add(e.id)
            asset_by_id[e.id] = e
        else:
            host_ids = (e.attrs or {}).get("_assets") or []
            if not host_ids:
                return None
            anchors.update(host_ids)
    if len(anchors) != 1:
        return None
    aid = next(iter(anchors))
    host = asset_by_id.get(aid) or graph.entities.get(aid)
    return [host] if host is not None else None


def clarify_text(result: dict) -> str | None:
    """The assistant's clarifying reply when a mention is ambiguous or looks like
    a typo — or None when nothing needs asking. Reads as natural conversation."""
    parts = []
    for a in result.get("ambiguous", []):
        names = ", ".join(_label(e) for e in a["candidates"])
        parts.append(f'"{a["token"]}" matches multiple identities: {names}. '
                     f'Which one did you mean — or all of them?')
    for t in result.get("typos", []):
        sug = t["suggestions"]
        if len(sug) == 1:
            parts.append(f'I don\'t see "{t["token"]}" in this case. '
                         f'Did you mean {_label(sug[0])}? (yes / no)')
        else:
            names = ", ".join(_label(e) for e in sug)
            parts.append(f'I don\'t see "{t["token"]}" in this case. '
                         f'Did you mean one of: {names}?')
    return "\n".join(parts) if parts else None


# ---------------------------------------------------------------------------
# follow-up handling ("both" / "yes" / picking one of the offered names)
# ---------------------------------------------------------------------------
_AFFIRM_ALL = {"both", "all", "all of them", "everything", "yes both", "both of them"}
_AFFIRM_YES = {"yes", "y", "yep", "yeah", "sure", "ok", "okay", "correct", "right"}
# Only treat a turn as a clarify follow-up if the LAST assistant message actually
# was one of our clarify prompts — otherwise a normal answer that happens to name
# hosts would turn a later "show all" into "pin every host".
_CLARIFY_MARKERS = ("matches multiple identities", "did you mean")


def recall_candidates(graph, history) -> list:
    """Hosts/accounts named in the LAST assistant turn — the set a follow-up like
    'both' or 'yes' refers back to (so a clarifying round-trip can complete).
    Returns [] unless that turn was an actual clarify prompt."""
    last = ""
    for m in reversed(history or []):
        if (m.get("role") or "") in ("assistant", "ai", "system"):
            last = (m.get("content") or "").lower()
            break
    if not last or not any(mk in last for mk in _CLARIFY_MARKERS):
        return []
    hosts, accounts, _ = _build_index(graph)
    out = {}
    for (e, al) in hosts + accounts:
        if any(a and a in last for a in al):
            out[e.id] = e
    return list(out.values())


def resolve_followup(graph, question: str, history) -> list | None:
    """If the user is answering our prior clarify ('both' / 'yes' / a name), pin
    the right candidate(s). Returns a list of entities, or None if not a follow-up."""
    cands = recall_candidates(graph, history)
    if not cands:
        return None
    q = (question or "").strip().lower()
    if q in _AFFIRM_ALL:
        return cands
    if q in _AFFIRM_YES and len(cands) == 1:
        return cands
    # naming one (or a partial) of the offered candidates
    picked = resolve(graph, question)["resolved"]
    chosen = [e for e in picked if e.id in {c.id for c in cands}]
    return chosen or None
