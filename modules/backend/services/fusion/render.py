"""Render the case graph at three altitudes (macro / infrastructural attack
timeline / per-asset) and produce the compact distilled payload. All
DETERMINISTIC — the graph already holds the findings + timestamps, so this
is templating, not analysis. The LLM (real or simulated) only narrates over
``distilled()``.
"""

from __future__ import annotations

from . import severity as sev, keys
from .correlate import in_window, _assets_of, _host_label


def fmt_ts(v) -> str:
    """One display format for every timestamp: 'YYYY-MM-DDTHH:MM:SSZ' (second
    precision, trailing Z). Strips fractional/nanosecond tails so the timeline
    reads uniformly regardless of which artifact produced the row."""
    t = keys.norm_ts(v)            # -> 'YYYY-MM-DDTHH:MM:SS' (or None)
    return (t + "Z") if t else ""


def scope(graph, *, window=None, min_severity="informational"):
    """Return (assets, findings) filtered to the time window + severity."""
    findings = [f for f in graph.findings
                if sev.at_least(f.severity, min_severity) and in_window(f.ts, window)]
    assets = [e for e in graph.by_type("asset")]
    return assets, findings


def _artifacts_of(graph, f) -> list:
    """The collection artifact(s) that produced a finding — so the analyst can ask
    the IT team 'do you recognise what <artifact> flagged at <time>?'. Derived from
    the finding's (and its cited entities') evidence locators, which look like
    'Windows.Hayabusa.Rules/row=5'. Falls back to the source module label."""
    arts = []
    seen = set()

    def add_from(evlist):
        for ev in (evlist or []):
            loc = getattr(ev, "locator", "") or ""
            name = loc.split("/row=")[0].split("/")[0].strip()
            if name and name not in ("asset", "") and name not in seen:
                seen.add(name)
                arts.append(name)

    add_from(getattr(f, "evidence", None))
    if not arts:
        for eid in (f.entity_ids or []):
            e = graph.entities.get(eid)
            if e:
                add_from(getattr(e, "evidence", None))
    if not arts and f.sources:
        arts = list(dict.fromkeys(f.sources))
    return arts


def timeline(graph, *, window=None, initial_access=None):
    rows = []
    for f in graph.findings:
        if not in_window(f.ts, window):
            continue
        rows.append({"finding_id": f.id,            # stable key for real/not-real validation
                     "ts": fmt_ts(f.ts), "host": ", ".join(_host_label(graph, a) for a in f.asset_ids) or "-",
                     "phase": _phase(f), "title": f.title, "severity": f.severity,
                     "mitre": f.mitre, "artifacts": _artifacts_of(graph, f),
                     "source": "fusion"})
    rows.sort(key=lambda r: (r["ts"] or "9999"))
    return rows


_PHASES = ["Initial Access", "Execution / Injection", "Persistence",
           "Command & Control", "Lateral Movement", "Exposure"]


def _phase(f) -> str:
    t, m = f.title.lower(), set(f.mitre)
    if "inject" in t or "T1055" in m:
        return "Execution / Injection"
    if "account" in t or {"T1021", "T1078"} & m:
        return "Lateral Movement"
    if "indicator" in t or "T1071" in m or "c2" in t:
        return "Command & Control"
    if t.startswith("vulnerability"):
        return "Exposure"
    if "persist" in t or "service" in t or "autorun" in t or "scheduled" in t:
        return "Persistence"
    return "Execution / Injection"


# ---- report_detail: per-case explicitness control --------------------------
# Auto resolves to EXPLICIT (per-event evidence: real cmdline / path / user / full
# hash) for small, specific cases and SUMMARY (abstracted findings only) for big /
# cross-org cases. EXPLICIT_MAX_HOSTS mirrors correlate.FLEET_RELATIVE_MIN (the
# fleet-relative threshold) — below it a case is "specific", above it "at scale".
EXPLICIT_MAX_HOSTS = 12
EXPLICIT_MAX_FINDINGS = 150
EXPLICIT_EVENTS_PER_FINDING = 5            # evidence lines surfaced per finding
EXPLICIT_EVIDENCE_CHARS = 200             # per evidence line


def _resolve_detail(graph, detail, *, window=None, min_severity="informational"):
    """Resolve the per-case ``report_detail`` control to (effective_mode, reason).
    'explicit'/'summary' are honored verbatim; 'auto' picks explicit when the case
    is small AND specific (few hosts AND bounded finding volume), else summary."""
    d = (detail or "auto").lower()
    if d not in ("auto", "explicit", "summary"):
        d = "auto"
    if d != "auto":
        return d, d
    hosts = len(graph.by_type("asset"))
    _, findings = scope(graph, window=window, min_severity=min_severity)
    nf = len(findings)
    if hosts <= EXPLICIT_MAX_HOSTS and nf <= EXPLICIT_MAX_FINDINGS:
        return "explicit", f"auto — {hosts} host{'' if hosts == 1 else 's'}, {nf} findings"
    return "summary", f"auto — {hosts} hosts, {nf} findings (at scale)"


def _finding_evidence(graph, f, *, cap_events=EXPLICIT_EVENTS_PER_FINDING,
                      cap_chars=EXPLICIT_EVIDENCE_CHARS) -> list:
    """Per-event explicit evidence for a finding — the real cmdline / path / user /
    target IP / full hash captured on its linked event entities (EXPLICIT mode only;
    the lossy ontology drops these from the summary view). Capped for budget safety."""
    def _v(x):                              # usable value, or "" for noise/placeholders
        x = ("" if x is None else str(x)).strip()
        return "" if x.lower() in ("", "unknown", "-", "n/a", "none") else x

    lines = []
    for eid in (f.entity_ids or []):
        e = graph.entities.get(eid)
        if not e or e.type != "event":
            continue
        a = e.attrs or {}
        parts = []
        if _v(a.get("ev_user")):
            parts.append(f"user={_v(a.get('ev_user'))}")
        if _v(a.get("ev_cmdline")):
            parts.append(f"cmd: {_v(a.get('ev_cmdline'))}")
        elif _v(a.get("ev_proc")):
            parts.append(f"proc: {_v(a.get('ev_proc'))}")
        if _v(a.get("ev_tgtip")):
            parts.append(f"→ {_v(a.get('ev_tgtip'))}")
        if _v(a.get("ev_sha256")):
            parts.append(f"sha256={_v(a.get('ev_sha256'))}")
        if not parts and _v(a.get("details")):
            parts.append(_v(a.get("details")))
        if not parts:
            continue
        # Flatten to ONE clean line: raw details can carry newlines / tabs / backticks
        # (e.g. a multi-line Defender message + URL) which would break the markdown
        # inline-code span and corrupt the whole report. Collapse + neutralise.
        s = " · ".join(parts)
        s = " ".join(s.split()).replace("`", "'")
        if len(s) > cap_chars:
            s = s[:cap_chars - 1] + "…"
        if s and s not in lines:
            lines.append(s)
        if len(lines) >= cap_events:
            break
    return lines


def _known_identities(graph, limit=5000):
    # No practical cap: the whole point of this function is that a real person
    # is never dropped merely because their accounts carry no anomaly score.
    # `limit` exists only as a defensive ceiling against a pathological graph —
    # at ~100 bytes/identity even a genuinely huge case (hundreds of identities)
    # adds a rounding error to what this payload already carries.
    """Cross-host identity clusters (Identities tab data) as a compact summary.

    top_entities below is ranked by ANOMALY SCORE, so a person who is simply
    present on several hosts with no attached finding — anomaly=0 on every one
    of their per-host account records — never survives the truncation, however
    many entities the case has. That is a real gap: the Identities tab already
    knows this person exists and which hosts they operate (exact-username
    clustering across hosts), but the chat/report LLM had no access to that
    clustering at all and would flatly deny the person existed (reported
    2026-07-26 — asked about a real, 5-host identity named in the Identities
    tab; the model correctly said it wasn't in the evidence it was given,
    because it genuinely wasn't). Feed the same clustering in here so the two
    views of one case agree on who exists.
    """
    try:
        from .identities import resolve_identities
        idents = resolve_identities(graph)
    except Exception:
        return []
    # RANK BY WHAT MATTERS TO THE INVESTIGATION before any truncation.
    # resolve_identities() sorts for the Identities TAB — by infrastructure
    # breadth, then account count — which is right for browsing but wrong for a
    # budget cut: it would keep a quiet admin who happens to span 5 systems and
    # drop the person actually named in a critical finding. Re-rank here, for
    # the LLM payload only, so whatever survives a cut is the part that matters.
    acct_sev = {}                      # account entity id -> worst finding severity rank
    for f in graph.findings:
        r = sev.rank(f.severity)
        for eid in (f.entity_ids or []):
            if r > acct_sev.get(eid, -1):
                acct_sev[eid] = r

    def _risk(ident):
        ids = [a["id"] for a in ident["accounts"]]
        worst = max((acct_sev.get(i, -1) for i in ids), default=-1)
        n_findings = sum(1 for i in ids if i in acct_sev)
        return (worst, n_findings, len(ident["accounts"]))

    idents = sorted(idents, key=_risk, reverse=True)

    out = []
    for i in idents:
        # `i["hosts"]` is the OPERATES-hosts heuristic (hostname textually implies
        # this person administers it) — often empty, as it was for the person this
        # bug was found on. What "who is X" actually needs is where the account was
        # SEEN, which is each account's own ctx (the endpoint it was observed on).
        seen_on = sorted({a["ctx"] for a in i["accounts"] if a.get("ctx")})
        out.append({"name": i["name"], "accounts": len(i["accounts"]),
                    "seen_on_hosts": seen_on,
                    "operates_hosts": [h["label"] for h in i["hosts"]]})
    return out[:limit]


# Default identity ceiling when the case leaves 'Identity limit' empty.
# NOT tied to max_entities: identities cost ~27 tokens each (two orders of
# magnitude cheaper than an entity row) and answer a different question ("who
# exists here"), so binding them to an entity budget sized for a different kind
# of content silently dropped real people — chat's budget is 60 entities, so a
# 61st person became invisible to the very path where "who is X" is asked.
# The real overflow guard is distilled()'s budget_chars stepdown, which shrinks
# identities alongside entities when the payload genuinely doesn't fit.
DEFAULT_MAX_IDENTITIES = 500

# Floor for the finding stepdown. Even a hard budget squeeze leaves this many —
# below it the report has no material to narrate, and >= high findings are exempt
# from trimming anyway (_trim_findings), so this only bounds the low-severity tail.
_MIN_FINDINGS = 20


def _trim_findings(findings, max_findings):
    """Keep the highest-severity findings, dropping only the low-severity tail.

    `findings` arrives severity-sorted (correlate.assemble sorts by -severity,
    then ts), so the tail IS the least important. Anything >= high is exempt and
    survives regardless of the cap: a budget squeeze may cost the operator some
    medium/low noise, never a critical detection.
    """
    if not max_findings or len(findings) <= max_findings:
        return findings
    must_keep = [f for f in findings if sev.at_least(f.severity, "high")]
    tail = [f for f in findings if not sev.at_least(f.severity, "high")]
    room = max(0, max_findings - len(must_keep))
    return must_keep + tail[:room]


def _distilled_at(graph, *, window, min_severity, max_entities, detail="summary",
                  max_identities=None, max_findings=None):
    """`max_findings` caps findings AND the timeline built from them (they are the
    same set — the timeline is one row per finding), keeping them consistent so
    the payload never cites a finding_id it did not send.

    `max_identities` (the case's 'Identity limit' setting) caps identity rows
    INDEPENDENTLY of max_entities — see DEFAULT_MAX_IDENTITIES for why. Unset =
    DEFAULT_MAX_IDENTITIES, which covers any realistic engagement (~1.5
    identities per host). Overflow is still bounded: distilled() shrinks this in
    lockstep with max_entities on each budget_chars stepdown."""
    assets, findings = scope(graph, window=window, min_severity=min_severity)
    findings = _trim_findings(findings, max_findings)
    kept_ids = {f.id for f in findings}
    eff_detail, _ = _resolve_detail(graph, detail, window=window, min_severity=min_severity)
    ents = sorted((e for e in graph.entities.values()
                   if e.type != "asset" and sev.at_least(e.severity, min_severity)
                   and in_window(e.first_seen, window)),
                  key=lambda e: -e.anomaly)[:max_entities]

    def _fd(f):
        fd = {"title": f.title, "severity": f.severity, "confidence": f.confidence,
              "hosts": [_host_label(graph, x) for x in f.asset_ids],
              "summary": f.summary, "mitre": f.mitre, "kind": f.kind, "ts": f.ts}
        # EXPLICIT: surface real per-event evidence so the narrative can cite specifics.
        if eff_detail == "explicit" and (sev.at_least(f.severity, "high")
                                         or f.kind == "cross_host"):
            ev = _finding_evidence(graph, f)
            if ev:
                fd["evidence"] = ev
        return fd

    return {
        "case_id": graph.case_id,
        "report_detail": eff_detail,
        "assets": [{"id": a.id, "host": a.label, "severity": a.severity} for a in assets],
        "findings": [_fd(f) for f in findings],
        # Same set as `findings` above — filtered identically so a trimmed payload
        # never carries a timeline row for a finding it dropped.
        "timeline": [t for t in timeline(graph, window=window)
                     if max_findings is None or t.get("finding_id") in kept_ids],
        "top_entities": [{"type": e.type, "label": e.label, "severity": e.severity,
                          "anomaly": e.anomaly, "flags": e.flags,
                          "hosts": [_host_label(graph, x) for x in _assets_of(e)]} for e in ents],
        # Every identity the Identities tab shows, independent of anomaly score —
        # see _known_identities(). Cheap relative to the rest of this payload;
        # keeps "who is X" answerable for every real person in the case, not only
        # the ones a finding happens to be attached to.
        "identities": _known_identities(
            graph, limit=DEFAULT_MAX_IDENTITIES if max_identities is None
                         else max(0, int(max_identities))),
        # Per-host coverage roll-up. Exists because a narrative written from
        # `findings` alone follows finding VOLUME, and volume lives on noisy
        # workstations: a domain controller with 7 findings (two of them severe)
        # got a passing mention while a workstation with 27 got the whole story.
        # This states every host once, with its weight, so no host can be skipped
        # silently and the model can see which are infrastructure.
        "host_coverage": _host_coverage(graph, assets, findings),
    }


# Hosts whose ROLE matters more than their finding count. A CA or DC with a
# handful of findings outranks a workstation with dozens, and the narrative has
# to say so — certificate findings anywhere in a case become a different class
# of problem the moment they touch the CA.
_HOST_ROLE_HINTS = (
    ("dc", "domain controller"), ("ca", "certificate authority"),
    ("mecm", "config manager / software distribution"),
    ("sccm", "config manager / software distribution"),
    ("sql", "database server"), ("exch", "mail server"),
)


def _host_role(label: str) -> str:
    """Best-effort role from the hostname. Naming is a convention, not a fact, so
    this is a HINT for the narrative to verify — never asserted as ground truth."""
    lo = (label or "").lower()
    for token, role in _HOST_ROLE_HINTS:
        # token as a word-ish fragment: ALDC02 -> dc, ALCA01 -> ca
        if token in lo:
            return role
    return ""


def _host_coverage(graph, assets, findings) -> list:
    """One row per host: weight, span and role hint — so every host is visible to
    the narrative even when its finding count is small."""
    rows = []
    for a in assets:
        label = a.label
        fs = [f for f in findings if a.id in (f.asset_ids or [])]
        ts = sorted([f.ts for f in fs if f.ts])
        row = {
            "host": label,
            "severity": a.severity,
            "finding_count": len(fs),
            "first_activity": ts[0] if ts else None,
            "last_activity": ts[-1] if ts else None,
            "cross_host_findings": sum(1 for f in fs if f.kind == "cross_host"),
        }
        role = _host_role(label)
        if role:
            row["role_hint"] = role
        rows.append(row)
    # Severity first, then volume: the order the narrative should prioritise, not
    # the order finding counts alone would suggest.
    _sev = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    rows.sort(key=lambda r: (_sev.get(r["severity"], 9), -r["finding_count"]))
    return rows


def distilled(graph, *, window=None, min_severity="informational", max_entities=60,
              budget_chars=None, detail="summary", max_identities=None):
    """Compact, in-window, high-signal payload — what a real LLM would get.

    If ``budget_chars`` is set and the payload exceeds it, halve ``max_entities``
    up to ``budget.MAX_STEPDOWNS`` times. Findings/assets/timeline are always kept
    (they are the signal); only the ranked ``top_entities`` tail is trimmed.
    ``detail`` ('auto'/'explicit'/'summary') controls per-event evidence — explicit
    adds the real cmdline/path/hash to each high finding (see _resolve_detail)."""
    from . import budget as _b
    p = _distilled_at(graph, window=window, min_severity=min_severity,
                      max_entities=max_entities, detail=detail,
                      max_identities=max_identities)
    if not budget_chars:
        return p

    # The stepdown must shrink what the payload is actually MADE OF. Measured on a
    # real case: findings 51% + timeline 43% = 94% of the payload, entities 3.4%.
    # Halving only entities therefore reclaimed ~1.7k chars of a 99.7k payload that
    # was 3x over a 32k budget — it destroyed the cheapest, most useful context
    # (entities 60 -> 15), achieved nothing, then shipped over budget anyway.
    # So findings (and the timeline derived from them) shrink too, lowest-severity
    # first; _trim_findings never drops anything >= high.
    # Trim in order of COST PER UNIT OF VALUE — cut the bulk before the cheap,
    # high-value context. Entities are 3.4% of the payload and are what makes
    # "who/what is X" answerable, so they are the LAST thing to go, not the first
    # (the previous loop halved them immediately, which is the bug this fixes).
    steps = 0
    eff_ident = DEFAULT_MAX_IDENTITIES if max_identities is None else max_identities
    eff_findings = len(p.get("findings") or [])
    while _b.over_budget(p, budget_chars) and steps < _b.MAX_STEPDOWNS:
        before = (eff_findings, max_entities, eff_ident)
        if eff_findings > _MIN_FINDINGS:
            eff_findings = max(_MIN_FINDINGS, eff_findings // 2)   # the 94%
        else:
            # findings exhausted (or all remaining are >= high and exempt) — now
            # spend the cheap stuff
            max_entities = max(5, max_entities // 2)
            eff_ident = max(10, eff_ident // 2)
        if (eff_findings, max_entities, eff_ident) == before:
            break                                    # nothing left to give
        p = _distilled_at(graph, window=window, min_severity=min_severity,
                          max_entities=max_entities, detail=detail,
                          max_identities=eff_ident, max_findings=eff_findings)
        steps += 1
    return p


def _finding_dict(graph, f):
    return {"title": f.title, "severity": f.severity, "confidence": f.confidence,
            "hosts": [_host_label(graph, x) for x in f.asset_ids],
            "summary": f.summary, "mitre": f.mitre, "kind": f.kind, "ts": f.ts}


def _entity_dict(graph, e):
    return {"type": e.type, "label": e.label, "severity": e.severity, "anomaly": e.anomaly,
            "flags": e.flags, "hosts": [_host_label(graph, x) for x in _assets_of(e)]}


def chat_subgraph(graph, question, *, window=None, min_severity="informational",
                  max_entities=20, pin_ids=None, focus_labels=None):
    """Question-scoped subgraph for chat — far smaller than the whole distilled graph,
    so chat tokens stay flat as cases grow. ALWAYS includes every >=high finding
    (escalation-critical facts must never be retrieved away), plus the findings and
    entities lexically relevant to the question.

    `pin_ids` are entities resolved from the question (services/fusion/resolve.py)
    — a pinned host gets its FULL context (all its findings, not just >=high) so
    'why is desktop-566 bad?' loads everything about DESKTOP-566AT85. `focus_labels`
    is echoed back in the payload so the assistant states which host it answered on
    (the analyst can catch a mis-resolution)."""
    q = (question or "").lower()
    pin_ids = set(pin_ids or [])
    _, findings = scope(graph, window=window, min_severity=min_severity)
    picked: dict = {f.id: f for f in findings if sev.at_least(f.severity, "high")}
    rel_ents: list = []

    # Resolved pins: full context for the named host/account (every finding on it).
    pin_asset_ids = {i for i in pin_ids if i.startswith("asset:")}
    for f in findings:
        if pin_asset_ids & set(f.asset_ids) or (pin_ids & set(f.entity_ids)):
            picked[f.id] = f
    for e in graph.entities.values():
        if e.id in pin_ids:
            rel_ents.append(e)

    for a in graph.by_type("asset"):                       # host mentioned (lexical)
        if a.label and a.label.lower() in q:
            for f in findings:
                if a.id in f.asset_ids:
                    picked[f.id] = f
    for e in graph.entities.values():                      # ioc/account/process mentioned
        if e.type in ("ioc", "account", "process", "service") and e.label \
                and e.label.lower() in q:
            rel_ents.append(e)
            for f in findings:
                if e.id in f.entity_ids:
                    picked[f.id] = f
    intents = [(("lateral", "move", "pivot", "spread"), lambda f: f.kind == "cross_host"),
               (("persist", "service", "autorun", "task"),
                lambda f: any(k in f.title.lower() for k in ("service", "persist", "task"))),
               (("vuln", "cve", "patch"), lambda f: f.title.lower().startswith("vulnerab")),
               (("inject", "c2", "beacon"),
                lambda f: any(k in f.title.lower() for k in ("inject", "c2", "indicator")))]
    for kws, pred in intents:
        if any(k in q for k in kws):
            for f in findings:
                if pred(f):
                    picked[f.id] = f

    # entity budget: question-relevant first, then key identities (accounts seen on
    # >1 host — central to infrastructure insight, often only informational severity),
    # then high-anomaly fill.
    key_accts = sorted((e for e in graph.entities.values()
                        if e.type == "account" and len(_assets_of(e)) > 1),
                       key=lambda e: -len(_assets_of(e)))
    fill = sorted((e for e in graph.entities.values()
                   if e.type != "asset" and sev.at_least(e.severity, "high")),
                  key=lambda e: -e.anomaly)
    ents, seen = [], set()
    for e in rel_ents + key_accts + fill:
        if e.id not in seen:
            seen.add(e.id); ents.append(e)
        if len(ents) >= max_entities:
            break
    out = {
        "case_id": graph.case_id,
        "question_scope": True,
        "assets": [{"id": a.id, "host": a.label, "severity": a.severity}
                   for a in graph.by_type("asset")],
        "findings": [_finding_dict(graph, f) for f in picked.values()],
        "top_entities": [_entity_dict(graph, e) for e in ents],
    }
    if focus_labels:
        # The assistant must state which identity it resolved to, so a wrong
        # resolution is visible to the analyst before they act on it.
        out["resolved_focus"] = list(focus_labels)
    return out


# ------------------------------------------------------------------ report


def _sev_tally(findings):
    t = {lv: 0 for lv in sev.LEVELS}
    for f in findings:
        t[f.severity] = t.get(f.severity, 0) + 1
    return t


def _join_nat(items) -> str:
    """Oxford-comma natural-language join: [a,b,c] -> 'a, b, and c'."""
    items = [i for i in items if i]
    if not items:
        return ""
    if len(items) == 1:
        return items[0]
    return ", ".join(items[:-1]) + f", and {items[-1]}"


def _exec_summary(graph, assets, findings, *, initial_access=None, window=None) -> str:
    """A plain-language, story-telling executive summary: what happened in the
    organization, how the adversary operated, how far it spread, and the bottom line.
    Deterministic — the live LLM replaces this with a richer narrative."""
    if not findings:
        return ("This investigation did not surface findings at or above the configured "
                "severity threshold within the selected window. No adversary activity is "
                "indicated; routine monitoring is sufficient.")
    # Rank by risk_score first (same order as the Identity Risk table + Attack
    # Assessment) so "most affected" is consistent everywhere in the report.
    hosts = sorted(assets, key=lambda a: (-(a.attrs.get("risk_score") or 0),
                                          -sev.rank(a.severity)))
    crit = [f for f in findings if sev.at_least(f.severity, "critical")]
    high = [f for f in findings if f.severity == "high"]
    xh = [f for f in findings if f.kind == "cross_host"]
    affected = [a for a in assets if any(a.id in f.asset_ids for f in findings)]
    order = [lab for lab, _ in _ASSESS_TACTICS]
    fleet: dict = {}
    for a in assets:
        for lab in _host_tactics(findings, a.id):
            fleet.setdefault(lab, set()).add(a.label)
    objectives = [lab for lab in order if lab in fleet]
    tl = timeline(graph, window=window)
    first_ts = tl[0]["ts"] if tl else None
    last_ts = tl[-1]["ts"] if tl else None

    bits = []
    sev_word = "critical" if crit else ("high" if high else "moderate")
    bits.append(
        f"This investigation correlated suspicious activity across "
        f"**{len(affected) or len(assets)} of {len(assets)} host(s)** and surfaced "
        f"**{len(findings)} finding(s)** ({len(crit)} critical, {len(high)} high), "
        f"placing the overall severity of this incident at **{sev_word}**.")
    if first_ts:
        span = (f"between `{first_ts}` and `{last_ts}`" if last_ts and last_ts != first_ts
                else f"around `{first_ts}`")
        bits.append("The earliest time-anchored activity runs " + span
                    + (f", with initial access estimated near `{initial_access}`." if initial_access
                       else "."))
    if objectives:
        did = _join_nat([_TACTIC_VERB.get(l, l.lower()) for l in objectives])
        bits.append(f"Across the environment the adversary {did} — consistent with a "
                    f"hands-on-keyboard intrusion rather than isolated, unrelated alerts."
                    if (crit or high) else
                    f"Across the environment the observed activity involved {did}.")
    if hosts:
        w = hosts[0]
        wt = [lab for lab in order if lab in _host_tactics(findings, w.id)]
        nf = sum(1 for f in findings if w.id in f.asset_ids)
        focus = (" — the focal point, where activity spanned "
                 + _join_nat([_TACTIC_SHORT.get(l, l.lower()) for l in wt[:5]])) if wt else ""
        bits.append(f"**{w.label}** ({w.severity}, {nf} finding(s)) is the most affected "
                    f"system{focus}.")
    if xh:
        bits.append(f"Critically, **{len(xh)} finding(s)** correlate across multiple hosts — "
                    f"evidence the activity spread laterally or shares adversary infrastructure, "
                    f"so this should be treated as an environment-wide event, not single-host alerts.")
    if crit or high:
        bits.append("**Bottom line:** immediate containment of the priority hosts and a "
                    "deeper forensic review (memory, full timeline) are recommended before "
                    "the adversary consolidates access further.")
    return " ".join(bits)




def narrative_md(graph, *, window=None, min_severity="informational",
                 initial_access=None, case_name="Case") -> str:
    """The LLM-REPLACEABLE prose: exec summary, incident overview, attack narrative.
    When the real LLM is wired it regenerates this from ``distilled()`` — the
    deterministic fact tables in ``facts_md`` are never sent to it."""
    assets, findings = scope(graph, window=window, min_severity=min_severity)
    win = (f"{(window or {}).get('start') or 'open'} → {(window or {}).get('end') or 'now'}"
           if window else "all")
    out: list[str] = [f"# Incident Case Report — {case_name}\n"]
    out.append(f"_Scope: {len(assets)} host(s) · window {win} · initial access ≈ "
               f"{initial_access or 'unknown'} · severity ≥ {min_severity} · "
               f"{len(findings)} findings_\n")
    out.append("## Executive Summary\n")
    out.append(_exec_summary(graph, assets, findings,
                             initial_access=initial_access, window=window) + "\n")
    # NOTE: the deterministic "Incident Overview" + phase-grouped "Attack Narrative"
    # were removed — they duplicated the Executive Summary + the single Timeline. The
    # live-LLM path replaces this whole function with a real narrative.
    return "\n".join(out)


_STATE_LABEL = {"real": "True Positive", "not_real": "False Positive",
                "known_it": "Known (IT-confirmed)", "pending": "Pending"}


def _analyst_validations_md(graph, dispositions, validations) -> str:
    """What the analyst decided in the Timeline — so the report reflects the triage
    (confirmed real, dismissed as FP, or IT-acknowledged). Integration point with
    the Timeline tab."""
    title_of = {f.id: f.title for f in graph.findings}
    buckets = {"real": [], "not_real": [], "known_it": []}
    seen = set()
    for v in (validations or []):
        fid, st = v.get("finding_id"), v.get("status")
        if st in buckets and fid not in seen:
            seen.add(fid)
            buckets[st].append(title_of.get(fid, str(fid)))
    for d in (dispositions or []):                 # chat-driven triage not in the timeline
        tgt = d.get("target")
        if tgt in seen:
            continue
        seen.add(tgt)
        buckets["known_it" if d.get("attribution") == "it_admin" else "not_real"].append(
            title_of.get(tgt, str(tgt)))
    if not any(buckets.values()):
        return ""
    out = ["## Analyst Validations\n",
           "_Operator triage from the Timeline. False-positive and known/expected "
           "items are suppressed from risk scoring._\n"]
    for st in ("real", "not_real", "known_it"):
        items = buckets[st]
        if items:
            out.append(f"**{_STATE_LABEL[st]} ({len(items)}):**")
            out += [f"- {t}" for t in items[:20]]
            out.append("")
    return "\n".join(out)


def _recommendations_md(graph, findings, assets) -> str:
    """Actionable, deterministic next steps derived from the findings (containment →
    eradication → credentials → network → patching → deeper collection → evidence)."""
    recs: list[tuple] = []
    hot = sorted((a for a in assets if sev.at_least(a.severity, "high")),
                 key=lambda a: -sev.rank(a.severity))
    if hot:
        recs.append(("Containment", "Isolate the most-affected host(s) from the network "
                     "pending eradication: " + ", ".join(a.label for a in hot[:6]) + "."))
    pers = list(dict.fromkeys(f.title for f in findings
                if any(k in f.title.lower() for k in ("service", "persist", "task", "autorun"))))
    if pers:
        recs.append(("Eradication", "Remove the malicious persistence and confirm it does "
                     "not re-create: " + "; ".join(pers[:4]) + "."))
    xacct = [e for e in graph.by_type("account") if "cross_host" in (e.flags or [])]
    if xacct:
        recs.append(("Credentials", "Reset and review the accounts used across multiple "
                     "hosts (" + ", ".join(e.label for e in xacct[:6]) + "); rotate tier-0 "
                     "credentials if a privileged/domain account is involved."))
    # Only recommend blocking VALIDATED / high-confidence indicators — never the
    # merely-observed hashes (don't send the SOC to block a benign binary).
    kept_iocs = [i for i, _ in _high_confidence_iocs(graph)[0]]
    if kept_iocs:
        recs.append(("Network", "Block these indicators at the perimeter / EDR and hunt for "
                     "further callbacks: " + ", ".join(f"`{e.label}`" for e in kept_iocs[:8]) + "."))
    if [f for f in findings if f.title.lower().startswith("vulnerab")]:
        recs.append(("Patching", "Patch the exposed vulnerabilities on the affected hosts."))
    esc = [a for a in assets if a.attrs.get("escalate")]
    if esc:
        recs.append(("Deeper collection", "Collect memory + a full timeline (Timesketch) on "
                     + ", ".join(a.label for a in esc[:6]) + " — malicious under broad "
                     "collection but lacking deep forensics."))
    recs.append(("Evidence preservation", "Capture disk + memory images and relevant logs for "
                 "the confirmed-compromised hosts before remediation."))
    out = ["## Recommendations\n"]
    out += [f"{i + 1}. **{title}** — {body}" for i, (title, body) in enumerate(recs)]
    out.append("")
    return "\n".join(out)


def risk_table(graph, *, window=None, min_severity="informational") -> list:
    """Per-endpoint ('identity') risk rows for the 'who to focus on first + why'
    table. One row per asset, sorted by risk_score desc. Each row carries the
    score, the severity rollup, module coverage, escalate/deep flags, a
    per-severity finding tally, and the CONCRETE top reasons (highest-severity
    findings) driving the score — so the table answers both 'which client' and
    'why', deterministically (no LLM). Drives the report section + /risk API."""
    assets, findings = scope(graph, window=window, min_severity=min_severity)
    rows = []
    for a in assets:
        afind = [f for f in findings if a.id in f.asset_ids]
        tally = {lv: 0 for lv in sev.LEVELS}
        for f in afind:
            if f.severity in tally:
                tally[f.severity] += 1
        # Top reasons = highest-severity findings first, deduped by title, capped.
        seen, reasons = set(), []
        for f in sorted(afind, key=lambda f: (-sev.rank(f.severity), f.title or "")):
            t = (f.title or "").strip()
            if not t or t.lower() in seen:
                continue
            seen.add(t.lower())
            reasons.append(t + (" (cross-host)" if f.kind == "cross_host" else ""))
            if len(reasons) >= 4:
                break
        modules = a.attrs.get("modules") or []
        escalate, deep = bool(a.attrs.get("escalate")), bool(a.attrs.get("deep"))
        if escalate:
            action = "Deep-dive now — run memory + Timesketch"
        elif deep:
            action = "Deep coverage done — review findings"
        elif sev.at_least(a.severity, "medium"):
            action = "Triage / monitor"
        else:
            action = "Low priority"
        rows.append({
            "client_id": a.id,
            "host": a.label,
            "hostname": a.attrs.get("hostname") or a.label,
            "risk_score": int(a.attrs.get("risk_score") or 0),
            "risk_intensity": float(a.attrs.get("risk_intensity") or 0),
            "severity": a.severity,
            "escalate": escalate,
            "deep": deep,
            "modules": list(modules),
            "finding_count": len(afind),
            "by_severity": tally,
            "cross_host": any(f.kind == "cross_host" for f in afind),
            "reasons": reasons,
            "why": "; ".join(reasons[:3]) or "no findings in window",
            "next_action": action,
        })
    # risk_score encodes the tier band; raw intensity breaks display-integer ties
    # so 'who is #1 of the hosts showing 100' is always answered.
    rows.sort(key=lambda r: (-r["risk_score"], -r["risk_intensity"],
                             -sev.rank(r["severity"]), r["host"]))
    return rows


def risk_table_md(graph, *, window=None, min_severity="informational") -> str:
    """Markdown rendering of risk_table() — the 'Identity Risk / focus order'
    section. Deterministic; appended verbatim, never sent to the LLM."""
    rows = risk_table(graph, window=window, min_severity=min_severity)
    if not rows:
        return ""
    # "Host Risk", not "Identity Risk": every column here is a HOST (Host, Risk,
    # Severity, Findings, Coverage). It predated the Identities feature and the
    # old name now sits beside a real "Identities and Attribution" section about
    # people, so the two read as the same thing when they are not.
    out = ["## Host Risk — who to focus on first\n",
           "Endpoints ranked by risk (0-100) — severity tier sets the band "
           "(critical 80-100, high 60-79, medium 40-59, low 20-39) so a 'critical' host "
           "always outranks a 'high' one; finding intensity orders hosts within the band. "
           "Cross-host findings are weighted relative to fleet size. _Why_ = the top "
           "findings driving the score; _Next_ = the recommended action.\n",
           "| # | Host | Risk | Severity | Findings (C/H/M) | Why | Coverage | Next |",
           "|---|------|-----:|----------|------------------|-----|----------|------|"]
    for i, r in enumerate(rows, 1):
        cov = ", ".join(r["modules"]) or "—"
        cov += " 🔺" if r["escalate"] else (" ✓deep" if r["deep"] else "")
        t = r["by_severity"]
        chm = f"{t.get('critical',0)}/{t.get('high',0)}/{t.get('medium',0)}"
        why = (r["why"] or "").replace("|", "／")[:140]
        out.append(f"| {i} | **{r['host']}** | {r['risk_score']} | {r['severity']} | "
                   f"{chm} | {why} | {cov} | {r['next_action']} |")
    out.append("")
    return "\n".join(out)


# ATT&CK-tactic synthesis for the Attack Assessment — categorises each detection by
# what the adversary was DOING (objective), turning a flat detection list into
# analysis. Kept separate from correlate's coord proxy so it never affects calibration.
_ASSESS_TACTICS = [
    ("Execution",
     ("powershell", "encoded", "base64", "scriptblock", "mshta", "rundll", "wscript",
      "cscript", "iex", "frombase64", "obfuscat", "wmi exec", "script interpreter")),
    ("Process Injection", ("inject", "hollow", " rwx")),
    ("Credential Access",
     ("lsass", "mimikatz", "credential", "ntds", "sam dump", "password dump", "dumper",
      "rubeus", "kerberos", "dcsync", "secretsdump", "hashdump", "wdigest", "certipy",
      "krbrelay", "petitpotam", "safetykatz", "sharpdump", "seatbelt")),
    ("Defense Evasion",
     ("log file cleared", "eventlog cleared", "disable", "bypass", "amsi", "etw",
      "defender", "real-time protection", "threat detection", "tamper", "uac",
      "renamed", "masquerad", "rename of", "exploitation framework", "hacktool",
      "relevant file paths", "antivirus")),
    ("Discovery",
     ("discovery", "recon", "whoami", "nltest", "enumerat", "adfind", "bloodhound",
      "sharphound", "ldap", "net group", "ip scanner", "epmap", "powerscan")),
    ("Lateral Movement",
     ("rdp", "psexec", "smbexec", "wmiexec", "crackmapexec", "netexec", "remote desktop",
      "outbound rdp", "pass the", "across ", "lateral")),
    ("Persistence",
     ("autorun", "run key", "service install", "scheduled task", "new service",
      "registry run", "startup", "service creation", "service path", "service name",
      "schtasks", "boot", "sharpersist", "inveigh")),
    ("Command & Control",
     ("beacon", "cobalt strike", "download", "webrequest", "dns query", "named pipe",
      "file sharing", "callback", "anydesk", "teamviewer", "tailscale", "quick assist")),
    ("Exfiltration / Tooling", ("data transfer", "7-zip", "archive", "rclone", "exfil")),
]

# Natural-language verb phrase per tactic (for the prose Attack Assessment + exec
# summary) and a short noun form (for inline lists), so the report reads as sentences
# describing what the adversary DID — not a flat list of detection titles.
_TACTIC_VERB = {
    "Execution": "executed code on the host",
    "Process Injection": "injected code into running processes",
    "Credential Access": "harvested credentials",
    "Defense Evasion": "took steps to evade or disable defenses",
    "Discovery": "performed host and domain reconnaissance",
    "Lateral Movement": "moved laterally to other systems",
    "Persistence": "established persistence",
    "Command & Control": "established command-and-control",
    "Exfiltration / Tooling": "staged tooling or data for exfiltration",
}
_TACTIC_SHORT = {
    "Execution": "code execution", "Process Injection": "process injection",
    "Credential Access": "credential theft", "Defense Evasion": "defense evasion",
    "Discovery": "reconnaissance", "Lateral Movement": "lateral movement",
    "Persistence": "persistence", "Command & Control": "command-and-control",
    "Exfiltration / Tooling": "exfiltration tooling",
}


def _clean_det(title: str) -> str:
    """A detection's display name: drop 'SIGMA:'/rule wrappers + the trailing host."""
    import re as _re
    t = title
    for p in ("Hayabusa/SIGMA rule ", "SIGMA: ", "Detection '", "Detection: "):
        if t.startswith(p):
            t = t[len(p):]
    t = _re.sub(r"\s+(on|across)\s+.*$", "", t)
    return t.strip().strip("'\"").rstrip(".")


def _host_tactics(findings, host_id) -> dict:
    """{tactic-label: {detection names}} for one host — by adversary objective."""
    buckets: dict = {}
    for f in findings:
        if host_id not in f.asset_ids:
            continue
        tl = f.title.lower()
        for label, kws in _ASSESS_TACTICS:   # first (highest-priority) tactic wins — one bucket
            if any(w in tl for w in kws) or (label == "Lateral Movement" and f.kind == "cross_host"):
                buckets.setdefault(label, set()).add(_clean_det(f.title))
                break
    return buckets


def _attack_assessment(graph, assets, findings, *, window=None, initial_access=None) -> str:
    """Reconstruct the intrusion as ONE infrastructure-wide story — how the adversary
    likely entered, moved between hosts (shared credentials / reused tooling), and what
    they did — ordered by the timeline rather than treating each host in isolation.
    More-malicious hosts (higher risk score / severity) get the deeper write-up."""
    order = [lab for lab, _ in _ASSESS_TACTICS]
    prof = []
    for a in assets:
        af = [f for f in findings if a.id in f.asset_ids]
        if not af:
            continue
        tac = _host_tactics(findings, a.id)
        ts_list = sorted(f.ts for f in af if f.ts)
        prof.append({"host": a.label, "sev": a.severity,
                     "risk": int(a.attrs.get("risk_score") or 0),
                     "tactics": [l for l in order if l in tac], "tac_map": tac,
                     "first": ts_list[0] if ts_list else None, "n": len(af)})
    if not prof:
        return ""
    chrono = sorted(prof, key=lambda p: (p["first"] or "9999", -p["risk"]))
    worst = max(prof, key=lambda p: (p["risk"], sev.rank(p["sev"])))
    entry = chrono[0]

    # how the adversary moved between systems (the "infrastructure" view)
    xacct = [e for e in graph.by_type("account") if "cross_host" in (e.flags or [])]
    xhash = [e for e in graph.by_type("ioc")
             if e.attrs.get("ioc_kind") == "hash" and "cross_host" in (e.flags or [])]
    xfind = [f for f in findings if f.kind == "cross_host"]

    out = ["## Attack Assessment\n"]
    # 1. opening — entry point + scope, as a story
    lead = (f"The earliest observed activity was on **{entry['host']}** "
            + (f"around `{entry['first']}`" if entry['first'] else "(time not anchored)")
            + (f", where the adversary "
               + _join_nat([_TACTIC_VERB.get(l, l.lower()) for l in entry['tactics'][:3]])
               if entry['tactics'] else "") + ".")
    if initial_access:
        lead += f" Initial access is estimated near `{initial_access}`."
    out.append(f"This reconstructs the likely course of the intrusion across "
               f"**{len(prof)} affected host(s)** as a single campaign — ordered as it "
               f"unfolded, not host-by-host in isolation. {lead}")

    # 2. lateral movement — how he pivoted across the infrastructure
    move = []
    if xacct:
        move.append("the account(s) " + _join_nat([f"`{e.label}`" for e in xacct[:3]])
                    + " authenticated on multiple hosts")
    if xhash:
        move.append(f"{len(xhash)} tool/binary hash(es) were reused across hosts")
    if xfind and not (xacct or xhash):
        move.append(_join_nat([f.title for f in xfind[:2]]))
    if move:
        out.append(f"\nThe adversary pivoted between systems rather than acting locally: "
                   f"{_join_nat(move)} — evidence of lateral movement using shared "
                   f"credentials or tooling. Treat this as one environment-wide intrusion.")

    # 3. the focal point — most-compromised host gets the spotlight
    if worst['tactics']:
        out.append(f"\n**{worst['host']}** ({worst['sev']}, {worst['n']} finding(s)) is the "
                   f"focal point of the compromise, where activity reached "
                   f"{_join_nat([_TACTIC_SHORT.get(l, l.lower()) for l in worst['tactics'][:5]])}.")

    # 4. reconstructed progression by host — deeper detail for the malicious ones
    out.append("\n**Reconstructed progression:**")
    for p in chrono:
        when = f"`{p['first']}` — " if p['first'] else ""
        if sev.at_least(p['sev'], "high") or p['risk'] >= 60:    # malicious → full prose
            clauses = [f"{_TACTIC_VERB.get(l, l.lower())} "
                       f"({', '.join(sorted(p['tac_map'][l])[:2])})" for l in p['tactics']]
            body = _join_nat(clauses) if clauses else "suspicious activity recorded"
        else:                                                    # lower signal → brief
            body = _join_nat([_TACTIC_SHORT.get(l, l.lower())
                              for l in p['tactics']]) or "lower-severity activity"
        out.append(f"- {when}**{p['host']}** ({p['sev']}): the adversary {body}.")
    out.append("")
    return "\n".join(out)


def _high_confidence_iocs(graph, validations=None):
    """Filter IOCs to those we can stand behind, so the IOC list is genuine indicators
    rather than an inventory of every benign hash on disk. KEEP an indicator only when:
      - validated — cited by a finding the analyst confirmed TRUE POSITIVE ('by us'),
      - detection — cited by any finding (it drove a detection),
      - cross-host — the same artefact appears on 2+ hosts (tool reuse / lateral spread),
      - high-anomaly — independently scored high on its own.
    Everything else (a hash merely seen once, low/zero anomaly) is dropped as noise.
    Returns (list[(ioc, reason)], suppressed_count)."""
    iocs = graph.by_type("ioc")
    cited = set()
    for f in graph.findings:
        cited.update(f.entity_ids or [])
    real_fids = {v.get("finding_id") for v in (validations or [])
                 if v.get("status") == "real"}
    validated = set()
    for f in graph.findings:
        if f.id in real_fids:
            validated.update(f.entity_ids or [])
    kept = []
    for i in iocs:
        if i.id in validated:
            reason = "validated"
        elif "cross_host" in (i.flags or []):
            reason = "cross-host"
        elif i.id in cited:
            reason = "detection"
        elif sev.at_least(i.severity, "high"):
            reason = "high-anomaly"
        else:
            continue
        kept.append((i, reason))
    # validated/detection/cross-host first, then by host spread
    rank = {"validated": 0, "detection": 1, "cross-host": 2, "high-anomaly": 3}
    kept.sort(key=lambda kr: (rank.get(kr[1], 9), -len(_assets_of(kr[0])), kr[0].label))
    return kept, len(iocs) - len(kept)


def report_header(graph, *, window=None, min_severity="informational") -> str:
    """Provenance block: what was examined, over what period, under what filter.

    Every professional DFIR report opens with this and ours did not — it began at
    "## Executive Summary" with no statement of scope, so a reader could not tell
    which hosts were in scope, how much data backed it, or what the filters
    excluded. Without that, "9 hosts, 93 findings" is unfalsifiable: findings
    BELOW the severity floor or outside the window are invisible, and a reader who
    does not know the floor cannot tell absence-of-evidence from evidence-of-
    absence. Timestamps are stamped UTC explicitly for the same reason — a
    forensic timeline whose zone is assumed is a timeline that gets misread.
    """
    from datetime import datetime, timezone
    assets, findings = scope(graph, window=window, min_severity=min_severity)
    sev = _sev_tally(findings)
    w = window or {}
    start, end = (w.get("start") or "open"), (w.get("end") or "now")
    ts = [f.ts for f in findings if f.ts]
    span = f"{min(ts)} → {max(ts)}" if ts else "no time-anchored activity"
    rows = [
        "> **All timestamps are UTC.**",
        "",
        f"| | |",
        f"|---|---|",
        f"| **Report generated** | {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')} |",
        f"| **Hosts in scope** | {len(assets)} |",
        f"| **Findings** | {len(findings)} "
        f"({sev.get('critical',0)} critical, {sev.get('high',0)} high, "
        f"{sev.get('medium',0)} medium) |",
        f"| **Evidence span** | {span} |",
        f"| **Analysis window** | {start} → {end} |",
        f"| **Severity floor** | {min_severity} — findings below this are excluded |",
        f"| **Entities correlated** | {len(graph.entities):,} across {len(graph.relationships):,} links |",
    ]
    return "\n".join(rows) + "\n"


def facts_md(graph, *, window=None, min_severity="informational", initial_access=None,
             dispositions=None, validations=None, detail="auto", narrated=False) -> str:
    """DETERMINISTIC report body — Priority Hosts table, cross-host correlation,
    analyst validations, ONE flat chronological timeline, IOC appendix, MITRE,
    recommendations. Appended verbatim to every report; NEVER sent to the LLM.

    Deliberately NOT here (they duplicated each other): a second host-ranking list,
    an Escalation section (the table's Next column says it), per-host detail (the
    single timeline carries it), and phase-split sub-sections."""
    assets, findings = scope(graph, window=window, min_severity=min_severity)
    eff_detail, reason = _resolve_detail(graph, detail, window=window,
                                         min_severity=min_severity)
    out: list[str] = []
    out.append(f"_Report detail: **{eff_detail}** ({reason})._\n")

    # ---- Attack Assessment (infrastructure-wide story from the timeline) ----
    # Suppressed when the model wrote the narrative: it reconstructs the same
    # intrusion the LLM's "Attack Narrative" just told, in weaker prose, directly
    # underneath it. The per-host progression it carried is not lost — it now goes
    # INTO the payload as host_coverage, where it does more good.
    if not narrated:
        aa = _attack_assessment(graph, assets, findings, window=window,
                                initial_access=initial_access)
        if aa:
            out.append(aa)

    # ---- Cross-host correlation (stated ONCE) -------------------------
    xh = [f for f in findings if f.kind == "cross_host"]
    shared_hashes = [e for e in graph.by_type("ioc")
                     if e.attrs.get("ioc_kind") == "hash" and "cross_host" in e.flags]
    if narrated:
        # The LLM writes its own "Cross-Host Correlation" with hashes, direction
        # and reasoning. Emitting this one too produced two sections of the same
        # name in one report, the second strictly weaker. Keep only the fact the
        # bullet list had that the narrative does not reliably state — the shared
        # hash COUNT — and attach it to the IOC appendix that holds them.
        if shared_hashes:
            out.append(f"_{len(shared_hashes)} file hash(es) are shared across hosts "
                       f"(tool reuse / lateral transfer) — listed in the IOC appendix below._\n")
    elif xh or shared_hashes:
        out.append("## Cross-Host Correlation\n")
        from collections import Counter
        for title, n in Counter(f.title for f in xh).items():   # collapse identical titles
            out.append(f"- {title}" + (f" (×{n})" if n > 1 else ""))
        if shared_hashes:
            out.append(f"- {len(shared_hashes)} file hash(es) shared across hosts "
                       f"(tool reuse / lateral transfer) — full hashes in the IOC appendix")
        out.append("")

    # ---- analyst validations (Timeline triage) ------------------------
    av = _analyst_validations_md(graph, dispositions, validations)
    if av:
        out.append(av)

    # ---- ONE flat chronological timeline — what happened, in order ----
    tally = _sev_tally(findings)
    out.append("## Timeline of Events\n")
    out.append("_" + ", ".join(f"{tally[lv]} {lv}" for lv in reversed(sev.LEVELS) if tally[lv])
               + " — high/critical events in chronological order (host in each entry)._\n")
    tl = sorted((f for f in findings
                 if f.ts and in_window(f.ts, window)
                 and f.kind != "cross_host"                         # in Cross-Host Correlation
                 and not f.title.startswith("Coordinated suspicious activity")  # vacuous rollup
                 and sev.at_least(f.severity, "high")),
                key=lambda f: (f.ts, -sev.rank(f.severity)))
    if not tl:
        out.append("_No time-anchored high/critical activity in window._\n")
    else:
        for f in tl:
            mitre = f" `[{', '.join(f.mitre)}]`" if f.mitre else ""
            out.append(f"- `{fmt_ts(f.ts)}` · **[{f.severity}]** {f.title}{mitre}")
            if eff_detail == "explicit":           # real per-event evidence inline
                for ev in _finding_evidence(graph, f):
                    out.append(f"    - `{ev}`")
    out.append("")

    # ---- 4. Key Indicators (IOCs) — high-confidence / validated only --------
    kept_iocs, suppressed = _high_confidence_iocs(graph, validations)
    if kept_iocs:
        out.append("## Indicators of Compromise (IOCs)\n")
        out.append("_Only validated or high-confidence indicators are listed; "
                   f"{suppressed} merely-observed artefact(s) were suppressed as noise._\n"
                   if suppressed else
                   "_Validated or high-confidence indicators._\n")
        out.append("| Indicator | Type | Confidence | Hosts | Cross-host |")
        out.append("|---|---|---|---|---|")
        for i, reason in kept_iocs:
            hosts = ", ".join(_host_label(graph, x) for x in _assets_of(i))
            out.append(f"| `{i.label}` | {i.attrs.get('ioc_kind', '?')} | {reason} | {hosts} | "
                       f"{'⚠ YES' if 'cross_host' in i.flags else 'no'} |")
        out.append("")

    # ---- 5. MITRE ATT&CK ----------------------------------------------
    techs: dict[str, list] = {}
    for f in findings:
        for t in f.mitre:
            techs.setdefault(t, []).append(f.title)
    if techs:
        out.append("## MITRE ATT&CK Mapping\n")
        for t in sorted(techs):
            extra = f" (+{len(techs[t]) - 1} more)" if len(techs[t]) > 1 else ""
            name = _MITRE_NAMES.get(t)
            label = f"{t} — {name}" if name else t          # no dangling '— ' when unknown
            out.append(f"- **{label}** · {techs[t][0]}{extra}")
        out.append("")

    # ---- Identity Risk (focus order) — placed near the bottom -------------
    rt = risk_table_md(graph, window=window, min_severity=min_severity)
    if rt:
        out.append(rt)

    # ---- Recommendations (actionable next steps) ----------------------
    out.append(_recommendations_md(graph, findings, assets))

    return "\n".join(out)


def report(graph, *, window=None, min_severity="informational", initial_access=None,
           case_name="Case", dispositions=None, validations=None, detail="auto") -> str:
    """Full deterministic report = narrative prose + deterministic fact tables.
    The real-LLM path (llm_sim) swaps ONLY ``narrative_md`` for an LLM call over
    ``distilled()`` and re-appends ``facts_md`` verbatim."""
    return (narrative_md(graph, window=window, min_severity=min_severity,
                         initial_access=initial_access, case_name=case_name)
            + "\n" + facts_md(graph, window=window, min_severity=min_severity,
                              dispositions=dispositions, validations=validations,
                              initial_access=initial_access, detail=detail))


_MITRE_NAMES = {
    "T1055": "Process Injection", "T1071": "Application Layer Protocol (C2)",
    "T1021": "Remote Services", "T1078": "Valid Accounts",
    "T1543": "Create/Modify System Process", "T1053": "Scheduled Task/Job",
    "T1547": "Boot/Logon Autostart", "T1059": "Command & Scripting Interpreter",
    "T1570": "Lateral Tool Transfer", "T1574": "Hijack Execution Flow",
    "T1003": "OS Credential Dumping", "T1558": "Steal or Forge Kerberos Tickets",
    "T1562": "Impair Defenses", "T1070": "Indicator Removal", "T1105": "Ingress Tool Transfer",
    "T1082": "System Information Discovery", "T1087": "Account Discovery",
    "T1018": "Remote System Discovery", "T1049": "System Network Connections Discovery",
    "T1136": "Create Account", "T1218": "System Binary Proxy Execution",
    "T1548": "Abuse Elevation Control Mechanism", "T1134": "Access Token Manipulation",
    "T1027": "Obfuscated Files or Information", "T1036": "Masquerading",
    "T1112": "Modify Registry", "T1569": "System Services", "T1219": "Remote Access Software",
    "T1560": "Archive Collected Data", "T1048": "Exfiltration Over Alternative Protocol",
}
