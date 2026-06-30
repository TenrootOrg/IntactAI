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


def _distilled_at(graph, *, window, min_severity, max_entities):
    assets, findings = scope(graph, window=window, min_severity=min_severity)
    ents = sorted((e for e in graph.entities.values()
                   if e.type != "asset" and sev.at_least(e.severity, min_severity)
                   and in_window(e.first_seen, window)),
                  key=lambda e: -e.anomaly)[:max_entities]
    return {
        "case_id": graph.case_id,
        "assets": [{"id": a.id, "host": a.label, "severity": a.severity} for a in assets],
        "findings": [{"title": f.title, "severity": f.severity, "confidence": f.confidence,
                      "hosts": [_host_label(graph, x) for x in f.asset_ids],
                      "summary": f.summary, "mitre": f.mitre, "kind": f.kind, "ts": f.ts}
                     for f in findings],
        "timeline": timeline(graph, window=window),
        "top_entities": [{"type": e.type, "label": e.label, "severity": e.severity,
                          "anomaly": e.anomaly, "flags": e.flags,
                          "hosts": [_host_label(graph, x) for x in _assets_of(e)]} for e in ents],
    }


def distilled(graph, *, window=None, min_severity="informational", max_entities=60,
              budget_chars=None):
    """Compact, in-window, high-signal payload — what a real LLM would get.

    If ``budget_chars`` is set and the payload exceeds it, halve ``max_entities``
    up to ``budget.MAX_STEPDOWNS`` times. Findings/assets/timeline are always kept
    (they are the signal); only the ranked ``top_entities`` tail is trimmed."""
    from . import budget as _b
    p = _distilled_at(graph, window=window, min_severity=min_severity, max_entities=max_entities)
    if budget_chars:
        steps = 0
        while _b.over_budget(p, budget_chars) and steps < _b.MAX_STEPDOWNS and max_entities > 5:
            max_entities = max(5, max_entities // 2)
            p = _distilled_at(graph, window=window, min_severity=min_severity,
                              max_entities=max_entities)
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
def _attack_story(graph, findings, assets, initial_access=None):
    """A short templated narrative (this is where a live LLM would shine)."""
    if not findings:
        return ""
    hosts = sorted(assets, key=lambda a: -sev.rank(a.severity))
    crit = [f for f in findings if sev.at_least(f.severity, "high")]
    bits = [f"Across **{len(assets)} host(s)**, the most affected is **"
            f"{hosts[0].label if hosts else 'a host'}** "
            f"({hosts[0].severity if hosts else '?'})"
            + (f", with activity centred on the initial-access window (~{initial_access})"
               if initial_access else "") + "."]
    lead = [f for f in crit if f.kind in ("derived", "single")
            and "vulnerab" not in f.title.lower()]
    if lead:
        bits.append(f"Lead: {lead[0].summary}")
    xh = [f for f in findings if f.kind == "cross_host"]
    if xh:
        bits.append("Cross-host: " + "; ".join(f.title for f in xh[:3]) + ".")
    pers = [f for f in findings if "service" in f.title.lower() or "persist" in f.title.lower()]
    if pers:
        bits.append(f"Persistence: {pers[0].title}.")
    return " ".join(bits)


def _sev_tally(findings):
    t = {lv: 0 for lv in sev.LEVELS}
    for f in findings:
        t[f.severity] = t.get(f.severity, 0) + 1
    return t


def _exec_summary(graph, assets, findings) -> str:
    """A plain-language executive summary (what / how big / how bad / bottom line)."""
    hosts = sorted(assets, key=lambda a: -sev.rank(a.severity))
    crit = [f for f in findings if sev.at_least(f.severity, "critical")]
    high = [f for f in findings if f.severity == "high"]
    xh = [f for f in findings if f.kind == "cross_host"]
    bits = [f"This investigation correlated activity across **{len(assets)} host(s)** and "
            f"identified **{len(findings)} finding(s)**"
            + (f" — {len(crit)} critical, {len(high)} high" if (crit or high) else "") + "."]
    if hosts:
        w = hosts[0]
        nf = sum(1 for f in findings if w.id in f.asset_ids)
        bits.append(f"The most affected system is **{w.label}** ({w.severity}, {nf} finding(s)), "
                    f"the likely focal point of the activity.")
    if xh:
        bits.append(f"**{len(xh)} finding(s)** span multiple hosts, indicating lateral "
                    f"movement or shared adversary infrastructure.")
    word = "critical" if crit else ("high" if high else "moderate")
    bits.append(f"Overall severity is assessed **{word}**"
                + (" and immediate containment is recommended." if (crit or high) else "."))
    return " ".join(bits)


def _attack_narrative(graph, window, initial_access) -> str:
    """The kill chain as ordered prose, grouped by phase (deterministic)."""
    tl = timeline(graph, window=window)
    if not tl:
        return ""
    phases: dict[str, list] = {}
    order: list[str] = []
    for r in tl:
        ph = r.get("phase") or "Activity"
        if ph not in phases:
            phases[ph] = []
            order.append(ph)
        phases[ph].append(r)
    steps = []
    for ph in order:
        rows = phases[ph]
        hosts = sorted({h.strip() for r in rows for h in (r["host"] or "").split(",") if h.strip()})
        titles = list(dict.fromkeys(r["title"] for r in rows))
        extra = f" (and {len(rows) - len(titles[:3])} more)" if len(rows) > 3 else ""
        steps.append(f"**{ph}** — from `{rows[0]['ts'] or '—'}` on "
                     f"{', '.join(hosts[:6])}: " + "; ".join(titles[:3]) + extra + ".")
    return "\n".join(f"{i + 1}. {s}" for i, s in enumerate(steps))


def narrative_md(graph, *, window=None, min_severity="informational",
                 initial_access=None, case_name="Case") -> str:
    """The LLM-REPLACEABLE prose: exec summary, incident overview, attack narrative.
    When the real LLM is wired it regenerates this from ``distilled()`` — the
    deterministic fact tables in ``facts_md`` are never sent to it."""
    assets, findings = scope(graph, window=window, min_severity=min_severity)
    win = f"{(window or {}).get('start','?')} → {(window or {}).get('end','?')}" if window else "all"
    out: list[str] = [f"# Incident Case Report — {case_name}\n"]
    out.append(f"_Scope: {len(assets)} host(s) · window {win} · initial access ≈ "
               f"{initial_access or 'unknown'} · severity ≥ {min_severity} · "
               f"{len(findings)} findings_\n")
    out.append("## Executive Summary\n")
    out.append(_exec_summary(graph, assets, findings) + "\n")
    out.append("## Incident Overview\n")
    story = _attack_story(graph, findings, assets, initial_access)
    out.append((story or "_No activity above the configured severity threshold._") + "\n")
    narr = _attack_narrative(graph, window, initial_access)
    if narr:
        out.append("## Attack Narrative\n")
        out.append(narr + "\n")
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
    iocs = graph.by_type("ioc")
    if iocs:
        recs.append(("Network", "Block these indicators at the perimeter / EDR and hunt for "
                     "further callbacks: " + ", ".join(f"`{e.label}`" for e in iocs[:8]) + "."))
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
    out = ["## 🎯 Identity Risk — who to focus on first\n",
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


def facts_md(graph, *, window=None, min_severity="informational", initial_access=None,
             dispositions=None, validations=None) -> str:
    """DETERMINISTIC report body — identity-risk table, escalation, risk ranking,
    analyst validations, timeline, per-host detail, IOC table, MITRE,
    recommendations. Appended verbatim to every report; NEVER sent to the LLM."""
    assets, findings = scope(graph, window=window, min_severity=min_severity)
    out: list[str] = []

    # ---- Identity Risk table (who to focus on first + why) ------------
    rt = risk_table_md(graph, window=window, min_severity=min_severity)
    if rt:
        out.append(rt)

    # ---- Escalation (the Phase-1 triage hero) -------------------------
    esc = sorted((a for a in assets if a.attrs.get("escalate")),
                 key=lambda a: -(a.attrs.get("risk_score") or 0))
    if esc:
        out.append("## ⚠ Escalation — recommend deep-dive\n")
        out.append("Malicious under broad collection (Velociraptor / cloud) but **no "
                   "memory or Timesketch yet** — run those on these hosts next:\n")
        for a in esc:
            out.append(f"- **{a.label}** — {a.severity}, risk {a.attrs.get('risk_score', 0)} "
                       f"· seen by [{', '.join(a.attrs.get('modules') or [])}]")
        out.append("")

    # ---- analyst validations (Timeline triage) ------------------------
    av = _analyst_validations_md(graph, dispositions, validations)
    if av:
        out.append(av)

    # ---- Risk overview (NO host-ranking list — that's the Identity Risk table) ----
    out.append("## Risk Overview\n")
    tally = _sev_tally(findings)
    out.append("**Findings by severity:** " + ", ".join(
        f"{tally[lv]} {lv}" for lv in reversed(sev.LEVELS) if tally[lv]) + "\n")
    ranked_assets = sorted(assets, key=lambda a: -(a.attrs.get("risk_score") or 0))
    xh = [f for f in findings if f.kind == "cross_host"]
    if xh:
        out.append(f"**Cross-host activity:** {len(xh)} finding(s) span multiple hosts "
                   f"(lateral movement / shared infrastructure):")
        for f in xh:
            out.append(f"- {f.title}")
        out.append("")
    # shared file hashes are summarised once here + detailed in the IOC appendix,
    # NOT repeated as one finding per hash.
    shared_hashes = [e for e in graph.by_type("ioc")
                     if e.attrs.get("ioc_kind") == "hash" and "cross_host" in e.flags]
    if shared_hashes:
        out.append(f"**Shared binaries:** {len(shared_hashes)} file hash(es) appear on "
                   f"more than one host (tool reuse / lateral transfer) — full hashes in "
                   f"the IOC appendix.\n")

    # ---- Timeline -----------------------------------------------------
    out.append("## Timeline of Key Events\n")
    tl = timeline(graph, window=window, initial_access=initial_access)
    if not tl:
        out.append("_No time-anchored activity in window._\n")
    else:
        cur_phase = None
        for row in tl:
            if row["phase"] != cur_phase:
                cur_phase = row["phase"]
                out.append(f"\n**▸ {cur_phase}**")
            mitre = f" `[{', '.join(row['mitre'])}]`" if row["mitre"] else ""
            out.append(f"- `{row['ts'] or '—'}` · **{row['host']}** · "
                       f"{row['title']} ({row['severity']}){mitre}")
    out.append("")

    # ---- Affected hosts detail ----------------------------------------
    out.append("## Affected Hosts — Detail\n")
    for a in ranked_assets:
        out.append(f"### {a.label}  ({a.severity})")
        # findings in CHRONOLOGICAL order (a per-host timeline), not a flat dump
        afind = sorted((f for f in findings if a.id in f.asset_ids),
                       key=lambda f: (f.ts or "9999", -sev.rank(f.severity)))
        for f in afind:
            ts = f"`{fmt_ts(f.ts)}` · " if f.ts else ""
            out.append(f"- {ts}**[{f.severity}]** {f.summary}")
        # notable entities on this host (suspicious only — no benign baseline noise)
        procs = sorted((e for e in graph.by_type("process")
                        if a.id in _assets_of(e) and (e.anomaly >= 20 or "injected" in e.flags)),
                       key=lambda e: -e.anomaly)[:8]
        if procs:
            out.append("  - _suspicious processes:_ " + ", ".join(
                f"{p.label}{'⚠' if 'injected' in p.flags else ''}" for p in procs))
        # IOCs are NOT dumped per host (they're in the appendix) — just a pointer.
        iocs = [e for e in graph.by_type("ioc") if a.id in _assets_of(e)]
        if iocs:
            out.append(f"  - _{len(iocs)} indicator(s) on this host — see IOC appendix._")
        accts = [e for e in graph.by_type("account") if a.id in _assets_of(e)]
        if accts:
            out.append("  - _accounts:_ " + ", ".join(
                f"{x.label}{'⚠' if 'cross_host' in x.flags else ''}" for x in accts[:10]))
        if not afind and not procs and not iocs:
            out.append("- _no findings above threshold._")
        out.append("")

    # ---- 4. Key Indicators (IOCs) -------------------------------------
    iocs = graph.by_type("ioc")
    if iocs:
        out.append("## Indicators of Compromise (IOCs)\n")
        out.append("| Indicator | Type | Hosts | Cross-host |")
        out.append("|---|---|---|---|")
        for i in sorted(iocs, key=lambda e: (-len(_assets_of(e)), e.label)):
            hosts = ", ".join(_host_label(graph, x) for x in _assets_of(i))
            out.append(f"| `{i.label}` | {i.attrs.get('ioc_kind', '?')} | {hosts} | "
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
            out.append(f"- **{t} — {_MITRE_NAMES.get(t, '')}** · {techs[t][0]}{extra}")
        out.append("")

    # ---- Recommendations (actionable next steps) ----------------------
    out.append(_recommendations_md(graph, findings, assets))

    return "\n".join(out)


def report(graph, *, window=None, min_severity="informational", initial_access=None,
           case_name="Case", dispositions=None, validations=None) -> str:
    """Full deterministic report = narrative prose + deterministic fact tables.
    The real-LLM path (llm_sim) swaps ONLY ``narrative_md`` for an LLM call over
    ``distilled()`` and re-appends ``facts_md`` verbatim."""
    return (narrative_md(graph, window=window, min_severity=min_severity,
                         initial_access=initial_access, case_name=case_name)
            + "\n" + facts_md(graph, window=window, min_severity=min_severity,
                              dispositions=dispositions, validations=validations,
                              initial_access=initial_access))


_MITRE_NAMES = {
    "T1055": "Process Injection", "T1071": "Application Layer Protocol (C2)",
    "T1021": "Remote Services", "T1078": "Valid Accounts",
    "T1543": "Create/Modify System Process", "T1053": "Scheduled Task/Job",
    "T1547": "Boot/Logon Autostart", "T1059": "Command & Scripting Interpreter",
}
