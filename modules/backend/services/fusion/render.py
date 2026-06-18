"""Render the case graph at three altitudes (macro / infrastructural attack
timeline / per-asset) and produce the compact distilled payload. All
DETERMINISTIC — the graph already holds the findings + timestamps, so this
is templating, not analysis. The LLM (real or simulated) only narrates over
``distilled()``.
"""

from __future__ import annotations

from . import severity as sev
from .correlate import in_window, _assets_of, _host_label


def scope(graph, *, window=None, min_severity="informational"):
    """Return (assets, findings) filtered to the time window + severity."""
    findings = [f for f in graph.findings
                if sev.at_least(f.severity, min_severity) and in_window(f.ts, window)]
    assets = [e for e in graph.by_type("asset")]
    return assets, findings


def timeline(graph, *, window=None, initial_access=None):
    rows = []
    for f in graph.findings:
        if not in_window(f.ts, window):
            continue
        rows.append({"ts": f.ts or "", "host": ", ".join(_host_label(graph, a) for a in f.asset_ids) or "-",
                     "phase": _phase(f), "title": f.title, "severity": f.severity,
                     "mitre": f.mitre})
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


def narrative_md(graph, *, window=None, min_severity="informational",
                 initial_access=None, case_name="Case") -> str:
    """The LLM-REPLACEABLE prose: title, scope, attack story. When the real LLM is
    wired it regenerates exactly this from ``distilled()`` — the deterministic fact
    tables in ``facts_md`` are never sent to it (so IOCs/CVEs can't be hallucinated)."""
    assets, findings = scope(graph, window=window, min_severity=min_severity)
    out: list[str] = []
    out.append(f"# Incident Case Report — {case_name}\n")
    win = f"{(window or {}).get('start','?')} → {(window or {}).get('end','?')}" if window else "all"
    out.append(f"_Scope: {len(assets)} host(s), window {win}, initial access ≈ "
               f"{initial_access or 'unknown'}; severity ≥ {min_severity}. "
               f"{len(findings)} findings._\n")
    story = _attack_story(graph, findings, assets, initial_access)
    if story:
        out.append("> " + story + "\n")
    return "\n".join(out)


def facts_md(graph, *, window=None, min_severity="informational", initial_access=None) -> str:
    """DETERMINISTIC fact tables — escalation, risk ranking, timeline, per-host,
    IOC table, MITRE. Appended verbatim to every report; NEVER sent to the LLM."""
    assets, findings = scope(graph, window=window, min_severity=min_severity)
    out: list[str] = []

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

    # ---- 1. Macro / risk ----------------------------------------------
    out.append("## 1. Executive / Risk Overview\n")
    tally = _sev_tally(findings)
    out.append("**Findings by severity:** " + ", ".join(
        f"{tally[lv]} {lv}" for lv in reversed(sev.LEVELS) if tally[lv]) + "\n")
    ranked_assets = sorted(assets, key=lambda a: -(a.attrs.get("risk_score") or 0))
    out.append("**Hosts (by risk):**")
    for a in ranked_assets:
        nf = sum(1 for f in findings if a.id in f.asset_ids)
        mods = ", ".join(a.attrs.get("modules") or [])
        flag = "  🔺 escalate" if a.attrs.get("escalate") else ("  ✓ deep" if a.attrs.get("deep") else "")
        out.append(f"- **{a.label}** — {a.severity} · risk {a.attrs.get('risk_score', 0)} · "
                   f"{nf} findings · [{mods}]{flag}")
    xh = [f for f in findings if f.kind == "cross_host"]
    if xh:
        out.append(f"\n**Cross-host activity:** {len(xh)} finding(s) span multiple hosts "
                   f"(lateral movement / shared infrastructure):")
        for f in xh:
            out.append(f"- {f.title}")
    out.append("")

    # ---- 2. Infrastructural attack timeline ---------------------------
    out.append("## 2. Infrastructural Attack Timeline\n")
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

    # ---- 3. Per-asset drill-down --------------------------------------
    out.append("## 3. Per-Host Detail\n")
    for a in ranked_assets:
        out.append(f"### {a.label}  ({a.severity})")
        afind = [f for f in findings if a.id in f.asset_ids]
        for f in afind:
            out.append(f"- **[{f.severity}]** {f.summary}")
        # notable entities on this host (suspicious only — no benign baseline noise)
        procs = sorted((e for e in graph.by_type("process")
                        if a.id in _assets_of(e) and (e.anomaly >= 20 or "injected" in e.flags)),
                       key=lambda e: -e.anomaly)[:8]
        if procs:
            out.append("  - _suspicious processes:_ " + ", ".join(
                f"{p.label}{'⚠' if 'injected' in p.flags else ''}" for p in procs))
        iocs = [e for e in graph.by_type("ioc") if a.id in _assets_of(e)]
        if iocs:
            out.append("  - _indicators:_ " + ", ".join(i.label for i in iocs[:12]))
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
        out.append("## 4. Key Indicators\n")
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
        out.append("## 5. MITRE ATT&CK\n")
        for t in sorted(techs):
            extra = f" (+{len(techs[t]) - 1} more)" if len(techs[t]) > 1 else ""
            out.append(f"- **{t} — {_MITRE_NAMES.get(t, '')}** · {techs[t][0]}{extra}")
        out.append("")

    return "\n".join(out)


def report(graph, *, window=None, min_severity="informational", initial_access=None,
           case_name="Case") -> str:
    """Full deterministic report = narrative prose + deterministic fact tables.
    The real-LLM path (llm_sim) swaps ONLY ``narrative_md`` for an LLM call over
    ``distilled()`` and re-appends ``facts_md`` verbatim."""
    return (narrative_md(graph, window=window, min_severity=min_severity,
                         initial_access=initial_access, case_name=case_name)
            + "\n" + facts_md(graph, window=window, min_severity=min_severity,
                              initial_access=initial_access))


_MITRE_NAMES = {
    "T1055": "Process Injection", "T1071": "Application Layer Protocol (C2)",
    "T1021": "Remote Services", "T1078": "Valid Accounts",
    "T1543": "Create/Modify System Process", "T1053": "Scheduled Task/Job",
    "T1547": "Boot/Logon Autostart", "T1059": "Command & Scripting Interpreter",
}
