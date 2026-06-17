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


def distilled(graph, *, window=None, min_severity="informational", max_entities=60):
    """Compact, in-window, high-signal payload — what a real LLM would get."""
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


# ------------------------------------------------------------------ report
def _sev_tally(findings):
    t = {lv: 0 for lv in sev.LEVELS}
    for f in findings:
        t[f.severity] = t.get(f.severity, 0) + 1
    return t


def report(graph, *, window=None, min_severity="informational", initial_access=None,
           case_name="Case") -> str:
    assets, findings = scope(graph, window=window, min_severity=min_severity)
    out: list[str] = []
    out.append(f"# Incident Case Report — {case_name}\n")
    win = f"{(window or {}).get('start','?')} → {(window or {}).get('end','?')}" if window else "all"
    out.append(f"_Scope: {len(assets)} host(s), window {win}, initial access ≈ "
               f"{initial_access or 'unknown'}; severity ≥ {min_severity}. "
               f"{len(findings)} findings._\n")

    # ---- 1. Macro / risk ----------------------------------------------
    out.append("## 1. Executive / Risk Overview\n")
    tally = _sev_tally(findings)
    out.append("**Findings by severity:** " + ", ".join(
        f"{tally[lv]} {lv}" for lv in reversed(sev.LEVELS) if tally[lv]) + "\n")
    ranked_assets = sorted(assets, key=lambda a: -sev.rank(a.severity))
    out.append("**Hosts (most → least severe):**")
    for a in ranked_assets:
        nf = sum(1 for f in findings if a.id in f.asset_ids)
        out.append(f"- **{a.label}** — {a.severity} ({nf} findings)")
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
        # notable entities on this host
        procs = sorted((e for e in graph.by_type("process") if a.id in _assets_of(e) and e.anomaly > 0),
                       key=lambda e: -e.anomaly)[:8]
        if procs:
            out.append("  - _processes:_ " + ", ".join(
                f"{p.label}{'⚠' if 'injected' in p.flags else ''}" for p in procs))
        iocs = [e for e in graph.by_type("ioc") if a.id in _assets_of(e)]
        if iocs:
            out.append("  - _indicators:_ " + ", ".join(i.label for i in iocs[:12]))
        if not afind and not procs and not iocs:
            out.append("- _no findings above threshold._")
        out.append("")

    return "\n".join(out)
