"""Correlation — assemble per-module contributions into ONE case graph and
derive the deterministic findings (NO LLM). This is where cross-module +
cross-host truth is established.

  assemble(case_id, contributions, run_ids) -> FusionGraph
    1. upsert all entities/relationships (merge same real-world thing by
       natural key — process by asset+pid+createtime, IOC/domain-account
       global, etc.)
    2. flag PID reuse (same asset+pid, different identity)
    3. cross-host detection (IOC/account touching >1 asset = lateral movement)
    4. derived findings (injected+C2, yara matches, persistence, high anomaly)
    5. severity rollup
"""

from __future__ import annotations

import hashlib

from .schema import FusionGraph, Finding, EvidenceRef
from . import severity as sev


def _fid(*parts) -> str:
    return "f_" + hashlib.sha1("|".join(str(p) for p in parts).encode()).hexdigest()[:12]


def _assets_of(e) -> list[str]:
    return list(dict.fromkeys(e.attrs.get("_assets") or []))


def assemble(case_id: str, contributions, run_ids) -> FusionGraph:
    g = FusionGraph(case_id=case_id)
    for rid in run_ids or []:
        g.note_run(rid)
    for ents, rels in contributions:
        for e in ents:
            g.upsert(e)
        for r in rels:
            g.relate(r)
    _rollup_severity(g)
    _flag_pid_reuse(g)
    _cross_host_findings(g)
    _derive_findings(g)
    _rollup_asset_severity(g)
    g.findings.sort(key=lambda f: (-sev.rank(f.severity), f.ts or "9999"))
    return g


def _rollup_asset_severity(g: FusionGraph) -> None:
    """Each host's severity = the worst finding touching it (so the macro
    view ranks hosts correctly instead of leaving them 'informational')."""
    for a in g.by_type("asset"):
        best = a.severity
        for f in g.findings:
            if a.id in f.asset_ids:
                best = sev.max_level(best, f.severity)
        a.severity = best


def _rollup_severity(g: FusionGraph) -> None:
    for e in g.entities.values():
        e.severity = sev.max_level(e.severity, sev.from_anomaly(e.anomaly))


def _flag_pid_reuse(g: FusionGraph) -> None:
    """Same (asset, pid) resolving to DIFFERENT process entities = PID reuse
    (createtime bucket already kept them separate — we just annotate)."""
    seen: dict[tuple, list[str]] = {}
    for e in g.entities.values():
        if e.type != "process":
            continue
        asset = (_assets_of(e) or ["?"])[0]
        pid = e.attrs.get("pid")
        if pid is None:
            continue
        seen.setdefault((asset, str(pid)), []).append(e.id)
    for (_a, _p), ids in seen.items():
        if len(ids) > 1:
            for eid in ids:
                e = g.entities[eid]
                if "pid_reused" not in e.flags:
                    e.flags.append("pid_reused")


def _cross_host_findings(g: FusionGraph) -> None:
    for e in g.entities.values():
        assets = _assets_of(e)
        if len(assets) < 2 or e.type not in ("ioc", "account", "yarahit"):
            continue
        if "cross_host" not in e.flags:
            e.flags.append("cross_host")
        hosts = ", ".join(_host_label(g, a) for a in assets)
        if e.type == "account":
            title = f"Account '{e.label}' used across {len(assets)} hosts"
            summ = (f"The account {e.label} authenticated / executed on multiple assets "
                    f"({hosts}) — consistent with lateral movement using shared credentials.")
            mitre = ["T1021", "T1078"]
            severity = "high"
        elif e.type == "ioc":
            title = f"Indicator {e.label} seen on {len(assets)} hosts"
            summ = (f"The indicator {e.label} ({e.attrs.get('ioc_kind')}) appears on multiple "
                    f"assets ({hosts}) — shared C2 / common infrastructure across hosts.")
            mitre = ["T1071"]
            severity = "high"
        else:
            title = f"YARA rule {e.label} hit on {len(assets)} hosts"
            summ = f"Signature {e.label} matched on multiple assets ({hosts})."
            mitre = []
            severity = "high"
        g.add_finding(Finding(
            id=_fid("xhost", e.id), title=title, severity=severity, confidence="high",
            summary=summ, entity_ids=[e.id], asset_ids=assets, sources=e.sources,
            evidence=list(e.evidence), mitre=mitre, ts=e.first_seen, kind="cross_host"))


def _host_label(g: FusionGraph, asset_id: str) -> str:
    a = g.entities.get(asset_id)
    return (a.label if a and a.label else asset_id.split(":")[-1])


def _linked_iocs(g: FusionGraph, proc_id: str) -> list:
    """IOCs reachable from a process within 2 hops via 'connected'."""
    out = []
    for r in g.out_edges(proc_id):
        if r.kind != "connected":
            continue
        dst = g.entities.get(r.dst)
        if dst is None:
            continue
        if dst.type == "ioc":
            out.append(dst)
        elif dst.type == "netconn":
            for r2 in g.out_edges(dst.id):
                if r2.kind == "connected" and g.entities.get(r2.dst) and g.entities[r2.dst].type == "ioc":
                    out.append(g.entities[r2.dst])
    return out


def _matched_yara(g: FusionGraph, proc_id: str) -> list:
    return [g.entities[r.src] for r in g.in_edges(proc_id)
            if r.kind == "matched" and g.entities.get(r.src)]


def _derive_findings(g: FusionGraph) -> None:
    for e in list(g.entities.values()):
        if e.type != "process":
            continue
        asset = _assets_of(e)
        host = _host_label(g, asset[0]) if asset else "?"
        injected = "injected" in e.flags or e.anomaly >= 100
        yaras = _matched_yara(g, e.id)
        iocs = _linked_iocs(g, e.id)
        if injected and (yaras or iocs):
            ev = list(e.evidence) + [x for y in yaras for x in y.evidence]
            g.add_finding(Finding(
                id=_fid("c2", e.id), title=f"Injected process with C2 — {e.label} on {host}",
                severity="critical", confidence="high",
                summary=(f"{e.label} on {host} has injected/RWX memory"
                         + (f", matches {', '.join(y.label for y in yaras)}" if yaras else "")
                         + (f", and connects to {', '.join(i.label for i in iocs)}" if iocs else "")
                         + " — a code-injected process beaconing to external infrastructure."),
                entity_ids=[e.id] + [y.id for y in yaras] + [i.id for i in iocs],
                asset_ids=asset, sources=sorted(set(e.sources + [s for y in yaras for s in y.sources])),
                evidence=ev, mitre=["T1055", "T1071"], ts=e.first_seen, kind="derived"))
        elif injected:
            g.add_finding(Finding(
                id=_fid("inj", e.id), title=f"Code injection — {e.label} on {host}",
                severity="high", confidence="high",
                summary=f"{e.label} (PID {e.attrs.get('pid')}) on {host} contains RWX/injected memory "
                        f"({e.attrs.get('protection') or 'PAGE_EXECUTE_READWRITE'}).",
                entity_ids=[e.id], asset_ids=asset, sources=e.sources,
                evidence=list(e.evidence), mitre=["T1055"], ts=e.first_seen, kind="single"))
        elif yaras:
            y = yaras[0]
            g.add_finding(Finding(
                id=_fid("yara", e.id), title=f"Signature match — {y.label} in {e.label} on {host}",
                severity="high", confidence="high",
                summary=f"YARA rule {y.label} matched in {e.label} (PID {e.attrs.get('pid')}) on {host}.",
                entity_ids=[e.id, y.id], asset_ids=asset,
                sources=sorted(set(e.sources + y.sources)),
                evidence=list(e.evidence) + list(y.evidence), ts=e.first_seen, kind="single"))
        elif e.anomaly >= 20:   # >=2 strong signals — a single benign AppData path (10) is NOT a finding
            g.add_finding(Finding(
                id=_fid("susp", e.id), title=f"Suspicious process — {e.label} on {host}",
                severity=sev.from_anomaly(e.anomaly), confidence="medium",
                summary=f"{e.label} (PID {e.attrs.get('pid')}) on {host} shows suspicious indicators"
                        f"{' (cmdline: ' + str(e.attrs.get('cmdline'))[:80] + ')' if e.attrs.get('cmdline') else ''}.",
                entity_ids=[e.id], asset_ids=asset, sources=e.sources,
                evidence=list(e.evidence), ts=e.first_seen, kind="single"))

    # persistence — suspicious services
    for e in g.by_type("service"):
        if e.anomaly >= 10:
            asset = _assets_of(e)
            host = _host_label(g, asset[0]) if asset else "?"
            g.add_finding(Finding(
                id=_fid("svc", e.id), title=f"Suspicious service — {e.label} on {host}",
                severity=sev.from_anomaly(e.anomaly), confidence="medium",
                summary=f"Service '{e.label}' on {host} has a suspicious binary/path "
                        f"({e.attrs.get('binary') or e.attrs.get('state') or '?'}).",
                entity_ids=[e.id], asset_ids=asset, sources=e.sources,
                evidence=list(e.evidence), mitre=["T1543"], ts=e.first_seen, kind="single"))

    # vulnerabilities
    for e in g.by_type("vuln"):
        g.add_finding(Finding(
            id=_fid("vuln", e.id), title=f"Vulnerability {e.label}",
            severity=e.severity, confidence="high",
            summary=f"{e.label} present on {', '.join(_host_label(g, a) for a in _assets_of(e))}"
                    f" (CVSS {e.attrs.get('cvss', '?')}).",
            entity_ids=[e.id], asset_ids=_assets_of(e), sources=e.sources,
            evidence=list(e.evidence), ts=e.first_seen, kind="single"))


# ------------------------------------------------------------------ scope
def in_window(ts, window) -> bool:
    if not window:
        return True
    if not ts:
        return True            # structural (no time) — kept; filtered by link elsewhere
    start, end = window.get("start"), window.get("end")
    if start and ts < start:
        return False
    if end and ts > end:
        return False
    return True
