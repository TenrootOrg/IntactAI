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


def assemble(case_id: str, contributions, run_ids, *, baseline=None, window=None) -> FusionGraph:
    g = FusionGraph(case_id=case_id)
    for rid in run_ids or []:
        g.note_run(rid)
    for ents, rels in contributions:
        for e in ents:
            g.upsert(e)
        for r in rels:
            g.relate(r)
    _resolve_host_assets(g)
    _bridge_hashes(g)
    _rollup_severity(g)
    _flag_pid_reuse(g)
    _cross_host_findings(g)
    _derive_findings(g, baseline=baseline, window=window)
    _coordinated_activity(g, window=window, baseline=baseline)
    _corroboration(g)
    _rollup_asset_severity(g)
    _score_assets(g)
    g.findings.sort(key=lambda f: (-sev.rank(f.severity), f.ts or "9999"))
    return g


def _baseline_sigma_titles(baseline) -> set:
    return set((baseline or {}).get("sigma_titles") or [])


def baseline_fingerprint(g: FusionGraph) -> dict:
    """A per-environment fingerprint of 'normal' from a known-CLEAN fused graph:
    the SIGMA detection titles + finding titles + suspicious service binary paths
    that fired with no attack present. Set-membership; subtracted in _derive_findings."""
    sigma_titles = sorted({e.attrs.get("title") or e.label
                           for e in g.by_type("event") if "sigma" in e.flags
                           and (e.attrs.get("title") or e.label)})
    finding_titles = sorted({f.title.split(" on ")[0] for f in g.findings})
    svc_paths = sorted({(e.attrs.get("binary") or "").lower()
                        for e in g.by_type("service") if e.attrs.get("binary")})
    assets = list(g.by_type("asset"))
    return {"sigma_titles": sigma_titles, "finding_titles": finding_titles,
            "service_paths": svc_paths,
            "host_role": assets[0].label if assets else "?"}


def _corroboration(g: FusionGraph) -> None:
    """Raise confidence on findings corroborated by >=2 distinct modules (the
    entities they cite were observed by multiple collectors). Post-processing
    only — never creates findings, so it cannot add false positives."""
    for f in g.findings:
        mods = set()
        for eid in f.entity_ids:
            e = g.entities.get(eid)
            if e:
                mods.update(e.sources)
        if len(mods) >= 2 and f.confidence != "high":
            f.confidence = "high"
            f.summary += f" [corroborated by {len(mods)} modules: {', '.join(sorted(mods))}]"


_RISK_W = {"critical": 100, "high": 40, "medium": 10, "low": 2, "informational": 0}


def _score_assets(g: FusionGraph) -> None:
    """Per-host triage score + which modules have data on it — drives the
    Phase-1 'which endpoints to deep-dive' recommendation. A high-risk host
    seen ONLY by the broad tools (velociraptor/cloud), with no memory/
    timesketch yet, is an escalation candidate."""
    for a in g.by_type("asset"):
        score = 0
        for f in g.findings:
            if a.id in f.asset_ids:
                score += _RISK_W.get(f.severity, 0) * (2 if f.kind == "cross_host" else 1)
        modules = set()
        for e in g.entities.values():
            if a.id in _assets_of(e):
                modules.update(e.sources)
        a.attrs["risk_score"] = score
        a.attrs["modules"] = sorted(modules)
        a.attrs["deep"] = bool({"memory", "timesketch"} & modules)
        # escalate: looks malicious (high/critical) but only broad tooling has touched it
        a.attrs["escalate"] = (sev.at_least(a.severity, "high") and not a.attrs["deep"])


def _rollup_asset_severity(g: FusionGraph) -> None:
    """Each host's severity = the worst finding touching it (so the macro
    view ranks hosts correctly instead of leaving them 'informational')."""
    for a in g.by_type("asset"):
        best = a.severity
        for f in g.findings:
            if a.id in f.asset_ids:
                best = sev.max_level(best, f.severity)
        a.severity = best


def _resolve_host_assets(g: FusionGraph) -> None:
    """Merge hostname-keyed assets (e.g. from CVE rows that only have a
    Hostname) into the canonical client_id asset when the hostname matches —
    so one physical host is ONE node, not two."""
    from .keys import norm_host
    canon: dict[str, str] = {}
    for a in g.by_type("asset"):
        if a.id.startswith("asset:endpoint:host="):
            continue
        h = norm_host(a.attrs.get("hostname") or "")
        if h:
            canon[h] = a.id
    remap: dict[str, str] = {}
    for a in g.by_type("asset"):
        if not a.id.startswith("asset:endpoint:host="):
            continue
        h = a.id[len("asset:endpoint:host="):]
        tgt = canon.get(norm_host(h))
        if tgt and tgt != a.id:
            remap[a.id] = tgt
    if not remap:
        return
    for old, new in remap.items():                 # merge the asset node itself
        if old in g.entities:
            e = g.entities.pop(old)
            e.id = new
            g.upsert(e)
    for e in g.entities.values():                  # remap every entity's asset list
        al = e.attrs.get("_assets")
        if al:
            e.attrs["_assets"] = list(dict.fromkeys(remap.get(x, x) for x in al))
    for r in g.relationships:                       # remap edge endpoints
        r.src, r.dst = remap.get(r.src, r.src), remap.get(r.dst, r.dst)
    seen: dict = {}                                 # dedup (src,dst,kind) after remap
    fresh: list = []
    for r in g.relationships:
        k = r.key()
        if k in seen:
            cur = fresh[seen[k]]
            for s in r.sources:
                if s not in cur.sources:
                    cur.sources.append(s)
        else:
            seen[k] = len(fresh)
            fresh.append(r)
    g.relationships = fresh
    g.rebuild_indexes()                             # refresh src/dst/key indexes


def _bridge_hashes(g: FusionGraph) -> None:
    """Collapse hash IOC nodes that are the SAME binary keyed by different algos.
    A node carrying both SHA256 (full_hash) and a SHA1/MD5 attr (Pslist nested Hash,
    Hayabusa Details) defines the alias SHA1/MD5 -> SHA256; a node keyed by that bare
    SHA1/MD5 (e.g. Amcache, sha1-only) is remapped INTO the canonical SHA256 node.
    Reuses the proven _resolve_host_assets remap; cross-host still works (SHA256 key
    is global, _assets union on merge). Alias only toward a co-observed SHA256."""
    from . import keys
    alias: dict[str, str] = {}                      # sha1|md5 -> sha256
    for e in g.by_type("ioc"):
        if e.attrs.get("ioc_kind") != "hash":
            continue
        sha256 = str(e.attrs.get("full_hash") or "").lower()
        if len(sha256) != 64:
            continue
        for k in ("sha1", "md5"):
            v = str(e.attrs.get(k) or "").lower()
            if v and v != sha256:
                alias[v] = sha256
    if not alias:
        return
    remap: dict[str, str] = {}
    for e in list(g.by_type("ioc")):
        if e.attrs.get("ioc_kind") != "hash":
            continue
        val = str(e.attrs.get("full_hash") or "").lower()
        if val in alias:                            # keyed by a sha1/md5 with a sha256 twin
            canon = keys.ioc_id("hash", alias[val])
            if canon != e.id:
                remap[e.id] = canon
    if not remap:
        return
    for old, new in remap.items():
        if old in g.entities:
            e = g.entities.pop(old)
            e.id = new
            g.upsert(e)                             # merges sources/flags/_assets/evidence
    for r in g.relationships:
        r.src, r.dst = remap.get(r.src, r.src), remap.get(r.dst, r.dst)
    seen: dict = {}
    fresh: list = []
    for r in g.relationships:
        k = r.key()
        if k in seen:
            cur = fresh[seen[k]]
            for s in r.sources:
                if s not in cur.sources:
                    cur.sources.append(s)
        else:
            seen[k] = len(fresh)
            fresh.append(r)
    g.relationships = fresh
    g.rebuild_indexes()


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
        # a pure-context indicator (anomaly 0 — e.g. benign cloud telemetry linked
        # from a detection's Details) on N hosts is NOT lateral movement; skip it.
        if e.type == "ioc" and e.anomaly < 1:
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


def _parent(g: FusionGraph, proc_id: str):
    for r in g.in_edges(proc_id):
        if r.kind == "spawned" and g.entities.get(r.src):
            return g.entities[r.src]
    return None


def _derive_findings(g: FusionGraph, *, baseline=None, window=None) -> None:
    base_titles = _baseline_sigma_titles(baseline)
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

    # suspicious spawn chains (office/browser -> script interpreter = phishing exec)
    _OFFICE = ("winword", "excel", "powerpnt", "outlook", "onenote", "chrome",
               "msedge", "firefox", "acrord", "msaccess", "mspub")
    _SCRIPT = ("powershell", "cmd.exe", "wscript", "cscript", "mshta", "rundll32",
               "regsvr32", "bitsadmin", "certutil")
    for e in g.by_type("process"):
        name = (e.attrs.get("name") or "").lower()
        if not any(s in name for s in _SCRIPT):
            continue
        par = next((g.entities[r.src] for r in g.in_edges(e.id)
                    if r.kind == "spawned" and g.entities.get(r.src)
                    and any(o in (g.entities[r.src].attrs.get("name") or "").lower()
                            for o in _OFFICE)), None)
        if par:
            asset = _assets_of(e)
            host = _host_label(g, asset[0]) if asset else "?"
            g.add_finding(Finding(
                id=_fid("chain", e.id),
                title=f"Suspicious spawn chain — {par.label} → {e.label} on {host}",
                severity="high", confidence="high",
                summary=f"{par.label} spawned {e.label} on {host} — an office/browser app "
                        f"launching a script interpreter is a hallmark of phishing-driven "
                        f"execution.",
                entity_ids=[par.id, e.id], asset_ids=asset,
                sources=sorted(set(e.sources + par.sources)),
                evidence=list(e.evidence), mitre=["T1059", "T1566"],
                ts=e.first_seen, kind="derived"))

    # persistence — suspicious services (path-aware score; trusted roots = 0,
    # so this no longer flags every svchost/Defender service)
    for e in g.by_type("service"):
        if e.anomaly >= 20:
            asset = _assets_of(e)
            host = _host_label(g, asset[0]) if asset else "?"
            g.add_finding(Finding(
                id=_fid("svc", e.id), title=f"Suspicious service — {e.label} on {host}",
                severity=sev.from_anomaly(e.anomaly), confidence="medium",
                summary=f"Service '{e.label}' on {host} has a suspicious binary/path "
                        f"({e.attrs.get('binary') or e.attrs.get('state') or '?'}).",
                entity_ids=[e.id], asset_ids=asset, sources=e.sources,
                evidence=list(e.evidence), mitre=["T1543"], ts=e.first_seen, kind="single"))

    # BYOVD / malicious loaded driver (LolDrivers)
    for e in g.by_type("module"):
        if "byovd" not in e.flags and "loldriver" not in e.flags:
            continue
        asset = _assets_of(e)
        host = _host_label(g, asset[0]) if asset else "?"
        byovd = "byovd" in e.flags
        g.add_finding(Finding(
            id=_fid("loldrv", e.id),
            title=f"{'Malicious' if byovd else 'Vulnerable'} driver — "
                  f"{e.attrs.get('driver', e.label)} on {host}",
            severity="high" if byovd else "medium", confidence="medium",
            summary=f"{'Known-malicious' if byovd else 'Known-vulnerable (LOLDriver)'} driver "
                    f"'{e.attrs.get('driver', e.label)}' on {host}"
                    f"{' — bring-your-own-vulnerable-driver' if byovd else ''}.",
            entity_ids=[e.id], asset_ids=asset, sources=e.sources,
            evidence=list(e.evidence), mitre=["T1068"], ts=e.first_seen, kind="single"))

    # DLL sideloading (HijackLibs) + bad bootloader (firmware)
    for e in g.by_type("event"):
        if "dll_hijack" in e.flags:
            asset = _assets_of(e)
            host = _host_label(g, asset[0]) if asset else "?"
            g.add_finding(Finding(
                id=_fid("hijack", e.id),
                title=f"DLL sideloading — {e.attrs.get('dll', e.label)} on {host}",
                severity=sev.from_anomaly(e.anomaly), confidence="medium",
                summary=f"Possible DLL search-order hijack / sideload of "
                        f"'{e.attrs.get('dll', e.label)}' on {host}.",
                entity_ids=[e.id], asset_ids=asset, sources=e.sources,
                evidence=list(e.evidence), mitre=["T1574"], ts=e.first_seen, kind="single"))
        elif "firmware_bad" in e.flags:
            asset = _assets_of(e)
            host = _host_label(g, asset[0]) if asset else "?"
            g.add_finding(Finding(
                id=_fid("boot", e.id), title=f"Suspicious bootloader on {host}",
                severity="high", confidence="medium",
                summary=f"Bootloader '{e.label}' on {host} flagged (revoked/known-bad).",
                entity_ids=[e.id], asset_ids=asset, sources=e.sources,
                evidence=list(e.evidence), mitre=["T1542"], ts=e.first_seen, kind="single"))

    # suspicious Kerberos tickets (Golden/Silver-Ticket triage)
    for e in g.by_type("event"):
        if "kerberos_suspicious" not in e.flags:
            continue
        asset = _assets_of(e)
        host = _host_label(g, asset[0]) if asset else "?"
        g.add_finding(Finding(
            id=_fid("krb", e.id),
            title=f"Suspicious Kerberos {e.attrs.get('ticket_type', 'ticket')} on {host}",
            severity="high", confidence="medium",
            summary=f"Kerberos {e.attrs.get('ticket_type')} {e.attrs.get('client')} -> "
                    f"{e.attrs.get('server')} on {host} flagged suspicious "
                    f"(enctype {e.attrs.get('enctype')}) — possible Golden/Silver Ticket.",
            entity_ids=[e.id], asset_ids=asset, sources=e.sources,
            evidence=list(e.evidence), mitre=["T1558"], ts=e.first_seen, kind="single"))

    # endpoint SIGMA detections (Hayabusa) -> findings, grouped by detection
    # title per host so a rule firing N times is ONE finding (not N). Only
    # high/critical surface as findings; medium/low stay as ranked events.
    _sigma_groups: dict = {}
    for e in g.by_type("event"):
        if "sigma" not in e.flags:
            continue
        if not sev.at_least(e.severity, "high"):
            continue
        for a in _assets_of(e) or ["?"]:
            _sigma_groups.setdefault((a, e.attrs.get("title") or e.label), []).append(e)
    for (asset_id, title), evs in _sigma_groups.items():
        host = _host_label(g, asset_id)
        top = max(evs, key=lambda x: x.anomaly)
        # baseline-subtraction: a rule that ALSO fires on the clean environment is
        # provisioning/automation noise, not signal — suppress it. Never suppress
        # >=critical (a real critical that happens to match baseline still surfaces).
        if title in base_titles and not sev.at_least(top.severity, "critical"):
            continue
        chans = sorted({x.attrs.get("channel") for x in evs if x.attrs.get("channel")})
        g.add_finding(Finding(
            id=_fid("sigma", f"{asset_id}:{title}"),
            title=f"SIGMA: {title} on {host}",
            severity=top.severity, confidence="medium",
            summary=f"Hayabusa/SIGMA rule '{title}' matched {len(evs)}× on {host}"
                    f"{(' (' + ', '.join(chans) + ')') if chans else ''}.",
            entity_ids=[e.id for e in evs[:25]], asset_ids=[asset_id],
            sources=top.sources, evidence=list(top.evidence), mitre=[],
            ts=top.first_seen, kind="single"))

    # cloud SIGMA detections (AWS/Azure) -> findings; cross-domain corroboration
    # (same account/IP also on an endpoint) is surfaced automatically via the
    # global account/IOC keys + the cross-host pass.
    for e in g.by_type("event"):
        if not e.attrs.get("cloud_finding"):
            continue
        prov = e.attrs.get("provider", "cloud")
        g.add_finding(Finding(
            id=_fid("cloud", e.id), title=f"{prov.upper()}: {e.attrs.get('rule')}",
            severity=e.severity, confidence="high",
            summary=f"{prov.upper()} detection — {e.attrs.get('rule')}.",
            entity_ids=[e.id], asset_ids=_assets_of(e), sources=e.sources,
            evidence=list(e.evidence), mitre=list(e.attrs.get("mitre") or []),
            ts=e.first_seen, kind="single"))

    # vulnerabilities
    for e in g.by_type("vuln"):
        g.add_finding(Finding(
            id=_fid("vuln", e.id), title=f"Vulnerability {e.label}",
            severity=e.severity, confidence="high",
            summary=f"{e.label} present on {', '.join(_host_label(g, a) for a in _assets_of(e))}"
                    f" (CVSS {e.attrs.get('cvss', '?')}).",
            entity_ids=[e.id], asset_ids=_assets_of(e), sources=e.sources,
            evidence=list(e.evidence), ts=e.first_seen, kind="single"))


# ---------------------------------------------------- coordinated activity
# Tactic buckets — a cheap, robust proxy for ATT&CK tactics when Hayabusa rows
# lack consistent MITRE tags. Keyword match on the SIGMA detection title.
_TACTIC_KW = {
    "execution": ("powershell", "base64", "encoded", "scriptblock", "mshta",
                  "rundll", "wscript", "cscript", "pwsh", "wmi exec"),
    "persistence": ("autorun", "run key", "service install", "scheduled task",
                    "new service", "registry run", "startup"),
    "defense_evasion": ("log file cleared", "eventlog cleared", "insecure level",
                        "disable", "bypass", "policies", "amsi", "etw"),
    "discovery": ("discovery", "recon", "whoami", "net user", "nltest", "dclist",
                  "enumerat", "reconnaissance"),
    "c2_network": ("net conn", "download", "beacon", "webrequest", "remote thread",
                   "dns query", "named pipe"),
    "credential": ("lsass", "mimikatz", "credential", "ntds", "sam dump"),
}
# Tunable by calibrate.sweep — the bar for a coordinated-activity finding AFTER
# baseline-subtraction (so these count only NON-baseline detections).
COORD_MIN_TITLES = 3
COORD_MIN_TACTICS = 2


def _tactics_of(title: str) -> set:
    t = (title or "").lower()
    return {k for k, kws in _TACTIC_KW.items() if any(w in t for w in kws)}


def _coordinated_activity(g: FusionGraph, *, window=None, baseline=None) -> None:
    """Within the operator's INCIDENT window, a burst of diverse medium+ SIGMA
    detections that are NOT in the environment baseline is coordinated activity —
    one high-confidence finding tying the scattered medium signals together.

    Gated on BOTH a window (background outside it is excluded) AND baseline-
    subtraction (provisioning noise removed) — the two levers that make this safe;
    a global volume heuristic could not tell provisioning from attack (measured)."""
    if not window or not (window.get("start") or window.get("end")):
        return
    base_titles = _baseline_sigma_titles(baseline)
    per_asset: dict = {}
    for e in g.by_type("event"):
        if "sigma" not in e.flags or not sev.at_least(e.severity, "medium"):
            continue
        title = e.attrs.get("title") or e.label
        if title in base_titles:                    # baseline noise — not signal
            continue
        if not in_window(e.first_seen, window):
            continue
        for a in _assets_of(e) or ["?"]:
            per_asset.setdefault(a, []).append(e)
    for asset_id, evs in per_asset.items():
        titles = {e.attrs.get("title") or e.label for e in evs}
        tactics = set().union(*[_tactics_of(e.attrs.get("title") or e.label) for e in evs]) \
            if evs else set()
        if len(titles) < COORD_MIN_TITLES or len(tactics) < COORD_MIN_TACTICS:
            continue
        host = _host_label(g, asset_id)
        g.add_finding(Finding(
            id=_fid("coord", asset_id), title=f"Coordinated suspicious activity on {host}",
            severity="high", confidence="high",
            summary=f"{len(titles)} distinct non-baseline SIGMA detections spanning "
                    f"{len(tactics)} ATT&CK tactics ({', '.join(sorted(tactics))}) fired on "
                    f"{host} inside the incident window — a coordinated-activity pattern, not "
                    f"isolated noise. Detections: {', '.join(sorted(titles)[:8])}.",
            entity_ids=[e.id for e in evs[:25]], asset_ids=[asset_id],
            sources=["agentic"], evidence=list(evs[0].evidence),
            mitre=[], ts=min((e.first_seen for e in evs if e.first_seen), default=None),
            kind="derived"))


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
