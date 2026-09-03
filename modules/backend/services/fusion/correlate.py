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
import re

from .schema import FusionGraph, Finding, EvidenceRef
from . import severity as sev
from . import keys


def _fid(*parts) -> str:
    return "f_" + hashlib.sha1("|".join(str(p) for p in parts).encode()).hexdigest()[:12]


def _assets_of(e) -> list[str]:
    return list(dict.fromkeys(e.attrs.get("_assets") or []))


# Structural pivots that are never window/severity-filtered on ingest — they anchor
# the graph and link everything else, so time-judging them would orphan their edges.
_STRUCTURAL_TYPES = {"asset", "account", "ioc", "identity", "config"}


def assemble(case_id: str, contributions, run_ids, *, baseline=None, window=None,
             min_severity="informational", dispositions=None, seed=None) -> FusionGraph:
    """Build the case graph from `contributions`.

    `seed` is an existing graph to add to instead of starting empty — the
    incremental path, used when new data lands and NOTHING about the case's
    filters changed. Adding to it is safe because both merge primitives are
    keyed and idempotent: FusionGraph.upsert merges an entity that is already
    present (union sources/flags, max anomaly, widen first/last seen) and
    relate() dedupes on Relationship.key(), so the derivation passes below can
    run again over the merged graph without duplicating what they created last
    time.

    Findings are the exception and are CLEARED. Every finding here is derived
    from entities further down (mappers return only entities and relationships),
    so keeping the seed's would double them. Re-deriving is also what makes the
    result correct rather than merely cheap: a finding's severity, occurrence
    watermark and cross-host status all depend on the whole graph, and the run
    that just landed is allowed to change them for entities it never touched.

    A caller must NOT pass a seed when the window, severity floor, module
    selection, baseline or dispositions have changed — the stored graph is the
    FILTERED set (see the ingest filter below), so those are global and require a
    rebuild. store._fuse_case_locked decides that.
    """
    g = seed if seed is not None else FusionGraph(case_id=case_id)
    if seed is not None:
        g.findings = []
    for rid in run_ids or []:
        g.note_run(rid)
    # INGEST FILTER (performance + relevance): only fuse non-asset entities that
    # fall inside the case's time window AND meet the severity floor, so the stored
    # graph and ALL downstream processing skip the bulk of low-signal / out-of-window
    # rows instead of building the full graph and filtering only at render time
    # (that was storing ~190 MB and re-parsing it on every API call). Assets (hosts)
    # are always kept so the graph stays anchored. Severity uses the anomaly-derived
    # effective level (matches _rollup_severity) so a high-anomaly row with a low base
    # severity isn't dropped. Trade-off: the graph is now the FILTERED set, so changing
    # the window/severity requires a Refusion (it's no longer a free re-render).
    pending_rels = []
    for ents, rels in contributions:
        for e in ents:
            # Filter ONLY time-stamped rows (the bulk: events / files / hashes) by
            # window + severity. NEVER drop:
            #   - assets (hosts) — the graph's anchors;
            #   - accounts, IOCs, identities, config — structural pivots we can't
            #     time-judge, and the most reusable correlation signal. Dropping
            #     these would silently lose key info (e.g. 36k account + IOC entities
            #     on a real case) AND orphan the events that link to them.
            # The exemption is BY TYPE, not "has no first_seen": a mapper that stamps
            # first_seen on a pivot (e.g. the cloud mapper on AWS accounts/IOCs) must
            # still be exempt, else its accounts/IOCs + all their edges get window-cut.
            if e.type not in _STRUCTURAL_TYPES and e.first_seen:
                eff = sev.max_level(e.severity, sev.from_anomaly(e.anomaly))
                if not (sev.at_least(eff, min_severity) and in_window(e.first_seen, window)):
                    continue
            g.upsert(e)
        pending_rels.extend(rels)
    # Drop edges whose endpoint was filtered out (no dangling relationships).
    for r in pending_rels:
        if r.src in g.entities and r.dst in g.entities:
            g.relate(r)
    _resolve_host_assets(g)
    _bridge_hashes(g)
    _rollup_severity(g)
    _flag_pid_reuse(g)
    _cross_host_findings(g)
    _identity_cross_host_findings(g)
    _derive_findings(g, baseline=baseline, window=window)
    _coordinated_activity(g, window=window, baseline=baseline)
    _recover_mitre_from_text(g)               # after EVERY finding exists
    _corroboration(g)
    _stamp_finding_watermarks(g)              # occurrence watermark — before dispositions
    _apply_dispositions(g, dispositions)      # operator triage — before severity rollup
    _rollup_asset_severity(g)
    _score_assets(g)
    g.findings.sort(key=lambda f: (-sev.rank(f.severity), f.ts or "9999"))
    return g


# A SIGMA/Hayabusa rule name usually CARRIES its technique id -- "Evtx:
# T1562.001-Win Defender Disabled on ALClient022" -- but nothing parsed it, so
# `finding.mitre` was populated only by the handful of hand-written correlation
# rules below. Measured on live cases: 13 of 183 findings mapped on test4 and 12 of
# 152 on test3, which put both under MITRE_MIN_COVERAGE_PCT. The report therefore
# suppressed its ATT&CK matrix as "too sparse" and the phase table printed a column
# of dashes, while the technique ids sat unread in the titles all along. Recovering
# them takes test4 to 60/183 and test3 to 56/152.
_MITRE_RX = re.compile(r"\bT(?:1\d{3}|\d{4})(?:\.\d{3})?\b")


def _recover_mitre_from_text(g: FusionGraph) -> None:
    """Fill in `finding.mitre` from technique ids written into the finding's own text.

    Additive and conservative: a finding that already carries ids is left alone, so a
    curated mapping always wins over a parsed one. Nothing is invented -- an id is
    only ever copied out of text the detection itself produced."""
    for f in g.findings:
        if getattr(f, "mitre", None):
            continue
        blob = " ".join(str(x) for x in (
            getattr(f, "title", "") or "",
            getattr(f, "summary", "") or "",
            getattr(f, "rule", "") or "",
        ))
        # dict.fromkeys: de-duplicate (title AND rule normally both carry the id)
        # while keeping first-seen order, so the list is stable across runs.
        found = list(dict.fromkeys(_MITRE_RX.findall(blob)))
        if found:
            f.mitre = found


def _stamp_finding_watermarks(g: FusionGraph) -> None:
    """Ensure every finding carries an occurrence watermark (occ_count + occ_latest).
    Aggregated findings (sigma/coord) set these at creation; for the rest we derive
    them from the cited entities, so single-entity findings also re-open when their
    entity gains newer activity on a later re-fuse."""
    for f in g.findings:
        if not f.occ_latest:
            latest = f.ts
            for eid in (f.entity_ids or []):
                e = g.entities.get(eid)
                if not e:
                    continue
                for t in (e.last_seen, e.first_seen):
                    if t and (latest is None or t > latest):
                        latest = t
            f.occ_latest = latest
        if not f.occ_count or f.occ_count < 1:
            f.occ_count = max(1, len(f.entity_ids or []))


def _wm_new_activity(stored, current) -> bool:
    """True if `current` watermark shows occurrences BEYOND what `stored` covered —
    more hits OR a later one. That means the verdict snapshotting `stored` is stale
    (new activity arrived since), so the finding should re-open rather than stay
    suppressed. Removal / re-narrowing (fewer, not-later) does NOT count as stale."""
    if not stored:
        return False
    try:
        sc, sl = str(stored).split("|", 1)
        cc, cl = str(current).split("|", 1)
        # F2b: compare the time halves as INSTANTS, not lexicographically — a
        # fractional-second- or format-different newer occurrence must still count
        # as "later" so a stale verdict re-opens. Fall back to string compare.
        try:
            dc, ds = keys.to_utc_dt(cl), keys.to_utc_dt(sl)
            later = (dc > ds) if (dc and ds) else (cl > sl)
        except Exception:
            later = cl > sl
        return int(cc) > int(sc) or later
    except Exception:
        return False


def _apply_dispositions(g: FusionGraph, dispositions) -> None:
    """Operator triage — the human-in-the-loop FP killer. A finding whose id or a cited
    entity is dispositioned `benign` (e.g. 'that PsExec was IT') is down-ranked to
    informational + annotated with the attribution, so it stops driving host risk; never
    silently for >=critical (surfaced anyway for review). `malicious` raises confidence.

    WATERMARK: a benign disposition only suppresses the occurrences it covered. If the
    matched finding now shows new activity beyond the disposition's watermark, the
    verdict is stale — we DON'T suppress (it re-enters risk) and note it re-opened."""
    for d in (dispositions or []):
        if not isinstance(d, dict):
            continue
        target = d.get("target")
        if not target:
            continue
        verdict = (d.get("verdict") or "benign").lower()
        attr = d.get("attribution") or "operator"
        reason = d.get("reason") or ""
        wm = d.get("watermark")
        note = f" [operator: {attr}" + (f" — {reason}" if reason else "") + "]"
        for f in g.findings:
            if f.id != target and target not in (f.entity_ids or []):
                continue
            if verdict == "benign" and wm and _wm_new_activity(wm, f.watermark()):
                # Stale verdict: new activity since it was made → re-open, don't suppress.
                f.summary += " [re-opened: new activity since the prior verdict]"
                continue
            if verdict == "benign":
                if sev.at_least(f.severity, "critical"):
                    f.summary += note + " (≥critical — surfaced anyway for review)"
                else:
                    f.severity = "informational"
                    f.confidence = "low"
                    f.kind = "dispositioned"
                    f.summary += note
            elif verdict == "malicious":
                f.confidence = "high"
                f.summary += f" [operator-confirmed malicious{(' — ' + reason) if reason else ''}]"


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


# Severity-weighted intensity. These only ORDER hosts that share a top tier —
# tier dominance itself is enforced by the 0-100 bands below.
_RISK_W = {"critical": 50, "high": 20, "medium": 5, "low": 2, "informational": 0}

# risk_score is a 0-100 scale split into per-tier BANDS. A host sits in the band
# of its WORST finding (a.severity); its position INSIDE the band is set by
# intensity (severity-weighted, fleet-adjusted finding sum). Bands don't overlap
# (high tops out at 79, critical starts at 80), so accumulation of lower-tier
# findings can NEVER push a host into a higher tier ('critical must never sit
# below high'). REF_INTENSITY = how much intensity 'fills' a band — the knob for
# how fast a host climbs within its own tier.
_BAND_BASE = {"critical": 80, "high": 60, "medium": 40, "low": 20, "informational": 0}
# Critical reaches 100; lower tiers stop 1 point below the next floor so integer
# rounding can never collide two tiers (e.g. a high maxes at 79, never 80).
_BAND_SPAN = {"critical": 20, "high": 19, "medium": 19, "low": 19, "informational": 19}
# Within-band fill reference. We FLOAT it to the fleet's p95 intensity (per tier)
# once an environment is breached enough that the fixed floor would saturate, so
# the worst ~5% peg at 100 and the rest SPREAD instead of a wall of identical
# 100s (the large-heavy-fleet failure mode). Below that the floor keeps a small/
# calm fleet on an absolute scale (a mild worst-host is NOT inflated to 100).
REF_FLOOR = 900.0


def _percentile(values, p: float) -> float:
    """Linear-interpolation percentile (p in [0, 1]); no numpy dependency."""
    s = sorted(values)
    if not s:
        return 0.0
    if len(s) == 1:
        return float(s[0])
    k = (len(s) - 1) * p
    lo = int(k)
    hi = min(lo + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (k - lo)

# Cross-host scoring. Small fleets keep the historical FLAT x2; once a fleet is
# large enough the boost scales by prevalence (k affected / N total) so 2-of-100
# hosts is no longer worth the same as 2-of-3 — 'relative to the environment
# above some amount of machines'. Tune FLEET_RELATIVE_MIN per deployment.
FLEET_RELATIVE_MIN = 12
_CROSS_HOST_FLAT = 2.0


def _cross_host_factor(f, n_hosts: int) -> float:
    if getattr(f, "kind", None) != "cross_host":
        return 1.0
    if n_hosts < FLEET_RELATIVE_MIN:
        return _CROSS_HOST_FLAT                       # flat / absolute for small fleets
    k = len(set(f.asset_ids or []))
    return 1.0 + min(1.0, k / max(n_hosts, 1))        # prevalence-scaled, in (1, 2]


def score_assets_over(assets, findings, n_hosts: int) -> dict:
    """Band-score a set of assets against a GIVEN finding set.

    Extracted so the same formula serves two callers with different scopes:
    _score_assets() scores the whole graph (what the asset entity carries), and
    render.risk_table() scores the WINDOW/SEVERITY-FILTERED findings it is actually
    displaying. The table used to mix the two -- tally and 'Why' were scoped, while
    risk_score and severity were read off the fusion-time entity -- so a host whose
    findings all fell outside the window rendered as 'high, 61' beside '0/0/0 - no
    findings in window'. Same formula, one definition, no drift.

    Returns {asset_id: {"severity", "risk_intensity", "risk_score"}}.
    """
    per_asset = {}
    by_tier: dict[str, list] = {}
    for a in assets:
        afind = [f for f in findings if a.id in f.asset_ids]
        intensity = sum(_RISK_W.get(f.severity, 0) * _cross_host_factor(f, n_hosts)
                        for f in afind)
        # Tier is the worst finding IN SCOPE -- not the entity's all-time severity.
        tier = "informational"
        for f in afind:
            if f.severity in _BAND_BASE and sev.rank(f.severity) > sev.rank(tier):
                tier = f.severity
        per_asset[a.id] = {"severity": tier, "risk_intensity": round(intensity, 2)}
        by_tier.setdefault(tier, []).append(intensity)
    ref = {t: max(REF_FLOOR, _percentile(v, 0.95)) for t, v in by_tier.items()}
    for aid, d in per_asset.items():
        tier = d["severity"]
        frac = min(d["risk_intensity"] / max(ref.get(tier, REF_FLOOR), 1.0), 1.0)
        d["risk_score"] = int(round(_BAND_BASE[tier] + frac * _BAND_SPAN[tier]))
    return per_asset


def _score_assets(g: FusionGraph) -> None:
    """Per-host triage score (0-100) + which modules have data on it — drives
    the Phase-1 'which endpoints to deep-dive' recommendation. The score is
    tier-dominant (see _BAND_BASE) so the ranking never puts a 'critical' host
    below a 'high' one, and cross-host weighting is fleet-relative above
    FLEET_RELATIVE_MIN hosts. A high-risk host seen ONLY by the broad tools
    (velociraptor/cloud), with no memory/timesketch yet, is an escalation
    candidate. Runs after _rollup_asset_severity, so a.severity is the host's
    worst-finding tier (the band floor)."""
    assets = list(g.by_type("asset"))
    n_hosts = len(assets)
    # Pass 1 — raw intensity per host + the per-tier intensity distribution.
    by_tier: dict[str, list] = {}
    for a in assets:
        intensity = 0.0
        for f in g.findings:
            if a.id in f.asset_ids:
                intensity += _RISK_W.get(f.severity, 0) * _cross_host_factor(f, n_hosts)
        a.attrs["risk_intensity"] = round(intensity, 2)   # exact within-band sort tiebreaker
        tier = a.severity if a.severity in _BAND_BASE else "informational"
        by_tier.setdefault(tier, []).append(intensity)
    # Per-tier fill reference: float to the fleet's p95 once it exceeds the floor.
    ref = {t: max(REF_FLOOR, _percentile(v, 0.95)) for t, v in by_tier.items()}
    # Pass 2 — band position + coverage flags.
    for a in assets:
        tier = a.severity if a.severity in _BAND_BASE else "informational"
        frac = min(a.attrs["risk_intensity"] / max(ref.get(tier, REF_FLOOR), 1.0), 1.0)
        a.attrs["risk_score"] = int(round(_BAND_BASE[tier] + frac * _BAND_SPAN[tier]))
        modules = set()
        for e in g.entities.values():
            if a.id in _assets_of(e):
                modules.update(e.sources)
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



def _entity_ts(g: FusionGraph, e) -> "str | None":
    """first_seen for an entity, falling back to the SAME IDENTITY's other records.

    A domain-qualified account (`DOMAIN\\user`) gets a GLOBAL id and often carries no
    timestamp — the artifact that named it (a user/SAM listing) has no event time —
    while the per-host bare-SAM records for the same person DO carry times. The
    cross-host finding was built with `ts=e.first_seen`, so it shipped with
    `ts: null`, and a null ts costs the analysis the two things it most needs:
    sequence and direction. Observed on a real case: "adatumlab\\giladt used across 3
    hosts ... does not prove the initiating endpoint or direction because ts is null",
    while two bare `giladt` records were dated all along.

    So fall back to the earliest time recorded for the same normalized username.
    Best-effort and read-only; returns None when nothing is dated."""
    if e.first_seen:
        return e.first_seen
    try:
        from .identities import _norm_user
        stem = _norm_user(e.label)
        if not stem:
            return None
        times = [o.first_seen for o in g.entities.values()
                 if o.type == e.type and o.first_seen and _norm_user(o.label) == stem]
        return min(times) if times else None
    except Exception:                                   # noqa: BLE001
        return None


def _cross_host_findings(g: FusionGraph) -> None:
    for e in g.entities.values():
        assets = _assets_of(e)
        if len(assets) < 2 or e.type not in ("ioc", "account", "yarahit"):
            continue
        # A pure-context domain/IP (anomaly 0 — e.g. benign cloud telemetry, every
        # host hits microsoft.com) on N hosts is NOT lateral movement; skip it.
        # A shared *hash* is different: the same binary on multiple hosts is a real
        # cross-host signal (shared tooling / lateral tool transfer), so let hashes
        # through regardless of anomaly (severity is graded below).
        if e.type == "ioc" and e.anomaly < 1 and e.attrs.get("ioc_kind") != "hash":
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
            kind = e.attrs.get("ioc_kind")
            if kind == "hash":
                # A SUSPICIOUS shared binary (unsigned/renamed/detection, anomaly>=1)
                # is worth one cross-host finding; a benign shared hash (anomaly 0) is
                # reported ONLY in the IOC appendix (with hosts + the cross_host flag
                # set above) — this kills the dozens of duplicate hash lines that
                # flooded every section. The full hash lives in the appendix; the
                # finding title stays short (no long hash repeated everywhere).
                if e.anomaly < 1:
                    continue
                title = f"Shared binary seen on {len(assets)} hosts"
                summ = (f"A suspicious binary (sha256 {e.label}) is present on multiple "
                        f"assets ({hosts}) — shared tooling / lateral tool transfer.")
                mitre = ["T1570"]
                severity = "high" if e.anomaly >= 20 else "medium"
                g.add_finding(Finding(
                    id=_fid("xhost", e.id), title=title, severity=severity,
                    confidence="high", summary=summ, entity_ids=[e.id], asset_ids=assets,
                    sources=e.sources, evidence=list(e.evidence), mitre=mitre,
                    ts=_entity_ts(g, e), kind="cross_host"))
                continue
            title = f"Indicator {e.label} seen on {len(assets)} hosts"
            summ = (f"The indicator {e.label} ({kind}) appears on multiple "
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
            evidence=list(e.evidence), mitre=mitre, ts=_entity_ts(g, e), kind="cross_host"))


def _identity_cross_host_findings(g: FusionGraph) -> None:
    """An actor whose account is written DIFFERENTLY on each host — `DOMAIN\\user`
    here, `user@domain` there, a bare SAM on a third — produces three SEPARATE account
    entities (a domain-qualified account gets a global id, bare/UPN forms get
    asset-scoped ids), each spanning one host. So `_cross_host_findings` above, which
    keys on ONE entity spanning >=2 assets, never fires and the lateral movement is
    invisible as a finding — even though the Identities view already clusters them into
    one person. Measured: 3 hosts, 1 actor, 0 cross-host findings.

    Derive it from that SAME shipped clustering (identities.resolve_identities, which
    backs the Identities page and honours analyst merges/splits) so the two views of a
    case agree. Fires only when the cluster spans >=2 endpoint hosts AND no single
    account entity in it already spans >=2 (which the rule above would have caught, so
    no duplicate). Best-effort: identity resolution is optional and must never break a
    fuse."""
    try:
        from .identities import resolve_identities
        idents = resolve_identities(g) or []
    except Exception:                                   # noqa: BLE001
        return
    for ident in idents:
        try:
            accts = ident.get("accounts") or []
            hosts = sorted({a.get("ctx") for a in accts if a.get("ctx")})
            ids = [a.get("id") for a in accts if a.get("id") in g.entities]
            if len(accts) < 2 or len(hosts) < 2 or len(ids) < 2:
                continue
            if any(len(_assets_of(g.entities[i])) >= 2 for i in ids):
                continue                                # already covered above
            ents = [g.entities[i] for i in ids]
            # AMBIGUITY GUARD (measured FP): resolve_identities clusters on the
            # username STEM, so `corpa\jsmith` and `corpb\jsmith` — two DIFFERENT
            # people in two domains — land in one cluster. Clustering them on the
            # Identities page is one thing; asserting lateral movement as a
            # high-severity FINDING is another. Emit only when the forms do not
            # carry two DIFFERENT explicit domain roots; a bare SAM or a matching
            # root (corp\u + u@corp.local) stays eligible.
            roots = set()
            for e in ents:
                lbl = str(e.label or "").strip().lower()
                if "\\" in lbl:
                    roots.add(lbl.split("\\", 1)[0].split(".", 1)[0])
                elif "@" in lbl:
                    roots.add(lbl.split("@", 1)[1].split(".", 1)[0])
            if len({r for r in roots if r}) > 1:
                continue                                # ambiguous: possibly two people
            assets = sorted({a for e in ents for a in _assets_of(e)})
            if len(assets) < 2:
                continue
            conf = float(ident.get("confidence") or 0)
            name = str(ident.get("name") or "?")
            forms = ", ".join(sorted({str(e.label) for e in ents}))[:120]
            # SEVERITY IS DERIVED, NOT ASSUMED: roll up the worst severity the
            # clustered accounts actually carry (which _rollup_severity has already
            # reconciled with their anomaly scores). A benign admin legitimately on
            # three hosts stays low/informational and never shouts; an identity whose
            # accounts are themselves suspicious inherits that weight. Hard-coding a
            # level here would assert a risk the evidence has not established.
            worst = max((e.severity for e in ents if e.severity),
                        key=lambda s: sev.rank(s), default="informational")
            g.add_finding(Finding(
                id=_fid("idxhost", str(ident.get("key") or name)),
                title=f"Identity '{name}' active on {len(hosts)} hosts under different "
                      "account forms",
                severity=worst,
                confidence="high" if conf >= 1.0 else "medium",
                summary=(f"One person ({name}) appears as {len(ents)} different account "
                         f"forms ({forms}) across {', '.join(hosts)}. The same identity "
                         "moving between hosts — written differently on each, so it does "
                         "not surface as a single shared account."),
                entity_ids=ids, asset_ids=assets,
                sources=sorted({s for e in ents for s in (e.sources or [])}),
                evidence=[ev for e in ents for ev in (e.evidence or [])][:6],
                mitre=["T1021", "T1078"],
                ts=min((e.first_seen for e in ents if e.first_seen), default=None),
                kind="cross_host"))
        except Exception:                               # noqa: BLE001
            continue


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




def _derive_findings(g: FusionGraph, *, baseline=None, window=None) -> None:
    base_titles = _baseline_sigma_titles(baseline)
    # baseline_fingerprint() also captures known-clean service binary paths,
    # but until now nothing ever read them back — every environment's normal
    # (signed, expected) services with a nonzero anomaly score re-flagged as
    # "suspicious" on every single run instead of being subtracted like the
    # SIGMA-title baseline already is.
    base_service_paths = set((baseline or {}).get("service_paths") or [])
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
            binary_path = (e.attrs.get("binary") or "").lower()
            if binary_path and binary_path in base_service_paths:
                continue        # baseline noise — this exact binary already fired clean
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

    # suspicious / rogue ACCOUNTS on a single host. Cross-host account abuse already
    # surfaces via _cross_host_findings (which stamps 'cross_host'); this catches the
    # single-host case the mapper explicitly flagged 'detection' (e.g. a rogue uid-0
    # backdoor account, anomaly 60) that previously produced NO finding because the
    # generic detection loop only iterates events.
    for e in g.by_type("account"):
        fl = e.flags or []
        if "detection" not in fl or "cross_host" in fl:
            continue
        if not sev.at_least(e.severity, "medium"):
            continue
        asset = _assets_of(e)
        host = _host_label(g, asset[0]) if asset else "?"
        mitre = (["T1548"] if "privilege_escalation" in fl else
                 ["T1136"] if "persistence" in fl else ["T1078"])
        tags = ", ".join(t for t in fl if t not in ("detection", "linux", "windows")) or "suspicious"
        uid = e.attrs.get("uid")
        shell = e.attrs.get("shell")
        detail = (f" — uid {uid}" if uid is not None else "") + (f", shell {shell}" if shell else "")
        g.add_finding(Finding(
            id=_fid("acct", e.id),
            title=f"Suspicious account '{e.label}' on {host}",
            severity=sev.from_anomaly(e.anomaly), confidence="medium",
            summary=f"Account '{e.label}' on {host} flagged ({tags}){detail}.",
            entity_ids=[e.id], asset_ids=asset, sources=e.sources,
            evidence=list(e.evidence), mitre=mitre, ts=e.first_seen, kind="single"))

    # YARA signature hits on a single host. Same gap the account loop above
    # exists for: the generic detection loop only iterates events, and a yarahit
    # is its own entity type, so a flagged hit produced NO finding unless it
    # appeared on 2+ assets via _cross_host_findings. Measured on a live
    # endpoint: 14 webshell hits over three files (b.jsp, tests.jsp, cmd.aspx)
    # under an ATT&CK T1505.003 path landed in the graph and never reached the
    # timeline, because they were all on one host. A webshell on disk is a
    # detection on one machine as much as on five.
    for e in g.by_type("yarahit"):
        fl = e.flags or []
        if "detection" not in fl or "cross_host" in fl:
            continue
        if not sev.at_least(e.severity, "medium"):
            continue
        asset = _assets_of(e)
        host = _host_label(g, asset[0]) if asset else "?"
        path = e.attrs.get("path")
        fname = str(path).replace("\\", "/").rstrip("/").split("/")[-1] if path else None
        # T1505.003 (web shell) when the rule says so, else the generic
        # "malicious file" technique — the rule name is the evidence either way.
        rule_l = str(e.attrs.get("rule") or e.label or "").lower()
        mitre = ["T1505.003"] if "webshell" in rule_l or "web_shell" in rule_l else ["T1204.002"]
        g.add_finding(Finding(
            id=_fid("yara", e.id),
            title=(f"YARA {e.label} matched {fname} on {host}" if fname
                   else f"YARA {e.label} matched on {host}"),
            severity=sev.from_anomaly(e.anomaly), confidence="high",
            summary=(f"Signature '{e.label}' matched "
                     + (f"{path} " if path else "")
                     + f"on {host}."),
            entity_ids=[e.id], asset_ids=asset, sources=e.sources,
            evidence=list(e.evidence), mitre=mitre, ts=e.first_seen, kind="single"))

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
            ts=top.first_seen, kind="single",
            occ_count=len(evs),
            occ_latest=max((e.first_seen for e in evs if e.first_seen), default=top.first_seen)))

    # Generic detection findings: every NON-SIGMA detection event (MFT, named-pipe,
    # binary-rename, web, …) grouped per host + detection name, so each detection
    # artifact kind surfaces in the timeline (with watermark + click-detail) — not
    # only SIGMA. Keyed by the 'detection' flag the mapper stamps; medium+ only
    # (anything lower was already dropped at ingest). SIGMA has its own loop above.
    _det_groups: dict = {}
    for e in g.by_type("event"):
        if "detection" not in e.flags or "sigma" in e.flags:
            continue
        if not sev.at_least(e.severity, "medium"):
            continue
        title = e.attrs.get("title") or e.attrs.get("detection") or e.label
        for a in _assets_of(e) or ["?"]:
            _det_groups.setdefault((a, title), []).append(e)
    for (asset_id, title), evs in _det_groups.items():
        host = _host_label(g, asset_id)
        top = max(evs, key=lambda x: x.anomaly)
        g.add_finding(Finding(
            id=_fid("det", f"{asset_id}:{title}"),
            title=f"{title} on {host}",
            severity=top.severity, confidence="medium",
            summary=f"Detection '{title}' fired {len(evs)}× on {host}.",
            entity_ids=[e.id for e in evs[:25]], asset_ids=[asset_id],
            sources=top.sources, evidence=list(top.evidence), mitre=[],
            ts=top.first_seen, kind="single",
            occ_count=len(evs),
            occ_latest=max((e.first_seen for e in evs if e.first_seen), default=top.first_seen)))

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

    # BASELINE SUBTRACTION (environment-normal): drop any finding whose title also
    # fired on the clean baseline — admin tooling / provisioning noise that is
    # normal for THIS environment — except >=critical (always surfaced for review).
    # The SIGMA loop already subtracts sigma_titles inline; this generalizes that to
    # the generic-detection / account / driver / sideload findings the inline check
    # missed, so a clean box that is its own baseline silences to ~0 and an attack
    # keeps only its non-baseline signal. baseline_fingerprint() already records
    # finding_titles (title without the ' on <host>' suffix).
    base_finding_titles = set((baseline or {}).get("finding_titles") or [])
    if base_finding_titles:
        g.findings = [f for f in g.findings
                      if sev.at_least(f.severity, "critical")
                      or f.title.split(" on ")[0] not in base_finding_titles]


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
        # Fingerprint on the actual composition (titles), not just the host —
        # otherwise an operator dispositioning ONE burst as benign silently
        # mutes every future coordinated-activity finding on that host, even
        # one composed of a completely different set of detections (the
        # watermark re-open check only catches MORE/LATER occurrences, not a
        # differently-composed burst with an equal-or-lower count).
        composition_fp = hashlib.sha1("|".join(sorted(titles)).encode()).hexdigest()[:8]
        g.add_finding(Finding(
            id=_fid("coord", asset_id, composition_fp), title=f"Coordinated suspicious activity on {host}",
            severity="high", confidence="high",
            summary=f"{len(titles)} distinct non-baseline SIGMA detections spanning "
                    f"{len(tactics)} ATT&CK tactics ({', '.join(sorted(tactics))}) fired on "
                    f"{host} inside the incident window — a coordinated-activity pattern, not "
                    f"isolated noise. Detections: {', '.join(sorted(titles)[:8])}.",
            entity_ids=[e.id for e in evs[:25]], asset_ids=[asset_id],
            sources=["agentic"], evidence=list(evs[0].evidence),
            mitre=[], ts=min((e.first_seen for e in evs if e.first_seen), default=None),
            kind="derived",
            occ_count=len(evs),
            occ_latest=max((e.first_seen for e in evs if e.first_seen), default=None)))


# ------------------------------------------------------------------ scope
def in_window(ts, window) -> bool:
    if not window:
        return True
    if not ts:
        return True            # structural (no time) — kept; filtered by link elsewhere
    # Parse both sides to tz-aware UTC and compare as INSTANTS, not raw strings.
    # String compare mixed frames (local-wall-clock picker bounds vs UTC event
    # times) and sorted a trailing 'Z'/fractional-second row above a 19-char bound
    # at the same instant, so freshly-collected in-window rows were dropped.
    t = keys.to_utc_dt(ts)
    if t is None:
        return True            # unparseable — keep, never silently drop
    s_dt = keys.to_utc_dt(window.get("start"))
    e_dt = keys.to_utc_dt(window.get("end"))
    # A degenerate window (start >= end — e.g. start == end from a date picker
    # that defaulted both ends to the same instant) would drop every timestamped
    # row and silently produce an edgeless graph: only the events/files/hashes
    # carry time + edges, so filtering them all out leaves structural pivots
    # (accounts, IOCs) with nothing to connect. Treat it as OPEN instead of
    # nuking the case. (2026-07-26: a real hunt-import case with
    # start==end='2026-05-01T12:00:00' fused to 568 entities / 0 links; the same
    # data with an open window fuses to 18,768 entities / 368 links.)
    if s_dt and e_dt and s_dt >= e_dt:
        return True
    if s_dt and t < s_dt:
        return False
    if e_dt and t > e_dt:
        return False
    return True
