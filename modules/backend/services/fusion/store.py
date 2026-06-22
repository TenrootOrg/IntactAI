"""Case persistence + fuse orchestration.

A Case is just a workflow row (``automation_type='case'``) whose ``details``
hold the window/severity, member run ids, the fused graph, the report, and
chat. Reuses workflow_service entirely — no new table. Member runs are
fetched, dispatched to their module mapper, assembled into one graph by
``correlate.assemble``, then narrated by ``llm_sim`` (simulated).
"""

from __future__ import annotations

import json

from .schema import FusionGraph
from . import correlate, llm_sim, keys, render, budget
from .mappers import map_memory, map_agentic, map_cve, map_timesketch, map_cloud

CASE_TYPE = "case"
BASELINE_TYPE = "fusion_baseline"
DEFAULT_CASE_NAME = "Default"
SYSTEM_CASE_NAME = "System"


def _env_key_from_members(members) -> str | None:
    """Stable environment identity = normalised primary hostname across member runs.
    Baselines are keyed by this so a clean snapshot subtracts from later cases on the
    same box/image."""
    ws = _ws()
    for rid in members or []:
        run = ws.get_automation_run(rid) or {}
        det = run.get("details") or {}
        hostnames = det.get("hostnames")
        host = None
        if isinstance(hostnames, dict) and hostnames:
            host = next(iter(hostnames.values()))
        elif isinstance(hostnames, list) and hostnames:
            host = hostnames[0]
        host = host or det.get("client_name")
        if host:
            return keys.norm_host(str(host))
    return None


def capture_baseline(case_id, *, env_key=None) -> dict:
    """Snapshot a known-CLEAN case's fingerprint as the environment baseline. Stored
    as its own workflow row (automation_type='fusion_baseline') — no new table."""
    ws = _ws()
    d = get_case(case_id)
    members = _members_for_case(case_id, d)
    env_key = env_key or _env_key_from_members(members) or case_id
    g = fuse_case(case_id, _record=False)
    fp = correlate.baseline_fingerprint(g)
    rid = ws.create_automation_run(
        automation_type=BASELINE_TYPE, name=f"Baseline — {env_key}",
        details={"env_key": env_key, "source_case": case_id, "fingerprint": fp})
    ws.update_run_status(rid, "completed", details={"env_key": env_key,
                         "source_case": case_id, "fingerprint": fp})
    return fp


def set_disposition(case_id, target, *, verdict="benign", attribution="it_admin",
                    reason="", scope="case", by="operator") -> dict:
    """Record an operator triage on a finding/entity ('that PsExec was IT'), re-fuse so it
    takes effect, and — when scope='environment' — fold it into the env baseline so it
    suppresses across FUTURE cases too. Returns the disposition."""
    ws = _ws()
    d = get_case(case_id)
    disp = {"target": target, "verdict": verdict, "attribution": attribution,
            "reason": reason, "scope": scope, "by": by}
    existing = [x for x in (d.get("dispositions") or []) if x.get("target") != target]
    ws.update_run_status(case_id, "pending", details={"dispositions": existing + [disp]})
    if scope == "environment" and verdict == "benign":
        _promote_disposition_to_baseline(case_id, target)
    fuse_case(case_id)
    return disp


def clear_disposition(case_id, target) -> dict:
    """Reverse an operator triage on a target (un-suppress) and re-fuse so a
    finding marked not-real / known-IT comes back to its real severity. The
    counterpart to set_disposition — makes validation reversible."""
    ws = _ws()
    d = get_case(case_id)
    remaining = [x for x in (d.get("dispositions") or []) if x.get("target") != target]
    ws.update_run_status(case_id, "pending", details={"dispositions": remaining})
    fuse_case(case_id)
    return {"target": target, "cleared": True}


def _promote_disposition_to_baseline(case_id, target) -> None:
    """Fold a dispositioned finding's SIGMA title into the environment baseline fingerprint
    so future cases on the same host subtract it (reuses the baseline mechanism)."""
    g = fuse_case(case_id, _record=False)
    titles = {f.title.split(" on ")[0] for f in g.findings
              if f.id == target or target in (f.entity_ids or [])}
    if not titles:
        return
    members = (get_case(case_id).get("member_run_ids") or [])
    env = _env_key_from_members(members)
    fp = load_baseline(env) or {"sigma_titles": [], "finding_titles": [], "service_paths": []}
    fp["finding_titles"] = sorted(set(fp.get("finding_titles") or []) | titles)
    fp["sigma_titles"] = sorted(set(fp.get("sigma_titles") or [])
                                | {t.replace("SIGMA: ", "") for t in titles})
    ws = _ws()
    rid = ws.create_automation_run(automation_type=BASELINE_TYPE,
                                   name=f"Baseline — {env}",
                                   details={"env_key": env, "source_case": case_id,
                                            "fingerprint": fp, "from_disposition": True})
    ws.update_run_status(rid, "completed", details={"env_key": env, "source_case": case_id,
                                                    "fingerprint": fp, "from_disposition": True})


def load_baseline(env_key) -> dict | None:
    """Most recent baseline fingerprint for an environment, or None."""
    if not env_key:
        return None
    ws = _ws()
    try:
        runs = [r for r in (ws.get_all_automation_runs() or [])
                if r.get("automation_type") == BASELINE_TYPE
                and (r.get("details") or {}).get("env_key") == env_key]
    except Exception:
        return None
    if not runs:
        return None
    runs.sort(key=lambda r: r.get("created_at") or r.get("updated_at") or "", reverse=True)
    return (runs[0].get("details") or {}).get("fingerprint")


def _raw_payload_size(run) -> int:
    """Approx tokens a NORMAL (non-fusion) LLM run would feed for this run — the
    raw module rows. Best-effort; used only for the fusion-vs-raw A/B headline."""
    det = run.get("details") or {}
    blob = (det.get("collected_data") or det.get("plugins") or det.get("events")
            or det.get("timeline_events") or det.get("findings") or det.get("sigma_findings"))
    if not blob and run.get("automation_type") in ("agentic", "velociraptor_upload"):
        # Agentic / offline-import runs persist their rows to disk
        # (/data/downloads/<rid>/raw_results.json), not into details — read them
        # back so the raw-vs-fusion token A/B reflects the real input size.
        blob = _agentic_collected_data(run.get("run_id"), det) or None
    return budget.approx_tokens(blob) if blob else 0


def _ws():
    from services import workflow_service as ws
    return ws


def create_case(name, *, time_window=None, initial_access=None,
                min_severity="medium", member_run_ids=None, is_default=False,
                is_system=False) -> str:
    # The case row is itself a workflow row but is NEVER case-scoped — pass
    # case_id=None explicitly so the request's active case doesn't tag it.
    return _ws().create_automation_run(
        automation_type=CASE_TYPE, name=f"Case — {name}", case_id=None,
        details={"name": name, "time_window": time_window or {},
                 "initial_access_estimate": initial_access, "min_severity": min_severity,
                 "member_run_ids": list(member_run_ids or []),
                 "is_default": bool(is_default), "is_system": bool(is_system),
                 "fusion_graph": {}, "report_md": "", "chat_messages": []})


def get_case(case_id) -> dict:
    return (_ws().get_automation_run(case_id) or {}).get("details") or {}


def _members_for_case(case_id, d=None) -> list:
    """A case's members = every analysis run TAGGED to it (the workspace model),
    unioned with any legacy explicit member_run_ids for back-compat."""
    ws = _ws()
    tagged = [r.get("run_id") for r in ws.get_automation_runs_by_case(case_id)
              if r.get("automation_type") in ws.AGENTIC_TYPES]
    if d is None:
        d = get_case(case_id)
    seen = set(tagged)
    legacy = [r for r in (d.get("member_run_ids") or []) if r not in seen]
    return tagged + legacy


def attach_runs(case_id, run_ids) -> list:
    """Legacy explicit attach (kept for back-compat / the API). In the workspace
    model runs auto-belong via their case_id tag; this also stamps the tag so a
    manually-attached run shows up under the case everywhere."""
    from services.file_storage_service import get_workflow
    d = get_case(case_id)
    members = list(dict.fromkeys((d.get("member_run_ids") or []) + list(run_ids)))
    _ws().update_run_status(case_id, "pending", details={"member_run_ids": members})
    for rid in run_ids:                       # tag the run into this workspace too
        run = get_workflow(rid)
        if run and not run.get("case_id"):
            run["case_id"] = case_id
            from services.file_storage_service import save_workflow
            save_workflow(run)
    return members


EXPORT_KIND = "intact_case_export"
EXPORT_SCHEMA = 1


def export_case(case_id) -> dict | None:
    """Build a self-contained, importable bundle for one case (workspace):
    the case record (its details cache the fused graph + report + config +
    dispositions) plus every member run's full record (the fusion inputs). A
    later import recreates the case verbatim and can re-fuse from the runs."""
    ws = _ws()
    case_run = ws.get_automation_run(case_id)
    if not case_run or case_run.get("automation_type") != CASE_TYPE:
        return None
    member_ids = _members_for_case(case_id)
    runs = [r for r in (ws.get_automation_run(rid) for rid in member_ids) if r]
    det = case_run.get("details") or {}
    return {
        "kind": EXPORT_KIND,
        "schema": EXPORT_SCHEMA,
        "name": det.get("name") or case_run.get("name") or "case",
        "case": case_run,
        "runs": runs,
    }


def import_case(bundle: dict, *, name: str | None = None) -> dict:
    """Recreate a case from an export bundle. Creates a FRESH case container and
    re-tags the bundled member runs into it (run ids are preserved so the cached
    graph/findings, which reference run ids, stay consistent — intended for
    moving a case to another install). Returns {case_id, name, runs_imported}."""
    if not isinstance(bundle, dict) or bundle.get("kind") != EXPORT_KIND:
        raise ValueError("not an Intact case export bundle")
    src_case = bundle.get("case") or {}
    src_runs = bundle.get("runs") or []
    src_det = src_case.get("details") or {}
    disp_name = (name or src_det.get("name") or src_case.get("name") or "Imported case").strip()

    ws = _ws()
    from services.file_storage_service import save_workflow

    # Fresh case container (never inherits default/system status from the source).
    new_case_id = ws.create_automation_run(
        automation_type=CASE_TYPE, name=f"Case — {disp_name}", case_id=None, details={},
    )

    # Upsert each member run, preserving its id + payload, re-tagged to the new case.
    member_ids = []
    for r in src_runs:
        rid = (r or {}).get("run_id")
        if not rid:
            continue
        rec = dict(r)
        rec["case_id"] = new_case_id
        save_workflow(rec)
        member_ids.append(rid)

    # New case details = the source case's cached state, re-pointed + de-privileged.
    new_det = dict(src_det)
    new_det["name"] = disp_name
    new_det["member_run_ids"] = member_ids
    new_det.pop("is_default", None)
    new_det.pop("is_system", None)
    ws.update_run_status(new_case_id, src_case.get("status") or "completed", details=new_det)

    return {"case_id": new_case_id, "name": disp_name, "runs_imported": len(member_ids)}


def ensure_default_case() -> str:
    """Return the id of the Default workspace, creating it if missing. Idempotent —
    safe to call on every startup."""
    ws = _ws()
    for r in ws.get_all_automation_runs() or []:
        if r.get("automation_type") != CASE_TYPE:
            continue
        det = r.get("details") or {}
        if det.get("is_default") or det.get("name") == DEFAULT_CASE_NAME:
            return r.get("run_id")
    return create_case(DEFAULT_CASE_NAME, is_default=True)


def ensure_system_case() -> str:
    """Return the id of the System workspace (where Settings-page/system runs live),
    creating it if missing. Idempotent — safe to call on every startup."""
    ws = _ws()
    for r in ws.get_all_automation_runs() or []:
        if r.get("automation_type") != CASE_TYPE:
            continue
        det = r.get("details") or {}
        if det.get("is_system") or det.get("name") == SYSTEM_CASE_NAME:
            return r.get("run_id")
    return create_case(SYSTEM_CASE_NAME, is_system=True)


def is_default_case(case_id) -> bool:
    d = get_case(case_id)
    return bool(d.get("is_default") or d.get("name") == DEFAULT_CASE_NAME)


def is_system_case(case_id) -> bool:
    d = get_case(case_id)
    return bool(d.get("is_system") or d.get("name") == SYSTEM_CASE_NAME)


def delete_case(case_id) -> dict:
    """Delete a workspace and EVERYTHING in it: every tagged run, the baseline this
    case captured, and the case row. Refuses to delete the Default/System workspaces."""
    from services.file_storage_service import delete_workflow
    ws = _ws()
    d = get_case(case_id)
    if not d:
        return {"deleted": False, "error": "not found"}
    if d.get("is_default") or d.get("name") == DEFAULT_CASE_NAME:
        return {"deleted": False, "error": "default workspace cannot be deleted"}
    if d.get("is_system") or d.get("name") == SYSTEM_CASE_NAME:
        return {"deleted": False, "error": "system workspace cannot be deleted"}
    run_ids = [r.get("run_id") for r in ws.get_automation_runs_by_case(case_id)]
    for rid in run_ids:
        delete_workflow(rid)
    # baselines this case captured (match by source_case only — never touch a
    # baseline another workspace may rely on)
    removed_baselines = 0
    for r in ws.get_all_automation_runs() or []:
        if r.get("automation_type") != BASELINE_TYPE:
            continue
        if (r.get("details") or {}).get("source_case") == case_id:
            delete_workflow(r.get("run_id"))
            removed_baselines += 1
    delete_workflow(case_id)
    return {"deleted": True, "runs_deleted": len(run_ids),
            "baselines_deleted": removed_baselines}


def _memory_contribution(rid, det):
    asset = keys.asset_id(det.get("client_id") or rid)
    host = det.get("client_name")
    from services.memory.volweb_client import VolWebClient
    from services.memory.analyzers import _build_plugin_payload, _build_yara_payload
    client = VolWebClient()
    evid = det.get("evidence_id")
    plugins, _w = _build_plugin_payload(client, evid)
    try:                                  # yara is optional — never lose plugins over it
        hits, _t = _build_yara_payload(client, evid)
    except Exception:
        hits = []
    return map_memory({"plugins": plugins, "yara": hits, "host": host},
                      run_id=rid, asset=asset, hostname=host)


def _cve_contribution(rid, det):
    import json
    import os
    for base in (f"/app/data/downloads/{rid}", f"/data/downloads/{rid}",
                 det.get("output_dir") or ""):
        fp = os.path.join(base, "findings.json") if base else ""
        if fp and os.path.exists(fp):
            with open(fp) as f:
                return map_cve(json.load(f), run_id=rid)
    return [], []


def _agentic_collected_data(rid, det):
    """The real agentic pipeline persists rows to /data/downloads/<rid>/raw_results.json
    (not into details, to avoid bloating the SQLite blob). Prefer details.collected_data
    (test/legacy runs), else read the file. This is what makes a REAL agentic run fuseable."""
    cd = det.get("collected_data")
    if cd:
        return cd
    import json
    import os
    for base in (f"/app/data/downloads/{rid}", f"/data/downloads/{rid}",
                 det.get("output_dir") or ""):
        fp = os.path.join(base, "raw_results.json") if base else ""
        if fp and os.path.exists(fp):
            try:
                with open(fp) as f:
                    return json.load(f)
            except Exception:
                return {}
    return {}


def _relabel_source(ents, rels, frm, to):
    """Rewrite a module/source label on a contribution in place. Used so an
    offline-collector import (mapped by map_agentic for code reuse) is attributed
    to "velociraptor", not "agentic" — no agent ran, it's imported artifacts."""
    def fix(seq):
        if seq:
            for i, s in enumerate(seq):
                if s == frm:
                    seq[i] = to
    for e in ents or []:
        fix(getattr(e, "sources", None))
        for ev in (getattr(e, "evidence", None) or []):
            if getattr(ev, "module", None) == frm:
                ev.module = to
    for r in rels or []:
        fix(getattr(r, "sources", None))


def _contribution_for_run(run, log=None):
    atype, rid = run.get("automation_type"), run.get("run_id")
    det = run.get("details") or {}
    try:
        if atype == "memory":
            return _memory_contribution(rid, det)
        # "agentic" = a live/collect agentic run; "velociraptor_upload" = an
        # offline-collector import fused into its own upload row (one workflow
        # row, not two). Both persist rows the same way and fuse via the same
        # mapper — but the offline import ran NO agent, so relabel its source
        # "agentic" -> "velociraptor" (the data is just imported Velociraptor
        # artifacts) so the report doesn't read as if an agent had run.
        if atype in ("agentic", "velociraptor_upload"):
            ents, rels = map_agentic(_agentic_collected_data(rid, det), run_id=rid,
                                     hostnames=det.get("hostnames") or {})
            if atype == "velociraptor_upload":
                _relabel_source(ents, rels, "agentic", "velociraptor")
            return ents, rels
        if atype == "cve_scan":
            return _cve_contribution(rid, det)
        if atype == "timesketch":
            evs = det.get("events") or det.get("timeline_events")
            if evs:
                asset = keys.asset_id(det.get("client_id") or rid)
                return map_timesketch(evs, run_id=rid, asset=asset,
                                      hostname=det.get("client_name"))
        if atype in ("aws_scan", "azure_scan"):
            prov = "aws" if atype == "aws_scan" else "azure"
            finds = det.get("findings") or det.get("sigma_findings")
            if not finds:
                fb = det.get("findings_by_severity")
                if isinstance(fb, dict):
                    finds = [x for v in fb.values() for x in (v or [])]
            if finds:
                return map_cloud(finds, run_id=rid, provider=prov,
                                 account=det.get("account") or det.get("account_id")
                                 or det.get("tenant_id"))
    except Exception as e:  # never let one run break the fuse
        if log:
            log(f"fuse: run {rid} ({atype}) skipped: {e}", "warning")
    return [], []


def fuse_case(case_id, *, contributions_override=None, log=None, _record=True) -> FusionGraph:
    ws = _ws()
    d = get_case(case_id)
    members = _members_for_case(case_id, d)
    # include/exclude: scope the fusion to a chosen subset of the case's runs (None = all)
    inc = d.get("included_run_ids")
    if inc is not None:
        members = [m for m in members if m in set(inc)]
    if contributions_override is not None:
        contributions = contributions_override
    else:
        contributions = []
        for rid in members:
            run = ws.get_automation_run(rid)
            if run:
                contributions.append(_contribution_for_run(run, log=log))
    window = d.get("time_window") or None
    min_sev = d.get("min_severity", "informational")
    # subtract the environment baseline (if one was captured) so provisioning /
    # automation noise doesn't read as attack signal.
    baseline = None if d.get("is_baseline") else load_baseline(_env_key_from_members(members))
    g = correlate.assemble(case_id, contributions, members, baseline=baseline, window=window,
                           dispositions=d.get("dispositions") or None)
    if not _record:
        return g
    # cross-case KB: enrich with prior sightings, then index this case (best-effort,
    # degrades silently when ES is down — never a dependency).
    try:
        from . import kb
        kb.enrich(g, current_case_id=case_id)
        kb.index_case_entities(case_id, g)
    except Exception:
        pass
    # masking (customer-facing): anonymize host/user/ip in the report + LLM payload
    mask = None
    mk = d.get("masking") or {}
    if mk.get("enabled"):
        try:
            from services.data_anonymizer import DataAnonymizer
            mask = DataAnonymizer(custom_patterns=mk.get("patterns") or [])
        except Exception:
            mask = None
    # host-exclusion: cut excluded hosts' data from the report/LLM (token saving). The
    # FULL graph `g` is still stored so the picker can list/re-include every host.
    gv = _filter_graph_by_hosts(g, d.get("excluded_hosts"))
    report = llm_sim.generate_report(
        gv, window=window, min_severity=min_sev,
        initial_access=d.get("initial_access_estimate"),
        case_name=d.get("name", "Case"), run_id=case_id,
        audience=d.get("audience", "both"), language=d.get("language", "en"),
        master_prompt=d.get("master_prompt"), mask=mask)
    # ADVISORY analyst pass — incident-grouping + grounded hypotheses. Stored SEPARATELY
    # from the deterministic findings (never conflated); fed prior operator dispositions.
    analysis = llm_sim.analyze(gv, window=window, min_severity=min_sev, run_id=case_id,
                               dispositions=d.get("dispositions") or None)
    # customer-confirmation checklist — generate once (preserve operator decisions on re-fuse)
    checklist = d.get("disposition_checklist")
    if not checklist:
        try:
            checklist = llm_sim.generate_disposition_checklist(
                gv, window=window, min_severity=min_sev, run_id=case_id)
        except Exception:
            checklist = []

    # Token A/B: raw rows a normal run would feed vs the distilled payload the LLM
    # actually sees. raw_approx is necessarily an estimate (we never send raw), so
    # it's labelled _approx; real model tokens land on llm_metrics via call_llm.
    try:
        raw_approx = 0
        for rid in members:
            run = ws.get_automation_run(rid)
            if run:
                raw_approx += _raw_payload_size(run)
        distilled = render.distilled(g, window=window, min_severity=min_sev,
                                     max_entities=budget.REPORT_MAX_ENTITIES,
                                     budget_chars=budget.REPORT_BUDGET_CHARS)
        fusion_approx = budget.approx_tokens(json.dumps(distilled))
        token_ab = {"raw_approx": raw_approx, "fusion_approx": fusion_approx,
                    "reduction_ratio": round(raw_approx / max(fusion_approx, 1), 1)}
    except Exception:
        token_ab = {}

    ws.update_run_status(case_id, "completed",
                         details={"fusion_graph": g.pruned().to_dict(), "report_md": report,
                                  "token_ab": token_ab, "analysis": analysis,
                                  "disposition_checklist": checklist})
    log_case_event(case_id, "Fuse", "ok",
                   f"rebuilt case graph — {len(g.entities):,} entities, "
                   f"{len(g.relationships):,} links, {len(g.findings):,} findings "
                   f"across {len(members)} run(s)")
    return g


def watch_and_fuse(case_id, run_id, *, poll=10, timeout=10800) -> None:
    """Background: wait until a member run reaches a terminal state, then
    re-fuse the whole case. Makes a Case a living workspace — attach an
    in-flight run and the graph/report refresh themselves when it lands."""
    import time
    ws = _ws()
    start = time.time()
    while time.time() - start < timeout:
        r = ws.get_automation_run(run_id) or {}
        if (r.get("status") or "") in ("completed", "failed", "cancelled"):
            break
        time.sleep(poll)
    try:
        fuse_case(case_id)
    except Exception:
        pass


def load_graph(case_id) -> FusionGraph:
    d = get_case(case_id)
    return FusionGraph.from_dict(d.get("fusion_graph") or {"case_id": case_id})


def _filter_graph_by_hosts(g, excluded_labels) -> FusionGraph:
    """Return a view of the graph with the named hosts excluded — their asset nodes,
    the entities/findings that live ONLY on them, and now-dangling relationships are
    dropped. Cuts excluded-host data from the report/LLM (token saving) while the stored
    graph keeps every host for the picker. No-op when nothing is excluded."""
    excluded = {keys.norm_host(h) for h in (excluded_labels or []) if h}
    if not excluded:
        return g
    ex_assets = set()
    for a in g.by_type("asset"):
        if keys.norm_host(a.attrs.get("hostname") or "") in excluded \
                or keys.norm_host(a.label or "") in excluded:
            ex_assets.add(a.id)
    if not ex_assets:
        return g
    gv = FusionGraph(case_id=g.case_id, run_ids=list(g.run_ids))
    keep = set()
    for e in g.entities.values():
        if e.id in ex_assets:
            continue
        al = e.attrs.get("_assets")
        if al and set(al) <= ex_assets:        # belongs only to excluded hosts
            continue
        gv.entities[e.id] = e
        keep.add(e.id)
    for f in g.findings:
        aid = set(f.asset_ids or [])
        if aid and aid <= ex_assets:           # finding only on excluded hosts
            continue
        gv.findings.append(f)
    for r in g.relationships:
        if r.src in keep and r.dst in keep:
            gv.relationships.append(r)
    gv.rebuild_indexes()
    return gv


def _merge_case_details(case_id, patch) -> None:
    """Merge a patch into the case details without disturbing its status."""
    ws = _ws()
    cur = (ws.get_automation_run(case_id) or {}).get("status") or "completed"
    ws.update_run_status(case_id, cur, details=patch)


def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


# ---- Case Analysis activity log (audit trail — the case has no workflow row) ----
_CASE_LOG_CAP = 500


def log_case_event(case_id, action, status="ok", detail="", **meta) -> None:
    """Append an entry to the case's activity log. Best-effort + bounded: logging
    must NEVER raise into (or break) the action it records. Captures both the
    action and its outcome (ok/error) so the Log tab can follow everything that
    happens inside Case Analysis."""
    try:
        if not get_case(case_id):
            return                       # not a real case (e.g. 'quick', calibration ids)
        entry = {"ts": _now_iso() + "Z", "action": str(action)[:120],
                 "status": "error" if status == "error" else "ok",
                 "detail": str(detail)[:500]}
        for k, v in (meta or {}).items():
            entry[k] = v

        def _append(details):            # atomic read-append-write under the run lock
            log = list(details.get("activity_log") or [])
            log.append(entry)
            details["activity_log"] = log[-_CASE_LOG_CAP:] if len(log) > _CASE_LOG_CAP else log

        _ws().mutate_run_details(case_id, _append)
    except Exception as e:  # noqa: BLE001 — telemetry only
        print(f"[CASE-LOG] failed to record '{action}' for {case_id}: {e}", flush=True)


def graph_counts(case_id) -> dict:
    """Lightweight stat-bar counts from the STORED (pruned) graph — no re-fuse and
    no multi-MB payload to the browser. Lets Case Analysis show hosts/entities/
    links/findings/cross-host without downloading the whole graph."""
    fg = (get_case(case_id) or {}).get("fusion_graph") or {}
    ents = fg.get("entities") or {}
    findings = fg.get("findings") or []
    return {"hosts": sum(1 for e in ents.values() if (e or {}).get("type") == "asset"),
            "entities": len(ents),
            "links": len(fg.get("relationships") or []),
            "findings": len(findings),
            "cross_host": sum(1 for f in findings if (f or {}).get("kind") == "cross_host")}


def get_case_log(case_id) -> list:
    return list((get_case(case_id) or {}).get("activity_log") or [])


def clear_case_log(case_id) -> dict:
    _merge_case_details(case_id, {"activity_log": []})
    return {"cleared": True}


# ---- engagement-grade reporting on the case (branding + audience + steering) ----

_CASE_SYNTH_SYSTEM = (
    "You are condensing a DFIR analyst's chat about an incident case into a short "
    "briefing that the next report regeneration will read verbatim as ground truth. "
    "Write flowing prose — a few short paragraphs, no bullets, no headings, no IDs. "
    "Capture: which activity turned out to be legitimate/benign and why, what the "
    "operator wants removed or de-emphasised, what to focus on, and environment "
    "context that should colour the next pass (host ownership, what's normal here)."
)


def set_branding(case_id, *, customer_name=None, customer_logo_b64=None, tlp=None,
                 audience=None, language=None) -> dict:
    """Persist report branding/options on the case (logo, customer, TLP, audience)."""
    patch = {}
    for k, v in (("customer_name", customer_name), ("customer_logo_b64", customer_logo_b64),
                 ("tlp", tlp), ("audience", audience), ("language", language)):
        if v is not None:
            patch[k] = v
    if patch:
        _merge_case_details(case_id, patch)
    return {k: ("<logo>" if k == "customer_logo_b64" else v) for k, v in patch.items()}


def set_master_prompt(case_id, text) -> None:
    """Hand-set the operator steering brief (works without an LLM)."""
    _merge_case_details(case_id, {"master_prompt": (text or "").strip()})


def synthesize_master_prompt(case_id) -> str:
    """Compress the case chat into a master-prompt brief (needs a real LLM). Stores +
    returns it. Raises on no-chat / LLM failure (route surfaces the error)."""
    d = get_case(case_id)
    msgs = d.get("chat_messages") or []
    if not msgs:
        raise ValueError("no chat history to synthesise — chat about the case first")
    from services.agentic.analyzers import call_llm
    from services.memory.pipeline import _llm_config_from_runtime
    transcript = json.dumps(msgs, indent=2, default=str)
    user = (f"Chat transcript:\n```json\n{transcript[:80000]}\n```\n\n"
            "Write the briefing as described — flowing prose, no bullets/headings.")
    master = call_llm(user, _CASE_SYNTH_SYSTEM, _llm_config_from_runtime(), run_id=case_id)
    master = (master or "").strip()
    if not master:
        raise RuntimeError("synthesis returned empty")
    _merge_case_details(case_id, {"master_prompt": master})
    return master


def regenerate_report(case_id, *, audience=None) -> dict:
    """Re-narrate report + advisory from the STORED graph (no re-collect/re-fuse),
    applying the case's audience + master_prompt. Cheap interactive regeneration."""
    if audience:
        set_branding(case_id, audience=audience)
    d = get_case(case_id)
    g = load_graph(case_id)
    window = d.get("time_window") or None
    min_sev = d.get("min_severity", "informational")
    report = llm_sim.generate_report(
        g, window=window, min_severity=min_sev,
        initial_access=d.get("initial_access_estimate"), case_name=d.get("name", "Case"),
        run_id=case_id, audience=d.get("audience", "both"), language=d.get("language", "en"),
        master_prompt=d.get("master_prompt"))
    analysis = llm_sim.analyze(g, window=window, min_severity=min_sev, run_id=case_id,
                               dispositions=d.get("dispositions") or None)
    _merge_case_details(case_id, {"report_md": report, "analysis": analysis})
    return {"report_md": report, "audience": d.get("audience", "both")}


def engagement_markdown(case_id) -> str:
    """Branded full report markdown (engagement-style cover + report body) for MD/PDF
    download. Reuses the engagement cover_block so the shared PDF renderer parses it."""
    from datetime import datetime, timezone
    from services.engagement.templates import cover_block
    d = get_case(case_id)
    ws = _ws()
    sources = []
    for rid in _members_for_case(case_id, d):
        r = ws.get_automation_run(rid) or {}
        sources.append({"run_id": rid, "name": r.get("name") or rid, "section": "",
                        "automation_type": r.get("automation_type")})
    cover = cover_block(d.get("name", "Case"),
                        datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
                        sources, tlp=d.get("tlp", "AMBER"), version=1,
                        customer_name=d.get("customer_name", ""))
    body = d.get("report_md") or "_No report yet — fuse the case first._"
    return f"{cover}\n\n{body}"


# ---- Case Analysis console: config + rescan + checklist + timeline validation ----

def set_analysis_config(case_id, cfg) -> dict:
    """Persist the analysis variables from the config rail (time window, severity,
    masking, included runs, audience/branding/language). Only provided keys change."""
    patch = {}
    if "time_window" in cfg:
        tw = cfg.get("time_window") or {}
        patch["time_window"] = {"start": tw.get("start"), "end": tw.get("end")}
    for k in ("min_severity", "audience", "language", "tlp", "customer_name",
              "customer_logo_b64", "master_prompt"):
        if cfg.get(k) is not None:
            patch[k] = cfg[k]
    if "masking" in cfg:
        mk = cfg.get("masking") or {}
        patch["masking"] = {"enabled": bool(mk.get("enabled")),
                            "patterns": [p for p in (mk.get("patterns") or []) if p]}
    if "included_run_ids" in cfg:          # None = all; list = subset (legacy)
        patch["included_run_ids"] = cfg["included_run_ids"]
    if "excluded_hosts" in cfg:            # host labels to drop from the report/LLM
        patch["excluded_hosts"] = [h for h in (cfg.get("excluded_hosts") or []) if h]
    if patch:
        _merge_case_details(case_id, patch)
    return {k: ("<logo>" if k == "customer_logo_b64" else v) for k, v in patch.items()}


def rescan(case_id, cfg=None) -> dict:
    """THE config-driven action: persist the rail's variables then re-correlate +
    regenerate. Replaces the bare re-fuse for the UI."""
    if cfg:
        set_analysis_config(case_id, cfg)
    g = fuse_case(case_id)
    return {"entities": len(g.entities), "relationships": len(g.relationships),
            "findings": len(g.findings),
            "cross_host_findings": sum(1 for f in g.findings if f.kind == "cross_host")}


def case_members(case_id) -> list:
    """Runs tagged to the case + their host + whether they're currently included — feeds
    the include/exclude picker in the config rail."""
    ws = _ws()
    d = get_case(case_id)
    inc = d.get("included_run_ids")
    inc_set = set(inc) if inc is not None else None
    # best-effort OS per host, reusing the velociraptor snapshot (host/client_id -> os)
    os_by = {}
    try:
        from services.velociraptor_service import get_clients_from_snapshot
        for c in (get_clients_from_snapshot(include_offline=True) or []):
            o = (c.get("os") or "").lower() or "unknown"
            if c.get("hostname"):
                os_by[str(c["hostname"]).lower()] = o
            if c.get("client_id"):
                os_by[str(c["client_id"]).lower()] = o
    except Exception:
        pass
    out = []
    for rid in _members_for_case(case_id, d):
        r = ws.get_automation_run(rid) or {}
        det = r.get("details") or {}
        host = det.get("client_name") or det.get("account") or det.get("account_id") \
            or det.get("tenant_id") or det.get("subscription_id")
        if not host:
            hn = det.get("hostnames")
            if isinstance(hn, dict):
                host = ", ".join(str(v) for v in hn.values()) or None
            elif isinstance(hn, list):
                host = ", ".join(str(v) for v in hn) or None
        # last resort: the run's human name (e.g. "AWS Scan: …") — never the raw run_id,
        # which read as "run names not hosts". Cloud scans with no account land here.
        # host-scoped = a single endpoint (agentic/memory/timesketch on a client). Hunts,
        # CVE sweeps, engagement reports and cloud scans are NOT a single host.
        host_scoped = bool(det.get("client_name") or det.get("hostnames"))
        host = host or r.get("name") or rid
        atype = r.get("automation_type")
        if atype in ("aws_scan", "azure_scan"):
            os_name = "aws" if atype == "aws_scan" else "azure"
        elif host_scoped:
            cid = det.get("client_id")
            os_name = os_by.get(str(host).lower()) \
                or (os_by.get(str(cid).lower()) if cid else None) or "unknown"
        else:
            os_name = "unknown"
        out.append({"run_id": rid, "type": atype, "host": host, "os": os_name,
                    "host_scoped": host_scoped, "status": r.get("status"),
                    "included": (inc_set is None) or (rid in inc_set)})
    return out


def decide_checklist_item(case_id, item_id, decision) -> dict:
    """Customer confirms a checklist item. accept => the finding is benign (dispositioned
    + re-fused, suppressed); decline => kept as a real finding."""
    d = get_case(case_id)
    items = d.get("disposition_checklist") or []
    item = next((x for x in items if x.get("id") == item_id), None)
    if not item:
        return {"error": "checklist item not found"}
    decision = "accept" if decision == "accept" else "decline"
    item["status"] = "accepted" if decision == "accept" else "declined"
    _merge_case_details(case_id, {"disposition_checklist": items})
    if decision == "accept" and item.get("finding_id"):
        # benign confirmation -> disposition + re-fuse (this re-persists the checklist too)
        set_disposition(case_id, item["finding_id"], verdict="benign",
                        attribution="customer",
                        reason=f"customer-confirmed benign: {item.get('question', '')}",
                        scope="case")
    return {"item_id": item_id, "status": item["status"]}


# Timeline validation states (fully reversible — every transition is allowed):
#   real      -> confirmed malicious / keep      (clears any suppression)
#   not_real  -> false positive                  (suppress: disposition benign / operator)
#   known_it  -> IT confirms expected activity   (suppress: disposition benign / it_admin)
#   pending   -> not yet triaged                 (clears any suppression + the record)
_TL_STATES = ("real", "not_real", "known_it", "pending")


def validate_timeline(case_id, finding_id, status, notes="") -> dict:
    """Operator triages a timeline entry. Reversible: changing the status removes
    the previous record and re-applies/clears the matching suppression so a row
    can move freely between real / not_real / known_it / pending.

    Manual events (finding_id 'manual:…') carry their own status on the event
    record — they have no graph finding to suppress."""
    status = status if status in _TL_STATES else "pending"

    if str(finding_id).startswith("manual:"):
        return _set_manual_event_status(case_id, finding_id, status, notes)

    d = get_case(case_id)
    vals = [v for v in (d.get("timeline_validations") or []) if v.get("finding_id") != finding_id]
    if status != "pending":
        vals.append({"finding_id": finding_id, "status": status, "notes": notes})
    _merge_case_details(case_id, {"timeline_validations": vals})

    if status == "not_real":
        set_disposition(case_id, finding_id, verdict="benign", attribution="operator",
                        reason=f"timeline: marked not real{(' — ' + notes) if notes else ''}",
                        scope="case")
    elif status == "known_it":
        set_disposition(case_id, finding_id, verdict="benign", attribution="it_admin",
                        reason=f"timeline: IT confirms expected{(' — ' + notes) if notes else ''}",
                        scope="case")
    else:
        # real or pending — un-suppress (no-op if there was no disposition).
        clear_disposition(case_id, finding_id)
    return {"finding_id": finding_id, "status": status}


def add_manual_timeline_event(case_id, event) -> dict:
    """Operator-entered timeline fact (e.g. 'IT pushed a GPO at 14:05'). Stored on
    the case, merged into the timeline. Editable + deletable; never suppressed by
    fuse since it isn't a graph finding."""
    if not get_case(case_id):
        return {"error": "case not found"}
    eid = "manual:" + keys._h(f"{case_id}:{event.get('ts','')}:{event.get('title','')}"
                              f":{_now_iso()}", 12)
    row = {"finding_id": eid, "manual": True, "source": "manual",
           "ts": (event.get("ts") or "").strip(),
           "host": (event.get("host") or "").strip() or "-",
           "title": (event.get("title") or "").strip() or "(manual event)",
           "severity": (event.get("severity") or "informational").strip().lower(),
           "artifacts": ["manual"], "phase": "Manual",
           "status": (event.get("status") if event.get("status") in _TL_STATES else "real"),
           "notes": (event.get("notes") or event.get("description") or "").strip(),
           "created_at": _now_iso()}
    d = get_case(case_id)
    evs = list(d.get("manual_timeline_events") or []) + [row]
    _merge_case_details(case_id, {"manual_timeline_events": evs})
    return row


def delete_manual_timeline_event(case_id, event_id) -> dict:
    d = get_case(case_id)
    evs = [e for e in (d.get("manual_timeline_events") or []) if e.get("finding_id") != event_id]
    _merge_case_details(case_id, {"manual_timeline_events": evs})
    return {"event_id": event_id, "deleted": True}


def _set_manual_event_status(case_id, event_id, status, notes="") -> dict:
    d = get_case(case_id)
    evs = list(d.get("manual_timeline_events") or [])
    hit = next((e for e in evs if e.get("finding_id") == event_id), None)
    if not hit:
        return {"error": "manual event not found"}
    hit["status"] = status
    if notes:
        hit["notes"] = notes
    _merge_case_details(case_id, {"manual_timeline_events": evs})
    return {"finding_id": event_id, "status": status}


def case_hosts(case_id) -> list:
    """The case's host IDENTITIES = the fused graph's asset nodes (endpoints, already
    deduped by client_id/hostname across modules; + cloud accounts), with OS and the
    current excluded state. This is what the 'Hosts (include)' picker lists."""
    d = get_case(case_id)
    g = load_graph(case_id)
    excluded = {keys.norm_host(h) for h in (d.get("excluded_hosts") or [])}
    os_by = {}
    try:
        from services.velociraptor_service import get_clients_from_snapshot
        for c in (get_clients_from_snapshot(include_offline=True) or []):
            o = (c.get("os") or "").lower() or "unknown"
            if c.get("hostname"):
                os_by[str(c["hostname"]).lower()] = o
            if c.get("client_id"):
                os_by[str(c["client_id"]).lower()] = o
    except Exception:
        pass
    out = []
    for a in g.by_type("asset"):
        label = a.label or a.id
        if a.id.startswith("asset:cloud_account:"):
            parts = a.id.split(":")
            out.append({"host": label, "os": parts[2] if len(parts) > 2 else "cloud",
                        "kind": "cloud", "sources": list(a.sources or []),
                        "excluded": keys.norm_host(label) in excluded})
        else:
            cid = a.id.split(":")[-1]
            os_name = os_by.get(str(label).lower()) or os_by.get(str(cid).lower()) or "unknown"
            out.append({"host": label, "os": os_name, "kind": "endpoint",
                        "sources": list(a.sources or []),
                        "excluded": keys.norm_host(label) in excluded})
    out.sort(key=lambda h: (h["os"], h["host"].lower()))
    return out


def get_timeline(case_id) -> list:
    """Unified case timeline: every finding (with its source artifact + 4-state
    validation) PLUS operator-added manual events, sorted by time. Honors
    host-exclusion so it matches the report.

    Each row: finding_id, ts, host, phase, title, severity, mitre, artifacts,
    source ('fusion'|'manual'), validation ('real'|'not_real'|'known_it'|
    'pending'), suggested_benign (analyst hinted it looks expected), manual."""
    d = get_case(case_id)
    g = _filter_graph_by_hosts(load_graph(case_id), d.get("excluded_hosts"))
    vmap = {v.get("finding_id"): v.get("status")
            for v in (d.get("timeline_validations") or [])}
    # analyst "looks benign" suggestions (the old checklist) -> inline hint
    suggested = {it.get("finding_id") for it in (d.get("disposition_checklist") or [])
                 if it.get("suggestion") == "benign"}
    rows = render.timeline(g, window=d.get("time_window") or None)
    for r in rows:
        r["validation"] = vmap.get(r.get("finding_id"), "pending")
        r["suggested_benign"] = r.get("finding_id") in suggested
        r["manual"] = False
    # manual events carry their own status on the record
    for e in (d.get("manual_timeline_events") or []):
        row = dict(e)
        row["ts"] = render.fmt_ts(e.get("ts"))     # same display format as findings
        row["validation"] = e.get("status", "real")
        row.setdefault("mitre", [])
        row.setdefault("suggested_benign", False)
        rows.append(row)
    rows.sort(key=lambda r: (r.get("ts") or "9999"))
    return rows


def chat_case(case_id, question) -> str:
    d = get_case(case_id)
    g = load_graph(case_id)
    # FP-triage via chat: if the message attributes activity to IT/employee/etc and grounds
    # to a real finding/entity, record the disposition + re-fuse, then confirm.
    disp = llm_sim.detect_disposition(g, question)
    if disp:
        set_disposition(case_id, disp["target"], verdict=disp["verdict"],
                        attribution=disp["attribution"], reason=disp.get("reason", ""),
                        scope=disp.get("scope", "case"))
        ans = (f"Noted — marked **{disp['label']}** as {disp['verdict']} "
               f"({disp['attribution']}). It's suppressed from active findings and won't "
               f"drive host risk; re-fused. Say 'environment' to suppress it fleet-wide.")
    else:
        ans = llm_sim.chat(g, question, history=d.get("chat_messages") or [],
                           window=d.get("time_window") or None,
                           min_severity=d.get("min_severity", "informational"),
                           run_id=case_id, dispositions=d.get("dispositions") or None)
    def _append_msgs(details):           # atomic, so concurrent turns don't clobber
        msgs = list(details.get("chat_messages") or [])
        msgs += [{"role": "user", "content": question},
                 {"role": "assistant", "content": ans}]
        details["chat_messages"] = msgs
    _ws().mutate_run_details(case_id, _append_msgs)
    return ans


def get_chat(case_id) -> list:
    """The persisted conversation for a case (survives page refreshes)."""
    return list((get_case(case_id) or {}).get("chat_messages") or [])


def clear_chat(case_id) -> dict:
    _merge_case_details(case_id, {"chat_messages": []})
    return {"cleared": True}
