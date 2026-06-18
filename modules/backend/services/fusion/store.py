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
    return budget.approx_tokens(blob) if blob else 0


def _ws():
    from services import workflow_service as ws
    return ws


def create_case(name, *, time_window=None, initial_access=None,
                min_severity="medium", member_run_ids=None, is_default=False) -> str:
    # The case row is itself a workflow row but is NEVER case-scoped — pass
    # case_id=None explicitly so the request's active case doesn't tag it.
    return _ws().create_automation_run(
        automation_type=CASE_TYPE, name=f"Case — {name}", case_id=None,
        details={"name": name, "time_window": time_window or {},
                 "initial_access_estimate": initial_access, "min_severity": min_severity,
                 "member_run_ids": list(member_run_ids or []),
                 "is_default": bool(is_default),
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


def is_default_case(case_id) -> bool:
    d = get_case(case_id)
    return bool(d.get("is_default") or d.get("name") == DEFAULT_CASE_NAME)


def delete_case(case_id) -> dict:
    """Delete a workspace and EVERYTHING in it: every tagged run, the baseline this
    case captured, and the case row. Refuses to delete the Default workspace."""
    from services.file_storage_service import delete_workflow
    ws = _ws()
    d = get_case(case_id)
    if not d:
        return {"deleted": False, "error": "not found"}
    if d.get("is_default") or d.get("name") == DEFAULT_CASE_NAME:
        return {"deleted": False, "error": "default workspace cannot be deleted"}
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


def _contribution_for_run(run, log=None):
    atype, rid = run.get("automation_type"), run.get("run_id")
    det = run.get("details") or {}
    try:
        if atype == "memory":
            return _memory_contribution(rid, det)
        if atype == "agentic":
            return map_agentic(_agentic_collected_data(rid, det), run_id=rid,
                               hostnames=det.get("hostnames") or {})
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
    report = llm_sim.generate_report(
        g, window=window, min_severity=min_sev,
        initial_access=d.get("initial_access_estimate"),
        case_name=d.get("name", "Case"), run_id=case_id)
    # ADVISORY analyst pass — incident-grouping + grounded hypotheses. Stored SEPARATELY
    # from the deterministic findings (never conflated); fed prior operator dispositions.
    analysis = llm_sim.analyze(g, window=window, min_severity=min_sev, run_id=case_id,
                               dispositions=d.get("dispositions") or None)

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
                                  "token_ab": token_ab, "analysis": analysis})
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
    msgs = (d.get("chat_messages") or []) + [
        {"role": "user", "content": question}, {"role": "assistant", "content": ans}]
    _ws().update_run_status(case_id, "completed", details={"chat_messages": msgs})
    return ans
