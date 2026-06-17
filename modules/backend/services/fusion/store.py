"""Case persistence + fuse orchestration.

A Case is just a workflow row (``automation_type='case'``) whose ``details``
hold the window/severity, member run ids, the fused graph, the report, and
chat. Reuses workflow_service entirely — no new table. Member runs are
fetched, dispatched to their module mapper, assembled into one graph by
``correlate.assemble``, then narrated by ``llm_sim`` (simulated).
"""

from __future__ import annotations

from .schema import FusionGraph
from . import correlate, llm_sim, keys
from .mappers import map_memory, map_agentic, map_cve, map_timesketch

CASE_TYPE = "case"


def _ws():
    from services import workflow_service as ws
    return ws


def create_case(name, *, time_window=None, initial_access=None,
                min_severity="medium", member_run_ids=None) -> str:
    return _ws().create_automation_run(
        automation_type=CASE_TYPE, name=f"Case — {name}",
        details={"name": name, "time_window": time_window or {},
                 "initial_access_estimate": initial_access, "min_severity": min_severity,
                 "member_run_ids": list(member_run_ids or []),
                 "fusion_graph": {}, "report_md": "", "chat_messages": []})


def get_case(case_id) -> dict:
    return (_ws().get_automation_run(case_id) or {}).get("details") or {}


def attach_runs(case_id, run_ids) -> list:
    d = get_case(case_id)
    members = list(dict.fromkeys((d.get("member_run_ids") or []) + list(run_ids)))
    _ws().update_run_status(case_id, "pending", details={"member_run_ids": members})
    return members


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


def _contribution_for_run(run, log=None):
    atype, rid = run.get("automation_type"), run.get("run_id")
    det = run.get("details") or {}
    try:
        if atype == "memory":
            return _memory_contribution(rid, det)
        if atype == "agentic":
            return map_agentic(det.get("collected_data") or {}, run_id=rid,
                               hostnames=det.get("hostnames") or {})
        if atype == "cve_scan":
            return _cve_contribution(rid, det)
        if atype == "timesketch":
            evs = det.get("events") or det.get("timeline_events")
            if evs:
                asset = keys.asset_id(det.get("client_id") or rid)
                return map_timesketch(evs, run_id=rid, asset=asset,
                                      hostname=det.get("client_name"))
    except Exception as e:  # never let one run break the fuse
        if log:
            log(f"fuse: run {rid} ({atype}) skipped: {e}", "warning")
    return [], []


def fuse_case(case_id, *, contributions_override=None, log=None) -> FusionGraph:
    ws = _ws()
    d = get_case(case_id)
    members = d.get("member_run_ids") or []
    if contributions_override is not None:
        contributions = contributions_override
    else:
        contributions = []
        for rid in members:
            run = ws.get_automation_run(rid)
            if run:
                contributions.append(_contribution_for_run(run, log=log))
    g = correlate.assemble(case_id, contributions, members)
    report = llm_sim.generate_report(
        g, window=d.get("time_window") or None,
        min_severity=d.get("min_severity", "informational"),
        initial_access=d.get("initial_access_estimate"),
        case_name=d.get("name", "Case"), run_id=case_id)
    ws.update_run_status(case_id, "completed",
                         details={"fusion_graph": g.to_dict(), "report_md": report})
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
    ans = llm_sim.chat(g, question, history=d.get("chat_messages") or [],
                       window=d.get("time_window") or None,
                       min_severity=d.get("min_severity", "informational"), run_id=case_id)
    msgs = (d.get("chat_messages") or []) + [
        {"role": "user", "content": question}, {"role": "assistant", "content": ans}]
    _ws().update_run_status(case_id, "completed", details={"chat_messages": msgs})
    return ans
