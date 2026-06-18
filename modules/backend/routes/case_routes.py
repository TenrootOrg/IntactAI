"""Case (entity-fusion) routes.

A Case groups module runs (memory/agentic/…), fuses them into one
cross-module + cross-host graph, and serves the 3-altitude report + chat.
The Case is a workflow row (automation_type='case') — see
services/fusion/store.py. Strictly additive; touches no existing pipeline.
"""

from __future__ import annotations

from flask import Blueprint, jsonify, request

from services.fusion import store, render
from services.fusion.schema import FusionGraph

case_bp = Blueprint("case", __name__)

_BOOTSTRAP_DONE = False


@case_bp.before_app_request
def _bind_active_case():
    """Workspace model (runs app-wide via before_app_request, so it does NOT depend
    on editing the single-file-mounted app.py): the browser sends its active case as
    the X-Case-Id header on every /api request. Stash it on `g` so
    create_automation_run() tags new analysis runs and the list endpoints filter by
    workspace. Also does a one-time Default-case bootstrap + legacy backfill."""
    from flask import g, request
    g.case_id = (request.headers.get("X-Case-Id") or "").strip() or None

    global _BOOTSTRAP_DONE
    if not _BOOTSTRAP_DONE:
        _BOOTSTRAP_DONE = True
        try:
            from services import workflow_service as ws
            from services.file_storage_service import reassign_null_case
            default_id = store.ensure_default_case()
            n = reassign_null_case(default_id, list(ws.AGENTIC_TYPES))
            if n:
                print(f"[CASES] backfilled {n} legacy run(s) into Default ({default_id})",
                      flush=True)
        except Exception as e:
            print(f"[CASES] default-case bootstrap failed: {e}", flush=True)


@case_bp.route("/api/cases", methods=["POST"])
def create_case():
    d = request.get_json(silent=True) or {}
    name = (d.get("name") or "").strip()
    if not name:
        return jsonify({"error": "name is required"}), 400
    tw = d.get("time_window") or {}
    rid = store.create_case(
        name, time_window={"start": tw.get("start"), "end": tw.get("end")} if tw else {},
        initial_access=d.get("initial_access_estimate") or d.get("initial_access"),
        min_severity=(d.get("min_severity") or "medium"),
        member_run_ids=d.get("member_run_ids") or [])
    return jsonify({"case_id": rid, "status": "created"})


@case_bp.route("/api/cases", methods=["GET"])
def list_cases():
    from services import workflow_service as ws
    runs = ws.get_all_automation_runs() if hasattr(ws, "get_all_automation_runs") else []
    cases = []
    for r in runs:
        if r.get("automation_type") != store.CASE_TYPE:
            continue
        det = r.get("details") or {}
        cid = r.get("run_id")
        is_default = bool(det.get("is_default") or det.get("name") == store.DEFAULT_CASE_NAME)
        # member count = runs tagged to this workspace (+ legacy explicit members)
        members = ws.get_automation_runs_by_case(cid) if hasattr(ws, "get_automation_runs_by_case") else []
        cases.append({"case_id": cid, "name": det.get("name"),
                      "status": r.get("status"), "is_default": is_default,
                      "members": len(members) or len(det.get("member_run_ids") or []),
                      "created_at": r.get("created_at")})
    # Default first, then newest-first among the rest (two stable passes)
    cases.sort(key=lambda c: c.get("created_at") or "", reverse=True)
    cases.sort(key=lambda c: not c["is_default"])
    return jsonify({"cases": cases})


@case_bp.route("/api/cases/runs", methods=["GET"])
def attachable_runs():
    """Module runs in the active workspace (the X-Case-Id header scopes this)."""
    from flask import g
    from services import workflow_service as ws
    case_id = getattr(g, "case_id", None)
    if case_id:
        runs = ws.get_automation_runs_by_case(case_id)
    else:
        runs = ws.get_all_automation_runs() if hasattr(ws, "get_all_automation_runs") else []
    out = []
    for r in runs:
        if r.get("automation_type") in ("memory", "agentic", "timesketch", "cve_scan",
                                        "aws_scan", "azure_scan"):
            d = r.get("details") or {}
            host = d.get("client_name") or d.get("account") or d.get("account_id") \
                or d.get("tenant_id")
            if not host:
                hn = d.get("hostnames")
                if isinstance(hn, dict):
                    host = ", ".join(str(v) for v in hn.values()) or None
                elif isinstance(hn, list):
                    host = ", ".join(str(v) for v in hn) or None
            out.append({"run_id": r.get("run_id"), "type": r.get("automation_type"),
                        "status": r.get("status"), "host": host,
                        "evidence_id": d.get("evidence_id"), "created_at": r.get("created_at")})
    out.sort(key=lambda x: x.get("created_at") or "", reverse=True)
    return jsonify({"runs": out[:200]})


def _llm_enabled() -> bool:
    try:
        from services.agentic.analyzers import is_llm_configured
        from services.memory.pipeline import _llm_config_from_runtime
        return is_llm_configured(_llm_config_from_runtime())
    except Exception:
        return False


@case_bp.route("/api/cases/<case_id>", methods=["GET"])
def get_case(case_id):
    d = store.get_case(case_id)
    if not d:
        return jsonify({"error": "case not found"}), 404
    return jsonify({"case_id": case_id, "name": d.get("name"),
                    "time_window": d.get("time_window"),
                    "initial_access_estimate": d.get("initial_access_estimate"),
                    "min_severity": d.get("min_severity"),
                    "member_run_ids": d.get("member_run_ids") or [],
                    "has_graph": bool(d.get("fusion_graph")),
                    "is_default": bool(d.get("is_default")
                                       or d.get("name") == store.DEFAULT_CASE_NAME),
                    # null-guarded for cases created before these existed
                    "analysis": d.get("analysis") or {},
                    "dispositions": d.get("dispositions") or [],
                    "token_ab": d.get("token_ab") or {},
                    "llm_enabled": _llm_enabled()})


@case_bp.route("/api/cases/<case_id>", methods=["DELETE"])
def delete_case(case_id):
    """Delete a workspace and everything in it (its tagged runs + baseline). The
    Default workspace cannot be deleted (409)."""
    if not store.get_case(case_id):
        return jsonify({"error": "case not found"}), 404
    res = store.delete_case(case_id)
    if not res.get("deleted"):
        code = 409 if "default" in (res.get("error") or "") else 400
        return jsonify(res), code
    return jsonify({"case_id": case_id, **res})


@case_bp.route("/api/cases/<case_id>/attach", methods=["POST"])
def attach(case_id):
    d = request.get_json(silent=True) or {}
    rids = d.get("run_ids") or ([d["run_id"]] if d.get("run_id") else [])
    if not rids:
        return jsonify({"error": "run_ids required"}), 400
    members = store.attach_runs(case_id, rids)
    resp = {"case_id": case_id, "member_run_ids": members}
    if d.get("watch"):                                  # auto-fuse when in-flight runs land
        import threading
        for rid in rids:
            threading.Thread(target=store.watch_and_fuse, args=(case_id, rid), daemon=True).start()
        resp["watching"] = rids
    elif d.get("fuse"):                                 # fuse now
        g = store.fuse_case(case_id)
        resp.update({"fused": True, "entities": len(g.entities), "findings": len(g.findings)})
    return jsonify(resp)


@case_bp.route("/api/cases/quick", methods=["POST"])
def quick_case():
    """0 -> 1 in one call: create a case, attach runs, fuse, return the report."""
    d = request.get_json(silent=True) or {}
    name = (d.get("name") or "").strip()
    rids = d.get("run_ids") or []
    if not name or not rids:
        return jsonify({"error": "name and run_ids are required"}), 400
    tw = d.get("time_window") or {}
    cid = store.create_case(
        name, time_window={"start": tw.get("start"), "end": tw.get("end")} if tw else {},
        initial_access=d.get("initial_access_estimate") or d.get("initial_access"),
        min_severity=(d.get("min_severity") or "medium"), member_run_ids=rids)
    logs = []
    g = store.fuse_case(cid, log=lambda m, l="info": logs.append((l, m)))
    return jsonify({
        "case_id": cid, "status": "fused", "entities": len(g.entities),
        "relationships": len(g.relationships), "findings": len(g.findings),
        "cross_host_findings": sum(1 for f in g.findings if f.kind == "cross_host"),
        "warnings": [m for lv, m in logs if lv == "warning"],
        "report_md": store.get_case(cid).get("report_md", "")})


@case_bp.route("/api/cases/<case_id>/fuse", methods=["POST"])
def fuse(case_id):
    logs = []
    g = store.fuse_case(case_id, log=lambda m, l="info": logs.append((l, m)))
    return jsonify({"case_id": case_id, "status": "fused",
                    "entities": len(g.entities), "relationships": len(g.relationships),
                    "findings": len(g.findings),
                    "cross_host_findings": sum(1 for f in g.findings if f.kind == "cross_host"),
                    "warnings": [m for l, m in logs if l == "warning"]})


@case_bp.route("/api/cases/<case_id>/report", methods=["GET"])
def report(case_id):
    d = store.get_case(case_id)
    if not d:
        return jsonify({"error": "case not found"}), 404
    return jsonify({"case_id": case_id, "report_md": d.get("report_md") or ""})


@case_bp.route("/api/cases/<case_id>/graph", methods=["GET"])
def graph(case_id):
    d = store.get_case(case_id)
    return jsonify({"case_id": case_id, "fusion_graph": d.get("fusion_graph") or {}})


@case_bp.route("/api/cases/<case_id>/timeline", methods=["GET"])
def timeline(case_id):
    d = store.get_case(case_id)
    g = FusionGraph.from_dict(d.get("fusion_graph") or {"case_id": case_id})
    return jsonify({"case_id": case_id,
                    "timeline": render.timeline(g, window=d.get("time_window") or None)})


@case_bp.route("/api/cases/<case_id>/chat", methods=["POST"])
def chat(case_id):
    d = request.get_json(silent=True) or {}
    q = (d.get("question") or d.get("message") or "").strip()
    if not q:
        return jsonify({"error": "question required"}), 400
    ans = store.chat_case(case_id, q)
    return jsonify({"case_id": case_id, "answer": ans})


@case_bp.route("/api/cases/<case_id>/analysis", methods=["GET"])
def analysis(case_id):
    """The ADVISORY analyst pass (incident_groups + grounded hypotheses) — separate from
    the deterministic findings, never a determination."""
    d = store.get_case(case_id)
    if not d:
        return jsonify({"error": "case not found"}), 404
    return jsonify({"case_id": case_id, "analysis": d.get("analysis") or {}})


@case_bp.route("/api/cases/<case_id>/dispositions", methods=["GET"])
def dispositions(case_id):
    d = store.get_case(case_id)
    if not d:
        return jsonify({"error": "case not found"}), 404
    return jsonify({"case_id": case_id, "dispositions": d.get("dispositions") or []})


@case_bp.route("/api/cases/<case_id>/metrics", methods=["GET"])
def metrics(case_id):
    d = store.get_case(case_id)
    if not d:
        return jsonify({"error": "case not found"}), 404
    return jsonify({"case_id": case_id, "token_ab": d.get("token_ab") or {},
                    "llm_enabled": _llm_enabled()})


@case_bp.route("/api/cases/<case_id>/disposition", methods=["POST"])
def disposition(case_id):
    """Operator triage: mark a finding/entity benign (IT/employee/etc) -> suppressed +
    annotated on re-fuse. The structured path alongside the chat-driven one."""
    d = request.get_json(silent=True) or {}
    target = (d.get("target") or "").strip()
    if not target:
        return jsonify({"error": "target (finding_id or entity_id) required"}), 400
    if not store.get_case(case_id):
        return jsonify({"error": "case not found"}), 404
    disp = store.set_disposition(
        case_id, target, verdict=(d.get("verdict") or "benign"),
        attribution=(d.get("attribution") or "it_admin"), reason=(d.get("reason") or ""),
        scope=(d.get("scope") or "case"))
    return jsonify({"case_id": case_id, "disposition": disp})


@case_bp.route("/api/cases/<case_id>/baseline", methods=["POST"])
def baseline(case_id):
    """Snapshot this (clean) case as the environment baseline so its noise subtracts from
    future cases on the same host(s)."""
    if not store.get_case(case_id):
        return jsonify({"error": "case not found"}), 404
    fp = store.capture_baseline(case_id)
    return jsonify({"case_id": case_id, "baseline": {
        "sigma_titles": len(fp.get("sigma_titles") or []),
        "host_role": fp.get("host_role")}})
