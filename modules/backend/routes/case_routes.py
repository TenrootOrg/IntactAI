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
    cases = [{"case_id": r.get("run_id"), "name": (r.get("details") or {}).get("name"),
              "status": r.get("status"),
              "members": len(((r.get("details") or {}).get("member_run_ids") or [])),
              "created_at": r.get("created_at")}
             for r in runs if r.get("automation_type") == store.CASE_TYPE]
    return jsonify({"cases": cases})


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
                    "has_graph": bool(d.get("fusion_graph"))})


@case_bp.route("/api/cases/<case_id>/attach", methods=["POST"])
def attach(case_id):
    d = request.get_json(silent=True) or {}
    rids = d.get("run_ids") or ([d["run_id"]] if d.get("run_id") else [])
    if not rids:
        return jsonify({"error": "run_ids required"}), 400
    members = store.attach_runs(case_id, rids)
    resp = {"case_id": case_id, "member_run_ids": members}
    if d.get("fuse"):                                   # auto-fuse after attach
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
