"""Case (entity-fusion) routes.

A Case groups module runs (memory/agentic/…), fuses them into one
cross-module + cross-host graph, and serves the 3-altitude report + chat.
The Case is a workflow row (automation_type='case') — see
services/fusion/store.py. Strictly additive; touches no existing pipeline.
"""

from __future__ import annotations

from flask import Blueprint, jsonify, request, Response

from services.fusion import store, render
from services.fusion.schema import FusionGraph

case_bp = Blueprint("case", __name__)

# At most one import and one export in flight at a time, system-wide. The backend
# is a single threaded process (app.run(threaded=True)), so module-level locks are
# global. Independent locks, so one import + one export may overlap.
import threading
_export_lock = threading.Lock()
_import_lock = threading.Lock()

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
            system_id = store.ensure_system_case()
            n = reassign_null_case(default_id, list(ws.AGENTIC_TYPES))
            m = reassign_null_case(system_id, list(ws.SYSTEM_TYPES))
            if n or m:
                print(f"[CASES] backfilled {n} run(s) into Default, {m} into System",
                      flush=True)
        except Exception as e:
            print(f"[CASES] workspace bootstrap failed: {e}", flush=True)


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
        is_system = bool(det.get("is_system") or det.get("name") == store.SYSTEM_CASE_NAME)
        # member count = runs tagged to this workspace (+ legacy explicit members)
        members = ws.get_automation_runs_by_case(cid) if hasattr(ws, "get_automation_runs_by_case") else []
        cases.append({"case_id": cid, "name": det.get("name"),
                      "status": r.get("status"), "is_default": is_default,
                      "is_system": is_system, "builtin": is_default or is_system,
                      "members": len(members) or len(det.get("member_run_ids") or []),
                      "created_at": r.get("created_at")})
    # Default first, then System, then newest-first among the rest (stable passes)
    cases.sort(key=lambda c: c.get("created_at") or "", reverse=True)
    cases.sort(key=lambda c: (not c["is_default"], not c["is_system"]))
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
                    "is_system": bool(d.get("is_system")
                                      or d.get("name") == store.SYSTEM_CASE_NAME),
                    "masking": d.get("masking") or {"enabled": False, "patterns": []},
                    "included_run_ids": d.get("included_run_ids"),
                    # null-guarded for cases created before these existed
                    "analysis": d.get("analysis") or {},
                    "dispositions": d.get("dispositions") or [],
                    "token_ab": d.get("token_ab") or {},
                    "llm_enabled": _llm_enabled()})


@case_bp.route("/api/cases/<case_id>", methods=["DELETE"])
def delete_case(case_id):
    """Delete a workspace and everything in it (its tagged runs + baseline). The
    built-in Default and System workspaces cannot be deleted (409)."""
    if not store.get_case(case_id):
        return jsonify({"error": "case not found"}), 404
    res = store.delete_case(case_id)
    if not res.get("deleted"):
        code = 409 if "cannot be deleted" in (res.get("error") or "") else 400
        return jsonify(res), code
    return jsonify({"case_id": case_id, **res})


@case_bp.route("/api/cases/<case_id>/export", methods=["GET"])
def export_case(case_id):
    """Download a self-contained bundle for one workspace (case record + member
    runs) that `POST /api/cases/import` can recreate on this or another install."""
    import json as _json
    if not _export_lock.acquire(blocking=False):
        return jsonify({"error": "an export is already in progress; try again shortly"}), 409
    try:
        bundle = store.export_case(case_id)
        if bundle is None:
            return jsonify({"error": "case not found"}), 404
        safe = "".join(c if c.isalnum() or c in "-_" else "_"
                       for c in (bundle.get("name") or "case"))[:60] or "case"
        payload = _json.dumps(bundle, indent=2, default=str)
    finally:
        # The bundle is fully built in-memory; releasing here serialises the
        # (heavy) build, not the subsequent byte-streaming to the client.
        _export_lock.release()
    return Response(payload, mimetype="application/json", headers={
        "Content-Disposition": f'attachment; filename="{safe}.intactcase.json"'})


@case_bp.route("/api/cases/import", methods=["POST"])
def import_case():
    """Recreate a workspace from an exported bundle (multipart `file`, or a raw
    JSON body). Tracked as a System-workspace operation, not the active case."""
    import json as _json
    if not _import_lock.acquire(blocking=False):
        return jsonify({"error": "an import is already in progress; try again shortly"}), 409
    try:
        bundle = None
        f = request.files.get("file")
        if f is not None:
            try:
                bundle = _json.loads(f.read().decode("utf-8"))
            except Exception as e:
                return jsonify({"error": f"could not parse file: {e}"}), 400
        else:
            bundle = request.get_json(silent=True)
        if not isinstance(bundle, dict):
            return jsonify({"error": "no case bundle provided"}), 400
        name = request.form.get("name") or None
        try:
            res = store.import_case(bundle, name=name)
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
        # Audit the import as a System-workspace op (case_import is a SYSTEM_TYPE).
        try:
            from services import workflow_service as ws
            rid = ws.create_automation_run(
                "case_import", f"Import workspace: {res['name']}",
                details={"imported_case_id": res["case_id"],
                         "runs_imported": res["runs_imported"]})
            ws.update_run_status(rid, "completed", progress=100)
        except Exception:
            pass
        return jsonify(res)
    finally:
        _import_lock.release()


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


@case_bp.route("/api/cases/<case_id>/rescan", methods=["POST"])
def rescan(case_id):
    """THE Case Analysis action: persist the config rail's variables (time window,
    severity, masking, included hosts, audience/branding/master-prompt) then re-correlate
    + regenerate the report/advisory/checklist."""
    if not store.get_case(case_id):
        return jsonify({"error": "case not found"}), 404
    cfg = request.get_json(silent=True) or {}
    res = store.rescan(case_id, cfg)
    return jsonify({"case_id": case_id, "status": "rescanned", **res})


@case_bp.route("/api/cases/<case_id>/members", methods=["GET"])
def members(case_id):
    """Runs tagged to the case + host + included flag (legacy run-level picker)."""
    if not store.get_case(case_id):
        return jsonify({"error": "case not found"}), 404
    return jsonify({"case_id": case_id, "members": store.case_members(case_id)})


@case_bp.route("/api/cases/<case_id>/hosts", methods=["GET"])
def hosts(case_id):
    """Host identities in the fused data (endpoints + cloud accounts), deduped, with OS
    and excluded state — the source for the Hosts (include) picker."""
    if not store.get_case(case_id):
        return jsonify({"error": "case not found"}), 404
    return jsonify({"case_id": case_id, "hosts": store.case_hosts(case_id)})


@case_bp.route("/api/cases/<case_id>/checklist", methods=["GET"])
def get_checklist(case_id):
    d = store.get_case(case_id)
    if not d:
        return jsonify({"error": "case not found"}), 404
    return jsonify({"case_id": case_id, "checklist": d.get("disposition_checklist") or []})


@case_bp.route("/api/cases/<case_id>/checklist/<item_id>", methods=["POST"])
def decide_checklist(case_id, item_id):
    """accept = customer confirms benign (dispositioned + re-fused); decline = keep."""
    if not store.get_case(case_id):
        return jsonify({"error": "case not found"}), 404
    decision = (request.get_json(silent=True) or {}).get("decision", "accept")
    res = store.decide_checklist_item(case_id, item_id, decision)
    return (jsonify(res), 404) if res.get("error") else jsonify({"case_id": case_id, **res})


@case_bp.route("/api/cases/<case_id>/timeline/validate", methods=["POST"])
def timeline_validate(case_id):
    """Mark a timeline entry real / not_real. not_real => suppressed on re-fuse."""
    if not store.get_case(case_id):
        return jsonify({"error": "case not found"}), 404
    b = request.get_json(silent=True) or {}
    fid = (b.get("finding_id") or "").strip()
    if not fid:
        return jsonify({"error": "finding_id required"}), 400
    res = store.validate_timeline(case_id, fid, b.get("status", "real"), b.get("notes", ""))
    return jsonify({"case_id": case_id, **res})


@case_bp.route("/api/cases/<case_id>/report", methods=["GET"])
def report(case_id):
    d = store.get_case(case_id)
    if not d:
        return jsonify({"error": "case not found"}), 404
    return jsonify({"case_id": case_id, "report_md": d.get("report_md") or "",
                    "audience": d.get("audience", "both"),
                    "customer_name": d.get("customer_name", ""), "tlp": d.get("tlp", "AMBER"),
                    "has_logo": bool(d.get("customer_logo_b64")),
                    "master_prompt": d.get("master_prompt", "")})


@case_bp.route("/api/cases/<case_id>/branding", methods=["POST"])
def set_branding(case_id):
    """Set report branding/options: customer_name, customer_logo_b64, tlp, audience, language."""
    if not store.get_case(case_id):
        return jsonify({"error": "case not found"}), 404
    b = request.get_json(silent=True) or {}
    saved = store.set_branding(
        case_id, customer_name=b.get("customer_name"),
        customer_logo_b64=b.get("customer_logo_b64"), tlp=b.get("tlp"),
        audience=b.get("audience"), language=b.get("language"))
    return jsonify({"case_id": case_id, "saved": saved})


@case_bp.route("/api/cases/<case_id>/report", methods=["POST"])
def regenerate_report(case_id):
    """Re-narrate the report (+ advisory) at the chosen audience, applying the operator
    master-prompt — cheap, from the stored graph (no re-collect)."""
    if not store.get_case(case_id):
        return jsonify({"error": "case not found"}), 404
    b = request.get_json(silent=True) or {}
    res = store.regenerate_report(case_id, audience=b.get("audience"))
    return jsonify({"case_id": case_id, **res})


@case_bp.route("/api/cases/<case_id>/synthesize", methods=["POST"])
def synthesize(case_id):
    """Compress the case chat into the master-prompt steering brief (needs a real LLM)."""
    if not store.get_case(case_id):
        return jsonify({"error": "case not found"}), 404
    b = request.get_json(silent=True) or {}
    if b.get("master_prompt") is not None:                 # hand-set (no LLM needed)
        store.set_master_prompt(case_id, b["master_prompt"])
        return jsonify({"case_id": case_id, "master_prompt": b["master_prompt"]})
    try:
        mp = store.synthesize_master_prompt(case_id)
        return jsonify({"case_id": case_id, "master_prompt": mp})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:                                  # LLM unavailable, etc.
        return jsonify({"error": f"synthesis failed: {e}"}), 503


@case_bp.route("/api/cases/<case_id>/report/download", methods=["GET"])
def report_download(case_id):
    """Branded engagement-style markdown (cover + body)."""
    if not store.get_case(case_id):
        return jsonify({"error": "case not found"}), 404
    md = store.engagement_markdown(case_id)
    return Response(md, mimetype="text/markdown",
                    headers={"Content-Disposition": f'attachment; filename="case_{case_id}.md"'})


@case_bp.route("/api/cases/<case_id>/report/download/pdf", methods=["GET"])
def report_download_pdf(case_id):
    """Branded engagement-grade PDF (reuses the engagement WeasyPrint renderer)."""
    d = store.get_case(case_id)
    if not d:
        return jsonify({"error": "case not found"}), 404
    try:
        from services.engagement.pdf import render_engagement_pdf
        md = store.engagement_markdown(case_id)
        pdf = render_engagement_pdf(md, case_id, logo_b64=d.get("customer_logo_b64") or "")
    except Exception as e:
        return jsonify({"error": f"pdf render failed: {e}"}), 503
    return Response(pdf, mimetype="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="case_{case_id}.pdf"'})


@case_bp.route("/api/cases/<case_id>/graph", methods=["GET"])
def graph(case_id):
    d = store.get_case(case_id)
    fg = d.get("fusion_graph") or {}
    # Auto-populate: if the case has member runs but no graph has been built yet
    # (e.g. right after an offline import), fuse once on first view so Case
    # Analysis isn't blank. A non-empty cached graph is returned as-is (fast).
    if not (fg.get("entities")) and store._members_for_case(case_id, d):
        try:
            g = store.fuse_case(case_id)
            fg = g.to_dict()
        except Exception as e:
            print(f"[CASE] on-view fuse failed for {case_id}: {e}", flush=True)
    return jsonify({"case_id": case_id, "fusion_graph": fg})


@case_bp.route("/api/cases/<case_id>/timeline", methods=["GET"])
def timeline(case_id):
    if not store.get_case(case_id):
        return jsonify({"error": "case not found"}), 404
    # each row carries finding_id + validation status (real/not_real/unknown)
    return jsonify({"case_id": case_id, "timeline": store.get_timeline(case_id)})


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
