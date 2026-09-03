"""Case (entity-fusion) routes.

A Case groups module runs (memory/agentic/…), fuses them into one
cross-module + cross-host graph, and serves the 3-altitude report + chat.
The Case is a workflow row (automation_type='case') — see
services/fusion/store.py. Strictly additive; touches no existing pipeline.
"""

from __future__ import annotations

import re

from flask import Blueprint, jsonify, request, Response

from services.fusion import store, render
from services.fusion.schema import FusionGraph

case_bp = Blueprint("case", __name__)


def _report_filename(d, ext):
    """A professional download name: 'IntactAI Incident Report - <Case> - <date>.<ext>'
    (the case/customer name sanitised to a filesystem-safe string)."""
    import re as _re
    from datetime import datetime, timezone
    base = (d.get("customer_name") or d.get("name") or "Case").strip()
    base = _re.sub(r"[^\w .-]", "", base).strip() or "Case"
    date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    return f"IntactAI Incident Report - {base} - {date}.{ext}"

# At most one import and one export in flight at a time, system-wide. The backend
# is a single threaded process (app.run(threaded=True)), so module-level locks are
# global. Independent locks, so one import + one export may overlap.
import threading
_export_lock = threading.Lock()
_import_lock = threading.Lock()

_BOOTSTRAP_DONE = False


# ---- Case Analysis audit log --------------------------------------------------
# The Case has no per-action workflow row, so we record every state-changing
# request (and every error) against the case itself. Generic: any /api/cases/<id>/
# mutation or failure is captured without instrumenting each handler.
def _audit_case_id():
    p = (request.path or "").strip("/").split("/")
    if len(p) >= 4 and p[0] == "api" and p[1] == "cases":
        return p[2], "/".join(p[3:])
    return None, None


# friendly labels for the common case actions (the raw path is the fallback)
_STATE_LABEL = {"real": "Real", "not_real": "Not real", "known_it": "Known", "pending": "Pending"}


def _audit_label(action):
    a = action.split("/")[0]
    if a == "timeline" and "validate" in action:
        return "Timeline status"
    if a == "timeline" and "event" in action:
        return "Delete timeline event" if request.method == "DELETE" else "Add timeline event"
    if a == "disposition":
        return "Disposition"
    if a == "chat":
        return "Clear chat" if request.method == "DELETE" else "Chat"
    if a == "report":
        return "Regenerate report"
    if a == "export":
        return "Export case"
    if a == "import":
        return "Import case"
    if a == "rescan":
        return "Rescan / re-fuse"
    if a in ("config", "hosts", "masking") or request.method in ("PUT", "PATCH"):
        return "Update configuration"
    if a == "fuse":
        return "Fuse"
    return f"{request.method} {action}"


def _safe_json(resp):
    try:
        return resp.get_json(silent=True) or {}
    except Exception:
        return {}


def _audit_detail(action, is_err, resp):
    """An explicit, human-readable description of what happened. Hardened: any
    failure to build the detail degrades to a short generic string, never raises."""
    try:
        a = action.split("/")[0]
        if is_err:
            # surface the real reason the action failed
            err = (_safe_json(resp).get("error") or "").strip()
            verb = _audit_label(action).lower()
            return f"{verb} failed — {err}" if err else f"{verb} failed ({resp.status_code})"

        b = request.get_json(silent=True) or {}
        if a == "timeline" and "validate" in action and b.get("finding_id"):
            what = b.get("title") or b.get("finding_id")
            state = _STATE_LABEL.get(b.get("status"), b.get("status", "real"))
            return f'marked "{what}" as {state}'
        if a == "timeline" and "event" in action:
            if request.method == "DELETE":
                return "removed a manual timeline event"
            return f'added manual event "{b.get("title", "")}"'.strip()
        if a == "disposition" and b.get("target"):
            return (f'{b.get("target")} → {b.get("verdict", "benign")} '
                    f'({b.get("attribution", "operator")})')
        if a == "chat" and request.method == "DELETE":
            return "conversation cleared"
        if a == "chat" and (b.get("question") or b.get("message")):
            # the answer itself is NOT stored here — just confirm it was answered
            q = (b.get("question") or b.get("message")).strip()
            ans = (_safe_json(resp).get("answer") or "").strip()
            outcome = "answered" if ans else "no answer produced"
            return f'{outcome} — "{q[:140]}"'
        if a == "report" and request.method == "POST":
            # 202 = the LLM path just STARTED on a background thread — logging
            # "report regenerated" here would claim it finished before the
            # first token was sent. The real completion (or failure) logs its
            # own line from inside regenerate_report(), seconds to minutes
            # later; this one only needs to mark that the click was received.
            if resp.status_code == 202:
                return "generation started — narrating in the background, no need to wait here"
            return "report regenerated"
        if a in ("rescan", "config", "hosts", "masking"):
            return "configuration updated, case re-fused"
        if a == "export":
            # The background run logs the real outcome (size, run count, the
            # file it produced); this line only marks when it was asked for.
            return "export started — building the bundle in the background"
        if a == "import":
            return action
        return ""
    except Exception:
        return ""


@case_bp.after_request
def _audit_case_activity(resp):
    try:
        cid, action = _audit_case_id()
        # skip the log's own reads/clears so polling doesn't self-fill the log
        if cid and action and action.split("/")[0] != "log":
            is_err = resp.status_code >= 400
            # A "busy" 409 (FusionBusy, ReportGenerationBusy, ...) is not a
            # failure — it means the case is already doing this, which is a
            # NORMAL collision (a double-click, two operators at once). Its own
            # handler already logs a friendly "deferred" line; recording it a
            # second time here as "X failed (409)" is what told an operator
            # this had broken when it was just still working.
            if resp.status_code == 409 and _safe_json(resp).get("busy"):
                return resp
            if request.method in ("POST", "PUT", "DELETE", "PATCH") or is_err:
                store.log_case_event(cid, _audit_label(action),
                                     "error" if is_err else "ok",
                                     _audit_detail(action, is_err, resp),
                                     code=resp.status_code)
    except Exception:
        pass
    return resp


@case_bp.errorhandler(store.FusionBusy)
def _case_busy(e):
    """A fuse is already running for this case → 409, never 500.

    409 is the honest code: the request is well-formed, the case is simply busy,
    and retrying will work. It used to fall through to the generic handler below,
    which returned 500 AND wrote "crashed" into the case activity log — so a
    perfectly normal collision (two operators triaging at once, or a triage action
    landing while a Rescan is still running) read as a product fault.

    Registered on the same blueprint as the catch-all: Flask walks the exception's
    MRO and prefers the most specific registered class, so this wins.

    Note several callers persist BEFORE they fuse — set_disposition and
    decide_checklist_item both write their decision, then re-fuse. A 409 from
    those means the decision IS saved and only the graph is behind, which is why
    the message says "not lost" rather than implying the action failed.
    """
    try:
        cid, action = _audit_case_id()
        if cid and action:
            store.log_case_event(cid, _audit_label(action), "warning",
                                 f"{_audit_label(action).lower()} deferred — "
                                 f"a fuse is already running for this case", code=409)
    except Exception:
        pass
    return jsonify({"error": str(e), "busy": True,
                    "hint": "the case is re-fusing — your change is saved, "
                            "retry in a moment to see it applied"}), 409


@case_bp.errorhandler(Exception)
def _audit_case_exception(e):
    from werkzeug.exceptions import HTTPException
    try:
        cid, action = _audit_case_id()
        if cid and action and action.split("/")[0] != "log":
            store.log_case_event(cid, _audit_label(action), "error",
                                 f"{_audit_label(action).lower()} crashed — {str(e)[:280]}",
                                 code=getattr(e, "code", 500) or 500)
    except Exception:
        pass
    if isinstance(e, HTTPException):
        return e
    print(f"[CASE] unhandled error on {request.path}: {e}", flush=True)
    return jsonify({"error": str(e)}), 500


@case_bp.route("/api/cases/<case_id>/log", methods=["GET"])
def case_log(case_id):
    if not store.get_case(case_id):
        return jsonify({"error": "case not found"}), 404
    return jsonify({"case_id": case_id, "log": store.get_case_log(case_id)})


@case_bp.route("/api/cases/<case_id>/log", methods=["DELETE"])
def case_log_clear(case_id):
    if not store.get_case(case_id):
        return jsonify({"error": "case not found"}), 404
    return jsonify({"case_id": case_id, **store.clear_case_log(case_id)})


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
            try:
                # Timers are in memory: data that landed just before a restart would
                # otherwise wait for the NEXT run to arrive before fusing.
                from services.fusion import autofuse
                autofuse.catch_up()
            except Exception as _e:      # noqa: BLE001 — never break request one
                print(f"[AUTOFUSE] catch-up failed: {_e}", flush=True)
            try:
                # report_generating is a flag on the CASE, tracking a thread that
                # lived only in the previous process's memory — a restart mid-
                # generation (crash, deploy) leaves it stuck True forever with
                # nothing left running to ever clear it, which would permanently
                # block Regenerate on that case. Nothing can genuinely still be
                # "generating" the instant this process starts.
                for _r in (ws.get_all_automation_runs() or []):
                    if _r.get("automation_type") != store.CASE_TYPE:
                        continue
                    if (_r.get("details") or {}).get("report_generating"):
                        store._merge_case_details(_r["run_id"], {
                            "report_generating": False,
                            "report_generating_started_at": None})
                        store.log_case_event(
                            _r["run_id"], "Report generation", "warning",
                            "interrupted by a backend restart — click Regenerate report to try again")
            except Exception as _e:      # noqa: BLE001 — never break request one
                print(f"[REPORT-GEN] stale-flag cleanup failed: {_e}", flush=True)
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
        if is_system:
            # System is no longer a selectable case/workspace — it's dropped from the
            # case list + workspace picker. Its run history is served separately by
            # GET /api/system/actions (Settings → Actions). Attribution/redirect for
            # system runs still uses the internal System case_id (unchanged).
            continue
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
        if r.get("automation_type") in ("memory", "velociraptor_collection", "timesketch",
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
    # Loading is FAST: show the cached graph as-is, no auto re-fuse (re-fusing a
    # large case on every open is slow). Surface two independent staleness signals
    # so the UI can offer the right action:
    #   data_stale   -> new runs not yet in the graph  -> Refusion (data, no LLM)
    #   report_stale -> new runs not in the report/chat -> Rescan (LLM)
    data_stale = store.stale_member_runs(case_id, d)
    report_stale = store.report_stale_runs(case_id, d)
    return jsonify({"case_id": case_id, "name": d.get("name"),
                    "time_window": d.get("time_window"),
                    "initial_access_estimate": d.get("initial_access_estimate"),
                    "min_severity": d.get("min_severity"),
                    "member_run_ids": d.get("member_run_ids") or [],
                    "has_graph": bool((d.get("graph_counts") or {}).get("entities")
                                      or d.get("fusion_graph")),
                    "is_default": bool(d.get("is_default")
                                       or d.get("name") == store.DEFAULT_CASE_NAME),
                    "is_system": bool(d.get("is_system")
                                      or d.get("name") == store.SYSTEM_CASE_NAME),
                    "masking": d.get("masking") or {"enabled": False, "patterns": []},
                    "included_run_ids": d.get("included_run_ids"),
                    # null-guarded for cases created before these existed
                    "dispositions": d.get("dispositions") or [],
                    "token_ab": d.get("token_ab") or {},
                    "counts": store.graph_counts(case_id),
                    # entity-cap textbox + module picker (velociraptor default;
                    # memory optional; timesketch/cve/cloud disabled for now)
                    # Single entity knob: sizes the stored graph AND the LLM payload.
                    "max_entities": d.get("max_entities") or store.DEFAULT_MAX_ENTITIES,
                    # Identity rows in the LLM payload — a CEILING inside the Entity
                    # limit above (min(this, max_entities)), so a large value here can
                    # never let identities escape the same context-safe budget. None =
                    # tied to the Entity limit with no separate action needed.
                    "max_identities": d.get("max_identities"),
                    # LOCKED to the model max: no per-case output cap any more.
                    # Kept in the response for API compatibility (None = model max).
                    "llm_max_output_tokens": None,
                    # Fold newly-landed runs into the graph automatically, after the
                    # case goes quiet. Default ON, absent included — same reasoning as
                    # above. It never calls the model and never redraws the view; the
                    # narrative still waits for an explicit Rescan.
                    "auto_fuse": bool(d.get("auto_fuse", True)),
                    # Exactly which runs the STORED graph was built from. The case
                    # view snapshots this at render time and the staleness poll
                    # compares against it, which is how "new runs arrived" is told
                    # apart from "a background fuse already folded them in".
                    "fused_run_ids": list(d.get("fused_run_ids") or []),
                    # LOCKED ON: the LLM payload is always sized from the selected
                    # model's REAL context window, never the static ~128k-model
                    # constant. Kept in the response for API compatibility.
                    "llm_use_full_context": True,
                    # LOCKED ON: chat always sends the FULL graph every message
                    # (host-resolution mode is too robotic). UI shows it fixed.
                    "chat_send_full_context": True,
                    # LOCKED to explicit: real cmdline / path / hash per finding.
                    "report_detail": "explicit",
                    # estimated USD cost of one Rescan (LLM) with the configured model.
                    "cost_estimate": store.estimate_rescan_cost(d),
                    "fusion_modules": store.normalize_modules(d.get("fusion_modules")),
                    "modules_catalog": store.fusion_modules_catalog(),
                    # Staleness split: data (new runs not in the graph) drives the
                    # Refusion hint; report (new runs not in the narrative) drives
                    # the Rescan (LLM) hint. Neither auto-runs on load.
                    "data_stale": len(data_stale),
                    "report_stale": len(report_stale),
                    "stale_run_ids": data_stale or report_stale,
                    # report_dirty: triage/disposition re-fuses changed the data but left
                    # the report frozen — so the report may not reflect recent changes.
                    "report_dirty": bool(d.get("report_dirty")),
                    "is_stale": bool(data_stale or report_stale or d.get("report_dirty")),
                    # WHY the report is (or is not) narrated, in the operator's
                    # terms. The Analysis tab shows this instead of leaving them to
                    # guess: "air-gap is ticked", "no model", "no API key" and "no
                    # route to the provider" all produce the same deterministic
                    # report but need completely different actions.
                    "llm_status": _llm_status_for(d),
                    "llm_enabled": _llm_enabled(),
                    # An LLM-narrated report can run for several minutes across
                    # two sequential calls — the frontend polls this to know
                    # when to stop showing "generating…" and refresh on its own.
                    "report_generating": store.report_generation_active(d),
                    # WHICH call is in flight. "advisory" means the narrative is
                    # already written and readable -- the page can say so, and
                    # refresh the body, instead of showing one undifferentiated
                    # spinner across two calls that can each take minutes.
                    "report_phase": d.get("report_phase"),
                    "report_phase_started_at": d.get("report_phase_started_at"),
                    "report_generating_started_at": d.get("report_generating_started_at")})


def _llm_status_for(d):
    """Never let a status probe break the case view — it is a hint, not the data."""
    try:
        from services.fusion import llm_sim
        return llm_sim.llm_status()
    except Exception:                       # noqa: BLE001
        return {"available": True, "code": "ok", "reason": "", "fix": ""}


@case_bp.route("/api/cases/<case_id>/risk", methods=["GET"])
def get_case_risk(case_id):
    """Per-endpoint identity-risk table — 'which clients to focus on first + why'.
    Read-only: derived deterministically from the case's already-fused graph
    (no re-fuse, no LLM). Each row = host, risk score, severity, finding tally,
    the concrete reasons driving the score, module coverage, and next action."""
    d = store.get_case(case_id)
    if not d:
        return jsonify({"error": "case not found"}), 404
    g = store.load_graph(case_id)
    rows = render.risk_table(g, window=d.get("time_window") or None,
                             min_severity=d.get("min_severity") or "informational")
    return jsonify({"case_id": case_id, "rows": rows, "total": len(rows),
                    "is_stale": bool(store.stale_member_runs(case_id, d))})


@case_bp.route("/api/cases/<case_id>/zoom_targets", methods=["GET"])
def get_zoom_targets(case_id):
    """Macro->micro zoom presets: the suspicious (host-cluster, time-window) hotspots
    an operator can one-click narrow to. Only meaningful for a MACRO-altitude case
    (returns [] for a focused one). Deterministic — no LLM, no re-fuse."""
    d = store.get_case(case_id)
    if not d:
        return jsonify({"error": "case not found"}), 404
    g = store.load_graph(case_id)
    win = d.get("time_window") or None
    ms = d.get("min_severity") or "informational"
    _mode = d.get("report_altitude") or "auto"
    altitude, reason = render._resolve_altitude(g, window=win, min_severity=ms, mode=_mode)
    # analysable() drops the coverage rollup and any window too small to be a scope;
    # the rollup is appended back as a non-clickable accounting row so the operator
    # can still see what was left out.
    _zt = (render.zoom_targets(g, window=win, min_severity=ms,
                               force_phases=(_mode == "macro"))
           if altitude == "macro" else [])
    targets = render.analysable(_zt) + [z for z in _zt if z.get("rollup")]
    if targets:
        # The model named each window in the report ("### Timeframe 3 — Ransomware
        # prep & C2"); carry that onto the card so it says what the window IS, not
        # only when it was. Absent (deterministic report, or not yet narrated) the
        # card keeps its date/count title.
        names = render.timeframe_names_from_report(d.get("report_md") or "")
        for z in targets:
            z["name"] = names.get(z.get("n"))
    return jsonify({"case_id": case_id, "altitude": altitude, "reason": reason,
                    "targets": targets})


@case_bp.route("/api/cases/<case_id>/zoom", methods=["POST"])
def apply_zoom(case_id):
    """Apply a zoom preset from the macro report: narrow the case to a target's hosts
    + time window and re-fuse (deterministic — the focused report renders at the new
    altitude). The operator can then hit Rescan (LLM) for the focused narrative.
    Body: {window:{start,end}, host_labels:[...]}."""
    d = store.get_case(case_id)
    if not d:
        return jsonify({"error": "case not found"}), 404
    body = request.get_json(silent=True) or {}
    win = body.get("window") or {}
    keep = {h for h in (body.get("host_labels") or []) if h}
    if not (win.get("start") and win.get("end")) or not keep:
        return jsonify({"error": "zoom needs window.start, window.end and host_labels"}), 400
    g = store.load_graph(case_id)
    all_labels = {a.label for a in g.by_type("asset")}
    excluded = sorted(all_labels - keep)              # keep ONLY the target's hosts
    cfg = {"time_window": {"start": win["start"], "end": win["end"]},
           "excluded_hosts": excluded}
    res = store.rescan(case_id, cfg, trigger=store.TRIGGER_MANUAL_REFUSION)
    return jsonify({"case_id": case_id, "status": "zoomed",
                    "scoped_to": sorted(keep), "window": cfg["time_window"], **res})


@case_bp.route("/api/cases/<case_id>/investigate", methods=["POST"])
def investigate_case(case_id):
    """Agentic drill-down: the model investigates a QUESTION by calling retrieval
    tools (list_findings / search / evidence / clusters) over the graph + raw
    evidence, grounding every claim in what they return. On-demand — costs several
    LLM calls — so it's an explicit 'dig deeper', not the default report path."""
    if not store.get_case(case_id):
        return jsonify({"error": "case not found"}), 404
    q = (request.get_json(silent=True) or {}).get("question")
    if not q:
        return jsonify({"error": "question required"}), 400
    from services.fusion import investigate as _inv
    rid = store._ws().create_automation_run("investigation", f"investigate {case_id}")
    # investigate() already turns transport failures (A3) and tool crashes (A2) into
    # a graceful result; this guard is defense-in-depth so any UNEXPECTED raise still
    # returns clean JSON instead of an opaque 500.
    try:
        res = _inv.investigate(case_id, q, run_id=rid)
    except Exception as e:  # noqa: BLE001
        return jsonify({"case_id": case_id, "question": q, "steps": [],
                        "error": f"investigation failed: {type(e).__name__}: {e}"}), 500
    # persist into the case's chat history (same cap/atomicity as a chat turn), so
    # the grounded answer survives reloads and feeds later chat turns as context
    try:
        trace = " → ".join(s.get("tool", "?") for s in (res.get("steps") or []))
        content = (res.get("answer") or "") + (
            f"\n\n---\n_🔧 investigated via: {trace}"
            + (" · step budget reached" if res.get("truncated") else "") + "_"
            if trace else "")
        store.append_chat_exchange(case_id, q, content)
    except Exception:
        pass                                  # persistence is a convenience, never a 500
    return jsonify({"case_id": case_id, "question": q, **res})


@case_bp.route("/api/cases/<case_id>/findings/<finding_id>/evidence", methods=["GET"])
def finding_evidence(case_id, finding_id):
    """Drill from a finding to the RAW rows its evidence locators point at — the
    retrieval primitive behind on-demand deepening (and the future agentic loop)."""
    if not store.get_case(case_id):
        return jsonify({"error": "case not found"}), 404
    rows = store.get_evidence_rows(case_id, finding_id)
    return jsonify({"case_id": case_id, "finding_id": finding_id,
                    "count": len(rows), "rows": rows})


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


# ---- portable case bundles (move a case between appliances) --------------------
# Export builds a multi-GB archive, so it CANNOT happen inside the request: nginx
# gives up waiting for a first byte after 300s and buffers the response besides.
# The route starts a background run and hands back its id; the finished file is
# fetched separately. Import is the mirror image, fed by the resumable tus upload
# path (the /api/ route caps at 500 MB, which one member payload already exceeds).


def _bundle_thread(target, run_id, *args, **kwargs):
    """Run a bundle job on a daemon thread, owning the run's terminal state and
    releasing `lock` no matter how it ends.

    The run is registered for cancellation before the thread starts, so the Stop
    button in Settings → Actions reaches it — a Stop that renders but does nothing
    is worse than no Stop at all.
    """
    import threading
    import traceback
    from services import workflow_service as ws
    lock = kwargs.pop("lock", None)
    cancel = ws.register_cancel_event(run_id)

    def _worker():
        try:
            res = target(*args, run_id=run_id, cancel=cancel, **kwargs)
            # No force=: if anything logged at error level, the platform's safety
            # net demotes this to 'failed', which is exactly right — a bundle with
            # an error in its log is not one to hand an operator as finished.
            ws.update_run_status(run_id, "completed", progress=100, details=res)
        except Exception as e:                            # noqa: BLE001
            if cancel.is_set():
                return          # request_stop() already marked it cancelled
            traceback.print_exc()
            ws.add_log_to_run(run_id, f"{e}", "error")
            ws.update_run_status(run_id, "failed", error=str(e))
        finally:
            try:
                ws.unregister_cancel(run_id)
            except Exception:
                pass
            if lock is not None:
                try:
                    lock.release()
                except Exception:
                    pass

    threading.Thread(target=_worker, daemon=True).start()


@case_bp.route("/api/cases/<case_id>/export", methods=["POST"])
def export_case(case_id):
    """Start building a portable bundle for this case. 202 + {run_id}."""
    from services import workflow_service as ws
    from services.fusion import case_bundle

    try:
        plan = case_bundle.plan_export(case_id)          # validates before we commit
    except case_bundle.BundleError as e:
        msg = str(e)
        return jsonify({"error": msg}), (404 if "not found" in msg else 409)

    if not _export_lock.acquire(blocking=False):
        return jsonify({"error": "an export is already in progress; try again shortly",
                        "busy": True}), 409
    try:
        run_id = ws.create_automation_run(
            "case_export", f"Export case: {plan['name']}",
            details={"case_id": case_id, "case_name": plan["name"],
                     "runs_exported": len(plan["member_ids"]),
                     "estimate_bytes": plan["estimate_bytes"]})
    except Exception as e:                                # noqa: BLE001
        _export_lock.release()
        return jsonify({"error": str(e)}), 500

    _bundle_thread(case_bundle.export_case_bundle, run_id, case_id, lock=_export_lock)
    return jsonify({"run_id": run_id, "case_id": case_id,
                    "estimate_bytes": plan["estimate_bytes"]}), 202


@case_bp.route("/api/cases/export/<run_id>/download", methods=["GET"])
def download_case_bundle(run_id):
    """Stream the archive built by `run_id`. Streamed by send_file, so the first
    byte leaves immediately however big the file is."""
    import os
    from flask import send_file
    from services import workflow_service as ws
    from services.fusion import case_bundle

    run = ws.get_automation_run(run_id)
    if not run or run.get("automation_type") != "case_export":
        return jsonify({"error": "no such export"}), 404
    det = run.get("details") or {}
    path = det.get("bundle_path")
    if not path:
        return jsonify({"error": "the export has not finished yet"}), 404
    # Containment: the path came out of a run row, and a run row is not a
    # trustworthy source of filesystem paths.
    real = os.path.realpath(path)
    if not real.startswith(os.path.realpath(case_bundle.EXPORT_DIR) + os.sep):
        return jsonify({"error": "that file is not an export bundle"}), 400
    if not os.path.exists(real):
        return jsonify({"error": "This bundle is no longer on disk (a Maintenance "
                                 "purge removes old exports). Export the case again."}), 410
    return send_file(real, as_attachment=True,
                     download_name=det.get("bundle_name") or f"{run_id}{case_bundle.BUNDLE_EXT}",
                     mimetype="application/zip")


@case_bp.route("/api/cases/import", methods=["POST"])
def import_case():
    """Import a bundle sent directly as multipart `file`.

    Kept for the API and the tests. The UI uses the tus path instead: nginx caps
    /api/ bodies at 500 MB and one member payload is bigger than that on its own.
    """
    import os
    from services import workflow_service as ws
    from services.fusion import case_bundle

    f = request.files.get("file")
    if f is None:
        return jsonify({"error": "no bundle provided — send the .intactcase.zip as "
                                 "multipart 'file'"}), 400
    if not _import_lock.acquire(blocking=False):
        return jsonify({"error": "an import is already in progress; try again shortly",
                        "busy": True}), 409
    tmp_dir = os.path.join(case_bundle.EXPORT_DIR, "incoming")
    tmp = os.path.join(tmp_dir, f"upload-{os.getpid()}-{id(f)}.zip")
    run_id = None
    try:
        os.makedirs(tmp_dir, exist_ok=True)
        f.save(tmp)
        run_id = ws.create_automation_run(
            "case_import", f"Import case: {f.filename or 'bundle'}",
            details={"filename": f.filename or "bundle"})
        res = case_bundle.import_case_bundle(tmp, run_id=run_id,
                                             name=request.form.get("name") or None)
        ws.update_run_status(run_id, "completed", progress=100, details=res)
        return jsonify(res)
    except Exception as e:                                # noqa: BLE001
        if run_id:
            ws.add_log_to_run(run_id, f"{e}", "error")
            ws.update_run_status(run_id, "failed", error=str(e))
        return jsonify({"error": str(e)}), 400
    finally:
        try:
            os.remove(tmp)
        except Exception:
            pass
        _import_lock.release()


@case_bp.route("/api/cases/<case_id>/attach", methods=["POST"])
def attach(case_id):
    # Every sibling <case_id>-scoped route checks this; attach() didn't —
    # store.attach_runs() doesn't raise on a bogus id, so a typo'd/stale
    # case_id would silently tag runs to a phantom case (they'd vanish from
    # every real case with no error), an evidence-contamination risk.
    if not store.get_case(case_id):
        return jsonify({"error": "case not found"}), 404
    d = request.get_json(silent=True) or {}
    rids = d.get("run_ids") or ([d["run_id"]] if d.get("run_id") else [])
    if not rids:
        return jsonify({"error": "run_ids required"}), 400
    members, rejected = store.attach_runs(case_id, rids)
    resp = {"case_id": case_id, "member_run_ids": members}
    if rejected:
        resp["rejected"] = rejected
        resp["warning"] = (
            f"{len(rejected)} run(s) already belong to a different case and were "
            f"NOT attached (a run may only belong to one case at a time)."
        )
    if d.get("watch"):                                  # auto-fuse when in-flight runs land
        import threading
        for rid in rids:
            threading.Thread(target=store.watch_and_fuse, args=(case_id, rid), daemon=True).start()
        resp["watching"] = rids
    elif d.get("fuse"):                                 # fuse now
        g = store.fuse_case(case_id, trigger=store.TRIGGER_API_FUSE)
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
    g = store.fuse_case(cid, log=lambda m, l="info": logs.append((l, m)),
                        trigger=store.TRIGGER_CASE_CREATED)
    return jsonify({
        "case_id": cid, "status": "fused", "entities": len(g.entities),
        "relationships": len(g.relationships), "findings": len(g.findings),
        "cross_host_findings": sum(1 for f in g.findings if f.kind == "cross_host"),
        "warnings": [m for lv, m in logs if lv == "warning"],
        "report_md": store.get_case(cid).get("report_md", "")})


@case_bp.route("/api/cases/<case_id>/fuse", methods=["POST"])
def fuse(case_id):
    logs = []
    g = store.fuse_case(case_id, log=lambda m, l="info": logs.append((l, m)),
                        trigger=store.TRIGGER_API_FUSE)
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
    # FusionBusy -> 409 via the blueprint handler (_case_busy), which now covers every
    # route rather than this one alone. Rescan is the benign case: set_analysis_config
    # runs before the fuse, so the config the operator just saved IS persisted and a
    # retry re-fuses with it.
    # The UI names the button it came from; anything else is an API caller.
    _trigs = {"refusion": store.TRIGGER_MANUAL_REFUSION,
              "rescan_llm": store.TRIGGER_MANUAL_RESCAN}
    res = store.rescan(case_id, cfg,
                       trigger=_trigs.get(cfg.get("trigger"), store.TRIGGER_API_FUSE))
    return jsonify({"case_id": case_id, "status": "rescanned", **res})


@case_bp.route("/api/cases/<case_id>/config", methods=["POST"])
def save_config(case_id):
    """Persist the config-rail settings WITHOUT re-fusing — the plain Save button.
    The settings take effect on the next Refusion / Rescan (LLM)."""
    if not store.get_case(case_id):
        return jsonify({"error": "case not found"}), 404
    cfg = request.get_json(silent=True) or {}
    saved = store.set_analysis_config(case_id, cfg)
    return jsonify({"case_id": case_id, "status": "saved", "saved": list(saved.keys())})


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


# ---- Identities: cross-infrastructure identity correlation ----
@case_bp.route("/api/cases/<case_id>/identities", methods=["GET"])
def identities(case_id):
    """Candidate + confirmed identity links for the Identities tab (best-effort)."""
    if not store.get_case(case_id):
        return jsonify({"error": "case not found"}), 404
    res = store.identity_view(case_id)
    return (jsonify(res), 404) if res.get("error") == "not found" else jsonify(res)


@case_bp.route("/api/cases/<case_id>/identities/<link_id>", methods=["POST"])
def decide_identity(case_id, link_id):
    """Confirm / decline a candidate identity link. Persists across re-fusion."""
    if not store.get_case(case_id):
        return jsonify({"error": "case not found"}), 404
    b = request.get_json(silent=True) or {}
    res = store.decide_identity_link(case_id, link_id, b.get("decision", "confirmed"),
                                     a_id=b.get("a_id"), b_id=b.get("b_id"),
                                     kind=b.get("kind"), reason=b.get("reason"))
    return (jsonify(res), 404) if res.get("error") else jsonify({"case_id": case_id, **res})


@case_bp.route("/api/cases/<case_id>/identities/group", methods=["POST"])
def decide_identity_grp(case_id):
    """Confirm / decline a whole grouped relationship (all its member links)."""
    if not store.get_case(case_id):
        return jsonify({"error": "case not found"}), 404
    b = request.get_json(silent=True) or {}
    res = store.decide_identity_group(case_id, b.get("members") or [],
                                      b.get("decision", "confirmed"))
    return (jsonify(res), 404) if res.get("error") else jsonify({"case_id": case_id, **res})


@case_bp.route("/api/cases/<case_id>/identities/account/split", methods=["POST"])
def split_identity_account(case_id):
    """Remove an account from its resolved person ('not this person')."""
    if not store.get_case(case_id):
        return jsonify({"error": "case not found"}), 404
    b = request.get_json(silent=True) or {}
    res = store.split_account(case_id, b.get("account_id"))
    return (jsonify(res), 400) if res.get("error") else jsonify({"case_id": case_id, **res})


@case_bp.route("/api/cases/<case_id>/identities/host/exclude", methods=["POST"])
def exclude_identity_host(case_id):
    """Remove a host from a person's operated-hosts."""
    if not store.get_case(case_id):
        return jsonify({"error": "case not found"}), 404
    b = request.get_json(silent=True) or {}
    res = store.exclude_host(case_id, b.get("name"), b.get("host_id"))
    return (jsonify(res), 400) if res.get("error") else jsonify({"case_id": case_id, **res})


@case_bp.route("/api/cases/<case_id>/identities/undo", methods=["POST"])
def undo_identity(case_id):
    """Undo any stored identity decision (merge / split / host-exclude / declined)."""
    if not store.get_case(case_id):
        return jsonify({"error": "case not found"}), 404
    b = request.get_json(silent=True) or {}
    res = store.undo_identity_decision(case_id, b.get("id"))
    return (jsonify(res), 404) if res.get("error") else jsonify({"case_id": case_id, **res})


@case_bp.route("/api/cases/<case_id>/identities/link", methods=["POST"])
def manual_identity_link(case_id):
    """Manually link two entities (same_identity / operates). Persisted + applied on fuse."""
    if not store.get_case(case_id):
        return jsonify({"error": "case not found"}), 404
    b = request.get_json(silent=True) or {}
    res = store.add_manual_identity_link(case_id, b.get("a_id"), b.get("b_id"),
                                         b.get("kind", "same_identity"))
    return (jsonify(res), 400) if res.get("error") else jsonify({"case_id": case_id, **res})


@case_bp.route("/api/cases/<case_id>/timeline/validate", methods=["POST"])
def timeline_validate(case_id):
    """Triage a timeline entry: real / not_real / known_it / pending. Reversible —
    any transition is allowed; not_real/known_it suppress, real/pending un-suppress."""
    if not store.get_case(case_id):
        return jsonify({"error": "case not found"}), 404
    b = request.get_json(silent=True) or {}
    fid = (b.get("finding_id") or "").strip()
    if not fid:
        return jsonify({"error": "finding_id required"}), 400
    res = store.validate_timeline(case_id, fid, b.get("status", "real"), b.get("notes", ""))
    return jsonify({"case_id": case_id, **res})


@case_bp.route("/api/cases/<case_id>/timeline/event", methods=["POST"])
def timeline_add_event(case_id):
    """Add a manual timeline event (IT-known activity, an out-of-band fact, etc.)."""
    if not store.get_case(case_id):
        return jsonify({"error": "case not found"}), 404
    b = request.get_json(silent=True) or {}
    if not (b.get("title") or "").strip():
        return jsonify({"error": "title required"}), 400
    res = store.add_manual_timeline_event(case_id, b)
    return jsonify({"case_id": case_id, "event": res})


@case_bp.route("/api/cases/<case_id>/timeline/event/<event_id>", methods=["DELETE"])
def timeline_delete_event(case_id, event_id):
    if not store.get_case(case_id):
        return jsonify({"error": "case not found"}), 404
    res = store.delete_manual_timeline_event(case_id, event_id)
    return jsonify({"case_id": case_id, **res})


@case_bp.route("/api/cases/<case_id>/report", methods=["GET"])
def report(case_id):
    d = store.get_case(case_id)
    if not d:
        return jsonify({"error": "case not found"}), 404
    return jsonify({"case_id": case_id, "report_md": d.get("report_md") or "",
                    "audience": d.get("audience", "both"),
                    "report_altitude": d.get("report_altitude") or "auto",
                    "customer_name": d.get("customer_name", ""), "tlp": d.get("tlp", "AMBER"),
                    "has_logo": bool(d.get("customer_logo_b64")),
                    "master_prompt": d.get("master_prompt", "")})


_LOGO_MAX_B64_BYTES = 2 * 1024 * 1024      # ~1.5 MB of image; a cover logo
_LOGO_DATA_URL_RE = re.compile(
    r'^data:image/(png|jpeg|jpg|gif|webp);base64,[A-Za-z0-9+/\r\n]+={0,2}$')


def _validate_logo_data_url(value: str):
    """Return an operator-facing error string, or None when the logo is fine.

    SVG is rejected on purpose even though it is an image: it can carry script
    and external references. Inert under the renderer's data-only fetcher, but
    there is no reason to store it, and the report is a customer deliverable.
    """
    if len(value) > _LOGO_MAX_B64_BYTES:
        return (f"customer_logo_b64 is {len(value) // 1024} KB; the limit is "
                f"{_LOGO_MAX_B64_BYTES // 1024} KB. Use a smaller cover logo.")
    if value.lower().startswith('data:image/svg'):
        return ("SVG logos are not accepted — they can carry script. Use PNG, "
                "JPEG, GIF or WebP.")
    if not _LOGO_DATA_URL_RE.match(value):
        return ("customer_logo_b64 must be an embedded image data URL, e.g. "
                "'data:image/png;base64,<...>'. Remote and local file "
                "references are not fetched when the report is rendered.")
    return None


@case_bp.route("/api/cases/<case_id>/branding", methods=["POST"])
def set_branding(case_id):
    """Set report branding/options: customer_name, customer_logo_b64, tlp, audience, language."""
    if not store.get_case(case_id):
        return jsonify({"error": "case not found"}), 404
    b = request.get_json(silent=True) or {}

    # The logo is interpolated into an <img src> in the generated PDF, so it
    # has to be an EMBEDDED image and nothing else. Unvalidated, a value like
    # "file:///etc/passwd" or an internal http:// URL was stored and then
    # fetched by the renderer. The renderer refuses non-data URLs now
    # (services/engagement/pdf.py:_data_only_url_fetcher); this stops the bad
    # value being persisted in the first place, so the operator finds out when
    # they set it rather than when a report fails months later.
    logo = b.get("customer_logo_b64")
    if logo is not None and str(logo).strip():
        err = _validate_logo_data_url(str(logo).strip())
        if err:
            return jsonify({"error": err}), 400

    saved = store.set_branding(
        case_id, customer_name=b.get("customer_name"),
        customer_logo_b64=b.get("customer_logo_b64"), tlp=b.get("tlp"),
        audience=b.get("audience"), language=b.get("language"))
    return jsonify({"case_id": case_id, "saved": saved})


@case_bp.route("/api/cases/<case_id>/report", methods=["POST"])
def regenerate_report(case_id):
    """Re-narrate the report (+ advisory) at the chosen audience, applying the
    operator master-prompt.

    The deterministic path (no LLM) is fast and answers synchronously, same as
    always. The LLM path (`use_llm: true`, the Regenerate report button) starts
    a BACKGROUND generation and returns immediately (202) — measured live at
    5:29 for a real case across two sequential LLM calls, well past nginx's
    300s /api/ read timeout, which was killing the operator's connection while
    the backend kept working underneath unseen. The frontend polls
    GET /api/cases/<id> (info.report_generating) and refreshes on its own when
    it flips back to false; the Analysis-tab banner already explains a failure
    if that's what happened, so this route doesn't need a separate error path
    for it."""
    if not store.get_case(case_id):
        return jsonify({"error": "case not found"}), 404
    b = request.get_json(silent=True) or {}
    use_llm = bool(b.get("use_llm"))
    if not use_llm:
        res = store.regenerate_report(case_id, audience=b.get("audience"), use_llm=False)
        return jsonify({"case_id": case_id, **res})
    try:
        res = store.regenerate_report_async(case_id, audience=b.get("audience"), use_llm=True)
    except store.ReportGenerationBusy as e:
        # A NORMAL collision (a double-click, or the operator switching tabs and
        # clicking again) — not a failure, so it's logged as one, matching
        # _case_busy's framing below. The generic after_request hook steps aside
        # for any "busy": true 409 so this doesn't ALSO get logged as "failed".
        store.log_case_event(case_id, "Regenerate report", "warning",
                             "deferred — a report is already being generated for "
                             "this case; it will refresh on its own when ready",
                             code=409)
        return jsonify({"error": str(e), "busy": True}), 409
    except ValueError as e:
        return jsonify({"error": str(e)}), 404
    return jsonify({"case_id": case_id, **res}), 202


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
                    headers={"Content-Disposition":
                             f'attachment; filename="{_report_filename(store.get_case(case_id), "md")}"'})


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
                    headers={"Content-Disposition":
                             f'attachment; filename="{_report_filename(d, "pdf")}"'})


@case_bp.route("/api/cases/<case_id>/graph", methods=["GET"])
def graph(case_id):
    d = store.get_case(case_id)
    g = store.load_graph(case_id)   # reads the sidecar (falls back to legacy inline)
    # Is a member still importing? An offline-collector upload / live hunt runs
    # ASYNChronously and can take minutes to pull its rows. Before this flag the
    # case view auto-fused whatever was present — so viewing mid-import showed a
    # blank/partial graph with no explanation and read as "fusion is broken"
    # (reported 2026-07-26). Surface it so the UI can say "importing…" and the
    # operator knows to wait + refresh rather than assume failure.
    import_in_progress = False
    try:
        for rid in store._members_for_case(case_id, d) or []:
            run = store._ws().get_automation_run(rid)
            if run and run.get("status") in ("running", "pending"):
                import_in_progress = True
                break
    except Exception:
        import_in_progress = False
    # Auto-populate: if the case has member runs but no graph has been built yet
    # (e.g. right after an offline import), fuse once on first view so Case
    # Analysis isn't blank. A non-empty cached graph is returned as-is (fast).
    if not g.entities and store._members_for_case(case_id, d):
        try:
            g = store.fuse_case(case_id, trigger=store.TRIGGER_AUTOMATIC_FIRST_VIEW)
        except store.FusionBusy:
            pass          # already fusing — the caller re-reads once it finishes
        except Exception as e:
            # stderr only used to hide this entirely from the operator; the case log
            # is where they are actually looking when the view comes up empty.
            store.log_case_event(case_id, "Refusion failed", "error",
                                 f"first-view automatic fuse failed — "
                                 f"{type(e).__name__}: {e}")
            print(f"[CASE] on-view fuse failed for {case_id}: {e}", flush=True)
    return jsonify({"case_id": case_id, "fusion_graph": g.to_dict(),
                    "import_in_progress": import_in_progress})


@case_bp.route("/api/cases/<case_id>/timeline", methods=["GET"])
def timeline(case_id):
    if not store.get_case(case_id):
        return jsonify({"error": "case not found"}), 404
    # each row carries finding_id + validation status (real/not_real/unknown)
    return jsonify({"case_id": case_id, "timeline": store.get_timeline(case_id)})


@case_bp.route("/api/cases/<case_id>/finding/<path:finding_id>", methods=["GET"])
def finding_detail(case_id, finding_id):
    """On-demand per-occurrence detail for one timeline finding (clicked row). Keeps the
    timeline table lean — detail is fetched only when needed."""
    if not store.get_case(case_id):
        return jsonify({"error": "case not found"}), 404
    det = store.get_finding_detail(case_id, finding_id)
    if det is None:
        return jsonify({"error": "case not found"}), 404
    return jsonify(det)


@case_bp.route("/api/cases/<case_id>/chat", methods=["POST"])
def chat(case_id):
    d = request.get_json(silent=True) or {}
    q = (d.get("question") or d.get("message") or "").strip()
    if not q:
        return jsonify({"error": "question required"}), 400
    ans = store.chat_case(case_id, q)
    return jsonify({"case_id": case_id, "answer": ans})


@case_bp.route("/api/cases/<case_id>/chat", methods=["GET"])
def chat_history(case_id):
    """The persisted conversation, so the chat survives a refresh."""
    if not store.get_case(case_id):
        return jsonify({"error": "case not found"}), 404
    return jsonify({"case_id": case_id, "messages": store.get_chat(case_id)})


@case_bp.route("/api/cases/<case_id>/chat", methods=["DELETE"])
def chat_clear(case_id):
    if not store.get_case(case_id):
        return jsonify({"error": "case not found"}), 404
    return jsonify({"case_id": case_id, **store.clear_chat(case_id)})


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


