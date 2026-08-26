#!/usr/bin/env python3
"""
Dashboard Routes - Dashboard/workflow endpoints
"""

import threading

from flask import Blueprint, jsonify

from services import (
    get_all_automation_runs,
    get_automation_run
)

dashboard_bp = Blueprint('dashboard', __name__)


def _transform_run(run):
    """Transform backend run data to frontend format."""
    if not run:
        return None
    return {
        "id": run.get("run_id", run.get("id")),
        "type": run.get("automation_type", run.get("type", "system")),
        "name": run.get("name", "Unknown"),
        "status": run.get("status", "unknown"),
        "progress": run.get("progress", 0),
        "started_at": run.get("created_at", run.get("started_at")),
        "updated_at": run.get("updated_at"),
        "logs": run.get("logs", []),
        "details": run.get("details", {}),
        "error": run.get("error"),
        # Auto-incremented by add_log_to_run() whenever level='error'.
        # Drives the small "N errors" badge in the Workflows tab so
        # operators can quickly see runs that finished with errors —
        # even when status='completed' was forced through with force=True.
        "error_count": int(run.get("error_count") or 0),
        # Observability fields surfaced for the dashboard. Each is a JSON
        # blob persisted by the pipeline; the frontend renders these into
        # per-stage timing bar, LLM cost summary, and per-rule detection tally.
        "phase_timings": run.get("phase_timings"),
        "llm_metrics": run.get("llm_metrics"),
        "sigma_rule_tally": run.get("sigma_rule_tally"),
    }


@dashboard_bp.route('/api/dashboard/automations')
def get_all_automations():
    """Get automation runs for the dashboard, STRICTLY scoped to the active
    workspace (the X-Case-Id header).

    Each workspace shows only its own runs. System/admin runs
    (upgrade/maintenance/purge/support-bundle/settings/…) always run as the
    built-in System workspace, so they appear only there — switch to the
    System workspace then Workflows to see them. They must NOT leak into an
    investigation workspace like Default."""
    from flask import g
    automation_runs = get_all_automation_runs()
    case_id = getattr(g, "case_id", None)
    if case_id:
        automation_runs = [r for r in automation_runs if r.get("case_id") == case_id]
    for run in automation_runs:
        _reconcile_velociraptor_hunt(run)
    transformed = [_transform_run(run) for run in automation_runs]
    return jsonify({
        "runs": transformed,
        "total": len(transformed)
    })

def _run_visible_in_active_workspace(run):
    """Mirror get_all_automations()' workspace scoping for single-resource
    lookups by run_id: run_id is a predictable id ({type}_{millis}), so
    without this check an operator in one case could read/stop/read-logs-of
    another case's (or the System workspace's) runs just by guessing/trying
    ids. Same rule as the list route: no active case_id means no filtering
    (admin/no-workspace-concept context).

    System-operation runs (SYSTEM_TYPES) are always visible regardless of
    the active case: /api/system/actions (Settings -> Actions) already
    lists them independent of X-Case-Id, since System stopped being a
    selectable workspace — but its "Logs"/"Stop" buttons reuse THIS same
    per-run lookup. Without this exemption, every one of those buttons
    404'd with "not found" for anyone whose active workspace isn't System
    (which is everyone, since System can no longer be selected), even
    though the run is right there in the list they clicked it from."""
    from flask import g
    from services.workflow_service import SYSTEM_TYPES
    if run.get("automation_type") in SYSTEM_TYPES:
        return True
    case_id = getattr(g, "case_id", None)
    if not case_id:
        return True
    return run.get("case_id") == case_id


@dashboard_bp.route('/api/dashboard/automation/<run_id>')
def get_automation_details(run_id):
    """Get detailed information about a specific automation run"""
    run = get_automation_run(run_id)
    if run and _run_visible_in_active_workspace(run):
        _reconcile_velociraptor_hunt(run)
        return jsonify(_transform_run(run))

    return jsonify({"error": f"Automation run {run_id} not found"}), 404


def _reconcile_velociraptor_hunt(run):
    """A velociraptor_hunt run is marked 'running' at dispatch time (the hunt
    object itself stays RUNNING for its whole expire window, so Velociraptor
    never tells us "done" the way a single flow does). On each poll of this
    endpoint, check whether every scheduled client has actually finished and
    flip the run to 'completed' — this is what makes the dashboard converge
    to an accurate status without a background poller."""
    if run.get("status") != "running" or run.get("automation_type") != "velociraptor_hunt":
        return
    hunt_id = (run.get("details") or {}).get("hunt_id")
    if not hunt_id:
        return
    from services.velociraptor_service import is_hunt_registered
    from services.workflow_service import update_run_status
    if is_hunt_registered(hunt_id):
        update_run_status(run.get("run_id", run.get("id")), "completed", progress=100)
        run["status"] = "completed"
        run["progress"] = 100

# How to replay each run type: the dispatch endpoint, plus how to rebuild the
# request body from what the run persisted.
#
# Deliberately returns a SPEC for the browser to POST rather than re-dispatching
# server-side. The rerun then travels the exact path the UI uses -- same
# validation, same workspace header, same error reporting -- instead of a second
# copy of the launch logic that drifts the first time a route gains a parameter.
#
# Investigation runs only. System operations (upgrade, system_purge,
# prepare_package, offline apply) are deliberately absent: "rerun" one click
# away in a list is how someone re-triggers a purge or a half-finished upgrade
# by accident, and those already have their own guarded entry points.
_RERUN_SPECS = {
    'velociraptor_collection': ('/api/agentic/run', lambda d: {
        'blueprint_id': d.get('blueprint_id'),
        'client_ids': d.get('client_ids') or [],
        'collection_minutes': d.get('collection_minutes') or 30,
    }),
    'velociraptor_hunt': ('/api/velociraptor/bestpractice', lambda d: {
        'artifacts': d.get('artifacts') or ([d['artifact']] if d.get('artifact') else []),
        'blueprint_name': d.get('blueprint') or 'Custom',
        'expire_minutes': d.get('expire_minutes') or 120,
        'timeout_seconds': d.get('timeout_seconds') or 10000,
        'cpu_limit': d.get('cpu_limit') or 50,
        'per_artifact': bool(d.get('per_artifact')),
        'include_labels': d.get('include_labels') or [],
    }),
    'memory': ('/api/memory/run', lambda d: {
        'client_id': d.get('client_id'),
        'blueprint_id': d.get('blueprint_id'),
        'include_yara': d.get('include_yara', True),
        'case_name': d.get('case_name'),
    }),
}

# A payload is only replayable when these are actually present. Checked instead
# of trusting the type: a run that died before its config was written, or one
# created by an older release that stored less, would otherwise "rerun" with
# defaults silently -- a different job wearing the same name.
# An entry may be a field name, or a tuple of alternatives when the same
# information has been stored under different keys across releases -- older
# hunt rows carry a singular `artifact` where current ones carry `artifacts`.
# The builder already handles that fallback; requiring the new name alone made
# the guard reject runs the builder could rebuild perfectly.
_RERUN_REQUIRED = {
    'velociraptor_collection': ('blueprint_id', 'client_ids'),
    'velociraptor_hunt': (('artifacts', 'artifact'),),
    'memory': ('client_id',),
}


@dashboard_bp.route('/api/dashboard/automation/<run_id>/rerun-spec', methods=['GET'])
def rerun_spec(run_id):
    """How to relaunch `run_id` with its original configuration.

    Returns {supported, endpoint, payload} so the caller can POST it, or
    {supported: false, reason} explaining why it cannot be replayed. Never
    launches anything itself -- a GET that started work would rerun on every
    accidental refresh.
    """
    run = get_automation_run(run_id)
    if not run or not _run_visible_in_active_workspace(run):
        return jsonify({"error": f"Automation run {run_id} not found"}), 404

    atype = run.get('automation_type')
    spec = _RERUN_SPECS.get(atype)
    if not spec:
        return jsonify({
            "supported": False,
            "reason": f"'{atype}' runs cannot be relaunched from here.",
        })

    details = run.get('details') or {}
    missing = []
    for req in _RERUN_REQUIRED.get(atype, ()):
        alts = (req,) if isinstance(req, str) else tuple(req)
        if not any(details.get(a) for a in alts):
            missing.append(' or '.join(alts))
    if missing:
        return jsonify({
            "supported": False,
            "reason": ("This run did not record its configuration ("
                       + ", ".join(missing) + "), so it cannot be reproduced. "
                       "Launch it from its own page instead."),
        })

    endpoint, build = spec
    try:
        payload = build(details)
    except Exception as e:      # noqa: BLE001 — a malformed run must not 500
        return jsonify({"supported": False,
                        "reason": f"Could not rebuild the configuration: {e}"})
    return jsonify({"supported": True, "endpoint": endpoint, "payload": payload,
                    "source_run_id": run_id, "automation_type": atype})


# ---------------------------------------------------------------------------
# RE-COLLECT — fetch what Velociraptor already has. NOT a re-run.
#
# The distinction is the whole feature. Re-run launches a fresh collection and
# costs the customer's endpoint another hour; re-collect touches no endpoint at
# all, it only asks the Velociraptor SERVER for results it is already holding.
#
# Every one of these leaves data on the server that the run never picked up, and
# three of them are not bugs:
#   * the collection budget expired while the flow was still going. Measured
#     2026-08-26 on DESKTOP-566AT85: a 10-minute BestPractice run ended with
#     "Some flows had not finished yet — they keep running in Velociraptor".
#     The operator set 10 minutes and the work needed longer. Nothing to fix.
#   * a hunt collects over its whole expire window, but its run is marked
#     completed as soon as Velociraptor HOLDS the hunt — seconds after dispatch.
#     Clients reporting over the next two hours arrive long after.
#   * runs collected before the errored-flow fix stopped at the first error.
#
# What it must never become is a second copy of the launch path. It re-uses the
# exact fetch fusion uses (get_existing_collection_results), so there is one
# implementation of "read a flow's results" and it cannot drift.
_RECOLLECTABLE = ("velociraptor_collection", "velociraptor_upload",
                  "velociraptor_hunt", "velociraptor_offline_import",
                  "velociraptor_adopt")

_recollect_lock = threading.Lock()
_recollecting = set()


def _recollect_locator(details):
    """(flow_id, hunt_id, client_ids) for the fetch, or None when unlocatable.

    A collection stores `flow_id` — as a LIST when several clients were selected,
    a bare string when one was. An offline import stores flow_id + client_id. A
    hunt stores hunt_id. Mirrors what fusion's _contribution_for_run accepts, so
    anything fusion can read, this can refetch.
    """
    hunt_id = details.get("hunt_id")
    if hunt_id:
        return None, hunt_id, None
    flow = details.get("flow_id")
    if isinstance(flow, list):
        flow = flow[0] if len(flow) == 1 else flow      # multi handled by caller
    if not flow:
        return None, None, None
    cid = details.get("client_id")
    return flow, None, ([cid] if cid else None)


def _recollect_worker(run_id, run):
    from services.workflow_service import add_log_to_run, mutate_run_details
    from services.agentic.collectors import (get_existing_collection_results,
                                             persist_pipeline_artifacts)
    details = run.get("details") or {}
    flow_id, hunt_id, client_ids = _recollect_locator(details)
    flows = flow_id if isinstance(flow_id, list) else ([flow_id] if flow_id else [])
    try:
        _what = f"hunt {hunt_id}" if hunt_id else (
            f"{len(flows)} flow(s)" if len(flows) != 1 else f"flow {flows[0]}")
        add_log_to_run(run_id, f"[Fetch] Asking Velociraptor for this run's results "
                               f"({_what}) — no new collection is being started.", "info")
        # progress_log=True: the fetch IS the operation here, and a hunt keeps
        # collecting after its window closes, so an operator re-fetches the same
        # run repeatedly. One line then two minutes of silence is
        # indistinguishable from a button that did nothing — every source is
        # reported as it lands, the same way a live collection reports.
        merged = {}
        if hunt_id:
            got, _arts, _ci = get_existing_collection_results(
                run_id, hunt_id=hunt_id, progress_log=True)
            merged.update(got or {})
        else:
            # Several flows (one per client) merge into one result set, exactly
            # as the original collection did.
            for _i, fid in enumerate(flows, 1):
                if len(flows) > 1:
                    add_log_to_run(run_id, f"[Fetch] Flow {_i}/{len(flows)}: {fid}", "info")
                got, _arts, _ci = get_existing_collection_results(
                    run_id, flow_id=fid, client_ids=client_ids, progress_log=True)
                for k, v in (got or {}).items():
                    merged.setdefault(k, [])
                    merged[k].extend(v or [])

        rows = sum(len(v or []) for v in merged.values())
        before = int(details.get("total_rows") or 0)
        if not merged:
            add_log_to_run(run_id, "[Fetch] Velociraptor returned nothing for this "
                                   "run. Its results may have expired on the server, or "
                                   "no client has reported yet.", "warning")
            return

        persist_pipeline_artifacts(run_id, merged)
        mutate_run_details(run_id, lambda d: d.update(
            {"total_rows": rows, "artifact_count": len(merged),
             "last_recollected_rows": rows}))
        gained = rows - before
        add_log_to_run(
            run_id,
            f"[Fetch] Done — {rows:,} row(s) across {len(merged)} artifact(s)"
            + (f", {gained:+,} vs the last fetch." if before else ".")
            + (" A hunt keeps collecting after its window closes; fetch again "
               "later to pick up more." if hunt_id else ""),
            "success")

        # Make the case treat this run as new data again. Without this the
        # re-collected rows sit in raw_results.json and never reach the graph:
        # stale_member_runs only counts members that are NOT in fused_run_ids,
        # so a run that has been fused once is never stale again however much
        # its data grows. Dropping it from that list is honest — it genuinely
        # holds something the graph has not seen.
        case_id = run.get("case_id")
        if case_id:
            try:
                from services.fusion import store as fusion_store, autofuse
                d = fusion_store.get_case(case_id) or {}
                fused = [x for x in (d.get("fused_run_ids") or []) if x != run_id]
                fusion_store._merge_case_details(case_id, {"fused_run_ids": fused})
                autofuse.schedule(case_id, reason=f"re-collected {run_id}")
                add_log_to_run(run_id, "[Fetch] The case will fold this in and "
                                       "refresh its report automatically.", "info")
            except Exception as e:      # noqa: BLE001 — the rows are saved either way
                add_log_to_run(run_id, f"[Fetch] Saved, but the case could not be "
                                       f"re-armed ({e}). Press Refusion on the case.",
                               "warning")
    except Exception as e:              # noqa: BLE001 — a worker thread must not die loudly
        add_log_to_run(run_id, f"[Fetch] Failed: {type(e).__name__}: {e}", "error")
    finally:
        with _recollect_lock:
            _recollecting.discard(run_id)


@dashboard_bp.route('/api/dashboard/automation/<run_id>/recollect', methods=['POST'])
def recollect(run_id):
    """Re-fetch this run's results from Velociraptor. Starts no collection."""
    run = get_automation_run(run_id)
    if not run or not _run_visible_in_active_workspace(run):
        return jsonify({"error": f"Automation run {run_id} not found"}), 404

    atype = run.get("automation_type")
    if atype not in _RECOLLECTABLE:
        return jsonify({"supported": False,
                        "error": f"'{atype}' runs hold no Velociraptor results to "
                                 f"re-fetch."}), 400
    if run.get("status") in ("running", "pending"):
        return jsonify({"supported": False,
                        "error": "This run is still collecting — wait for it to "
                                 "finish, then re-collect."}), 409

    details = run.get("details") or {}
    flow_id, hunt_id, _cids = _recollect_locator(details)
    if not flow_id and not hunt_id:
        return jsonify({"supported": False,
                        "error": "This run did not record a Velociraptor flow or "
                                 "hunt id, so there is nothing to re-fetch."}), 400

    with _recollect_lock:
        if run_id in _recollecting:
            return jsonify({"error": "A re-collect is already running for this "
                                     "run.", "busy": True}), 409
        _recollecting.add(run_id)

    threading.Thread(target=_recollect_worker, args=(run_id, run),
                     daemon=True, name=f"recollect-{run_id}").start()
    return jsonify({"success": True, "run_id": run_id,
                    "message": "Re-collecting from Velociraptor — follow the "
                               "run's log."}), 202


@dashboard_bp.route('/api/dashboard/automation/<run_id>/stop', methods=['POST'])
def stop_automation(run_id):
    """Stop a running workflow and clean up its resources"""
    from services.workflow_service import request_stop
    run = get_automation_run(run_id)
    if not run or not _run_visible_in_active_workspace(run):
        return jsonify({"error": f"Automation run {run_id} not found"}), 404
    if run.get('status') not in ('running', 'pending'):
        return jsonify({"error": f"Cannot stop workflow in '{run.get('status')}' state"}), 400

    # POINT OF NO RETURN: an upgrade that has committed Phase 1 cannot be
    # stopped, and pretending otherwise is worse than refusing.
    #
    # request_stop() sets an IN-MEMORY cancel event. Phase 1 ends by swapping
    # the backend image and restarting the container — which destroys that
    # event along with the process holding it. The boot-time resume in app.py
    # then finds the pending upgrade_state, registers a FRESH (unset) cancel
    # event, and drives Phase 2 to completion. Meanwhile update_run_status()
    # and add_log_to_run() both hard-ignore everything once a run is
    # 'cancelled', so none of that work is visible.
    #
    # Observed 2026-07-22: operator hit Stop at 5%, UI showed "cancelled",
    # and the platform went on to fully upgrade itself — backend swapped and
    # four modules installed — with no trace in the run log.
    #
    # Refusing is the honest answer AND the safe one: once the backend runs
    # the new image, Phase 2 is what converges the modules to match it.
    # Stopping in between strands the box on new platform code driving old
    # module versions. Pre-commit cancels (phase1, before any state is
    # written) still work exactly as before.
    # A guard used to live here refusing to stop an upgrade past its
    # 'point of no return' -- Phase 1 had swapped the backend image and only
    # Phase 2 could bring the modules up to match it. Upgrades run on the
    # host now and have no phases, so there is no half-applied state for a
    # stop to strand.
    request_stop(run_id)
    return jsonify({"status": "cancelled", "run_id": run_id})


@dashboard_bp.route('/api/dashboard/automation/<run_id>/logs')
def get_automation_logs(run_id):
    """Get logs for a specific automation run"""
    run = get_automation_run(run_id)
    if run and _run_visible_in_active_workspace(run):
        return jsonify({
            "id": run_id,
            "logs": run["logs"]
        })

    return jsonify({"error": f"Automation run {run_id} not found"}), 404
