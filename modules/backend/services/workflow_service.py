#!/usr/bin/env python3
"""
Workflow Service - Centralized workflow and job tracking with SQLite + Elasticsearch
"""

import os
import signal
import subprocess
import time
import threading
from datetime import datetime
from services.file_storage_service import (
    save_workflow,
    load_workflows,
    get_workflow as file_get_workflow,
    get_workflows_by_case,
)

# Investigation run types that belong to a case (workspace) — these get tagged
# with the active case and are shown ONLY in that workspace. System/admin runs
# (upgrade, online_upgrade, prepare_package, maintenance, support_bundle, settings,
# system_purge) and the internal case/fusion_baseline rows are NOT case work and
# never appear in a workspace's run list.
AGENTIC_TYPES = {"velociraptor_collection", "memory", "timesketch",
                 "aws_scan", "azure_scan",
                 "velociraptor_hunt",
                 # An offline-collector ZIP upload IS case work: it imports a
                 # flow AND (in the same run) collects it into the fused graph.
                 # Listing it here makes the single upload row a case member —
                 # it shows in the workspace and is picked up by the fuse.
                 "velociraptor_upload",
                 # A flow/hunt an analyst ran directly in the Velociraptor GUI and
                 # then adopted into this case by id. It is case work like any
                 # other collection — listing it here makes the run a case member
                 # and lets the terminal-status hook below arm the fuse, which is
                 # the whole point of adopting it.
                 "velociraptor_adopt"}

# Statuses that mean "this run's data is final and fuseable". Deliberately the
# SAME pair fusion.store.stale_member_runs counts as members, so the auto-fuse
# arms exactly when there is something new for it to fold in — arming on 'failed'
# or 'cancelled' would schedule a fuse that finds nothing stale and does nothing.
_TERMINAL_STATUSES = ("completed", "success")

# Settings-page / system-operation run types. These always run under the built-in
# "System" workspace (regardless of the browser's active case) so they have a home
# and never clutter an investigation workspace.
SYSTEM_TYPES = {"upgrade", "online_upgrade", "prepare_package", "maintenance",
                "system_purge", "support_bundle", "settings",
                "case_import", "case_export",
                # An imported upgrade PACKAGE upload is a system op, exactly like
                # the `upgrade`/`online_upgrade` apply it feeds. Without this it
                # was forced to the active/Default workspace while the apply run
                # went to System — so the import showed up as two rows in two
                # different workspaces (and "vanished" for an operator viewing
                # System). It rides in the SAME System workspace as the apply now.
                # NB: only the UPGRADE-package upload — velociraptor_upload /
                # timesketch_upload stay investigation-workspace runs.
                "upgrade_package_upload"}

# Internal bookkeeping run-types (match services.fusion.store CASE_TYPE /
# BASELINE_TYPE). The workspace row + fusion baseline marker are not case work
# and not system ops — they carry their own case_id and must never be forced to
# the active workspace or blocked by the System-workspace guard.
INTERNAL_CASE_TYPES = {"case", "fusion_baseline"}


_DEFAULT_CASE_CACHE = {"id": None}
_SYSTEM_CASE_CACHE = {"id": None}


class WorkspaceError(Exception):
    """An operation isn't allowed in the resolved workspace — e.g. an
    investigation feature targeting the built-in System workspace. The
    app-level errorhandler turns this into an HTTP 409 with this message."""
    pass


def _system_case_id():
    """Id of the built-in System workspace (cached). None if it can't be
    resolved (e.g. store unavailable)."""
    if not _SYSTEM_CASE_CACHE["id"]:
        try:
            from services.fusion import store
            _SYSTEM_CASE_CACHE["id"] = store.ensure_system_case()
        except Exception:
            pass
    return _SYSTEM_CASE_CACHE["id"]


def _active_case_from_request():
    """The browser's active case (X-Case-Id header), read off the Flask request
    context. Returns None outside a request (e.g. a background re-fuse)."""
    try:
        from flask import g, has_request_context
        if has_request_context():
            return getattr(g, "case_id", None)
    except Exception:
        pass
    return None


def _default_case_id():
    """Id of the built-in Default workspace (cached). Ensures it exists."""
    if not _DEFAULT_CASE_CACHE["id"]:
        try:
            from services.fusion import store
            _DEFAULT_CASE_CACHE["id"] = store.ensure_default_case()
        except Exception:
            pass
    return _DEFAULT_CASE_CACHE["id"]


def _mark_workspace_redirect(case_id):
    """Flag on the Flask request that a module run was redirected off the System
    workspace to `case_id` (Default), so an after_request hook can echo it to the
    browser (X-Active-Case) and the UI can follow. No-op outside a request."""
    try:
        from flask import g, has_request_context
        if has_request_context() and case_id:
            g.workspace_redirect = case_id
    except Exception:
        pass


def _resolve_case_id(automation_type, case_id):
    """Tag every run to a workspace. ONE universal rule so no module/feature can
    silently fall through and become invisible in the workspace-scoped views:

    - System-operation runs (SYSTEM_TYPES) ALWAYS go to the System workspace,
      regardless of the request's active case.
    - EVERYTHING ELSE is module/feature work and goes to the ACTIVE workspace:
      an explicitly-passed case_id wins, then the request's active case
      (X-Case-Id), then (scheduler/background, no request) the Default
      workspace. The System workspace is reserved for system ops, so module
      work must never land there.

    Previously only an allow-list (AGENTIC_TYPES) got the active-case treatment
    and anything else returned an untagged (None) run that vanished from every
    workspace's Workflows view (e.g. velociraptor_offline_collector). Defaulting
    to the active case closes that gap for all current and future run types.
    """
    # Internal bookkeeping rows — the workspace/case row itself ("case") and the
    # fusion baseline marker ("fusion_baseline"). These are neither module work
    # nor system ops: they manage their own case_id (passed explicitly, usually
    # None = untagged). They must bypass BOTH active-case tagging AND the
    # System-workspace guard, or creating a workspace WHILE the System workspace
    # is active raises WorkspaceError ("create failed"). Return case_id verbatim.
    if automation_type in INTERNAL_CASE_TYPES:
        return case_id

    if automation_type in SYSTEM_TYPES:
        return _system_case_id() or case_id

    # Module / feature run -> active workspace.
    cid = case_id or _active_case_from_request()
    if cid:
        if cid == _system_case_id():
            # Modules never run in the System workspace. Instead of blocking the
            # launch, transparently redirect it to the Default investigation
            # workspace and flag the request so the UI switches to Default too
            # (mirrors system ops -> System). This runs uniformly for every
            # module regardless of how its route reports errors — no dependency
            # on a WorkspaceError 409 reaching the browser. Only raises if the
            # Default workspace can't be resolved at all.
            default_id = _default_case_id()
            if default_id:
                _mark_workspace_redirect(default_id)
                return default_id
            raise WorkspaceError(
                "Modules run against an investigation workspace, not the System "
                "workspace. Switch to or create an investigation workspace first."
            )
        return cid

    # No active case (scheduler / background, no request context) -> Default.
    return _default_case_id()

# Try to import Elasticsearch service
try:
    from services.elasticsearch_service import (
        get_all_workflow_runs as es_get_all_workflows,
        get_workflow_run as es_get_workflow,
        update_workflow_status as es_update_workflow_status
    )
    ES_AVAILABLE = True
except ImportError:
    ES_AVAILABLE = False

# ES_AVAILABLE only means the `elasticsearch` package imported — it's a hard
# dependency baked into the image, so this was True even on installs where
# the operator left modules.elk.enabled: false in config.yaml (the common
# case). Nothing gated on the actual config flag, so cleanup_orphan_workflows/
# get_all_automation_runs/get_automation_run — called on nearly every
# dashboard load, case view, upload, and fusion re-fuse — each attempted a
# fresh network connection (with its own retries/timeout) to a host that was
# never even started. Cached (config rarely changes at runtime; a stale
# read for a few seconds is harmless) so this doesn't add a YAML parse to
# every one of those hot-path calls.
_elk_enabled_cache = {"value": None, "checked_at": 0.0}
_ELK_ENABLED_CACHE_TTL = 30.0


def _elk_enabled() -> bool:
    import time as _time
    now = _time.time()
    if _elk_enabled_cache["value"] is None or (now - _elk_enabled_cache["checked_at"]) > _ELK_ENABLED_CACHE_TTL:
        try:
            from config import is_module_enabled
            _elk_enabled_cache["value"] = ES_AVAILABLE and is_module_enabled('elk')
        except Exception:
            _elk_enabled_cache["value"] = False
        _elk_enabled_cache["checked_at"] = now
    return _elk_enabled_cache["value"]

# Enhanced job tracking with detailed logs
jobs = {}

# Cancel/stop infrastructure
_cancel_events: dict[str, threading.Event] = {}
_cleanup_callbacks: dict[str, list] = {}
_cancel_lock = threading.Lock()


def register_cancel_event(run_id) -> threading.Event:
    """Register a cancel event for a workflow run. Returns the Event to check in the pipeline."""
    with _cancel_lock:
        event = threading.Event()
        _cancel_events[run_id] = event
        _cleanup_callbacks[run_id] = []
        return event


def register_cleanup(run_id, callback):
    """Register a cleanup callback for a workflow run. Called when stop is requested."""
    with _cancel_lock:
        if run_id in _cleanup_callbacks:
            _cleanup_callbacks[run_id].append(callback)


def is_cancelled(run_id) -> bool:
    """Check if a workflow run has been cancelled."""
    event = _cancel_events.get(run_id)
    return event.is_set() if event else False


def get_cancel_event(run_id):
    """Return the cancel Event for a run, or None if no run/registration.

    Useful for downstream callees (subprocess loops, polling waits) that
    were handed only a run_id and need to poll cancellation. Mirrors the
    Event returned by register_cancel_event.
    """
    return _cancel_events.get(run_id)


def terminate_subprocess(process, timeout: float = 5.0) -> None:
    """SIGTERM the process's whole process group, wait briefly, then SIGKILL.

    Kills the ENTIRE process group, not just the immediate child. A command
    that forks a long-lived helper (docker build/buildx sessions are the
    observed case — `docker compose build backend` outliving its stated
    timeout by hours, freezing the calling thread forever) can otherwise
    survive: the immediate child dies, but the surviving grandchild keeps
    the captured stdout/stderr pipes open, so any subsequent read of them
    (communicate()) blocks forever with no further timeout protection.
    Requires the Popen to have been started with start_new_session=True;
    falls back to killing just the process itself otherwise.

    Idempotent — safe to call from a cleanup callback even if the process
    has already exited (returns silently). Best-effort: never raises.
    Centralised here so every Popen call site uses the same kill cadence
    instead of copy-pasted try/except blocks.
    """
    if not process or process.poll() is not None:
        return

    def _signal(sig):
        try:
            os.killpg(os.getpgid(process.pid), sig)
        except Exception:
            try:
                if sig == signal.SIGTERM:
                    process.terminate()
                else:
                    process.kill()
            except Exception:
                pass

    try:
        _signal(signal.SIGTERM)
        try:
            process.wait(timeout=timeout)
            return
        except subprocess.TimeoutExpired:
            pass
        _signal(signal.SIGKILL)
        try:
            process.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            pass
    except Exception:
        # Process already gone, OS doesn't know it, nothing useful to do.
        pass


def request_stop(run_id, reason=None):
    """Stop a running workflow: set cancel event, run cleanup callbacks, update status.

    `reason` is recorded on the run and named in the log. Without it every stop
    reads "Stop requested by user" and leaves `error: None` — which is a lie when
    the watchdog did it, and left an operator looking at a QA run that said
    "cancelled, 50%" with nothing anywhere stating why (measured 2026-08-26,
    velociraptor_collection_1787727431255).
    """
    with _cancel_lock:
        event = _cancel_events.get(run_id)
        callbacks = list(_cleanup_callbacks.get(run_id, []))

    if event:
        event.set()

    # Run all cleanup callbacks (outside lock to avoid deadlocks)
    for cb in callbacks:
        try:
            cb()
        except Exception as e:
            print(f"[WORKFLOW] Cleanup callback error for {run_id}: {e}", flush=True)

    add_log_to_run(run_id,
                   f"[Pipeline] {reason}" if reason else "[Pipeline] Stop requested by user",
                   "warning")
    update_run_status(run_id, "cancelled", error=reason or None)

    # Clean up registry
    with _cancel_lock:
        _cancel_events.pop(run_id, None)
        _cleanup_callbacks.pop(run_id, None)


def unregister_cancel(run_id):
    """Remove cancel registration when a workflow completes naturally."""
    with _cancel_lock:
        _cancel_events.pop(run_id, None)
        _cleanup_callbacks.pop(run_id, None)

# Initialize file storage on module load
print("[WORKFLOW] Using SQLite + Elasticsearch storage for workflows", flush=True)

# run_id was `{type}_{ms}` — two runs created in the SAME millisecond collided on the
# id and the second INSERT OR REPLACE silently overwrote the first (so a case could only
# ever hold one of them). Hand out monotonically-increasing ids under a lock to guarantee
# uniqueness. Format unchanged (`{type}_{int}`), so existing ids/paths stay valid.
_run_id_lock = threading.Lock()
_last_run_ms = [0]


def _next_run_id(automation_type) -> str:
    with _run_id_lock:
        ms = int(time.time() * 1000)
        if ms <= _last_run_ms[0]:
            ms = _last_run_ms[0] + 1
        _last_run_ms[0] = ms
    return f"{automation_type}_{ms}"


def create_automation_run(automation_type, name, details=None, case_id=None):
    """Create a new automation run entry with logging.

    `case_id` tags the run to a case (workspace). When not given explicitly and
    this is an analysis run type, it defaults to the browser's active case
    (X-Case-Id header on the current request). Infra/admin runs stay untagged."""
    run_id = _next_run_id(automation_type)

    case_id = _resolve_case_id(automation_type, case_id)

    # Create workflow run structure. `error_count` is incremented every
    # time add_log_to_run() is called with level='error'; it surfaces as
    # a small "N errors" badge in the Workflows tab so an operator can
    # quickly spot runs that finished with status='completed' but
    # actually had fatal errors logged. See the QA bug context — a
    # Velociraptor flow logged "Could not find flow ... No data found"
    # at error level and the run still went green.
    workflow_data = {
        "run_id": run_id,
        "automation_type": automation_type,
        "name": name,
        "details": details or {},
        "status": "pending",
        "progress": 0,
        "logs": [],
        "error_count": 0,
        "case_id": case_id,
        "created_at": datetime.now().isoformat(),
        "updated_at": datetime.now().isoformat()
    }

    # Save to file
    save_workflow(workflow_data)

    return run_id


def get_automation_runs_by_case(case_id):
    """All runs tagged to a case (workspace), newest first. SQLite-backed
    (the case_id column); ES-only rows are not case-scoped."""
    runs = get_workflows_by_case(case_id) or []
    runs.sort(key=lambda x: x.get('created_at', ''), reverse=True)
    return runs

# Per-run mutex registry. add_log_to_run does load-modify-save against the
# workflow row; without serialization, parallel worker threads (e.g. the
# ThreadPoolExecutor in agentic.analyzers) race and silently lose log
# entries — observed in run agentic_1777379525079 where 4 of 9 [Skill] /
# "Analysis complete" lines vanished.  Per-run granularity (not a global
# lock) lets independent runs continue writing in parallel.
_RUN_LOG_LOCKS: dict = {}
_RUN_LOG_LOCKS_GUARD = threading.Lock()


def _get_run_log_lock(run_id):
    """Return the per-run lock, creating it on first use. The guard lock
    only protects the dict-creation, never held during the actual log write.
    """
    with _RUN_LOG_LOCKS_GUARD:
        lock = _RUN_LOG_LOCKS.get(run_id)
        if lock is None:
            lock = threading.Lock()
            _RUN_LOG_LOCKS[run_id] = lock
        return lock


def add_log_to_run(run_id, log_message, log_level="info", force=False):
    """Add a log entry to an automation run.

    Thread-safe per run_id: load-modify-save is serialized so concurrent
    worker threads do not silently overwrite each other's log appends.

    Also auto-increments `error_count` when log_level == 'error'. The
    counter is read at terminal-status time so a pipeline that logs a
    fatal error mid-run can't accidentally end up marked 'completed'
    — see update_run_status() for the auto-flip rule.

    `force=True` writes even to a cancelled run. Use it ONLY for work the
    operator deliberately started after the cancel — see the guard below.
    """
    with _get_run_log_lock(run_id):
        workflow = file_get_workflow(run_id)
        if workflow:
            # Once a workflow is in the terminal 'cancelled' state,
            # the "[Pipeline] Stop requested by user" warning is the
            # last word. Any further logs are race-condition residue:
            # subprocess wrap-up that landed between when the cancel
            # event fired and when the background thread noticed.
            # Drop them so the UI shows a clean "cancelled" timeline
            # instead of confusing "success/failed" lines after Stop.
            #
            # But NOT everything after a cancel is residue. An operator can
            # stop a collection and then press Fetch on that same run to pull
            # what Velociraptor already has — a deliberate, later action whose
            # whole output this guard was swallowing. Reproduced on case
            # 'test2': the fetch ran, wrote 481,253 rows and updated the run's
            # details, and logged NOTHING, so the button looked dead. Callers
            # that own a post-cancel operation pass force=True.
            if workflow.get("status") == "cancelled" and not force:
                return

            if "logs" not in workflow:
                workflow["logs"] = []

            workflow["logs"].append({
                "timestamp": datetime.now().isoformat(),
                "level": log_level,
                "message": log_message
            })
            if log_level == "error":
                workflow["error_count"] = int(workflow.get("error_count") or 0) + 1
            workflow["updated_at"] = datetime.now().isoformat()

            save_workflow(workflow)



def update_run_status(run_id, status, progress=None, error=None, details=None, force=False):
    """Update automation run status and optionally merge additional details.

    Safety net: when `status='completed'` is requested on a run that
    already accumulated `error_count > 0` (any call to
    `add_log_to_run(..., 'error')`), the status is auto-flipped to
    'failed' and a clear summary log line is added. This catches the
    long-standing pattern where pipelines log fatal errors mid-run but
    still reach `update_run_status('completed')` at the end (e.g. the
    'No data found in flow' / 'Could not find flow' Velociraptor cases
    that left runs green in the UI despite producing nothing useful).

    Pipelines that legitimately log error-level entries but should
    still complete (e.g. one of N clients failed in a multi-client
    fan-out where the others succeeded) can pass `force=True` to opt
    out of the auto-flip. Use sparingly — the default is the safer
    behaviour.
    """
    # Serialise the whole read-modify-write under the per-run lock. The backend
    # is threaded and details writes can be slow + large (e.g. a case's fused
    # graph blob); without this, concurrent updates read a stale snapshot and
    # clobber each other's details — which silently dropped the case activity
    # log / chat history when several actions (each re-fusing) overlapped.
    with _get_run_log_lock(run_id):
        workflow = file_get_workflow(run_id)
        if not workflow:
            return False
        # Cancellation is terminal: once request_stop() flips a run to
        # 'cancelled', the background worker's killed-subprocess
        # exception will try to mark it 'failed' on the way out. Silently
        # ignore those late updates so the UI shows the clean cancelled
        # state instead of a stack trace.
        current = workflow.get("status")
        if current == "cancelled" and status != "cancelled":
            return False

        # Safety net: refuse to mark a run with logged errors as
        # 'completed' unless the caller explicitly forces it.
        if status == "completed" and not force:
            n_errors = int(workflow.get("error_count") or 0)
            if n_errors > 0:
                # Demote to 'failed' so the UI shows red instead of
                # green and the operator notices the run had real
                # problems even if the pipeline thought it was done.
                summary = (
                    f"[Workflow] Status auto-set to 'failed' because "
                    f"{n_errors} error-level log entr"
                    f"{'y was' if n_errors == 1 else 'ies were'} recorded "
                    f"during this run."
                )
                workflow["logs"] = workflow.get("logs") or []
                workflow["logs"].append({
                    "timestamp": datetime.now().isoformat(),
                    "level": "error",
                    "message": summary,
                })
                status = "failed"
                if not error:
                    error = f"{n_errors} fatal error(s) logged during the run"

        workflow["status"] = status
        if progress is not None:
            workflow["progress"] = progress
        if error:
            workflow["error"] = error
        if details:
            # Merge new details with existing details
            existing_details = workflow.get("details", {})
            existing_details.update(details)
            workflow["details"] = existing_details
        workflow["updated_at"] = datetime.now().isoformat()

        # Returned to the caller. save_workflow() catches every exception,
        # prints to stdout and returns False, so dropping this bool made an
        # unwritable database indistinguishable from a successful save --
        # callers logged "saved" over nothing. Whether the row landed is the
        # caller's business now.
        saved = save_workflow(workflow)

        # A run that just reached a terminal state is new data for its case. Arm the
        # debounced auto-fuse -- ARM only. This runs inside the per-run lock, so it
        # must not fuse inline, read the case, or touch the database; schedule() does
        # none of those, it starts a timer and returns. AGENTIC_TYPES only: infra and
        # admin runs are not case data. Best-effort by design -- a scheduling problem
        # must never fail the status write that carries the run's actual result.
        if status in _TERMINAL_STATUSES and workflow.get("case_id"):
            if workflow.get("automation_type") in AGENTIC_TYPES:
                try:
                    from services.fusion import autofuse
                    autofuse.schedule(workflow["case_id"],
                                      reason=f"run {run_id} finished")
                except Exception as e:      # noqa: BLE001
                    print(f"[AUTOFUSE] could not schedule for "
                          f"{workflow.get('case_id')}: {e}", flush=True)
        return saved


def mutate_run_details(run_id, mutator):
    """Atomically read-modify-write a run's `details` under the per-run lock.

    `mutator(details: dict) -> None` mutates the dict in place. This is the
    race-safe way to append to a list inside details (activity log, chat history)
    — doing get + modify + save across separate calls lets concurrent writers
    clobber each other. Only touches `details` + `updated_at`; never the status."""
    with _get_run_log_lock(run_id):
        workflow = file_get_workflow(run_id)
        if not workflow:
            return False
        details = workflow.get("details") or {}
        mutator(details)
        workflow["details"] = details
        workflow["updated_at"] = datetime.now().isoformat()
        return save_workflow(workflow)


def record_phase_timing(run_id, phase, seconds):
    """Append a per-phase elapsed time (seconds, float) to the workflow row.

    Stored as a dict {phase: seconds} so the dashboard can render
    "Collection: 11m, Detection: 3m, Analysis: 5m" without re-parsing logs.
    """
    with _get_run_log_lock(run_id):
        workflow = file_get_workflow(run_id)
        if not workflow:
            return
        timings = workflow.get("phase_timings") or {}
        if not isinstance(timings, dict):
            timings = {}
        # Sum if the phase ran more than once; rare but harmless
        timings[phase] = round(timings.get(phase, 0.0) + float(seconds), 2)
        workflow["phase_timings"] = timings
        workflow["updated_at"] = datetime.now().isoformat()
        save_workflow(workflow)


def record_llm_metrics(run_id, *, calls=0, input_tokens=0, output_tokens=0, cost_usd=0.0, model=None):
    """Accumulate LLM usage onto the workflow row.

    Each invocation adds to running totals. The analyzer calls this per LLM call
    (see analyzers.call_llm) so the final totals reflect the whole pipeline.
    """
    with _get_run_log_lock(run_id):
        workflow = file_get_workflow(run_id)
        if not workflow:
            return
        m = workflow.get("llm_metrics") or {}
        if not isinstance(m, dict):
            m = {}
        m["calls"] = m.get("calls", 0) + int(calls)
        m["input_tokens"] = m.get("input_tokens", 0) + int(input_tokens)
        m["output_tokens"] = m.get("output_tokens", 0) + int(output_tokens)
        m["cost_usd"] = round(m.get("cost_usd", 0.0) + float(cost_usd), 6)
        if model:
            # Track the most-recently-used model. Pipelines that mix models can
            # still see the per-call records in logs.
            m["model"] = model
        workflow["llm_metrics"] = m
        workflow["updated_at"] = datetime.now().isoformat()
        save_workflow(workflow)


def record_sigma_rule_tally(run_id, tally):
    """Set the per-SIGMA-rule hit counts on the workflow row.

    `tally` is a dict {rule_name: hit_count}. Replaces (does not merge) — the
    SIGMA stage runs once per workflow.
    """
    if not isinstance(tally, dict):
        return
    with _get_run_log_lock(run_id):
        workflow = file_get_workflow(run_id)
        if not workflow:
            return
        workflow["sigma_rule_tally"] = tally
        workflow["updated_at"] = datetime.now().isoformat()
        save_workflow(workflow)

def cleanup_orphan_workflows():
    """Mark workflows as failed if they look orphaned — `running`/`pending`
    with no activity (no log lines, no status updates) for more than the
    idle threshold.

    Historically this checked `created_at`, which broke the interactive
    re-run flow: an agentic workflow completed days ago can be put back
    into `running` momentarily by a Re-run on the chat panel, and the
    watchdog would see "created >10h ago + status=running" and slay it
    mid-rerun. Switched to `updated_at` (and the most recent log entry
    as a second-best fallback) so the semantics is "stale", not "old".
    A genuinely orphaned crash still has an ancient `updated_at` and
    still gets caught.
    """
    now = datetime.now()
    max_idle_hours = 10

    def _last_activity(wf):
        """Most recent of updated_at + last log timestamp; falls back to
        created_at when neither is parseable so we don't accidentally
        spare a row with garbage timestamps forever."""
        candidates = []
        for fld in ('updated_at', 'created_at'):
            v = wf.get(fld)
            if v:
                try:
                    candidates.append(datetime.fromisoformat(str(v).replace('Z', '+00:00')).replace(tzinfo=None))
                except Exception:
                    pass
        logs = wf.get('logs') or []
        if logs:
            last_log_ts = logs[-1].get('timestamp')
            if last_log_ts:
                try:
                    candidates.append(datetime.fromisoformat(str(last_log_ts).replace('Z', '+00:00')).replace(tzinfo=None))
                except Exception:
                    pass
        return max(candidates) if candidates else None

    # Clean up SQLite workflows
    sqlite_workflows = load_workflows()
    for workflow in sqlite_workflows:
        # A "case"/"fusion_baseline" row IS a workspace container, not a job —
        # it has no natural "completed" state and can legitimately sit
        # untouched for days between investigation sessions. Treating that as
        # "orphaned" auto-failed the built-in System AND Default workspaces
        # after they simply sat idle past the threshold, which in turn broke
        # every system-run's visibility (case_id pointed at a now-"failed"
        # workspace) — not the workflow's fault, the reaper's.
        if workflow.get('automation_type') in INTERNAL_CASE_TYPES:
            continue
        if workflow.get('status') in ['running', 'pending']:
            last_active = _last_activity(workflow)
            if last_active is None:
                continue
            try:
                idle_hours = (now - last_active).total_seconds() / 3600
                if idle_hours > max_idle_hours:
                    workflow['status'] = 'failed'
                    workflow['error'] = f'Workflow idle for {idle_hours:.1f}h with no updates (max: {max_idle_hours}h)'
                    workflow['updated_at'] = now.isoformat()

                    if 'logs' not in workflow:
                        workflow['logs'] = []
                    workflow['logs'].append({
                        'timestamp': now.isoformat(),
                        'level': 'error',
                        'message': f'Workflow automatically marked as failed - idle for {idle_hours:.1f}h (max: {max_idle_hours}h)'
                    })

                    save_workflow(workflow)
                    print(f"[WORKFLOW] Marked SQLite orphan workflow as failed: {workflow.get('run_id')}", flush=True)
            except Exception as e:
                print(f"[WORKFLOW] Error checking SQLite workflow age: {e}", flush=True)

    # Clean up Elasticsearch workflows
    if _elk_enabled():
        try:
            es_workflows = es_get_all_workflows(size=200)
            for workflow in es_workflows:
                if workflow.get('automation_type') in INTERNAL_CASE_TYPES:
                    continue
                if workflow.get('status') in ['running', 'pending']:
                    last_active = _last_activity(workflow)
                    if last_active is None:
                        continue
                    try:
                        idle_hours = (now - last_active).total_seconds() / 3600
                        if idle_hours > max_idle_hours:
                            run_id = workflow.get('run_id', workflow.get('id'))
                            es_update_workflow_status(
                                run_id,
                                status='failed',
                                error=f'Workflow idle for {idle_hours:.1f}h with no updates (max: {max_idle_hours}h)'
                            )
                            print(f"[WORKFLOW] Marked ES orphan workflow as failed: {run_id}", flush=True)
                    except Exception as e:
                        print(f"[WORKFLOW] Error checking ES workflow age: {e}", flush=True)
        except Exception as e:
            print(f"[WORKFLOW] Error cleaning ES workflows: {e}", flush=True)


def get_all_automation_runs():
    """Get all automation runs from SQLite + Elasticsearch (with automatic orphan cleanup)"""
    # Clean up orphan workflows first
    cleanup_orphan_workflows()

    # Get SQLite workflows
    sqlite_workflows = load_workflows()
    sqlite_ids = {w.get('run_id') for w in sqlite_workflows}

    # Get Elasticsearch workflows and merge (avoiding duplicates)
    all_workflows = list(sqlite_workflows)

    if _elk_enabled():
        try:
            es_workflows = es_get_all_workflows(size=200)
            for es_wf in es_workflows:
                es_id = es_wf.get('run_id', es_wf.get('id'))
                if es_id and es_id not in sqlite_ids:
                    # Normalize field names
                    all_workflows.append({
                        'run_id': es_id,
                        'automation_type': es_wf.get('type', es_wf.get('automation_type', 'unknown')),
                        'name': es_wf.get('name', 'Unknown'),
                        'status': es_wf.get('status', 'unknown'),
                        'progress': es_wf.get('progress', 0),
                        'created_at': es_wf.get('started_at', es_wf.get('created_at', '')),
                        'updated_at': es_wf.get('updated_at', ''),
                        'logs': es_wf.get('logs', []),
                        'details': es_wf.get('details', {}),
                        'error': es_wf.get('error')
                    })
        except Exception as e:
            print(f"[WORKFLOW] Error loading ES workflows: {e}", flush=True)

    # Sort by created_at descending (newest first)
    all_workflows.sort(key=lambda x: x.get('created_at', ''), reverse=True)
    return all_workflows

def get_automation_run(run_id):
    """Get a specific automation run by ID (checks SQLite first, then Elasticsearch)"""
    # Try SQLite first
    workflow = file_get_workflow(run_id)
    if workflow:
        return workflow

    # Try Elasticsearch
    if _elk_enabled():
        try:
            es_wf = es_get_workflow(run_id)
            if es_wf:
                return {
                    'run_id': es_wf.get('run_id', es_wf.get('id', run_id)),
                    'automation_type': es_wf.get('type', es_wf.get('automation_type', 'unknown')),
                    'name': es_wf.get('name', 'Unknown'),
                    'status': es_wf.get('status', 'unknown'),
                    'progress': es_wf.get('progress', 0),
                    'created_at': es_wf.get('started_at', es_wf.get('created_at', '')),
                    'updated_at': es_wf.get('updated_at', ''),
                    'logs': es_wf.get('logs', []),
                    'details': es_wf.get('details', {}),
                    'error': es_wf.get('error')
                }
        except Exception as e:
            print(f"[WORKFLOW] Error getting ES workflow {run_id}: {e}", flush=True)

    return None

def get_jobs():
    """Get all jobs"""
    return jobs

def add_job(flow_id, job_data):
    """Add a new job to tracking"""
    jobs[flow_id] = job_data

def get_job(flow_id):
    """Get a specific job"""
    return jobs.get(flow_id)

def update_job(flow_id, updates):
    """Update a job with new data"""
    if flow_id in jobs:
        jobs[flow_id].update(updates)
