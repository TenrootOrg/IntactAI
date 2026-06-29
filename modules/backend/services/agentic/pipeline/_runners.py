#!/usr/bin/env python3
"""
Agentic Pipeline - Main orchestration for forensics analysis pipeline
"""
import threading
import traceback
from datetime import datetime

from services.workflow_service import (
    add_log_to_run,
    update_run_status,
    is_cancelled,
    unregister_cancel,
    request_stop,
)


# Outer watchdog grace period: how long after the collection window the
# pipeline may keep running for synthesis / report generation / IRIS
# import before we force-kill it. The QA hang sat at "running" for
# nearly an hour with no upper bound — this is the absolute backstop
# even if every other safety check misses.
from services.file_storage_service import get_agentic_blueprint, get_workflow, save_workflow
from services.data_anonymizer import DataAnonymizer

from services.agentic.collectors import (
    create_collections,
    stream_collect_and_analyze,
    cancel_collections
)
from services.agentic.reports import (
    generate_empty_report,
    save_report_content,
    persist_pipeline_artifacts,
)
from services.agentic.utils import extract_timeline_events, filter_malicious_events
from services.agentic.pipeline._helpers import *  # noqa: F401,F403
from services.agentic.pipeline._helpers import (_start_watchdog, _collect_only_report, _update_phase, _PIPELINE_SYNTHESIS_GRACE_SECONDS)  # underscore members

def run_agentic_pipeline(run_id, blueprint_id, client_ids, collection_minutes, llm_config,
                         report_types=None, anonymize_data=False, custom_patterns=None,
                         import_to_iris=False, iris_case_name=None, time_filter=None,
                         min_severity='informational', external_files=None, cancel_event=None):
    """Background thread: full agentic forensics pipeline
    Args:
        report_types: List of report types to generate: ['technical'], or None for both
        anonymize_data: If True, mask sensitive data before LLM analysis
        custom_patterns: List of custom regex patterns to mask (e.g., ['acme-corp.com', 'ACMECORP\\'])
        import_to_iris: If True, import timeline events and IOCs to IRIS after report generation
        iris_case_name: Optional custom name for the IRIS case (auto-generated if not provided)
        time_filter: Optional time filter config: {enabled, mode, relative_range/start_datetime/end_datetime}
        min_severity: Minimum severity level to send to LLM (informational, low, medium, high, critical)
        external_files: Optional list of external log files [{upload_id, filename}, ...]
    """
    if report_types is None:
        report_types = ['technical']  # Default: both reports

    # Create anonymizer if enabled
    anonymizer = None
    if anonymize_data:
        anonymizer = DataAnonymizer(custom_patterns=custom_patterns)

    # Outer watchdog — the absolute backstop. Even if every other
    # safety check misses, the run cannot exceed
    # `collection_minutes + 15min synthesis grace`. See QA hang
    # context: pipeline stayed "running" for ~1 hour after the LLM
    # died because no outer timeout bounded the total wall-clock.
    _watchdog = _start_watchdog(run_id, collection_minutes, label="agentic")

    try:
        update_run_status(run_id, "running", progress=2)
        add_log_to_run(run_id, "[Collection] Starting Velociraptor collection", "info")

        # Collection-only: the run gathers artifacts and is then fused into a Case
        # for analysis. (No per-run analysis happens here.)
        llm_enabled = False
        add_log_to_run(run_id,
            "[Collection] Gathering artifacts — fuse this run into a Case for analysis.",
            "info")

        # Store report_types in workflow details for UI
        workflow = get_workflow(run_id)
        if workflow:
            if 'details' not in workflow:
                workflow['details'] = {}
            workflow['details']['report_types'] = report_types
            save_workflow(workflow)

        # Hostnames are stashed in workflow.details by agentic_routes when
        # the run is created (resolve_hostnames is called there so the
        # workflow name in the Workflows tab carries readable names from
        # the moment the row appears). Pull the same map here so the
        # report header + macro citations show those names instead of the
        # bare client_ids.
        hostnames = {}
        # Cross-client synthesis is opt-in (stashed in details by the route).
        # When False, multi-client runs still produce per-client reports
        # but skip the org-wide macro pass — saves one LLM call and one
        # markdown file (00_ORGANIZATION_SUMMARY.md) in the ZIP. When True,
        # the macro pass runs as it always has. Single-client runs never
        # generated a macro, so the flag is moot for N=1.
        cross_client_synthesis = False
        # Interactive-mode master prompt — present on re-runs triggered
        # from the chat panel (POST /api/agentic/run/<run_id>/rerun). Stashed
        # in details by the chat synthesis step; we thread it into every
        # LLM-call surface so the operator's corrections influence both
        # per-artifact analysis and report writing.
        master_prompt = None
        if workflow:
            details = workflow.get('details') or {}
            hostnames = details.get('hostnames') or {}
            cross_client_synthesis = bool(details.get('cross_client_synthesis'))
            master_prompt = details.get('master_prompt') or None
        if not hostnames:
            # Fallback: re-resolve. Cheap (one VQL call) and keeps this
            # pipeline robust against older runs that pre-date the route
            # change.
            try:
                from services.agentic.collectors import resolve_hostnames as _resolve_hn
                hostnames = _resolve_hn(client_ids)
            except Exception:
                hostnames = {cid: cid for cid in client_ids}

        # 1. Get blueprint
        blueprint = get_agentic_blueprint(blueprint_id)
        if not blueprint:
            add_log_to_run(run_id, f"[Pipeline] Blueprint '{blueprint_id}' not found", "error")
            update_run_status(run_id, "failed", progress=0, error="Blueprint not found")
            return

        artifacts = blueprint.get('artifacts', [])
        settings = blueprint.get('settings', {}).copy()  # Copy to avoid mutating blueprint

        # Merge user-provided time filter into settings
        if time_filter and time_filter.get('enabled'):
            settings['time_filter'] = time_filter
            mode = time_filter.get('mode', 'relative')
            if mode == 'relative':
                from datetime import timedelta
                range_str = time_filter.get('relative_range', '7d')
                now = datetime.now()
                if range_str.endswith('h'):
                    start = now - timedelta(hours=int(range_str[:-1]))
                elif range_str.endswith('d'):
                    start = now - timedelta(days=int(range_str[:-1]))
                else:
                    start = now - timedelta(days=7)
                add_log_to_run(run_id, f"[Pipeline] Time filter: last {range_str} ({start.strftime('%Y-%m-%d %H:%M')} to {now.strftime('%Y-%m-%d %H:%M')})", "info")
            else:
                add_log_to_run(run_id, f"[Pipeline] Time filter: between ({time_filter.get('start_datetime')} to {time_filter.get('end_datetime', 'now')})", "info")

        add_log_to_run(run_id, f"[Pipeline] Blueprint: {blueprint.get('name')} ({len(artifacts)} artifacts)", "info")
        add_log_to_run(run_id, f"[Pipeline] Clients: {len(client_ids)} selected", "info")
        add_log_to_run(run_id, f"[Pipeline] Collection time: {collection_minutes} minutes", "info")
        if anonymizer:
            pattern_count = len(custom_patterns) if custom_patterns else 0
            add_log_to_run(run_id, f"[Pipeline] Data anonymization: ENABLED ({pattern_count} custom patterns)", "info")
        if import_to_iris:
            add_log_to_run(run_id, f"[Pipeline] IRIS import: ENABLED", "info")

        # 2. Create collections on selected clients
        add_log_to_run(run_id, "[Velociraptor] Creating collections on selected clients...", "info")
        _update_phase(run_id, "creating_collections", 5)

        if cancel_event and cancel_event.is_set():
            return

        collection_results = create_collections(run_id, artifacts, settings, client_ids)
        success_collections = [c for c in collection_results if c['flow_id']]
        add_log_to_run(run_id, f"[Velociraptor] Created {len(success_collections)}/{len(client_ids)} collections ({len(artifacts)} artifacts each)", "info")

        # Persist the flow IDs back into workflow.details so a future
        # Full re-analysis (from the Interactive chat panel) can fetch
        # the same data without launching a new collection.
        try:
            launched_flow_ids = [c['flow_id'] for c in success_collections if c.get('flow_id')]
            if launched_flow_ids:
                _wf = get_workflow(run_id)
                if _wf is not None:
                    _wd = _wf.get('details') or {}
                    if not isinstance(_wd, dict):
                        _wd = {}
                    _wd['flow_id'] = launched_flow_ids if len(launched_flow_ids) > 1 else launched_flow_ids[0]
                    _wf['details'] = _wd
                    save_workflow(_wf)
        except Exception as _e:
            # Best-effort — re-analysis falls back to "unavailable" if
            # the stash misses; doesn't break the main pipeline.
            print(f"[PIPELINE] Failed to stash flow_ids on {run_id}: {_e}", flush=True)

        if not success_collections:
            add_log_to_run(run_id, "[Velociraptor] No collections were created successfully", "error")
            update_run_status(run_id, "failed", progress=0, error="Failed to create any collections")
            return

        if cancel_event and cancel_event.is_set():
            return

        # 3. Stream-collect: monitor flows, retrieve results as they become available.
        add_log_to_run(run_id, f"[Velociraptor] Collecting data for up to {collection_minutes} minutes...", "info")
        if min_severity != 'informational':
            add_log_to_run(run_id, f"[Pipeline] Severity filter active: {min_severity}+ only", "info")
        _update_phase(run_id, "collecting", 10)
        all_results, artifact_summaries, timed_out, total_rows_before_filter = stream_collect_and_analyze(
            run_id, success_collections, artifacts, collection_minutes, llm_config, anonymizer, _update_phase, min_severity, time_filter, cancel_event, master_prompt=master_prompt,
        )

        # 4. Cancel any remaining collections ONLY if we timed out
        if timed_out:
            add_log_to_run(run_id, "[Velociraptor] Collection timed out - stopping remaining collections...", "warning")
            cancel_collections(run_id, success_collections)
        else:
            add_log_to_run(run_id, "[Velociraptor] All flows completed naturally", "success")

        total_rows = sum(len(rows) for rows in all_results.values())
        add_log_to_run(run_id, f"[Pipeline] Collection complete: {total_rows} total rows across {len(all_results)} artifacts", "success")

        # Log masking summary before report generation
        if anonymizer:
            for line in anonymizer.get_masking_log_lines():
                add_log_to_run(run_id, line, "info")

        # 5. Load external log files (if provided)
        if external_files:
            add_log_to_run(run_id, f"[External] Loading {len(external_files)} external log file(s)...", "info")
            from services.agentic.external_data import parse_external_file, get_source_hint

            for file_info in external_files:
                upload_id = file_info.get('upload_id', '')
                filename = file_info.get('filename', 'unknown.csv')
                file_path = f"/data/uploads/{upload_id}"

                try:
                    rows = parse_external_file(file_path, filename)
                    if rows:
                        # Use filename to create descriptive artifact key
                        source_name = get_source_hint(filename)
                        artifact_key = f"External: {source_name}"

                        all_results[artifact_key] = rows
                        total_rows += len(rows)
                        add_log_to_run(run_id, f"[External] Loaded {len(rows)} rows from {filename}", "info")
                    else:
                        add_log_to_run(run_id, f"[External] No data found in {filename}", "warning")
                except Exception as e:
                    add_log_to_run(run_id, f"[External] Error loading {filename}: {str(e)}", "warning")

        if total_rows == 0:
            if total_rows_before_filter > 0:
                # Data existed but filters removed everything — this is a
                # configuration mismatch, not a fatal collection failure.
                # Keep status='completed' (with the warning visible) so the
                # operator notices the filter setting; auto-flip would
                # otherwise hide the legit-but-empty report.
                add_log_to_run(run_id, f"[Pipeline] Data was collected ({total_rows_before_filter} rows) but all rows were removed by filters (severity: {min_severity}+). Try lowering the severity filter or adjusting the time range.", "warning")
                report_content = generate_empty_report(blueprint, client_ids, collection_minutes)
                save_report_content(run_id, report_content)
                _update_phase(run_id, "completed", 100)
                update_run_status(run_id, "completed", progress=100, force=True)
                return
            else:
                # No data at all from Velociraptor — this IS a fatal
                # outcome, not a recoverable warning. Promote the logs
                # to 'error' level so the auto-flip in workflow_service
                # picks it up AND the operator sees red, AND set status
                # to 'failed' explicitly so future readers don't have
                # to chase through the auto-flip logic.
                add_log_to_run(run_id, "[Pipeline] No data was returned from the selected clients. Possible causes:", "error")
                add_log_to_run(run_id, "  - Collection time too short - try increasing it", "error")
                add_log_to_run(run_id, "  - Artifacts not applicable to this system - try a different blueprint", "error")
                add_log_to_run(run_id, "  - Clients may be offline - verify client status in Velociraptor", "error")
                update_run_status(
                    run_id, "failed", progress=0,
                    error="No data returned from selected clients during collection window",
                )
                return

        # 7. Generate report(s) - skip if no report types selected
        if cancel_event and cancel_event.is_set():
            return

        # Pre-synthesis success check: if every artifact analysis failed
        # (LLM was unreachable for the whole pipeline), skip synthesis —
        # which would otherwise call call_llm again, hit the same dead
        # endpoint, and hang for the full 600s timeout before failing.
        # Better to fail loudly right here with a clear message.
        if artifact_summaries:
            real_summaries = {
                k: v for k, v in artifact_summaries.items()
                if v and not (isinstance(v, str) and v.startswith("Analysis failed:"))
            }
            if not real_summaries:
                add_log_to_run(run_id,
                    f"[Pipeline] All {len(artifact_summaries)} artifact analyses errored — "
                    f"skipping synthesis (would hit the same dead LLM). "
                    f"Check Settings > Agentic and the LLM endpoint, then re-run.",
                    "error")
                update_run_status(
                    run_id, "failed", progress=0,
                    error=f"All {len(artifact_summaries)} analyses failed — LLM unreachable",
                )
                return

        report_content = {}
        # Emit the collection summary; the rows are persisted below for fusion.
        if not llm_enabled:
            add_log_to_run(run_id, f"[Collection] {total_rows} rows across "
                           f"{len(all_results)} artifacts collected — fuse this run into a "
                           f"Case for analysis.", "info")
            report_content = {'technical': _collect_only_report(
                total_rows, all_results, len(client_ids))}
            save_report_content(run_id, report_content)
            report_types = []   # skip the LLM report block below

        # LLM report generation REMOVED — agentic is collect-only; analysis +
        # reporting happen at Case Analysis (fusion). The collect-only report
        # above is the only per-run output; rows are persisted below for fusion.
        _update_phase(run_id, "report_ready", 85)

        # 9. Import to IRIS (if enabled)
        if cancel_event and cancel_event.is_set():
            return

        iris_result = None
        if import_to_iris:
            add_log_to_run(run_id, "[IRIS] Starting IRIS import...", "info")
            _update_phase(run_id, "importing_to_iris", 92)

            try:
                from services.iris_service import import_to_iris as iris_import
                from config import IRIS_CONFIG

                # Generate case name if not provided
                if not iris_case_name:
                    iris_case_name = f"Velociraptor Collection - {blueprint.get('name', 'Unknown')} - {datetime.now().strftime('%Y-%m-%d %H:%M')}"

                # Extract timeline events with severity filter applied
                all_events = extract_timeline_events(all_results, include_no_timestamp=True)
                timeline_events = filter_malicious_events(all_events, min_severity=min_severity)
                add_log_to_run(run_id, f"[IRIS] Extracted {len(timeline_events)} events for timeline (severity: {min_severity}+)", "info")

                # Get technical report for IOC extraction
                technical_report = ""
                if isinstance(report_content, dict):
                    technical_report = report_content.get('technical', '')
                elif isinstance(report_content, str):
                    technical_report = report_content

                # Get client information for assets
                from services.velociraptor_service import get_clients_from_snapshot
                all_clients = get_clients_from_snapshot()
                selected_clients = [c for c in all_clients if c.get('client_id') in client_ids]
                add_log_to_run(run_id, f"[IRIS] Found {len(selected_clients)} clients to add as assets", "info")

                # Import to IRIS - pass unfiltered events for IOC extraction
                # (Amcache/Prefetch have hashes but are filtered from timeline_events)
                # Per-artifact LLM summaries are the highest-fidelity IOC
                # source — see extract_iocs_from_summaries in iris_service.
                iris_result = iris_import(
                    run_id=run_id,
                    case_name=iris_case_name,
                    timeline_events=timeline_events,
                    technical_report=technical_report,
                    iris_config=IRIS_CONFIG,
                    clients=selected_clients,
                    blueprint_name=blueprint.get('name', 'Velociraptor Collection'),
                    all_events_for_iocs=all_events,
                    artifact_summaries=artifact_summaries,
                    min_ioc_severity=blueprint.get('min_ioc_severity'),
                    logger=lambda msg, level: add_log_to_run(run_id, msg, level)
                )

                if iris_result.get('success'):
                    add_log_to_run(run_id, f"[IRIS] Case created: {iris_result.get('case_url')}", "success")
                    add_log_to_run(run_id, f"[IRIS] Added {iris_result.get('assets_imported', 0)} assets", "info")
                    add_log_to_run(run_id, f"[IRIS] Imported {iris_result.get('events_imported')} timeline events", "info")
                    add_log_to_run(run_id, f"[IRIS] Imported {iris_result.get('iocs_imported')} IOCs", "info")

                    # Store IRIS result in workflow details
                    workflow = get_workflow(run_id)
                    if workflow:
                        if 'details' not in workflow:
                            workflow['details'] = {}
                        workflow['details']['iris_result'] = iris_result
                        save_workflow(workflow)
                else:
                    add_log_to_run(run_id, f"[IRIS] Import failed: {iris_result.get('error', 'Unknown error')}", "warning")

            except Exception as e:
                add_log_to_run(run_id, f"[IRIS] Import error: {str(e)}", "warning")
                # Don't fail the pipeline for IRIS import failure

        # Save artifact summaries + raw row data for interactive-mode
        # re-runs (chat → master prompt → reports-only regenerate). Cheap
        # to write, best-effort: failures are logged but don't fail the
        # pipeline.
        try:
            persist_pipeline_artifacts(run_id, artifact_summaries, all_results)
        except Exception as _e:
            print(f"[AGENTIC] persist_pipeline_artifacts failed (non-fatal): {_e}", flush=True)

        _update_phase(run_id, "completed", 100)
        add_log_to_run(run_id, "[Collection] Collection complete — fuse into a Case for analysis.", "success")
        if not is_cancelled(run_id):
            update_run_status(run_id, "completed", progress=100)

    except Exception as e:
        if is_cancelled(run_id):
            return  # Stop was requested, don't overwrite cancelled status
        error_msg = f"[Pipeline] Error: {str(e)}"
        print(f"[AGENTIC] {error_msg}", flush=True)
        traceback.print_exc()
        add_log_to_run(run_id, error_msg, "error")
        add_log_to_run(run_id, traceback.format_exc(), "error")
        update_run_status(run_id, "failed", error=str(e))
    finally:
        try:
            _watchdog.cancel()
        except Exception:
            pass
        unregister_cancel(run_id)
