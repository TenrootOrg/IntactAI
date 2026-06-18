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
_PIPELINE_SYNTHESIS_GRACE_SECONDS = 15 * 60  # 15 minutes


def _start_watchdog(run_id: str, collection_minutes: int, label: str = "agentic"):
    """Start a threading.Timer that calls request_stop(run_id) if the
    pipeline outlives `collection_minutes * 60 + grace`. The cancel
    event then propagates through every loop in collectors.py and
    pipeline.py exits via its existing `except`. Returns the Timer
    so the caller can .cancel() it in the finally block."""
    deadline = max(int(collection_minutes), 1) * 60 + _PIPELINE_SYNTHESIS_GRACE_SECONDS

    def _fire():
        # Log loudly so the operator sees this in the run log instead
        # of just a status flip.
        try:
            add_log_to_run(
                run_id,
                f"[Pipeline] Watchdog: {label} pipeline exceeded "
                f"{deadline}s — forcing cancellation",
                "error",
            )
            request_stop(run_id)
        except Exception:
            pass

    t = threading.Timer(deadline, _fire)
    t.daemon = True
    t.start()
    return t
from services.file_storage_service import get_agentic_blueprint, get_workflow, save_workflow
from services.data_anonymizer import DataAnonymizer

from services.agentic.collectors import (
    create_collections,
    stream_collect_and_analyze,
    cancel_collections
)
from services.agentic.reports import (
    generate_final_report,
    generate_empty_report,
    save_report_content,
    generate_multi_client_reports,
    create_report_package,
    persist_per_client_reports,
    get_client_hostname,
    persist_pipeline_artifacts,
)
from services.agentic.utils import extract_timeline_events, filter_malicious_events


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
        add_log_to_run(run_id, "[Pipeline] Starting Agentic Forensics pipeline", "info")

        # LLM is OPTIONAL. With a key/URL we validate + ping; without one we run
        # COLLECT-ONLY (collect artifacts, skip per-artifact analysis + synthesis) so
        # the product works with no LLM agreement. The run still completes + is fuseable.
        from services.agentic.analyzers import (
            validate_llm_config, ping_llm, is_llm_configured)
        llm_enabled = is_llm_configured(llm_config)
        if not llm_enabled:
            add_log_to_run(run_id,
                "[Pipeline] No LLM configured — running COLLECT-ONLY (no per-artifact "
                "analysis / synthesis). The run completes and is fuseable in a Case.", "info")
        else:
            try:
                validate_llm_config(llm_config)
            except ValueError as e:
                add_log_to_run(run_id, f"[Pipeline] Configuration error: {str(e)}", "error")
                update_run_status(run_id, "failed", progress=0, error=str(e))
                return
            # Pre-flight LLM reachability — fail fast (within ~30s) if the endpoint is
            # unreachable, instead of discovering it mid-collection.
            add_log_to_run(run_id, "[Pipeline] Pre-flight LLM reachability check...", "info")
            try:
                ping_llm(llm_config, timeout_seconds=30)
                add_log_to_run(run_id, "[Pipeline] ✓ LLM is reachable", "success")
            except Exception as e:
                err = f"LLM unreachable before pipeline start: {str(e)[:200]}"
                add_log_to_run(run_id, f"[Pipeline] ✗ {err}", "error")
                add_log_to_run(run_id,
                    "Check Settings > Agentic that your API key / Ollama URL is correct "
                    "and the endpoint is reachable from this host.", "error")
                update_run_status(run_id, "failed", progress=0, error=err)
                return

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
        # the same data without launching a new collection. Without
        # this stash, run_agentic_on_existing has nothing to point at
        # and the full-scope re-run is impossible.
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

        # 3. Stream collect and analyze - monitors flows, retrieves results as available, runs LLM in parallel
        add_log_to_run(run_id, f"[Velociraptor] Collecting data for up to {collection_minutes} minutes (streaming analysis)...", "info")
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
        multi_reports = None
        zip_path = None

        # No LLM -> emit a collect-only report (the rows are persisted below for
        # fusion). Skips the LLM report generators entirely.
        if not llm_enabled:
            add_log_to_run(run_id, f"[Report] Collect-only (no LLM): {total_rows} rows across "
                           f"{len(all_results)} artifacts — fuse this run into a Case for "
                           f"deterministic findings.", "info")
            report_content = {'technical': _collect_only_report(
                total_rows, all_results, len(client_ids))}
            save_report_content(run_id, report_content)
            report_types = []   # skip the LLM report block below

        if report_types:
            _update_phase(run_id, "generating_report", 85)

            # Multi-client: generate per-client reports + macro summary
            if len(client_ids) > 1:
                add_log_to_run(run_id, f"[Report] Multi-client mode: {len(client_ids)} clients", "info")
                try:
                    multi_reports = generate_multi_client_reports(
                        run_id, blueprint, client_ids, collection_minutes,
                        artifact_summaries, all_results, llm_config, anonymizer,
                        hostnames=hostnames,
                        generate_macro=cross_client_synthesis,
                        master_prompt=master_prompt,
                    )

                    # Create ZIP package
                    zip_path = create_report_package(run_id, multi_reports)
                    add_log_to_run(run_id, f"[Report] Created ZIP package: {zip_path}", "info")

                    # Also drop per-client reports on disk so the chat
                    # assistant can read them without unpacking the ZIP.
                    persist_per_client_reports(
                        run_id,
                        multi_reports.get('per_client') or {},
                        multi_reports.get('hostnames') or {},
                    )

                    # Save macro report as the main report (for backwards
                    # compatibility with the single-report download endpoint).
                    # When the operator didn't opt in to cross-client synthesis,
                    # multi_reports['macro'] is None — use a friendly pointer
                    # to the ZIP's per-client files instead, so /api/agentic/
                    # run/<run_id>/download?type=technical never returns empty.
                    macro_md = multi_reports.get('macro')
                    if not macro_md:
                        hn_list = list((multi_reports.get('hostnames') or {}).values())
                        macro_md = (
                            "# Multi-client run — per-client reports only\n\n"
                            "The organization-wide synthesis was not enabled for this run "
                            "(checkbox 'Generate organization-wide synthesis' was off).\n\n"
                            f"Per-host reports for the {len(multi_reports.get('per_client', {}))} "
                            f"client(s) are inside the ZIP — download it from the workflow row.\n\n"
                            f"Hosts: {', '.join(hn_list) if hn_list else '(unknown)'}.\n"
                        )
                    report_content = {'technical': macro_md}
                    save_report_content(run_id, report_content)

                    # Store multi-client info in workflow
                    workflow = get_workflow(run_id)
                    if workflow:
                        if 'details' not in workflow:
                            workflow['details'] = {}
                        workflow['details']['multi_client'] = True
                        workflow['details']['report_zip'] = zip_path
                        workflow['details']['client_count'] = len(client_ids)
                        workflow['details']['hostnames'] = multi_reports.get('hostnames', {})
                        save_workflow(workflow)
                except Exception as report_error:
                    add_log_to_run(run_id, f"[Report] Error generating multi-client report: {str(report_error)}", "warning")
                    print(f"[AGENTIC] Multi-client report error: {report_error}", flush=True)
                    traceback.print_exc()
                    # Create fallback report
                    fallback_content = "# Multi-Client Analysis (Partial)\n\n"
                    fallback_content += "**Note:** Report generation encountered an error. Raw summaries below.\n\n"
                    for artifact, summary in artifact_summaries.items():
                        fallback_content += f"## {artifact}\n{summary}\n\n"
                    report_content = {'technical': fallback_content}
                    save_report_content(run_id, report_content)

            # Single client: existing behavior
            else:
                report_type_str = " + ".join(report_types) if len(report_types) > 1 else report_types[0]
                add_log_to_run(run_id, f"[Report] Generating {report_type_str} report(s)...", "info")
                try:
                    report_content = generate_final_report(
                        run_id, blueprint, client_ids, collection_minutes,
                        artifact_summaries, all_results, llm_config, report_types, anonymizer,
                        hostnames=hostnames,
                        master_prompt=master_prompt,
                    )
                    # 8. Save report
                    save_report_content(run_id, report_content)
                except Exception as report_error:
                    # Log error but don't fail entire pipeline - save raw data summary instead
                    add_log_to_run(run_id, f"[Report] Error generating report: {str(report_error)}", "warning")
                    print(f"[AGENTIC] Report generation error: {report_error}", flush=True)
                    traceback.print_exc()
                    # Create minimal fallback report with raw summaries
                    fallback_content = "# Analysis Report (Partial)\n\n"
                    fallback_content += "**Note:** Full report generation encountered an error. Raw analysis summaries below.\n\n"
                    for artifact, summary in artifact_summaries.items():
                        fallback_content += f"## {artifact}\n{summary}\n\n"
                    report_content = {'technical': fallback_content}
                    save_report_content(run_id, report_content)
                    add_log_to_run(run_id, "[Report] Saved fallback report with raw summaries", "info")
        else:
            add_log_to_run(run_id, "[Report] No report types selected - skipping report generation", "info")
            _update_phase(run_id, "skipping_report", 85)

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
                    iris_case_name = f"Agentic Analysis - {blueprint.get('name', 'Unknown')} - {datetime.now().strftime('%Y-%m-%d %H:%M')}"

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
                    blueprint_name=blueprint.get('name', 'Agentic Analysis'),
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
        add_log_to_run(run_id, "[Pipeline] Analysis complete! Report ready for download.", "success")
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


def _collect_only_report(total_rows, all_results, client_count) -> str:
    """Deterministic report when no LLM is configured — states what was collected and
    points the operator at the Case fusion path for LLM-free findings."""
    arts = ", ".join(sorted(all_results.keys())) if all_results else "(none)"
    return (
        "# Collection complete — no LLM analysis\n\n"
        f"Collected **{total_rows} rows** across **{len(all_results)} artifact(s)** from "
        f"**{client_count} client(s)**.\n\n"
        "No LLM is configured, so per-artifact AI analysis and the narrative report were "
        "skipped. **This run is fully usable**: fuse it into a **Case** (Cases UI / "
        "`/api/cases`) to get deterministic, LLM-free correlation, findings, timeline, and "
        "interactive chat.\n\n"
        f"**Artifacts collected:** {arts}\n"
    )


def _update_phase(run_id, phase, progress):
    """Update workflow with current phase and progress"""
    workflow = get_workflow(run_id)
    if workflow:
        workflow['phase'] = phase
        workflow['progress'] = progress
        save_workflow(workflow)


def run_agentic_on_existing(run_id, flow_id, hunt_id, llm_config,
                             report_types=None, anonymize_data=False, custom_patterns=None,
                             import_to_iris=False, iris_case_name=None, time_filter=None,
                             min_severity='informational', external_files=None, cancel_event=None,
                             client_ids=None):
    """Run AI analysis on an existing Velociraptor flow or hunt (skip collection step)

    Args:
        run_id: Workflow run ID for tracking
        flow_id: Existing flow ID (F.xxx) - for single client collection
        hunt_id: Existing hunt ID (H.xxx OR F.xxx.H) - for multi-client hunt
        llm_config: LLM configuration dictionary
        report_types: List of report types to generate
        anonymize_data: If True, mask sensitive data before LLM analysis
        custom_patterns: List of custom patterns to mask
        import_to_iris: If True, import to IRIS after analysis
        iris_case_name: Optional custom IRIS case name
        time_filter: Optional time filter for post-collection filtering
        min_severity: Minimum severity level to send to LLM (informational, low, medium, high, critical)
        external_files: Optional list of external log files [{upload_id, filename}, ...]
        client_ids: Optional list of Velociraptor client IDs. When provided
            on a hunt-mode run, the hunt enumeration is scoped to those
            clients only (VQL-level WHERE filter). Ignored for single-flow.
    """
    if report_types is None:
        report_types = ['technical']

    # Create anonymizer if enabled
    anonymizer = None
    if anonymize_data:
        anonymizer = DataAnonymizer(custom_patterns=custom_patterns)

    # Outer watchdog — same backstop as the main pipeline. This path
    # has no Velociraptor collection window so we charge the whole
    # synthesis-grace budget for analyse + report + IRIS import.
    _watchdog = _start_watchdog(run_id, collection_minutes=1, label="agentic-existing")

    try:
        update_run_status(run_id, "running", progress=2)
        # flow_id may be a list (multi-flow run). Render as comma-joined for
        # any user-facing string; the collector below accepts either shape.
        if isinstance(flow_id, list):
            collection_id = ', '.join(flow_id)
        else:
            collection_id = flow_id or hunt_id
        collection_type = "flow" if flow_id else "hunt"
        add_log_to_run(run_id, f"[Pipeline] Analyzing existing {collection_type}: {collection_id}", "info")

        # Surface masking + IRIS-import gates up front (parity with the
        # run_agentic_pipeline path) so the operator can see in the
        # workflow log whether masking will run before each per-artifact
        # LLM call.
        if anonymizer:
            pattern_count = len(custom_patterns) if custom_patterns else 0
            add_log_to_run(
                run_id,
                f"[Pipeline] Data anonymization: ENABLED ({pattern_count} custom patterns)",
                "info",
            )
        if import_to_iris:
            add_log_to_run(run_id, "[Pipeline] IRIS import: ENABLED", "info")

        # Log time filter summary
        if time_filter and time_filter.get('enabled'):
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
                add_log_to_run(run_id, f"[Pipeline] Time filter: {time_filter.get('start_datetime')} to {time_filter.get('end_datetime', 'now')}", "info")

        # LLM is OPTIONAL. With a key/URL we validate + ping; without one we run
        # COLLECT-ONLY (collect artifacts, skip per-artifact analysis + synthesis) so
        # the product works with no LLM agreement. The run still completes + is fuseable.
        from services.agentic.analyzers import (
            validate_llm_config, ping_llm, is_llm_configured)
        llm_enabled = is_llm_configured(llm_config)
        if not llm_enabled:
            add_log_to_run(run_id,
                "[Pipeline] No LLM configured — running COLLECT-ONLY (no per-artifact "
                "analysis / synthesis). The run completes and is fuseable in a Case.", "info")
        else:
            try:
                validate_llm_config(llm_config)
            except ValueError as e:
                add_log_to_run(run_id, f"[Pipeline] Configuration error: {str(e)}", "error")
                update_run_status(run_id, "failed", progress=0, error=str(e))
                return
            # Pre-flight LLM reachability — fail fast (within ~30s) if the endpoint is
            # unreachable, instead of discovering it mid-collection.
            add_log_to_run(run_id, "[Pipeline] Pre-flight LLM reachability check...", "info")
            try:
                ping_llm(llm_config, timeout_seconds=30)
                add_log_to_run(run_id, "[Pipeline] ✓ LLM is reachable", "success")
            except Exception as e:
                err = f"LLM unreachable before pipeline start: {str(e)[:200]}"
                add_log_to_run(run_id, f"[Pipeline] ✗ {err}", "error")
                add_log_to_run(run_id,
                    "Check Settings > Agentic that your API key / Ollama URL is correct "
                    "and the endpoint is reachable from this host.", "error")
                update_run_status(run_id, "failed", progress=0, error=err)
                return

        _update_phase(run_id, "fetching_results", 5)

        # Fetch all results from existing flow/hunt
        from services.agentic.collectors import get_existing_collection_results
        all_results, artifacts, client_info = get_existing_collection_results(
            run_id, flow_id, hunt_id, time_filter, client_ids=client_ids
        )

        if not all_results:
            # This is the case the user reported as wrongly marked
            # 'completed' (UI showed green even though the Velociraptor
            # flow couldn't be found / had no rows). Promote to 'error'
            # so the auto-flip in workflow_service catches anything
            # downstream that calls update_run_status('completed'), and
            # mark 'failed' explicitly here so the intent is obvious.
            add_log_to_run(
                run_id,
                f"[Pipeline] No data found in {collection_type} {collection_id}. "
                f"The collection returned no results - try running a new collection "
                f"with more artifacts or a longer time window.",
                "error",
            )
            update_run_status(
                run_id, "failed", progress=0,
                error=f"No data found in {collection_type} {collection_id}",
            )
            return

        total_rows = sum(len(rows) for rows in all_results.values())
        original_total = total_rows  # Track for final summary
        add_log_to_run(run_id, f"[Pipeline] Retrieved {total_rows} rows across {len(all_results)} artifacts", "info")

        # Apply Python time filtering (more reliable than VQL filtering)
        time_filtered = False
        if time_filter and time_filter.get('enabled'):
            from services.agentic.utils import filter_results_by_time
            all_results = filter_results_by_time(all_results, time_filter, run_id)
            total_rows = sum(len(rows) for rows in all_results.values())
            time_filtered = True

        # Apply severity filtering before LLM analysis
        severity_filtered = False
        if min_severity != 'informational':
            from services.agentic.collectors import filter_by_severity
            before_filter = total_rows
            severity_filtered = True

            add_log_to_run(run_id, f"[Filter] Severity filter: {min_severity}+ only", "info")
            add_log_to_run(run_id, f"[Filter] ─────────────────────────────────────────────", "info")

            filtered_results = {}
            severity_stats = []  # [(artifact, before, after)]

            for source_name, rows in all_results.items():
                before = len(rows)
                filtered_rows = filter_by_severity(rows, min_severity)
                after = len(filtered_rows) if filtered_rows else 0
                severity_stats.append((source_name, before, after))
                if filtered_rows:
                    filtered_results[source_name] = filtered_rows

            # Log per-artifact stats
            for artifact, before, after in severity_stats:
                removed = before - after
                if removed > 0:
                    pct = (removed / before * 100) if before > 0 else 0
                    add_log_to_run(run_id, f"[Filter] {artifact}: {before} → {after} (-{removed}, {pct:.0f}% removed)", "info")

            all_results = filtered_results
            total_rows = sum(len(rows) for rows in all_results.values())
            total_removed = before_filter - total_rows

            # Log total summary
            add_log_to_run(run_id, f"[Filter] ─────────────────────────────────────────────", "info")
            pct_total = (total_removed / before_filter * 100) if before_filter > 0 else 0
            add_log_to_run(run_id, f"[Filter] TOTAL: {before_filter} → {total_rows} (-{total_removed} rows, {pct_total:.0f}% removed)", "success" if total_removed > 0 else "info")

        # Final combined summary if any filtering was applied
        if time_filtered or severity_filtered:
            total_removed_all = original_total - total_rows
            if total_removed_all > 0:
                pct_all = (total_removed_all / original_total * 100) if original_total > 0 else 0
                add_log_to_run(run_id, f"[Filter] ═════════════════════════════════════════════", "info")
                add_log_to_run(run_id, f"[Filter] FINAL: {original_total} → {total_rows} rows (-{total_removed_all}, {pct_all:.0f}% total removed)", "success")

        add_log_to_run(run_id, f"[Pipeline] Client info: {len(client_info)} clients", "info")

        # Load external log files (if provided)
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
            if original_total > 0:
                add_log_to_run(run_id, f"[Pipeline] Data was collected ({original_total} rows) but all rows were removed by filters. Try lowering the severity filter or adjusting the time range.", "warning")
            else:
                add_log_to_run(run_id, "[Pipeline] No data in collection results - try a different blueprint or longer collection time.", "warning")
            report_content = generate_empty_report(
                {"name": f"Existing {collection_type.title()}", "artifacts": artifacts},
                list(client_info.keys()),
                0
            )
            save_report_content(run_id, report_content)
            _update_phase(run_id, "completed", 100)
            update_run_status(run_id, "completed", progress=100)
            return

        # Run LLM analysis on the results
        if cancel_event and cancel_event.is_set():
            return

        if llm_enabled:
            add_log_to_run(run_id, "[LLM] Starting artifact analysis...", "info")
            _update_phase(run_id, "analyzing", 20)
            # Read master_prompt early (same pattern the main pipeline uses)
            # so analyze_artifacts can thread it into every per-artifact call.
            _wf_for_mp = get_workflow(run_id)
            _master_prompt_early = (((_wf_for_mp or {}).get('details') or {}).get('master_prompt')) or None
            if _master_prompt_early:
                add_log_to_run(run_id, "[Pipeline] Master prompt active — operator corrections will be applied to all LLM calls.", "info")
            from services.agentic.analyzers import analyze_artifacts
            artifact_summaries = analyze_artifacts(
                run_id, all_results, llm_config, anonymizer,
                master_prompt=_master_prompt_early,
            )
            add_log_to_run(run_id, f"[LLM] Analysis complete: {len(artifact_summaries)} artifact summaries", "success")
            _update_phase(run_id, "analyzing", 80)
        else:
            artifact_summaries = {}
            add_log_to_run(run_id, "[Pipeline] Collect-only (no LLM) — skipping artifact analysis.", "info")

        # Log masking summary before report generation
        if anonymizer:
            for line in anonymizer.get_masking_log_lines():
                add_log_to_run(run_id, line, "info")

        # Generate reports
        if cancel_event and cancel_event.is_set():
            return

        # Pre-synthesis success check — same rationale as the main
        # pipeline path: don't waste another LLM call on a dead endpoint
        # when every analysis already failed.
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
        multi_reports = None
        zip_path = None
        if not llm_enabled:
            add_log_to_run(run_id, f"[Report] Collect-only (no LLM): {total_rows} rows across "
                           f"{len(all_results)} artifacts — fuse into a Case for findings.", "info")
            report_content = {'technical': _collect_only_report(
                total_rows, all_results, len(client_info))}
            save_report_content(run_id, report_content)
            report_types = []
        if report_types:
            _update_phase(run_id, "generating_report", 85)

            # Build pseudo-blueprint for report generation
            pseudo_blueprint = {
                "name": f"Existing {collection_type.title()} Analysis",
                "description": f"Analysis of {collection_type} {collection_id}",
                "artifacts": artifacts
            }
            client_ids_list = list(client_info.keys())

            # Same details-read pattern as the main pipeline path. cross_client_
            # synthesis + master_prompt are stashed in workflow.details by the
            # route. Read once here and thread into both report-generation
            # variants below.
            _existing_workflow = get_workflow(run_id)
            _existing_details = (_existing_workflow.get('details') or {}) if _existing_workflow else {}
            existing_cross_client = bool(_existing_details.get('cross_client_synthesis'))
            existing_master_prompt = _existing_details.get('master_prompt') or None

            # Hostnames for the report header. Two-tier resolution:
            # 1. Prefer row-derived (`_hostname` tag from the original
            #    collection) — works in air-gap / uploaded-data scenarios.
            # 2. For any client that returned zero rows (so no _hostname
            #    to extract), fall back to a live VQL query against the
            #    Velociraptor server. Without the fallback the report
            #    header shows the ugly "Client-3653059e5f15efc6" stub
            #    for any client that didn't deliver data.
            existing_hostnames = {}
            needs_live_lookup = []
            for cid in client_ids_list:
                hn = get_client_hostname(cid, all_results)
                if hn and not hn.startswith('Client-'):
                    existing_hostnames[cid] = hn
                else:
                    needs_live_lookup.append(cid)
            if needs_live_lookup:
                try:
                    from services.agentic.collectors import resolve_hostnames as _rh
                    live = _rh(needs_live_lookup)
                    for cid in needs_live_lookup:
                        existing_hostnames[cid] = live.get(cid) or get_client_hostname(cid, all_results)
                except Exception:
                    for cid in needs_live_lookup:
                        existing_hostnames[cid] = get_client_hostname(cid, all_results)

            # Multi-client: generate per-client reports + macro summary + ZIP.
            # Mirrors the new-collection pipeline's multi-client branch
            # (~L209-246) so an analyze-existing run that pulled rows from
            # >1 client gets the same per-client + macro-level outputs and
            # downloadable ZIP package, not just a single merged report.
            if len(client_ids_list) > 1:
                add_log_to_run(run_id, f"[Report] Multi-client mode: {len(client_ids_list)} clients", "info")
                try:
                    multi_reports = generate_multi_client_reports(
                        run_id, pseudo_blueprint, client_ids_list, 0,
                        artifact_summaries, all_results, llm_config, anonymizer,
                        hostnames=existing_hostnames,
                        # Note: this used to reference an undefined
                        # `cross_client_synthesis` (lived in the main
                        # pipeline's scope, not here). Use the
                        # `existing_cross_client` value read from
                        # workflow.details a few lines up.
                        generate_macro=existing_cross_client,
                        master_prompt=existing_master_prompt,
                    )

                    # Create ZIP package (per-client MDs + macro summary)
                    zip_path = create_report_package(run_id, multi_reports)
                    add_log_to_run(run_id, f"[Report] Created ZIP package: {zip_path}", "info")

                    # Disk copy of per-client reports for the chat assistant.
                    persist_per_client_reports(
                        run_id,
                        multi_reports.get('per_client') or {},
                        multi_reports.get('hostnames') or {},
                    )

                    # Save macro report as the main report (back-compat with
                    # the single-report download endpoint)
                    report_content = {'technical': multi_reports['macro']}
                    save_report_content(run_id, report_content)

                    # Update workflow details so the UI surfaces per-client
                    # download buttons and the multi-client badge.
                    workflow = get_workflow(run_id)
                    if workflow:
                        if 'details' not in workflow:
                            workflow['details'] = {}
                        workflow['details']['multi_client'] = True
                        workflow['details']['report_zip'] = zip_path
                        workflow['details']['client_count'] = len(client_ids_list)
                        workflow['details']['hostnames'] = multi_reports.get('hostnames', {})
                        save_workflow(workflow)
                except Exception as report_error:
                    add_log_to_run(run_id, f"[Report] Error generating multi-client report: {str(report_error)}", "warning")
                    print(f"[AGENTIC] Multi-client report error: {report_error}", flush=True)
                    traceback.print_exc()
                    # Fallback: raw summaries glued together so the operator
                    # still has SOMETHING to read.
                    fallback_content = "# Multi-Client Analysis (Partial)\n\n"
                    fallback_content += "**Note:** Report generation encountered an error. Raw summaries below.\n\n"
                    for artifact, summary in artifact_summaries.items():
                        fallback_content += f"## {artifact}\n{summary}\n\n"
                    report_content = {'technical': fallback_content}
                    save_report_content(run_id, report_content)

            # Single client: existing behaviour preserved verbatim.
            else:
                add_log_to_run(run_id, f"[Report] Generating {' + '.join(report_types)} report(s)...", "info")
                try:
                    report_content = generate_final_report(
                        run_id, pseudo_blueprint, client_ids_list, 0,
                        artifact_summaries, all_results, llm_config, report_types, anonymizer,
                        hostnames=existing_hostnames,
                        master_prompt=existing_master_prompt,
                    )
                    save_report_content(run_id, report_content)
                except Exception as report_error:
                    add_log_to_run(run_id, f"[Report] Error generating report: {str(report_error)}", "warning")
                    print(f"[AGENTIC] Report generation error: {report_error}", flush=True)
                    traceback.print_exc()
                    # Create fallback report
                    fallback_content = "# Analysis Report (Partial)\n\n"
                    fallback_content += "**Note:** Report generation encountered an error. Raw summaries below.\n\n"
                    for artifact, summary in artifact_summaries.items():
                        fallback_content += f"## {artifact}\n{summary}\n\n"
                    report_content = {'technical': fallback_content}
                    save_report_content(run_id, report_content)

        # Import to IRIS if enabled
        if import_to_iris:
            add_log_to_run(run_id, "[IRIS] Starting IRIS import...", "info")
            _update_phase(run_id, "importing_to_iris", 92)

            try:
                from services.iris_service import import_to_iris as iris_import
                from config import IRIS_CONFIG

                # Extract timeline events with severity filter applied
                all_events = extract_timeline_events(all_results, include_no_timestamp=True)
                timeline_events = filter_malicious_events(all_events, min_severity=min_severity)
                add_log_to_run(run_id, f"[IRIS] Extracted {len(timeline_events)} events for timeline (severity: {min_severity}+)", "info")

                if not iris_case_name:
                    iris_case_name = f"Agentic Analysis - {collection_type.title()} {collection_id} - {datetime.now().strftime('%Y-%m-%d %H:%M')}"

                # Get technical report for IOC extraction
                technical_report = ""
                if report_content:
                    if isinstance(report_content, dict):
                        technical_report = report_content.get('technical', '')
                    elif isinstance(report_content, str):
                        technical_report = report_content

                add_log_to_run(run_id, f"[IRIS] Found {len(list(client_info.values()))} clients to add as assets", "info")

                # Pass unfiltered events for IOC extraction
                # Per-artifact LLM summaries are the highest-fidelity IOC
                # source — see extract_iocs_from_summaries in iris_service.
                # min_ioc_severity stays None on the re-ingest path: if the
                # user re-ran analysis they want everything the LLM flagged.
                iris_result = iris_import(
                    run_id=run_id,
                    case_name=iris_case_name,
                    timeline_events=timeline_events,
                    technical_report=technical_report,
                    iris_config=IRIS_CONFIG,
                    clients=list(client_info.values()),
                    blueprint_name=f"Existing {collection_type.title()}",
                    all_events_for_iocs=all_events,
                    artifact_summaries=artifact_summaries,
                    logger=lambda msg, level: add_log_to_run(run_id, msg, level)
                )

                if iris_result.get('success'):
                    add_log_to_run(run_id, f"[IRIS] Case created: {iris_result.get('case_url')}", "success")
                    add_log_to_run(run_id, f"[IRIS] Added {iris_result.get('assets_imported', 0)} assets", "info")
                    add_log_to_run(run_id, f"[IRIS] Imported {iris_result.get('events_imported')} timeline events", "info")
                    add_log_to_run(run_id, f"[IRIS] Imported {iris_result.get('iocs_imported')} IOCs", "info")
                    workflow = get_workflow(run_id)
                    if workflow:
                        if 'details' not in workflow:
                            workflow['details'] = {}
                        workflow['details']['iris_result'] = iris_result
                        save_workflow(workflow)
                else:
                    add_log_to_run(run_id, f"[IRIS] Import failed: {iris_result.get('error')}", "warning")

            except Exception as e:
                add_log_to_run(run_id, f"[IRIS] Import error: {str(e)}", "warning")

        # Persist artifact summaries + raw row data so interactive-mode
        # re-runs on this workflow can use the cheap reports-only path.
        # Mirrors the main pipeline's persistence step.
        try:
            persist_pipeline_artifacts(run_id, artifact_summaries, all_results)
        except Exception as _e:
            print(f"[AGENTIC] persist_pipeline_artifacts failed (non-fatal): {_e}", flush=True)

        _update_phase(run_id, "completed", 100)
        add_log_to_run(run_id, "[Pipeline] Analysis complete! Report ready.", "success")
        if not is_cancelled(run_id):
            update_run_status(run_id, "completed", progress=100)

    except Exception as e:
        if is_cancelled(run_id):
            return
        error_msg = f"[Pipeline] Error: {str(e)}"
        print(f"[AGENTIC] {error_msg}", flush=True)
        traceback.print_exc()
        add_log_to_run(run_id, error_msg, "error")
        update_run_status(run_id, "failed", error=str(e))
    finally:
        try:
            _watchdog.cancel()
        except Exception:
            pass
        unregister_cancel(run_id)
