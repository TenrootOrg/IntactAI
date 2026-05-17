#!/usr/bin/env python3
"""
Agentic Pipeline - Main orchestration for forensics analysis pipeline
"""

import traceback
from datetime import datetime

from services.workflow_service import (
    add_log_to_run,
    update_run_status,
    is_cancelled,
    unregister_cancel
)
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
    create_report_package
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

    try:
        update_run_status(run_id, "running", progress=2)
        add_log_to_run(run_id, "[Pipeline] Starting Agentic Forensics pipeline", "info")

        # Validate LLM configuration before starting
        from services.agentic.analyzers import validate_llm_config
        try:
            validate_llm_config(llm_config)
        except ValueError as e:
            add_log_to_run(run_id, f"[Pipeline] Configuration error: {str(e)}", "error")
            update_run_status(run_id, "failed", progress=0, error=str(e))
            return

        # Store report_types in workflow details for UI
        workflow = get_workflow(run_id)
        if workflow:
            if 'details' not in workflow:
                workflow['details'] = {}
            workflow['details']['report_types'] = report_types
            save_workflow(workflow)

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
            run_id, success_collections, artifacts, collection_minutes, llm_config, anonymizer, _update_phase, min_severity, time_filter, cancel_event
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
                # Data existed but filters removed everything
                add_log_to_run(run_id, f"[Pipeline] Data was collected ({total_rows_before_filter} rows) but all rows were removed by filters (severity: {min_severity}+). Try lowering the severity filter or adjusting the time range.", "warning")
            else:
                # No data at all from Velociraptor
                add_log_to_run(run_id, "[Pipeline] No data was returned from the selected clients. Possible causes:", "warning")
                add_log_to_run(run_id, "  - Collection time too short - try increasing it", "warning")
                add_log_to_run(run_id, "  - Artifacts not applicable to this system - try a different blueprint", "warning")
                add_log_to_run(run_id, "  - Clients may be offline - verify client status in Velociraptor", "warning")
            report_content = generate_empty_report(blueprint, client_ids, collection_minutes)
            save_report_content(run_id, report_content)
            _update_phase(run_id, "completed", 100)
            update_run_status(run_id, "completed", progress=100)
            return

        # 7. Generate report(s) - skip if no report types selected
        if cancel_event and cancel_event.is_set():
            return

        report_content = {}
        multi_reports = None
        zip_path = None

        if report_types:
            _update_phase(run_id, "generating_report", 85)

            # Multi-client: generate per-client reports + macro summary
            if len(client_ids) > 1:
                add_log_to_run(run_id, f"[Report] Multi-client mode: {len(client_ids)} clients", "info")
                try:
                    multi_reports = generate_multi_client_reports(
                        run_id, blueprint, client_ids, collection_minutes,
                        artifact_summaries, all_results, llm_config, anonymizer
                    )

                    # Create ZIP package
                    zip_path = create_report_package(run_id, multi_reports)
                    add_log_to_run(run_id, f"[Report] Created ZIP package: {zip_path}", "info")

                    # Save macro report as the main report (for backwards compatibility)
                    report_content = {'technical': multi_reports['macro']}
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
                        artifact_summaries, all_results, llm_config, report_types, anonymizer
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
        unregister_cancel(run_id)


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

        # Validate LLM configuration before starting
        from services.agentic.analyzers import validate_llm_config
        try:
            validate_llm_config(llm_config)
        except ValueError as e:
            add_log_to_run(run_id, f"[Pipeline] Configuration error: {str(e)}", "error")
            update_run_status(run_id, "failed", progress=0, error=str(e))
            return

        _update_phase(run_id, "fetching_results", 5)

        # Fetch all results from existing flow/hunt
        from services.agentic.collectors import get_existing_collection_results
        all_results, artifacts, client_info = get_existing_collection_results(
            run_id, flow_id, hunt_id, time_filter, client_ids=client_ids
        )

        if not all_results:
            add_log_to_run(run_id, f"[Pipeline] No data found in {collection_type} {collection_id}. The collection returned no results - try running a new collection with more artifacts or a longer time window.", "warning")
            update_run_status(run_id, "completed", progress=100)
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

        add_log_to_run(run_id, "[LLM] Starting artifact analysis...", "info")
        _update_phase(run_id, "analyzing", 20)
        from services.agentic.analyzers import analyze_artifacts
        artifact_summaries = analyze_artifacts(run_id, all_results, llm_config, anonymizer)
        add_log_to_run(run_id, f"[LLM] Analysis complete: {len(artifact_summaries)} artifact summaries", "success")
        _update_phase(run_id, "analyzing", 80)

        # Log masking summary before report generation
        if anonymizer:
            for line in anonymizer.get_masking_log_lines():
                add_log_to_run(run_id, line, "info")

        # Generate reports
        if cancel_event and cancel_event.is_set():
            return

        report_content = {}
        multi_reports = None
        zip_path = None
        if report_types:
            _update_phase(run_id, "generating_report", 85)

            # Build pseudo-blueprint for report generation
            pseudo_blueprint = {
                "name": f"Existing {collection_type.title()} Analysis",
                "description": f"Analysis of {collection_type} {collection_id}",
                "artifacts": artifacts
            }
            client_ids_list = list(client_info.keys())

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
                        artifact_summaries, all_results, llm_config, anonymizer
                    )

                    # Create ZIP package (per-client MDs + macro summary)
                    zip_path = create_report_package(run_id, multi_reports)
                    add_log_to_run(run_id, f"[Report] Created ZIP package: {zip_path}", "info")

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
                        artifact_summaries, all_results, llm_config, report_types, anonymizer
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
        unregister_cancel(run_id)
