#!/usr/bin/env python3
"""
Agentic Pipeline - Main orchestration for forensics analysis pipeline
"""

import traceback
from datetime import datetime

from services.workflow_service import (
    add_log_to_run,
    update_run_status
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
    save_report_content
)
from services.agentic.utils import extract_timeline_events, filter_high_severity_events


def run_agentic_pipeline(run_id, blueprint_id, client_ids, collection_minutes, llm_config,
                         report_types=None, severity_level='medium', anonymize_data=False, custom_patterns=None,
                         import_to_iris=False, iris_case_name=None):
    """Background thread: full agentic forensics pipeline
    Args:
        report_types: List of report types to generate: ['technical'], or None for both
        severity_level: Minimum severity level filter ('informational', 'low', 'medium', 'high', 'critical')
        anonymize_data: If True, mask sensitive data before LLM analysis
        custom_patterns: List of custom regex patterns to mask (e.g., ['acme-corp.com', 'ACMECORP\\'])
        import_to_iris: If True, import timeline events and IOCs to IRIS after report generation
        iris_case_name: Optional custom name for the IRIS case (auto-generated if not provided)
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
        settings = blueprint.get('settings', {})
        add_log_to_run(run_id, f"[Pipeline] Blueprint: {blueprint.get('name')} ({len(artifacts)} artifacts)", "info")
        add_log_to_run(run_id, f"[Pipeline] Clients: {len(client_ids)} selected", "info")
        add_log_to_run(run_id, f"[Pipeline] Collection time: {collection_minutes} minutes", "info")
        if anonymizer:
            pattern_count = len(custom_patterns) if custom_patterns else 0
            add_log_to_run(run_id, f"[Pipeline] Data anonymization: ENABLED ({pattern_count} custom patterns)", "info")
        add_log_to_run(run_id, f"[Pipeline] Severity filter: {severity_level.upper()}", "info")
        if import_to_iris:
            add_log_to_run(run_id, f"[Pipeline] IRIS import: ENABLED", "info")

        # 2. Create collections on selected clients
        add_log_to_run(run_id, "[Velociraptor] Creating collections on selected clients...", "info")
        _update_phase(run_id, "creating_collections", 5)

        collection_results = create_collections(run_id, artifacts, settings, client_ids)
        success_collections = [c for c in collection_results if c['flow_id']]
        add_log_to_run(run_id, f"[Velociraptor] Created {len(success_collections)}/{len(client_ids)} collections ({len(artifacts)} artifacts each)", "info")

        if not success_collections:
            add_log_to_run(run_id, "[Velociraptor] No collections were created successfully", "error")
            update_run_status(run_id, "failed", progress=0, error="Failed to create any collections")
            return

        # 3. Stream collect and analyze - monitors flows, retrieves results as available, runs LLM in parallel
        add_log_to_run(run_id, f"[Velociraptor] Collecting data for up to {collection_minutes} minutes (streaming analysis)...", "info")
        _update_phase(run_id, "collecting", 10)
        all_results, artifact_summaries, timed_out = stream_collect_and_analyze(
            run_id, success_collections, artifacts, collection_minutes, llm_config, anonymizer, severity_level, _update_phase
        )

        # 4. Cancel any remaining collections ONLY if we timed out
        if timed_out:
            add_log_to_run(run_id, "[Velociraptor] Collection timed out - stopping remaining collections...", "warning")
            cancel_collections(run_id, success_collections)
        else:
            add_log_to_run(run_id, "[Velociraptor] All flows completed naturally", "success")

        total_rows = sum(len(rows) for rows in all_results.values())
        add_log_to_run(run_id, f"[Pipeline] Collection complete: {total_rows} total rows across {len(all_results)} artifacts", "success")

        if total_rows == 0:
            add_log_to_run(run_id, "[Pipeline] No results collected from selected clients", "warning")
            report_content = generate_empty_report(blueprint, client_ids, collection_minutes)
            save_report_content(run_id, report_content)
            _update_phase(run_id, "completed", 100)
            add_log_to_run(run_id, "[Report] Report generated (no data collected)", "info")
            update_run_status(run_id, "completed", progress=100)
            return

        # 7. Generate report(s) - skip if no report types selected
        report_content = {}
        if report_types:
            report_type_str = " + ".join(report_types) if len(report_types) > 1 else report_types[0]
            add_log_to_run(run_id, f"[Report] Generating {report_type_str} report(s)...", "info")
            _update_phase(run_id, "generating_report", 85)
            report_content = generate_final_report(
                run_id, blueprint, client_ids, collection_minutes,
                artifact_summaries, all_results, llm_config, report_types, anonymizer
            )

            # 8. Save report
            save_report_content(run_id, report_content)
        else:
            add_log_to_run(run_id, "[Report] No report types selected - skipping report generation", "info")
            _update_phase(run_id, "skipping_report", 85)

        # 9. Import to IRIS (if enabled)
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

                # Extract timeline events and filter for high-severity only
                all_timeline_events = extract_timeline_events(all_results, include_no_timestamp=True)
                timeline_events = filter_high_severity_events(all_timeline_events)
                add_log_to_run(run_id, f"[IRIS] Filtered {len(all_timeline_events)} -> {len(timeline_events)} high-severity events for IRIS", "info")

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

                # Import to IRIS
                iris_result = iris_import(
                    run_id=run_id,
                    case_name=iris_case_name,
                    timeline_events=timeline_events,
                    technical_report=technical_report,
                    iris_config=IRIS_CONFIG,
                    clients=selected_clients,
                    blueprint_name=blueprint.get('name', 'Agentic Analysis'),
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
        update_run_status(run_id, "completed", progress=100)

    except Exception as e:
        error_msg = f"[Pipeline] Error: {str(e)}"
        print(f"[AGENTIC] {error_msg}", flush=True)
        traceback.print_exc()
        add_log_to_run(run_id, error_msg, "error")
        add_log_to_run(run_id, traceback.format_exc(), "error")
        update_run_status(run_id, "failed", error=str(e))


def _update_phase(run_id, phase, progress):
    """Update workflow with current phase and progress"""
    workflow = get_workflow(run_id)
    if workflow:
        workflow['phase'] = phase
        workflow['progress'] = progress
        save_workflow(workflow)


def run_agentic_on_existing(run_id, flow_id, hunt_id, llm_config,
                             report_types=None, severity_level='medium', anonymize_data=False, custom_patterns=None,
                             import_to_iris=False, iris_case_name=None):
    """Run AI analysis on an existing Velociraptor flow or hunt (skip collection step)

    Args:
        run_id: Workflow run ID for tracking
        flow_id: Existing flow ID (F.xxx) - for single client collection
        hunt_id: Existing hunt ID (H.xxx) - for multi-client hunt
        llm_config: LLM configuration dictionary
        report_types: List of report types to generate
        severity_level: Minimum severity level filter
        anonymize_data: If True, mask sensitive data before LLM analysis
        custom_patterns: List of custom patterns to mask
        import_to_iris: If True, import to IRIS after analysis
        iris_case_name: Optional custom IRIS case name
    """
    if report_types is None:
        report_types = ['technical']

    # Create anonymizer if enabled
    anonymizer = None
    if anonymize_data:
        anonymizer = DataAnonymizer(custom_patterns=custom_patterns)

    try:
        update_run_status(run_id, "running", progress=2)
        collection_id = flow_id or hunt_id
        collection_type = "flow" if flow_id else "hunt"
        add_log_to_run(run_id, f"[Pipeline] Analyzing existing {collection_type}: {collection_id}", "info")

        _update_phase(run_id, "fetching_results", 5)

        # Fetch results from existing flow/hunt
        from services.agentic.collectors import get_existing_collection_results
        all_results, artifacts, client_info = get_existing_collection_results(run_id, flow_id, hunt_id)

        if not all_results:
            add_log_to_run(run_id, f"[Pipeline] No results found in {collection_type} {collection_id}", "error")
            update_run_status(run_id, "failed", error="No results found in collection")
            return

        total_rows = sum(len(rows) for rows in all_results.values())
        add_log_to_run(run_id, f"[Pipeline] Retrieved {total_rows} rows across {len(all_results)} artifacts", "info")
        add_log_to_run(run_id, f"[Pipeline] Client info: {len(client_info)} clients", "info")

        if total_rows == 0:
            add_log_to_run(run_id, "[Pipeline] No data in collection results", "warning")
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
        add_log_to_run(run_id, "[LLM] Starting artifact analysis...", "info")
        _update_phase(run_id, "analyzing", 20)

        from services.agentic.analyzers import analyze_artifacts
        artifact_summaries = analyze_artifacts(run_id, all_results, llm_config, anonymizer)

        add_log_to_run(run_id, f"[LLM] Analysis complete: {len(artifact_summaries)} artifact summaries", "success")
        _update_phase(run_id, "analyzing", 80)

        # Generate reports
        report_content = {}
        if report_types:
            add_log_to_run(run_id, f"[Report] Generating {' + '.join(report_types)} report(s)...", "info")
            _update_phase(run_id, "generating_report", 85)

            # Build pseudo-blueprint for report generation
            pseudo_blueprint = {
                "name": f"Existing {collection_type.title()} Analysis",
                "description": f"Analysis of {collection_type} {collection_id}",
                "artifacts": artifacts
            }

            report_content = generate_final_report(
                run_id, pseudo_blueprint, list(client_info.keys()), 0,
                artifact_summaries, all_results, llm_config, report_types, anonymizer
            )
            save_report_content(run_id, report_content)

        # Import to IRIS if enabled
        if import_to_iris:
            add_log_to_run(run_id, "[IRIS] Starting IRIS import...", "info")
            _update_phase(run_id, "importing_to_iris", 92)

            try:
                from services.iris_service import import_to_iris as iris_import
                timeline_events = extract_timeline_events(all_results)
                filtered_events = filter_high_severity_events(timeline_events, artifact_summaries)

                if not iris_case_name:
                    iris_case_name = f"Agentic Analysis - {collection_type.title()} {collection_id} - {datetime.now().strftime('%Y-%m-%d %H:%M')}"

                iris_result = iris_import(
                    case_name=iris_case_name,
                    timeline_events=filtered_events,
                    artifact_summaries=artifact_summaries,
                    clients=list(client_info.values()),
                    blueprint_name=f"Existing {collection_type.title()}",
                    logger=lambda msg, level: add_log_to_run(run_id, msg, level)
                )

                if iris_result.get('success'):
                    add_log_to_run(run_id, f"[IRIS] Case created: {iris_result.get('case_url')}", "success")
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
        update_run_status(run_id, "completed", progress=100)

    except Exception as e:
        error_msg = f"[Pipeline] Error: {str(e)}"
        print(f"[AGENTIC] {error_msg}", flush=True)
        traceback.print_exc()
        add_log_to_run(run_id, error_msg, "error")
        update_run_status(run_id, "failed", error=str(e))
