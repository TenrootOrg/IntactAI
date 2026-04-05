"""
Azure Security Pipeline

Orchestrates the full Azure security automation workflow:
Collection → SIGMA Detection → LLM Analysis → Report → IRIS

Supports both online (live API) and offline (uploaded logs) modes.
"""

import os
import json
import traceback
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from concurrent.futures import ThreadPoolExecutor

# Local imports
from .collectors import collect_azure_logs, parse_uploaded_logs, LOG_SOURCES
from .sigma_runner import run_sigma_rules, load_azure_rules, validate_rules_directory

# Reuse existing agentic components
from services.agentic.analyzers import analyze_artifacts, validate_llm_config
from services.azure.reports import generate_azure_report, save_azure_report
from services.agentic.utils import (
    extract_timeline_events,
    filter_results_by_time,
    create_time_filter_func
)
from services.iris_service import import_to_iris
from services.workflow_logger import add_log_to_run


# =============================================================================
# Main Pipeline Entry Points
# =============================================================================

def run_azure_pipeline(
    run_id: str,
    azure_config: Dict[str, str],
    blueprint: Dict[str, Any],
    options: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Run the full Azure security pipeline (online mode).

    Args:
        run_id: Workflow run ID for logging
        azure_config: Azure credentials (tenant_id, client_id, client_secret)
        blueprint: Blueprint configuration with sources and settings
        options: Pipeline options (enable_llm, time_filter, iris_config, etc.)

    Returns:
        Pipeline result dict with collected data, findings, analysis, and report
    """
    result = {
        'run_id': run_id,
        'mode': 'online',
        'status': 'running',
        'start_time': datetime.utcnow().isoformat(),
        'phases': {}
    }

    try:
        # =====================================================================
        # Phase 1: Validate Configuration
        # =====================================================================
        # Log scan configuration summary
        bp_settings = blueprint.get('settings', {})
        target_users = options.get('target_users', [])
        target_ips = options.get('target_ips', [])
        pivot_mode = options.get('pivot_mode', False)
        time_filter = options.get('time_filter', {})
        enable_llm = options.get('enable_llm', False)

        add_log_to_run(run_id, "=" * 50, "info")
        add_log_to_run(run_id, f"Blueprint: {blueprint.get('name', 'Custom')}", "info")
        if isinstance(time_filter, dict):
            if time_filter.get('type') == 'between':
                add_log_to_run(run_id, f"Time Range: {time_filter.get('start', '?')} → {time_filter.get('end', 'now')}", "info")
            else:
                add_log_to_run(run_id, f"Time Range: Last {time_filter.get('value', '7d')}", "info")
        add_log_to_run(run_id, f"Sources: {', '.join(bp_settings.get('sources', ['all']))}", "info")
        if target_users:
            add_log_to_run(run_id, f"Target Users: {', '.join(target_users)}", "info")
        if target_ips:
            add_log_to_run(run_id, f"Target IPs: {', '.join(target_ips)}", "info")
        if pivot_mode:
            add_log_to_run(run_id, "Pivot Mode: ON (will discover other accounts from same IPs)", "info")
        add_log_to_run(run_id, f"LLM Analysis: {'ON' if enable_llm else 'OFF'}", "info")
        add_log_to_run(run_id, f"Min Severity: {options.get('min_severity', 'medium')}", "info")
        add_log_to_run(run_id, "=" * 50, "info")

        # Validate SIGMA rules are available
        rules_valid, rules_msg = validate_rules_directory()
        if not rules_valid:
            add_log_to_run(run_id, f"[AZURE] Warning: {rules_msg}", "warning")

        # Validate LLM config if enabled
        llm_config = options.get('llm_config', {})
        if enable_llm:
            try:
                validate_llm_config(llm_config)
            except ValueError as e:
                add_log_to_run(run_id, f"[AZURE] LLM disabled: {e}", "warning")
                enable_llm = False

        result['phases']['validation'] = {'status': 'complete'}

        # =====================================================================
        # Phase 2: Collection
        # =====================================================================
        add_log_to_run(run_id, "[AZURE] Phase 2: Collecting logs from Azure...", "info")

        sources = bp_settings.get('sources', ['all'])
        time_range_days = bp_settings.get('time_range_days', 7)

        # Time window
        start_date_str = None
        end_date_str = None
        if isinstance(time_filter, dict):
            if time_filter.get('type') == 'between':
                start_date_str = time_filter.get('start')
                end_date_str = time_filter.get('end')
            elif time_filter.get('type') == 'relative':
                val = time_filter.get('value', '7d')
                days = int(val.replace('d', '').replace('h', '')) if 'd' in val else 1
                if 'h' in val:
                    hours = int(val.replace('h', ''))
                    start_date_str = (datetime.utcnow() - timedelta(hours=hours)).strftime('%Y-%m-%dT%H:%M:%SZ')
                else:
                    time_range_days = days

        if target_users:
            add_log_to_run(run_id, f"[AZURE] Target users: {', '.join(target_users)}", "info")
        if target_ips:
            add_log_to_run(run_id, f"[AZURE] Target IPs: {', '.join(target_ips)}", "info")
        if pivot_mode:
            add_log_to_run(run_id, "[AZURE] Pivot mode enabled", "info")

        collected_data, collection_status = collect_azure_logs(
            azure_config=azure_config,
            sources=sources,
            time_range_days=time_range_days,
            start_date_str=start_date_str,
            end_date_str=end_date_str,
            target_users=target_users,
            target_ips=target_ips,
            pivot_mode=pivot_mode
        )

        result['phases']['collection'] = {
            'status': 'complete',
            'license_tier': collection_status.get('license_tier'),
            'sources_collected': list(collected_data.keys()),
            'total_records': collection_status.get('total_records', 0),
            'errors': collection_status.get('errors', [])
        }

        add_log_to_run(
            run_id,
            f"[AZURE] Collected {collection_status.get('total_records', 0)} records from {len(collected_data)} sources",
            "info"
        )

        # Log per-source results
        for source_key, records in collected_data.items():
            add_log_to_run(run_id, f"[AZURE] {source_key}: {len(records)} records", "success")

        # Log any errors/skipped sources
        for error in collection_status.get('errors', []):
            add_log_to_run(run_id, f"[AZURE] {error}", "warning")

        if not collected_data:
            total_errors = len(collection_status.get('errors', []))
            if total_errors > 0:
                add_log_to_run(run_id, "[AZURE] No data collected. Some sources were skipped - check license tier and API permissions.", "warning")
            else:
                add_log_to_run(run_id, "[AZURE] No events found in the selected time range.", "warning")
            result['status'] = 'completed'
            result['message'] = 'No data collected'
            return result

        # =====================================================================
        # Phase 3: Time Filtering (if enabled)
        # =====================================================================
        time_filter = options.get('time_filter')
        if time_filter:
            add_log_to_run(run_id, f"[AZURE] Applying time filter: {time_filter}", "info")
            time_filter_func = create_time_filter_func(time_filter)
            if time_filter_func:
                collected_data = filter_results_by_time(collected_data, time_filter_func)
                filtered_count = sum(len(v) for v in collected_data.values())
                add_log_to_run(run_id, f"[AZURE] After time filter: {filtered_count} records", "info")

        # Store collected data for API access
        result['collected_data'] = collected_data

        # =====================================================================
        # Phase 4: SIGMA Detection
        # =====================================================================
        add_log_to_run(run_id, "[AZURE] Phase 4: Running SIGMA detection rules...", "info")

        min_severity = options.get('min_severity') or bp_settings.get('min_severity', 'low')
        add_log_to_run(run_id, f"[AZURE] Minimum severity filter: {min_severity}+", "info")
        findings, detection_status = run_sigma_rules(
            logs=collected_data,
            min_level=min_severity
        )

        result['phases']['detection'] = {
            'status': 'complete',
            'rules_executed': detection_status.get('rules_count', 0),
            'total_findings': detection_status.get('total_findings', 0),
            'findings_by_severity': detection_status.get('matches_by_severity', {})
        }

        add_log_to_run(
            run_id,
            f"[AZURE] SIGMA detection complete: {detection_status.get('total_findings', 0)} findings",
            "info"
        )

        # Store findings for API access
        result['findings'] = findings

        # =====================================================================
        # Phase 5: LLM Analysis (if enabled)
        # =====================================================================
        analysis_results = {}
        if enable_llm and findings:
            add_log_to_run(run_id, "[AZURE] Phase 5: Running LLM analysis...", "info")

            try:
                # Analyze findings (not raw logs)
                analysis_results = analyze_artifacts(
                    run_id=run_id,
                    all_results=findings,
                    llm_config=llm_config,
                    anonymizer=options.get('anonymizer')
                )

                result['phases']['analysis'] = {
                    'status': 'complete',
                    'artifacts_analyzed': len(analysis_results)
                }

                add_log_to_run(
                    run_id,
                    f"[AZURE] LLM analysis complete: {len(analysis_results)} summaries",
                    "info"
                )
            except Exception as e:
                add_log_to_run(run_id, f"[AZURE] LLM analysis failed: {e}", "error")
                result['phases']['analysis'] = {'status': 'error', 'error': str(e)}
        else:
            result['phases']['analysis'] = {'status': 'skipped', 'reason': 'LLM disabled or no findings'}

        result['analysis'] = analysis_results

        # =====================================================================
        # Phase 6: Report Generation (if LLM enabled)
        # =====================================================================
        if enable_llm and analysis_results:
            add_log_to_run(run_id, "[AZURE] Phase 6: Generating reports...", "info")

            try:
                # Generate Azure-specific reports
                reports = generate_azure_report(
                    run_id=run_id,
                    blueprint=blueprint,
                    collected_data=collected_data,
                    findings=findings,
                    analysis_results=analysis_results,
                    llm_config=llm_config,
                    scan_metadata={
                        'time_filter': options.get('time_filter', {}),
                        'sources': list(collected_data.keys()),
                    }
                )

                result['reports'] = reports
                result['phases']['reporting'] = {'status': 'complete'}
                result['has_report'] = True

                # Save reports to storage
                save_azure_report(run_id, reports)

                # Mark workflow as having a report (for UI button visibility)
                from services.workflow_service import update_run_status
                update_run_status(run_id, "running", details={'has_report': True})

                add_log_to_run(run_id, "[AZURE] Reports generated successfully", "info")
            except Exception as e:
                add_log_to_run(run_id, f"[AZURE] Report generation failed: {e}", "error")
                result['phases']['reporting'] = {'status': 'error', 'error': str(e)}
        else:
            result['phases']['reporting'] = {'status': 'skipped'}

        # =====================================================================
        # Phase 7: IRIS Import (if configured)
        # =====================================================================
        iris_config = options.get('iris_config')
        if iris_config and iris_config.get('enabled'):
            add_log_to_run(run_id, "[AZURE] Phase 7: Importing to IRIS...", "info")

            try:
                # Extract timeline events for IRIS
                timeline_events = extract_timeline_events(findings, include_no_timestamp=True)

                iris_result = import_to_iris(
                    iris_config=iris_config,
                    all_results=findings,
                    timeline_events=timeline_events,
                    report_content=result.get('reports', {}).get('technical', ''),
                    case_name=f"Azure Investigation - {datetime.utcnow().strftime('%Y-%m-%d')}",
                    case_description=f"Azure security analysis from {blueprint.get('name', 'Unknown')} blueprint"
                )

                result['phases']['iris'] = {
                    'status': 'complete',
                    'case_id': iris_result.get('case_id'),
                    'case_url': iris_result.get('case_url'),
                    'events_imported': iris_result.get('events_imported', 0)
                }

                add_log_to_run(run_id, f"[AZURE] IRIS import complete: {iris_result.get('case_url', 'N/A')}", "info")
            except Exception as e:
                add_log_to_run(run_id, f"[AZURE] IRIS import failed: {e}", "error")
                result['phases']['iris'] = {'status': 'error', 'error': str(e)}
        else:
            result['phases']['iris'] = {'status': 'skipped'}

        # =====================================================================
        # Complete
        # =====================================================================
        result['status'] = 'complete'
        result['end_time'] = datetime.utcnow().isoformat()

        add_log_to_run(run_id, "[AZURE] Pipeline completed successfully", "info")

    except Exception as e:
        result['status'] = 'error'
        result['error'] = str(e)
        result['traceback'] = traceback.format_exc()
        result['end_time'] = datetime.utcnow().isoformat()

        add_log_to_run(run_id, f"[AZURE] Pipeline failed: {e}", "error")

    return result


def run_azure_on_existing(
    run_id: str,
    uploaded_data: Dict[str, List[Dict]],
    options: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Run Azure pipeline on uploaded/existing logs (offline mode).

    Args:
        run_id: Workflow run ID for logging
        uploaded_data: Dict of source_name → log records (already parsed)
        options: Pipeline options (enable_llm, time_filter, etc.)

    Returns:
        Pipeline result dict
    """
    result = {
        'run_id': run_id,
        'mode': 'offline',
        'status': 'running',
        'start_time': datetime.utcnow().isoformat(),
        'phases': {}
    }

    try:
        add_log_to_run(run_id, "[AZURE] Starting offline analysis pipeline", "info")

        # Validate we have data
        if not uploaded_data:
            raise ValueError("No log data provided")

        total_records = sum(len(v) for v in uploaded_data.values())
        add_log_to_run(run_id, f"[AZURE] Processing {total_records} uploaded records", "info")

        result['phases']['upload'] = {
            'status': 'complete',
            'sources': list(uploaded_data.keys()),
            'total_records': total_records
        }

        # Store for API access
        result['collected_data'] = uploaded_data

        # =====================================================================
        # Time Filtering (if enabled)
        # =====================================================================
        time_filter = options.get('time_filter')
        if time_filter:
            add_log_to_run(run_id, f"[AZURE] Applying time filter: {time_filter}", "info")
            time_filter_func = create_time_filter_func(time_filter)
            if time_filter_func:
                uploaded_data = filter_results_by_time(uploaded_data, time_filter_func)
                filtered_count = sum(len(v) for v in uploaded_data.values())
                add_log_to_run(run_id, f"[AZURE] After time filter: {filtered_count} records", "info")

        # =====================================================================
        # SIGMA Detection
        # =====================================================================
        add_log_to_run(run_id, "[AZURE] Running SIGMA detection rules...", "info")

        min_severity = options.get('min_severity', 'low')
        findings, detection_status = run_sigma_rules(
            logs=uploaded_data,
            min_level=min_severity
        )

        result['phases']['detection'] = {
            'status': 'complete',
            'rules_executed': detection_status.get('rules_count', 0),
            'total_findings': detection_status.get('total_findings', 0)
        }

        result['findings'] = findings

        add_log_to_run(
            run_id,
            f"[AZURE] Detection complete: {detection_status.get('total_findings', 0)} findings",
            "info"
        )

        # =====================================================================
        # LLM Analysis (if enabled)
        # =====================================================================
        enable_llm = options.get('enable_llm', False)
        llm_config = options.get('llm_config', {})

        if enable_llm and findings:
            add_log_to_run(run_id, "[AZURE] Running LLM analysis...", "info")

            try:
                analysis_results = analyze_artifacts(
                    all_results=findings,
                    llm_config=llm_config,
                    anonymizer=options.get('anonymizer')
                )

                result['analysis'] = analysis_results
                result['phases']['analysis'] = {
                    'status': 'complete',
                    'artifacts_analyzed': len(analysis_results)
                }

                # Generate reports
                timeline_events = extract_timeline_events(findings)
                reports = generate_final_report(
                    artifact_summaries=analysis_results,
                    timeline_events=timeline_events,
                    llm_config=llm_config,
                    metadata={
                        'platform': 'Azure',
                        'mode': 'offline',
                        'sources': list(uploaded_data.keys()),
                        'findings_count': detection_status.get('total_findings', 0)
                    }
                )
                result['reports'] = reports
                result['phases']['reporting'] = {'status': 'complete'}

            except Exception as e:
                add_log_to_run(run_id, f"[AZURE] LLM analysis failed: {e}", "error")
                result['phases']['analysis'] = {'status': 'error', 'error': str(e)}
        else:
            result['phases']['analysis'] = {'status': 'skipped'}
            result['phases']['reporting'] = {'status': 'skipped'}

        # =====================================================================
        # IRIS Import (if configured)
        # =====================================================================
        iris_config = options.get('iris_config')
        if iris_config and iris_config.get('enabled') and findings:
            try:
                timeline_events = extract_timeline_events(findings, include_no_timestamp=True)
                iris_result = import_to_iris(
                    iris_config=iris_config,
                    all_results=findings,
                    timeline_events=timeline_events,
                    report_content=result.get('reports', {}).get('technical', ''),
                    case_name=f"Azure Analysis (Offline) - {datetime.utcnow().strftime('%Y-%m-%d')}",
                    case_description="Azure security analysis from uploaded logs"
                )
                result['phases']['iris'] = {
                    'status': 'complete',
                    'case_id': iris_result.get('case_id')
                }
            except Exception as e:
                result['phases']['iris'] = {'status': 'error', 'error': str(e)}
        else:
            result['phases']['iris'] = {'status': 'skipped'}

        result['status'] = 'complete'
        result['end_time'] = datetime.utcnow().isoformat()

        add_log_to_run(run_id, "[AZURE] Offline analysis completed", "info")

    except Exception as e:
        result['status'] = 'error'
        result['error'] = str(e)
        result['end_time'] = datetime.utcnow().isoformat()

        add_log_to_run(run_id, f"[AZURE] Pipeline failed: {e}", "error")

    return result


# =============================================================================
# Blueprint Helpers
# =============================================================================

def get_azure_blueprints() -> List[Dict]:
    """Get available Azure DFIR blueprints (detection-first model)."""
    return [
        {
            'id': 'azure_quick_triage',
            'name': 'Quick Triage',
            'description': 'Fast check: security alerts + risk detections only (Tier 1)',
            'settings': {
                'sources': ['security_alerts', 'risk_detections', 'risky_signins'],
                'time_range_days': 7,
            },
            'min_severity': 'low'
        },
        {
            'id': 'azure_account_investigation',
            'name': 'Account Investigation',
            'description': 'Investigate specific accounts: sign-ins + audit filtered by target users',
            'settings': {
                'sources': ['security_alerts', 'risk_detections', 'risky_signins', 'signin_logs', 'audit_logs'],
                'time_range_days': 2,
            },
            'min_severity': 'low',
            'requires_target_users': True
        },
        {
            'id': 'azure_lateral_movement',
            'name': 'Lateral Movement',
            'description': 'Find other accounts accessed from same IPs as target users (pivot mode)',
            'settings': {
                'sources': ['security_alerts', 'risk_detections', 'signin_logs', 'audit_logs'],
                'time_range_days': 2,
            },
            'min_severity': 'low',
            'requires_target_users': True,
            'pivot_mode': True
        },
        {
            'id': 'azure_full_investigation',
            'name': 'Full Investigation',
            'description': 'All available sources (Tier 1 + 2 + 3). Higher volume.',
            'settings': {
                'sources': ['all'],
                'time_range_days': 7,
            },
            'min_severity': 'informational'
        }
    ]


def get_available_sources() -> List[Dict]:
    """Get list of available Azure log sources with their details."""
    return [
        {
            'id': source_id,
            'name': info['name'],
            'license': info['license'],
            'description': f"Requires {info['license'].upper()} license or higher"
        }
        for source_id, info in LOG_SOURCES.items()
    ]
