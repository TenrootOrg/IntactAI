"""
Azure Security Pipeline

Orchestrates the full Azure security automation workflow:
Collection → SIGMA Detection → LLM Analysis → Report → IRIS

Supports both online (live API) and offline (uploaded logs) modes.
"""

import os
import json
import traceback
from datetime import datetime, timedelta
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
    create_time_filter_func,
    normalize_all_results,
)
from services.iris_service import import_to_iris
from services.workflow_logger import add_log_to_run
from services.workflow_service import update_run_status as _update_run_status


def _set_progress(run_id: str, pct: int) -> None:
    """Update workflow progress percentage if run_id is set."""
    if run_id:
        try:
            _update_run_status(run_id, "running", progress=pct)
        except Exception:
            pass


def _make_phase_timer(run_id: str):
    """Build phase_start/phase_end helpers bound to a run_id.

    Each phase_end call persists `time.monotonic() - start` onto the workflow
    row's phase_timings dict. Helpers swallow exceptions so timing never breaks
    the pipeline. If the same phase name is started twice without an end the
    first start is silently overwritten — the timing dashboard would show only
    the second run, but real phases never re-enter.
    """
    import time as _time

    starts: Dict[str, float] = {}

    def phase_start(name: str) -> None:
        starts[name] = _time.monotonic()

    def phase_end(name: str) -> None:
        t0 = starts.pop(name, None)
        if t0 is None or not run_id:
            return
        try:
            from services.workflow_service import record_phase_timing
            record_phase_timing(run_id, name, _time.monotonic() - t0)
        except Exception as ex:
            print(f"[PIPELINE] phase timing failed for {name}: {ex}", flush=True)

    return phase_start, phase_end


def _run_post_collection_phases(
    run_id: str,
    collected_data: Dict[str, List[Dict]],
    options: Dict[str, Any],
    *,
    blueprint: Dict,
    azure_config: Dict,
    enable_llm: bool,
    llm_config: Dict,
    bp_settings: Dict,
    phase_start,
    phase_end,
    result: Dict,
) -> Dict:
    """Phases 3 through 7 of the Azure pipeline.

    Single source of truth shared by the online (`run_azure_pipeline`)
    and offline (`run_azure_on_existing`) entry points. The caller is
    responsible for getting `collected_data` populated — by collection
    against the live tenant, or by parsing uploaded files. Everything
    after that is identical:

      * Phase 3 — time filter
      * Timestamp normalisation (same canonical format on every path)
      * Phase 4 — SIGMA detection (with `scope_mode`)
      * Phase 4b — UAL operation-string pre-detection
      * Phase 4c — state-snapshot wrapping (CA policies, federation)
      * Phase 5 — LLM analysis (with `pipeline_kind="azure"`)
      * Phase 6 — Azure-formatted report (`generate_azure_report`)
      * Phase 7 — optional IRIS import

    `result` is mutated in place: phases dict, findings, analysis,
    reports, has_report, status. Returned for callers that want to
    chain.
    """
    from services.workflow_service import is_cancelled, record_sigma_rule_tally, update_run_status

    # Apply timestamp normalisation right at the entry — every downstream
    # phase (SIGMA matching, LLM prompt, report writer) sees one canonical
    # format. Same helper the on-prem (Velociraptor) flow uses.
    try:
        normalize_all_results(collected_data)
        add_log_to_run(run_id, "[AZURE] Normalized timestamps across all sources", "info")
    except Exception as ex:
        add_log_to_run(run_id, f"[AZURE] Timestamp normalization failed (non-fatal): {ex}", "warning")

    if is_cancelled(run_id):
        return result

    # ---- Phase 3: Time filter ----
    time_filter = options.get('time_filter')
    if time_filter:
        add_log_to_run(run_id, f"[AZURE] Applying time filter: {time_filter}", "info")
        time_filter_func = create_time_filter_func(time_filter)
        if time_filter_func:
            collected_data = filter_results_by_time(collected_data, time_filter_func)
            filtered_count = sum(len(v) for v in collected_data.values())
            add_log_to_run(run_id, f"[AZURE] After time filter: {filtered_count} records", "info")

    result['collected_data'] = collected_data
    _set_progress(run_id, 60)

    if is_cancelled(run_id):
        return result

    # ---- Phase 4: SIGMA detection ----
    add_log_to_run(run_id, "[AZURE] Phase 4: Running SIGMA detection rules...", "info")
    _set_progress(run_id, 65)
    phase_start("detection")

    min_severity = options.get('min_severity') or bp_settings.get('min_severity', 'low')
    add_log_to_run(run_id, f"[AZURE] Minimum severity filter: {min_severity}+", "info")
    findings, detection_status = run_sigma_rules(
        logs=collected_data,
        min_level=min_severity,
    )

    result['phases']['detection'] = {
        'status': 'complete',
        'rules_executed': detection_status.get('rules_count', 0),
        'total_findings': detection_status.get('total_findings', 0),
        'findings_by_severity': detection_status.get('matches_by_severity', {}),
        'rule_tally': detection_status.get('rule_tally', {}),
    }

    rule_tally = detection_status.get('rule_tally') or {}
    if rule_tally:
        try:
            record_sigma_rule_tally(run_id, rule_tally)
        except Exception as ex:
            print(f"[PIPELINE] sigma tally persist failed: {ex}", flush=True)

    add_log_to_run(
        run_id,
        f"[AZURE] SIGMA detection complete: {detection_status.get('total_findings', 0)} findings",
        "info",
    )
    for rname, rcount in sorted(rule_tally.items(), key=lambda kv: -kv[1]):
        add_log_to_run(run_id, f"[AZURE]   {rname}: {rcount}", "info")

    # ---- Phase 4b: UAL pre-detected findings ----
    SEVERITY_RANK = {'informational': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
    min_rank = SEVERITY_RANK.get(min_severity, 1)

    ual_events = collected_data.get('Azure.UnifiedAudit', [])
    ual_findings_added = 0
    if ual_events:
        filtered = [e for e in ual_events
                    if SEVERITY_RANK.get(e.get('_severity', 'low'), 1) >= min_rank]
        by_category = {}
        for event in filtered:
            cat = event.get('_category', 'unknown')
            if cat == 'unknown':
                continue
            key = f"UAL.{cat}"
            if key not in by_category:
                by_category[key] = []
            by_category[key].append({
                '_source': 'Azure.UnifiedAudit',
                '_severity': event.get('_severity'),
                '_category': event.get('_category'),
                '_description': event.get('_description'),
                '_timestamp': event.get('CreationTime') or event.get('_timestamp'),
                'rule_title': f"UAL: {event.get('_description', cat)}",
                'severity': event.get('_severity'),
                'matched_record': event,
                '_finding_time': datetime.utcnow().isoformat(),
            })
        for key, items in by_category.items():
            findings[key] = items
            ual_findings_added += len(items)
        if ual_findings_added > 0:
            add_log_to_run(
                run_id,
                f"[AZURE] Added {ual_findings_added} UAL pre-detected findings "
                f"in {len(by_category)} categories (severity >= {min_severity})",
                "info",
            )

    # ---- Phase 4c: state-snapshot findings ----
    STATE_SOURCE_MAP = {
        'Azure.CAPolicy': 'INV.ca_policies',
        'Azure.Federation': 'INV.federation',
    }
    state_findings_added = 0
    for src_key, finding_key in STATE_SOURCE_MAP.items():
        records = collected_data.get(src_key, [])
        if not records:
            continue
        filtered = [r for r in records
                    if SEVERITY_RANK.get(r.get('_severity', 'low'), 1) >= min_rank]
        if not filtered:
            continue
        findings[finding_key] = [
            {
                '_source': src_key,
                '_severity': r.get('_severity'),
                '_category': r.get('_category'),
                '_description': r.get('_description'),
                '_timestamp': None,
                'rule_title': f"State: {r.get('_description', finding_key)}",
                'rule_description': f'Current configuration of {src_key} (state snapshot, not an event)',
                'severity': r.get('_severity'),
                'matched_record': r,
                '_finding_time': datetime.utcnow().isoformat(),
                '_state_snapshot': True,
            }
            for r in filtered
        ]
        state_findings_added += len(filtered)
    if state_findings_added > 0:
        add_log_to_run(
            run_id,
            f"[AZURE] Added {state_findings_added} state-snapshot findings "
            f"from {len([k for k in STATE_SOURCE_MAP if STATE_SOURCE_MAP[k] in findings])} sources",
            "info",
        )

    result['findings'] = findings
    _set_progress(run_id, 70)
    phase_end("detection")

    if is_cancelled(run_id):
        return result

    # ---- Phase 5: LLM analysis ----
    analysis_results = {}
    if enable_llm and findings:
        add_log_to_run(run_id, "[AZURE] Phase 5: Running LLM analysis...", "info")
        _set_progress(run_id, 75)
        phase_start("analysis")
        try:
            analysis_results = analyze_artifacts(
                run_id=run_id,
                all_results=findings,
                llm_config=llm_config,
                anonymizer=options.get('anonymizer'),
                pipeline_kind="azure",
            )
            result['phases']['analysis'] = {
                'status': 'complete',
                'artifacts_analyzed': len(analysis_results),
            }
            add_log_to_run(
                run_id,
                f"[AZURE] LLM analysis complete: {len(analysis_results)} summaries",
                "info",
            )
        except Exception as e:
            add_log_to_run(run_id, f"[AZURE] LLM analysis failed: {e}", "error")
            result['phases']['analysis'] = {'status': 'error', 'error': str(e)}
        phase_end("analysis")
    else:
        skip_reason = "LLM disabled" if not enable_llm else "no findings"
        result['phases']['analysis'] = {'status': 'skipped', 'reason': skip_reason}
        add_log_to_run(run_id, f"[AZURE] LLM analysis skipped: {skip_reason}", "warning")

    result['analysis'] = analysis_results
    _set_progress(run_id, 90)

    if is_cancelled(run_id):
        return result

    # ---- Phase 6: Report generation ----
    # We only generate a "report" when LLM ran. Without an LLM pass,
    # the only thing we could produce is a markdown rendering of the
    # findings — which is just a worse view of the raw Data ZIP, so we
    # skip it entirely and let the user pull the Data button. The
    # workflow row records `llm_enabled=False` so the dashboard
    # surfaces this state instead of offering a misleading button.
    llm_skipped = not (enable_llm and analysis_results)
    if findings and not llm_skipped:
        add_log_to_run(run_id, "[AZURE] Phase 6: Generating reports...", "info")
        _set_progress(run_id, 95)
        phase_start("reporting")
        try:
            reports = generate_azure_report(
                run_id=run_id,
                blueprint=blueprint,
                collected_data=collected_data,
                findings=findings,
                analysis_results=analysis_results,
                llm_config=llm_config,
                scan_metadata={
                    'tenant_id': azure_config.get('tenant_id', ''),
                    'time_filter': options.get('time_filter', {}),
                    'sources': list(collected_data.keys()),
                },
            )
            result['reports'] = reports
            result['phases']['reporting'] = {'status': 'complete'}
            result['has_report'] = True
            result['llm_enabled'] = True
            result['report_kind'] = 'full'
            save_azure_report(run_id, reports)
            update_run_status(run_id, "running", details={
                'has_report': True,
                'llm_enabled': True,
                'report_kind': 'full',
            })
            add_log_to_run(run_id, "[AZURE] Reports generated successfully", "info")
        except Exception as e:
            add_log_to_run(run_id, f"[AZURE] Report generation failed: {e}", "error")
            result['phases']['reporting'] = {'status': 'error', 'error': str(e)}
        phase_end("reporting")
    else:
        # No report file. Two distinct skip reasons — log the right one
        # and tag the workflow row so the dashboard knows whether to
        # show the "no LLM" indicator vs. just no Report button at all.
        if not findings:
            skip_reason = "no findings"
        else:
            skip_reason = "LLM disabled — raw data is available via the Data button, no synthesis to render"
        result['phases']['reporting'] = {'status': 'skipped', 'reason': skip_reason}
        result['has_report'] = False
        result['llm_enabled'] = bool(enable_llm and analysis_results)
        result['report_kind'] = None
        update_run_status(run_id, "running", details={
            'has_report': False,
            'llm_enabled': result['llm_enabled'],
            'report_kind': None,
        })
        add_log_to_run(run_id, f"[AZURE] Report generation skipped: {skip_reason}", "warning")

    # ---- Phase 7: IRIS import ----
    iris_config = options.get('iris_config')
    if not iris_config:
        iris_skip_reason = "iris_config not provided in scan payload"
    elif not iris_config.get('enabled'):
        iris_skip_reason = "iris_config.enabled is false"
    elif not iris_config.get('url'):
        iris_skip_reason = "iris_config.url missing"
    elif not iris_config.get('api_key'):
        iris_skip_reason = "iris_config.api_key missing"
    else:
        iris_skip_reason = None

    if iris_skip_reason is None:
        add_log_to_run(run_id, "[AZURE] Phase 7: Importing to IRIS...", "info")
        phase_start("iris")
        try:
            timeline_events = extract_timeline_events(findings, include_no_timestamp=True)
            iris_result = import_to_iris(
                iris_config=iris_config,
                all_results=findings,
                timeline_events=timeline_events,
                report_content=result.get('reports', {}).get('technical', ''),
                case_name=f"Azure Investigation - {datetime.utcnow().strftime('%Y-%m-%d')}",
                case_description=f"Azure security analysis from {blueprint.get('name', 'Unknown')} blueprint",
            )
            result['phases']['iris'] = {
                'status': 'complete',
                'case_id': iris_result.get('case_id'),
                'case_url': iris_result.get('case_url'),
                'events_imported': iris_result.get('events_imported', 0),
            }
            add_log_to_run(run_id, f"[AZURE] IRIS import complete: {iris_result.get('case_url', 'N/A')}", "info")
        except Exception as e:
            add_log_to_run(run_id, f"[AZURE] IRIS import failed: {e}", "error")
            result['phases']['iris'] = {'status': 'error', 'error': str(e)}
        phase_end("iris")
    else:
        result['phases']['iris'] = {'status': 'skipped', 'reason': iris_skip_reason}
        add_log_to_run(run_id, f"[AZURE] IRIS import skipped: {iris_skip_reason}", "warning")

    return result


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

    phase_start, phase_end = _make_phase_timer(run_id)

    try:
        # =====================================================================
        # Phase 1: Validate Configuration
        # =====================================================================
        phase_start("validation")
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
        _set_progress(run_id, 10)
        phase_end("validation")

        # =====================================================================
        # Phase 2: Collection
        # =====================================================================
        add_log_to_run(run_id, "[AZURE] Phase 2: Collecting logs from Azure...", "info")
        _set_progress(run_id, 15)
        phase_start("collection")

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
                try:
                    if 'h' in val:
                        hours = int(val.replace('h', ''))
                        start_date_str = (datetime.utcnow() - timedelta(hours=hours)).strftime('%Y-%m-%dT%H:%M:%SZ')
                    else:
                        days = int(val.replace('d', ''))
                        start_date_str = (datetime.utcnow() - timedelta(days=days)).strftime('%Y-%m-%dT%H:%M:%SZ')
                        time_range_days = days
                except (ValueError, TypeError):
                    add_log_to_run(run_id, f"[AZURE] Invalid relative time format: {val}, defaulting to 7d", "warning")
                    start_date_str = (datetime.utcnow() - timedelta(days=7)).strftime('%Y-%m-%dT%H:%M:%SZ')
                    time_range_days = 7

        if target_users:
            add_log_to_run(run_id, f"[AZURE] Target users: {', '.join(target_users)}", "info")
        if target_ips:
            add_log_to_run(run_id, f"[AZURE] Target IPs: {', '.join(target_ips)}", "info")
        if pivot_mode:
            add_log_to_run(run_id, "[AZURE] Pivot mode enabled", "info")

        # Collection is the longest phase - especially UAL via DFIR-O365RC (~5-10 min)
        # Note this clearly in the log; progress only moves on real source completion.
        if 'unified_audit' in sources or 'all' in sources:
            add_log_to_run(run_id, "[AZURE] Note: UAL collection via DFIR-O365RC is the longest phase (~5-10 minutes)", "info")

        # Calculate progress per source: spread 15 -> 55 evenly across requested sources
        def _resolve_count(sources_list):
            if 'all' in sources_list:
                return 5  # signin, audit, unified_audit, activity_logs, security_alerts
            return max(len(sources_list), 1)
        total_sources = _resolve_count(sources)
        progress_per_source = max(1, (55 - 15) // total_sources)
        collection_progress = {'pct': 15, 'completed': 0}

        def collection_logger(msg, level="info"):
            add_log_to_run(run_id, f"[AZURE] {msg}" if not msg.startswith("[AZURE]") else msg, level)
            # Bump progress only when a source actually completes (success or skip)
            is_done = (
                (level == "success" and "Collected" in msg and "records from" in msg)
                or (level == "warning" and "Skipped" in msg)
                or ("No records found for" in msg)
            )
            if is_done:
                collection_progress['completed'] += 1
                collection_progress['pct'] = min(15 + collection_progress['completed'] * progress_per_source, 55)
                _set_progress(run_id, collection_progress['pct'])

        collected_data, collection_status = collect_azure_logs(
            azure_config=azure_config,
            sources=sources,
            time_range_days=time_range_days,
            start_date_str=start_date_str,
            end_date_str=end_date_str,
            target_users=target_users,
            target_ips=target_ips,
            pivot_mode=pivot_mode,
            logger=collection_logger,
            run_id=run_id,
            ual_mode=options.get('ual_mode', 'full'),
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
            phase_end("collection")
            return result

        phase_end("collection")

        # ---- Phases 3-7 are shared with the offline pipeline. ----
        # Single source of truth lives in `_run_post_collection_phases`.
        _run_post_collection_phases(
            run_id=run_id,
            collected_data=collected_data,
            options=options,
            blueprint=blueprint,
            azure_config=azure_config,
            enable_llm=enable_llm,
            llm_config=llm_config,
            bp_settings=bp_settings,
            phase_start=phase_start,
            phase_end=phase_end,
            result=result,
        )

        # =====================================================================
        # Complete (phases 3-7 ran in _run_post_collection_phases above)
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

    Thin wrapper around the shared post-collection helper. The customer
    runs collection-only on their machine, hands us a ZIP of the raw
    `Azure.<source>.json` files, and the analyst's server picks up here:
    timestamp normalisation → time filter → SIGMA → UAL pre-detection →
    state-snapshot wrapping → LLM analysis → Azure report → IRIS.

    Args:
        run_id: Workflow run ID for logging
        uploaded_data: Dict of source_name → log records (already parsed)
        options: Pipeline options (enable_llm, time_filter, llm_config,
                 min_severity, scope_mode, iris_config, ...)

    Returns:
        Pipeline result dict
    """
    result = {
        'run_id': run_id,
        'mode': 'offline',
        'status': 'running',
        'start_time': datetime.utcnow().isoformat(),
        'phases': {},
    }

    phase_start, phase_end = _make_phase_timer(run_id)

    try:
        add_log_to_run(run_id, "[AZURE] Starting offline analysis pipeline", "info")

        if not uploaded_data:
            raise ValueError("No log data provided")

        total_records = sum(len(v) for v in uploaded_data.values())
        add_log_to_run(
            run_id,
            f"[AZURE] Processing {total_records} uploaded records across {len(uploaded_data)} sources",
            "info",
        )
        for source_key, records in uploaded_data.items():
            add_log_to_run(run_id, f"[AZURE] {source_key}: {len(records)} records", "success")

        result['phases']['upload'] = {
            'status': 'complete',
            'sources': list(uploaded_data.keys()),
            'total_records': total_records,
        }
        result['collected_data'] = uploaded_data

        # ---- Phases 3-7 are shared with the online pipeline. ----
        # Stub blueprint / azure_config / bp_settings — offline mode has
        # no tenant credentials and no per-blueprint overrides.
        blueprint = {
            'name': 'Azure Offline Analysis',
            'id': 'azure_offline',
        }
        bp_settings: Dict[str, Any] = {}
        azure_config: Dict[str, Any] = {}
        enable_llm = bool(options.get('enable_llm', False))
        llm_config = options.get('llm_config') or {}

        _run_post_collection_phases(
            run_id=run_id,
            collected_data=uploaded_data,
            options=options,
            blueprint=blueprint,
            azure_config=azure_config,
            enable_llm=enable_llm,
            llm_config=llm_config,
            bp_settings=bp_settings,
            phase_start=phase_start,
            phase_end=phase_end,
            result=result,
        )

        result['status'] = 'complete'
        result['end_time'] = datetime.utcnow().isoformat()
        add_log_to_run(run_id, "[AZURE] Offline analysis completed", "info")

    except Exception as e:
        result['status'] = 'error'
        result['error'] = str(e)
        result['traceback'] = traceback.format_exc()
        result['end_time'] = datetime.utcnow().isoformat()
        add_log_to_run(run_id, f"[AZURE] Pipeline failed: {e}", "error")

    return result


# =============================================================================
# Blueprint Helpers
# =============================================================================

def get_azure_blueprints() -> List[Dict]:
    """Get available Azure DFIR blueprints (detection-first model).

    Each blueprint includes:
    - sources: which log sources are queried
    - source_details: human description of what each source contributes
    - use_case: when to run this blueprint
    - duration: rough expected runtime
    - volume: expected data volume
    - requirements: prerequisites (license tier, target users, permissions)
    """
    return [
        {
            'id': 'azure_quick_triage',
            'name': 'Quick Triage',
            'description': "Fast daily health check using Microsoft's pre-detected security signals.",
            'use_case': 'Morning SOC check, fast pulse on tenant health',
            'duration': '~30 sec - 1 min',
            'volume': 'Very low (only triggered alerts)',
            'settings': {
                'sources': ['security_alerts', 'risk_detections', 'risky_signins'],
                'time_range_days': 7,
            },
            'source_details': {
                'security_alerts': 'Microsoft 365 Defender / Defender for Cloud alerts (Graph API)',
                'risk_detections': 'Entra ID Protection risk events (Entra ID P2 license)',
                'risky_signins': 'Users flagged as risky by Entra ID Protection',
            },
            'requirements': [
                'API permissions: SecurityAlert.Read.All, IdentityRiskEvent.Read.All',
                'Optional: Entra ID P2 license for full risk detection coverage',
            ],
            'min_severity': 'low',
        },
        {
            'id': 'azure_account_investigation',
            'name': 'Account Investigation',
            'description': 'Deep dive into specific user accounts: sign-ins, directory operations, and pre-detected signals filtered to your target users.',
            'use_case': 'Suspected account compromise, post-incident analysis, employee offboarding review',
            'duration': '~1-2 min',
            'volume': 'Medium (filtered to target users)',
            'settings': {
                'sources': ['security_alerts', 'risk_detections', 'risky_signins', 'signin_logs', 'audit_logs'],
                'time_range_days': 2,
            },
            'source_details': {
                'security_alerts': 'Pre-detected Microsoft security alerts',
                'risk_detections': 'Identity Protection risk events for the targeted users',
                'risky_signins': 'Risky sign-in entries',
                'signin_logs': 'Every Entra ID sign-in attempt (success and failure) with IP, location, device, MFA result',
                'audit_logs': 'Directory operations: role changes, password resets, user updates, app changes',
            },
            'requirements': [
                'Target users (email addresses) MUST be specified',
                'API permissions: AuditLog.Read.All, Directory.Read.All',
                'Entra ID P1 license for sign-in/audit logs',
            ],
            'min_severity': 'low',
            'requires_target_users': True,
        },
        {
            'id': 'azure_lateral_movement',
            'name': 'Lateral Movement',
            'description': 'Pivot mode: starting from your target users, find OTHER accounts that signed in from the same IP addresses (potential compromise spread).',
            'use_case': 'Spreading attack discovery, multi-account compromise investigation',
            'duration': '~1-2 min',
            'volume': 'Medium-high (target users + their IPs + all other accounts on those IPs)',
            'settings': {
                'sources': ['security_alerts', 'risk_detections', 'signin_logs', 'audit_logs'],
                'time_range_days': 2,
            },
            'source_details': {
                'security_alerts': 'Pre-detected Microsoft security alerts',
                'risk_detections': 'Identity Protection risk events',
                'signin_logs': 'Sign-ins for target users + sign-ins from same IPs by ANY user',
                'audit_logs': 'Directory operations relevant to discovered accounts',
            },
            'requirements': [
                'Target users (email addresses) MUST be specified',
                'API permissions: AuditLog.Read.All, Directory.Read.All',
                'Entra ID P1 license',
            ],
            'min_severity': 'low',
            'requires_target_users': True,
            'pivot_mode': True,
        },
        {
            'id': 'azure_full_investigation',
            'name': 'Full Investigation',
            'description': 'Comprehensive tenant audit: every supported source including the Microsoft 365 Unified Audit Log (Exchange, SharePoint, Teams, Files) via DFIR-O365RC.',
            'use_case': 'Annual security review, post-breach forensics, deep tenant audit, IR scoping',
            'duration': '~6-10 min (UAL collection is the long part)',
            'volume': 'HIGH - thousands of events',
            'settings': {
                'sources': ['all'],
                'time_range_days': 7,
            },
            'source_details': {
                'security_alerts': 'Microsoft 365 Defender / Defender for Cloud alerts',
                'risk_detections': 'Entra ID Protection risk events',
                'risky_signins': 'Risky sign-ins from Identity Protection',
                'signin_logs': 'All Entra ID sign-ins (P1+)',
                'audit_logs': 'All Entra ID directory operations (P1+)',
                'unified_audit': 'Microsoft 365 Unified Audit Log via DFIR-O365RC: mailbox access, file ops, sharing, OAuth consent, mail rules, eDiscovery, Teams events',
                'activity_logs': 'Azure Resource Manager activity logs via DFIR-O365RC (subscription-level events)',
            },
            'requirements': [
                'API permissions: AuditLog.Read.All, AuditLogsQuery.Read.All, Directory.Read.All, '
                'SecurityAlert.Read.All, IdentityRiskEvent.Read.All, User.Read.All',
                'DFIR-O365RC certificate uploaded to App Registration',
                'Entra ID P1 (P2 recommended for full risk coverage)',
            ],
            'min_severity': 'informational',
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
