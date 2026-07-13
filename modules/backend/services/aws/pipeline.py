"""
AWS Security Pipeline

Orchestrates the AWS automation workflow:
Collection (stub fixtures for now) → SIGMA Detection → LLM Analysis → Report.

Mirrors `services.azure.pipeline`. In this scaffold the collection
layer returns fake data; everything from SIGMA onward is the same
real machinery the Azure pipeline uses.
"""

from __future__ import annotations

import json
import os
import traceback
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from .collectors import LOG_SOURCES, collect_aws_logs, parse_uploaded_logs
from .sigma_runner import load_aws_rules, run_sigma_rules, validate_rules_directory

from services.agentic.utils import (
    create_time_filter_func,
    filter_results_by_time,
    normalize_all_results,
)
from services.workflow_logger import add_log_to_run
from services.workflow_service import (
    is_cancelled,
    record_phase_timing,
    record_sigma_rule_tally,
    update_run_status as _update_run_status,
)



# Severity ladder shared with Azure for filtering / state-snapshot wrapping.
SEVERITY_RANK = {
    'informational': 0,
    'info': 0,
    'low': 1,
    'medium': 2,
    'high': 3,
    'critical': 4,
}


# State-snapshot sources — current configuration not time-bound events.
# AccessAnalyzer findings are current permissions; IAM principals are the
# current identity inventory. Both fold into the same "INV.*"
# finding-bucket pattern the Azure pipeline uses for CA policies / federation.
STATE_SOURCE_MAP = {
    'AWS.AccessAnalyzer': 'INV.access_analyzer',
    'AWS.IAM':            'INV.iam_principals',
}


# =============================================================================
# Helpers (mirrors azure/pipeline._set_progress + _make_phase_timer)
# =============================================================================


def _set_progress(run_id: str, pct: int) -> None:
    if run_id:
        try:
            _update_run_status(run_id, "running", progress=pct)
        except Exception:
            pass


def _make_phase_timer(run_id: str):
    import time as _time
    starts: Dict[str, float] = {}

    def phase_start(name: str) -> None:
        starts[name] = _time.monotonic()

    def phase_end(name: str) -> None:
        t0 = starts.pop(name, None)
        if t0 is None or not run_id:
            return
        try:
            record_phase_timing(run_id, name, _time.monotonic() - t0)
        except Exception as ex:
            print(f"[AWS-PIPELINE] phase timing failed for {name}: {ex}", flush=True)

    return phase_start, phase_end


# =============================================================================
# Shared post-collection phases (SIGMA → state-wrap → LLM → report)
# =============================================================================


def _run_post_collection_phases(
    run_id: str,
    collected_data: Dict[str, List[Dict]],
    options: Dict[str, Any],
    *,
    blueprint: Dict,
    aws_config: Dict,
    bp_settings: Dict,
    phase_start,
    phase_end,
    result: Dict,
) -> Dict:
    """Phases 3-5 (collect-only): normalize, detect. LLM analysis +
    reporting happen at Case Analysis (fusion)."""

    # Phase 3 — normalize + time filter
    try:
        normalize_all_results(collected_data)
        add_log_to_run(run_id, "[AWS] Normalized timestamps across all sources", "info")
    except Exception as ex:
        add_log_to_run(run_id, f"[AWS] Timestamp normalization failed (non-fatal): {ex}", "warning")

    if is_cancelled(run_id):
        return result

    time_filter = options.get('time_filter')
    if time_filter:
        add_log_to_run(run_id, f"[AWS] Applying time filter: {time_filter}", "info")
        time_filter_func = create_time_filter_func(time_filter)
        if time_filter_func:
            collected_data = filter_results_by_time(collected_data, time_filter_func)
            filtered_count = sum(len(v) for v in collected_data.values())
            add_log_to_run(run_id, f"[AWS] After time filter: {filtered_count} records", "info")

    result['collected_data'] = collected_data
    _set_progress(run_id, 60)
    if is_cancelled(run_id):
        return result

    # Phase 4 — SIGMA detection (against AWS rule subtree)
    add_log_to_run(run_id, "[AWS] Phase 4: Running SIGMA detection rules...", "info")
    _set_progress(run_id, 65)
    phase_start("detection")
    min_severity = options.get('min_severity') or bp_settings.get('min_severity', 'low')
    add_log_to_run(run_id, f"[AWS] Minimum severity filter: {min_severity}+", "info")
    aws_rules = load_aws_rules()
    findings, detection_status = run_sigma_rules(
        logs=collected_data,
        rules=aws_rules,
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
            print(f"[AWS-PIPELINE] sigma tally persist failed: {ex}", flush=True)
    add_log_to_run(
        run_id,
        f"[AWS] SIGMA detection complete: {detection_status.get('total_findings', 0)} findings",
        "info",
    )
    for rname, rcount in sorted(rule_tally.items(), key=lambda kv: -kv[1]):
        add_log_to_run(run_id, f"[AWS]   {rname}: {rcount}", "info")

    # Phase 4c — state-snapshot wrapping (AccessAnalyzer + IAM)
    min_rank = SEVERITY_RANK.get(min_severity, 1)
    state_findings_added = 0
    for src_key, finding_key in STATE_SOURCE_MAP.items():
        records = collected_data.get(src_key, [])
        if not records:
            continue
        # State records carry `severity` in lowercase or uppercase strings.
        def _rec_rank(r):
            sev = (r.get('severity') or r.get('_severity') or 'low').lower()
            return SEVERITY_RANK.get(sev, 1)
        filtered = [r for r in records if _rec_rank(r) >= min_rank]
        if not filtered:
            continue
        findings[finding_key] = [
            {
                '_source': src_key,
                '_severity': (r.get('severity') or r.get('_severity') or 'low').lower(),
                '_description': r.get('check_title') or r.get('Title') or finding_key,
                '_timestamp': None,
                'rule_title': f"State: {r.get('check_title') or r.get('Title') or finding_key}",
                'rule_description': f'Current configuration of {src_key} (state snapshot, not an event)',
                'severity': (r.get('severity') or r.get('_severity') or 'low').lower(),
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
            f"[AWS] Added {state_findings_added} state-snapshot findings from "
            f"{len([k for k in STATE_SOURCE_MAP if STATE_SOURCE_MAP[k] in findings])} sources",
            "info",
        )
        # Roll state-snapshot findings into the detection-phase counters
        # so the dashboard's findings tally reflects real coverage instead
        # of only SIGMA hits. Posture findings ARE findings.
        det = result['phases'].get('detection') or {}
        det['total_findings'] = det.get('total_findings', 0) + state_findings_added
        sev_counts = dict(det.get('findings_by_severity') or {})
        for finding_key in STATE_SOURCE_MAP.values():
            for f in findings.get(finding_key, []) or []:
                sev = (f.get('severity') or 'low').lower()
                sev_counts[sev] = sev_counts.get(sev, 0) + 1
        det['findings_by_severity'] = sev_counts
        result['phases']['detection'] = det
        add_log_to_run(
            run_id,
            f"[AWS] Detection totals updated — findings={det['total_findings']} "
            f"by_severity={sev_counts}",
            "info",
        )

    result['findings'] = findings
    _set_progress(run_id, 70)
    phase_end("detection")
    if is_cancelled(run_id):
        return result

    # Phases 5-6 (per-run LLM analysis + report) REMOVED. AWS is collect-only;
    # analysis + reporting happen at Case Analysis (fusion). No per-run report/LLM
    # state — the SIGMA findings feed the fused case via the cloud mapper.
    _set_progress(run_id, 90)
    return result


# =============================================================================
# Main entry points
# =============================================================================


def run_aws_pipeline(
    run_id: str,
    aws_config: Dict[str, str],
    blueprint: Dict[str, Any],
    options: Dict[str, Any],
) -> Dict[str, Any]:
    """Online pipeline: collect (fake) → SIGMA → LLM → report."""
    result: Dict[str, Any] = {
        'run_id': run_id,
        'mode': 'online',
        'status': 'running',
        'start_time': datetime.utcnow().isoformat(),
        'phases': {},
    }
    phase_start, phase_end = _make_phase_timer(run_id)
    try:
        # Phase 1 — validation
        phase_start("validation")
        bp_settings = blueprint.get('settings', {})
        time_filter = options.get('time_filter', {})

        add_log_to_run(run_id, "=" * 50, "info")
        add_log_to_run(run_id, f"Blueprint: {blueprint.get('name', 'Custom')}", "info")
        if isinstance(time_filter, dict):
            if time_filter.get('type') == 'between':
                add_log_to_run(run_id, f"Time Range: {time_filter.get('start', '?')} → {time_filter.get('end', 'now')}", "info")
            else:
                add_log_to_run(run_id, f"Time Range: Last {time_filter.get('value', '7d')}", "info")
        add_log_to_run(run_id, f"Sources: {', '.join(bp_settings.get('sources', ['all']))}", "info")
        add_log_to_run(run_id, f"Regions: {', '.join(options.get('regions') or [aws_config.get('region', 'us-east-1')])}", "info")
        if options.get('target_principals'):
            add_log_to_run(run_id, f"Target principals: {', '.join(options['target_principals'])}", "info")
        add_log_to_run(run_id, f"Min Severity: {options.get('min_severity', 'medium')}", "info")
        # Tell the run-log which collectors are live tools vs still on
        # fixtures. Updated as each tool integration lands.
        try:
            from . import iam_runner
            iam_avail = iam_runner.is_available(aws_config)
            if iam_avail.get('available'):
                add_log_to_run(run_id, "[AWS] Live collector: IAM principals via boto3 (CloudFox-equivalent: principals + access keys + effective-admin)", "info")
            else:
                add_log_to_run(run_id, f"[AWS] IAM runner unavailable — fixture fallback active ({iam_avail.get('message')})", "warning")
        except Exception as e:
            add_log_to_run(run_id, f"[AWS] IAM runner check raised {e!r} — fixture fallback active", "warning")
        try:
            from . import cloudtrail_runner, guardduty_runner, accessanalyzer_runner
            ct_a = cloudtrail_runner.is_available(aws_config)
            gd_a = guardduty_runner.is_available(aws_config)
            aa_a = accessanalyzer_runner.is_available(aws_config)
            add_log_to_run(
                run_id,
                f"[AWS] Live collectors: CloudTrail={ct_a.get('available')}, "
                f"GuardDuty={gd_a.get('available')}, AccessAnalyzer={aa_a.get('available')} "
                "(all via boto3; falls back to fixture per-source when unavailable / empty)",
                "info",
            )
        except Exception as e:
            add_log_to_run(run_id, f"[AWS] boto3 runner availability check raised {e!r}", "warning")
        add_log_to_run(run_id, "=" * 50, "info")

        rules_valid, rules_msg = validate_rules_directory()
        if not rules_valid:
            add_log_to_run(run_id, f"[AWS] Warning: {rules_msg}", "warning")

        result['phases']['validation'] = {'status': 'complete'}
        _set_progress(run_id, 10)
        phase_end("validation")

        # Phase 2 — collection (stubs return fixture data)
        add_log_to_run(run_id, "[AWS] Phase 2: Collecting logs...", "info")
        _set_progress(run_id, 15)
        phase_start("collection")
        sources = bp_settings.get('sources') or list(LOG_SOURCES.keys())
        if 'all' in sources:
            sources = list(LOG_SOURCES.keys())
        collected_data = collect_aws_logs(
            run_id=run_id,
            aws_config=aws_config,
            sources=sources,
            time_filter=time_filter if isinstance(time_filter, dict) else None,
            regions=options.get('regions'),
            target_principals=options.get('target_principals'),
            scope_mode=options.get('scope_mode', 'targeted'),
            cloudtrail_mode=options.get('cloudtrail_mode', bp_settings.get('cloudtrail_mode', 'light')),
            # Use the same `time_range_days` the rest of the scan honours
            # as the freshness window for IAM users/keys. See iam_runner
            # for what gets bumped to critical; this collapses the two
            # legacy DFIR age knobs into the generic scan-window concept.
            freshness_window_days=bp_settings.get('time_range_days'),
            # Per-region CloudTrail cap. Resolved as request override →
            # blueprint default → hard fallback in cloudtrail_runner.
            max_events_per_region=options.get('max_events_per_region') or bp_settings.get('max_events_per_region'),
        )
        total_records = sum(len(v) for v in collected_data.values())
        result['phases']['collection'] = {
            'status': 'complete',
            'sources_collected': list(collected_data.keys()),
            'total_records': total_records,
        }
        if not collected_data:
            add_log_to_run(run_id, "[AWS] No data collected — pipeline stopping.", "warning")
            result['status'] = 'completed'
            result['message'] = 'No data collected'
            phase_end("collection")
            return result
        phase_end("collection")

        _run_post_collection_phases(
            run_id=run_id,
            collected_data=collected_data,
            options=options,
            blueprint=blueprint,
            aws_config=aws_config,
            bp_settings=bp_settings,
            phase_start=phase_start,
            phase_end=phase_end,
            result=result,
        )

        result['status'] = 'complete'
        result['end_time'] = datetime.utcnow().isoformat()
        add_log_to_run(run_id, "[AWS] Pipeline completed successfully", "info")

    except Exception as e:
        result['status'] = 'error'
        result['error'] = str(e)
        result['traceback'] = traceback.format_exc()
        result['end_time'] = datetime.utcnow().isoformat()
        add_log_to_run(run_id, f"[AWS] Pipeline failed: {e}", "error")
    return result


def run_aws_on_existing(
    run_id: str,
    uploaded_data: Dict[str, List[Dict]],
    options: Dict[str, Any],
) -> Dict[str, Any]:
    """Offline pipeline: caller has already parsed uploaded files into the
    same shape `collect_aws_logs` returns. Run phases 3–7 only."""
    result: Dict[str, Any] = {
        'run_id': run_id,
        'mode': 'offline',
        'status': 'running',
        'start_time': datetime.utcnow().isoformat(),
        'phases': {},
    }
    phase_start, phase_end = _make_phase_timer(run_id)
    try:
        blueprint = options.get('blueprint', {})
        bp_settings = blueprint.get('settings', {})
        aws_config = options.get('aws_config', {})
        add_log_to_run(run_id, f"[AWS] Offline mode — {sum(len(v) for v in uploaded_data.values())} uploaded records", "info")
        _run_post_collection_phases(
            run_id=run_id,
            collected_data=uploaded_data,
            options=options,
            blueprint=blueprint,
            aws_config=aws_config,
            bp_settings=bp_settings,
            phase_start=phase_start,
            phase_end=phase_end,
            result=result,
        )
        result['status'] = 'complete'
        result['end_time'] = datetime.utcnow().isoformat()
    except Exception as e:
        result['status'] = 'error'
        result['error'] = str(e)
        result['traceback'] = traceback.format_exc()
        result['end_time'] = datetime.utcnow().isoformat()
        add_log_to_run(run_id, f"[AWS] Offline pipeline failed: {e}", "error")
    return result


# =============================================================================
# Blueprints + source catalog (returned by /api/aws/blueprints and /api/aws/sources)
# =============================================================================


def get_aws_blueprints() -> List[Dict]:
    """Built-in AWS DFIR blueprints. Mirrors get_azure_blueprints."""
    return [
        {
            'id': 'aws_quick_triage',
            'name': 'Quick Triage',
            'description': 'Fast pulse on the account: recent CloudTrail console logins, IAM events, GuardDuty findings.',
            'use_case': 'Morning SOC check, fast pulse on account health',
            'duration': '~30 sec - 1 min (stub: instant)',
            'volume': 'Low',
            'settings': {
                'sources': ['cloudtrail_console', 'cloudtrail_iam', 'guardduty_findings', 'iam_principals'],
                'time_range_days': 1,
                'cloudtrail_mode': 'light',
                'max_events_per_region': 500,
            },
            'min_severity': 'low',
        },
        {
            'id': 'aws_account_investigation',
            'name': 'Account Investigation',
            'description': 'Deep dive into specific IAM principals — full CloudTrail slice plus IAM state + GuardDuty + AccessAnalyzer.',
            'use_case': 'Suspected credential compromise, post-incident, principal offboarding review',
            'duration': '~1-2 min',
            'volume': 'Medium',
            'settings': {
                'sources': ['cloudtrail_console', 'cloudtrail_iam', 'cloudtrail_full', 'guardduty_findings', 'accessanalyzer_findings', 'iam_principals'],
                'time_range_days': 2,
                'cloudtrail_mode': 'full',
                'max_events_per_region': 2000,
            },
            'min_severity': 'low',
            'requires_target_principals': True,
        },
        {
            'id': 'aws_privilege_escalation',
            'name': 'Privilege Escalation Hunt',
            'description': 'Hunt for IAM privesc patterns — IAM principals + AccessAnalyzer + AttachUserPolicy/CreateAccessKey/AssumeRole events.',
            'use_case': 'Reactive after a flagged IAM event, or routine privilege drift audit',
            'duration': '~1-2 min',
            'volume': 'Medium',
            'settings': {
                'sources': ['cloudtrail_iam', 'accessanalyzer_findings', 'iam_principals'],
                'time_range_days': 7,
                'cloudtrail_mode': 'light',
                'max_events_per_region': 2000,
            },
            'min_severity': 'low',
        },
        {
            'id': 'aws_full_investigation',
            'name': 'Full Investigation',
            'description': 'Comprehensive account audit — every source including full CloudTrail and IAM posture.',
            'use_case': 'Annual review, post-breach forensics, deep audit',
            'duration': '~5-10 min (stub: instant)',
            'volume': 'HIGH',
            'settings': {
                'sources': ['all'],
                'time_range_days': 30,
                'cloudtrail_mode': 'full',
                'max_events_per_region': 10000,
            },
            'min_severity': 'informational',
        },
    ]


def _filter_aws_findings_by_severity(findings: Dict, analysis_results: Dict, min_severity: str, run_id: str):
    """Defensively drop sub-threshold records from cached findings + analysis.

    Cached `findings` should already be post-filter (scan-time applied
    `min_severity` to SIGMA + state-snapshot records), but a rerun is a
    cheap moment to re-enforce the threshold — and it matters when an
    older run was saved before that filter was complete. Rules whose
    records all drop out are removed; `analysis_results` is pruned to
    the surviving rule keys."""
    from services.workflow_service import add_log_to_run as _log
    min_rank = SEVERITY_RANK.get((min_severity or 'low').lower(), 1)
    out_findings = {}
    dropped = 0
    for rule_key, records in (findings or {}).items():
        if not isinstance(records, list):
            out_findings[rule_key] = records
            continue
        kept = []
        for r in records:
            sev = 'low'
            if isinstance(r, dict):
                sev = (r.get('_severity') or r.get('severity') or 'low').lower()
            if SEVERITY_RANK.get(sev, 1) >= min_rank:
                kept.append(r)
            else:
                dropped += 1
        if kept:
            out_findings[rule_key] = kept
    out_analysis = {k: v for k, v in (analysis_results or {}).items() if k in out_findings}
    if dropped:
        _log(run_id, f"[RERUN] Dropped {dropped} sub-threshold record(s) below {min_severity}", "info")
    return out_findings, out_analysis


def get_available_sources() -> List[Dict]:
    """Source catalog returned by /api/aws/sources."""
    return [
        {
            'id': source_id,
            'name': cfg['name'],
            'sigma_prefix': cfg['sigma_prefix'],
            'tier': cfg['tier'],
        }
        for source_id, cfg in LOG_SOURCES.items()
    ]
