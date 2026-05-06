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
    create_time_filter_func
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


def _build_findings_report(blueprint: Dict, collected_data: Dict, findings: Dict, time_filter: Dict) -> str:
    """Build a structured markdown report listing findings without LLM analysis.

    Used when LLM is disabled. Each finding gets the SIGMA/UAL metadata laid out
    so a human (or downstream LLM) can act on it.
    """
    lines = []
    lines.append("# Azure Security Findings Report")
    lines.append("")
    lines.append(f"**Scan Date:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
    lines.append(f"**Blueprint:** {blueprint.get('name', 'Custom')}")
    lines.append(f"**Sources:** {', '.join(collected_data.keys()) or 'none'}")
    total_events = sum(len(v) for v in collected_data.values())
    total_findings = sum(len(v) for v in findings.values())
    lines.append(f"**Total Events Collected:** {total_events:,}")
    lines.append(f"**Total Findings:** {total_findings:,}")
    lines.append(f"**Finding Categories:** {len(findings)}")
    if time_filter:
        lines.append(f"**Time Filter:** `{time_filter}`")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("> **Note:** This report was generated without LLM analysis. "
                 "Enable LLM in the scan options for forensic narrative + recommended actions.")
    lines.append("")

    # Summary table
    lines.append("## Findings Summary")
    lines.append("")
    lines.append("| Category / Rule | Count | Severity |")
    lines.append("|---|---|---|")
    for key, items in sorted(findings.items(), key=lambda kv: -len(kv[1])):
        if not items:
            continue
        # Get most common severity in this category
        sev_counts = {}
        for item in items:
            sev = item.get('severity') or item.get('_severity') or 'unknown'
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
        sev_str = ", ".join(f"{k}={v}" for k, v in sorted(sev_counts.items(), key=lambda x: -x[1]))
        lines.append(f"| {key} | {len(items)} | {sev_str} |")
    lines.append("")

    # Detailed findings per category
    lines.append("## Findings Detail")
    lines.append("")
    for key, items in sorted(findings.items(), key=lambda kv: -len(kv[1])):
        if not items:
            continue
        lines.append(f"### {key} ({len(items)} events)")
        lines.append("")
        for i, item in enumerate(items[:50], 1):  # cap at 50 per category
            record = item.get('matched_record', item)
            ts = item.get('_timestamp') or record.get('CreationTime') or record.get('createdDateTime') or '?'
            sev = item.get('severity') or item.get('_severity') or '?'
            cat = item.get('_category') or record.get('_category') or '?'
            desc = item.get('_description') or record.get('_description') or item.get('rule_title', '')

            # Extract actor from various possible field shapes
            actor = (
                record.get('UserId')
                or record.get('userPrincipalName')
                or record.get('Actor')
            )
            initiated_by = record.get('initiatedBy')
            if not actor and isinstance(initiated_by, dict):
                user_info = initiated_by.get('user') or {}
                if isinstance(user_info, dict):
                    actor = user_info.get('userPrincipalName')
            # UAL Actor field can be a list like [{Type:0, ID:"user@x.com"}]
            if not actor and isinstance(record.get('Actor'), list):
                for a in record['Actor']:
                    if isinstance(a, dict) and a.get('ID'):
                        actor = a['ID']
                        break
            actor = actor or '?'

            op = record.get('Operation') or record.get('activityDisplayName') or '?'
            lines.append(f"**{i}.** `{ts}` | **{sev.upper()}** | `{cat}`")
            lines.append(f"   - Operation: `{op}`")
            lines.append(f"   - Actor: `{actor}`")
            if desc and desc != op:
                lines.append(f"   - Description: {desc}")
            lines.append("")
        if len(items) > 50:
            lines.append(f"_(... {len(items) - 50} more events truncated, see raw data)_")
            lines.append("")

    return "\n".join(lines)


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

        # ---- ROADtools tenant-graph gather, in parallel with O365RC. ----
        # The graph is independent of event collection (different APIs,
        # different PowerShell sessions), so we spawn it now and join in
        # phase 4d. On runs where O365RC stalls (the common case), this
        # adds zero wall-clock cost. On clean runs the cold-cache cost
        # is ~30-120s; warm cache (within 24h) is ~0s.
        import threading as _threading
        _road_result = {"db_path": None, "available": False, "skipped_reason": None}

        def _gather_roadtools():
            try:
                from . import roadtools as _rt
                avail = _rt.is_available()
                if not avail['available']:
                    _road_result["skipped_reason"] = avail['message']
                    return
                _road_result["available"] = True
                _road_result["db_path"] = _rt.gather(
                    tenant_id=azure_config.get('tenant_id', ''),
                    app_id=azure_config.get('client_id', ''),
                    log_func=lambda msg, level="info": add_log_to_run(run_id, msg, level),
                )
            except Exception as ex:
                _road_result["skipped_reason"] = f"ROADtools thread raised: {ex}"

        _road_thread = _threading.Thread(target=_gather_roadtools, daemon=True)
        _road_thread.start()

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
            run_id=run_id
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

        from services.workflow_service import is_cancelled
        if is_cancelled(run_id):
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
        _set_progress(run_id, 60)

        if is_cancelled(run_id):
            return result

        # =====================================================================
        # Phase 4: SIGMA Detection
        # =====================================================================
        add_log_to_run(run_id, "[AZURE] Phase 4: Running SIGMA detection rules...", "info")
        _set_progress(run_id, 65)
        phase_start("detection")

        min_severity = options.get('min_severity') or bp_settings.get('min_severity', 'low')
        add_log_to_run(run_id, f"[AZURE] Minimum severity filter: {min_severity}+", "info")
        # Pass scope_mode so sigma_runner skips aggregate/baseline rules in
        # targeted mode (data window too narrow for them to fire).
        findings, detection_status = run_sigma_rules(
            logs=collected_data,
            min_level=min_severity,
            scope_mode=options.get('scope_mode', 'tenant_wide'),
        )

        result['phases']['detection'] = {
            'status': 'complete',
            'rules_executed': detection_status.get('rules_count', 0),
            'total_findings': detection_status.get('total_findings', 0),
            'findings_by_severity': detection_status.get('matches_by_severity', {}),
            'rule_tally': detection_status.get('rule_tally', {})
        }

        # Persist per-rule tally onto the workflow row so the dashboard can
        # render "Rule X fired N times" without re-parsing logs.
        rule_tally = detection_status.get('rule_tally') or {}
        if rule_tally:
            try:
                from services.workflow_service import record_sigma_rule_tally
                record_sigma_rule_tally(run_id, rule_tally)
            except Exception as ex:
                print(f"[PIPELINE] sigma tally persist failed: {ex}", flush=True)

        add_log_to_run(
            run_id,
            f"[AZURE] SIGMA detection complete: {detection_status.get('total_findings', 0)} findings",
            "info"
        )

        # One log line per fired rule so the operator sees the shape of
        # detection without having to look at the raw findings dict.
        for rname, rcount in sorted(rule_tally.items(), key=lambda kv: -kv[1]):
            add_log_to_run(run_id, f"[AZURE]   {rname}: {rcount}", "info")

        # =====================================================================
        # Phase 4b: UAL Severity-Tagged Events as Pre-Detected Findings
        # =====================================================================
        # The UAL filter (filter_and_score_ual_records) already does detection:
        # it tags events with _severity, _category, _description.
        # These are pre-detected findings — they don't need SIGMA rules.
        # Group them by category so each category becomes one "finding bucket".
        SEVERITY_RANK = {'informational': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
        min_rank = SEVERITY_RANK.get(min_severity, 1)

        ual_events = collected_data.get('Azure.UnifiedAudit', [])
        ual_findings_added = 0
        if ual_events:
            # Filter by min_severity (respecting the UI choice)
            filtered = [e for e in ual_events
                        if SEVERITY_RANK.get(e.get('_severity', 'low'), 1) >= min_rank]

            # Group by category for clean LLM artifact buckets
            by_category = {}
            for event in filtered:
                cat = event.get('_category', 'unknown')
                if cat == 'unknown':
                    continue  # Skip unknown ops to reduce noise
                key = f"UAL.{cat}"
                if key not in by_category:
                    by_category[key] = []
                # Wrap as a finding (matches SIGMA finding shape so LLM treats it the same)
                by_category[key].append({
                    '_source': 'Azure.UnifiedAudit',
                    '_severity': event.get('_severity'),
                    '_category': event.get('_category'),
                    '_description': event.get('_description'),
                    '_timestamp': event.get('CreationTime') or event.get('_timestamp'),
                    'rule_title': f"UAL: {event.get('_description', cat)}",
                    'severity': event.get('_severity'),
                    'matched_record': event,
                    '_finding_time': datetime.utcnow().isoformat()
                })

            # Merge into findings dict
            for key, items in by_category.items():
                findings[key] = items
                ual_findings_added += len(items)

            if ual_findings_added > 0:
                add_log_to_run(
                    run_id,
                    f"[AZURE] Added {ual_findings_added} UAL pre-detected findings "
                    f"in {len(by_category)} categories (severity >= {min_severity})",
                    "info"
                )

        # =====================================================================
        # Phase 4c: State-Snapshot Sources (CA policies, federation)
        # =====================================================================
        # These are NOT events — they're current configuration. They bypass
        # SIGMA entirely (no rule will match a config dump). Each state source
        # becomes its own INV.* finding bucket and goes straight to the LLM
        # with the "state snapshot" framing.
        STATE_SOURCE_MAP = {
            'Azure.CAPolicy': 'INV.ca_policies',
            'Azure.Federation': 'INV.federation',
        }
        state_findings_added = 0
        for src_key, finding_key in STATE_SOURCE_MAP.items():
            records = collected_data.get(src_key, [])
            if not records:
                continue
            # Filter by min_severity — same UI ladder used for everything else
            filtered = [r for r in records
                        if SEVERITY_RANK.get(r.get('_severity', 'low'), 1) >= min_rank]
            if not filtered:
                continue
            # Wrap each filtered record as a finding (same shape as SIGMA findings)
            findings[finding_key] = [
                {
                    '_source': src_key,
                    '_severity': r.get('_severity'),
                    '_category': r.get('_category'),
                    '_description': r.get('_description'),
                    '_timestamp': None,  # state snapshot — no event time
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
                "info"
            )

        # Store findings for API access
        result['findings'] = findings

        _set_progress(run_id, 70)
        phase_end("detection")

        if is_cancelled(run_id):
            return result

        # =====================================================================
        # Phase 4d: Blast-radius enrichment (ROADtools-backed, optional)
        # =====================================================================
        # Wait for the ROADtools graph (started in phase 2). If the gather
        # finished cleanly, query for each finding's actor and target and
        # attach a `_blast_radius` dict per finding bucket. The LLM and
        # report layers consume this for "blast radius" framing.
        # Failure modes: prereq not installed (no docker pull), gather
        # failed, query degraded — all logged and the pipeline continues
        # without enrichment.
        phase_start("enrichment")
        try:
            _road_thread.join(timeout=120)
            if _road_thread.is_alive():
                add_log_to_run(
                    run_id,
                    "[ROAD] Graph gather still running after 120s; skipping enrichment for this run",
                    "warning",
                )
            elif not _road_result.get("available"):
                reason = _road_result.get("skipped_reason") or "ROADtools unavailable"
                add_log_to_run(run_id, f"[ROAD] Skipping blast-radius: {reason}", "info")
            elif not _road_result.get("db_path"):
                add_log_to_run(run_id, "[ROAD] Graph gather did not produce a db; skipping", "info")
            else:
                from . import roadtools as _rt

                # Collect actor UPNs and target appIds/objectIds from findings
                actor_upns = set()
                target_app_ids = set()
                target_app_oids = set()
                for bucket_name, bucket_rows in (findings or {}).items():
                    for row in bucket_rows or []:
                        if not isinstance(row, dict):
                            continue
                        rec = row.get('matched_record') if isinstance(row.get('matched_record'), dict) else row
                        # Actor: initiatedBy.user.userPrincipalName (Graph audit shape)
                        ib = (rec.get('initiatedBy') or {}) if isinstance(rec, dict) else {}
                        user = ib.get('user') or {}
                        upn = user.get('userPrincipalName')
                        if upn:
                            actor_upns.add(upn)
                        # Some sign-in shapes carry UPN at top level
                        if isinstance(rec, dict):
                            top_upn = rec.get('userPrincipalName')
                            if top_upn:
                                actor_upns.add(top_upn)
                        # Targets: targetResources[*].id / displayName / type
                        for tr in (rec.get('targetResources') or []) if isinstance(rec, dict) else []:
                            if not isinstance(tr, dict):
                                continue
                            t_id = tr.get('id')
                            t_type = (tr.get('type') or '').lower()
                            if t_id and t_type in ('application', 'serviceprincipal'):
                                # tr.id is usually an objectId for these types
                                target_app_oids.add(t_id)

                if actor_upns or target_app_ids or target_app_oids:
                    blast = _rt.query_blast_radius(
                        db_path=_road_result["db_path"],
                        actor_upns=sorted(actor_upns),
                        target_app_ids=sorted(target_app_ids),
                        target_app_object_ids=sorted(target_app_oids),
                    )
                    # Attach the SAME blast dict to every finding bucket so the
                    # analyzer can see it once. Cheaper than per-row attachment
                    # and the LLM reads it as a single "## BLAST RADIUS CONTEXT"
                    # block.
                    result['blast_radius'] = blast

                    # Brief summary line so the operator sees what got computed
                    n_actors_with_role = blast.get('summary', {}).get('actors_with_role', 0)
                    n_high_risk = blast.get('summary', {}).get('targets_with_high_risk_perm', 0)
                    add_log_to_run(
                        run_id,
                        f"[ROAD] Blast radius: {len(blast.get('actors',{}))} actor(s), "
                        f"{len(blast.get('targets',{}))} target(s); "
                        f"{n_actors_with_role} actor(s) hold admin roles, "
                        f"{n_high_risk} target(s) have high-risk permissions",
                    )
                else:
                    add_log_to_run(
                        run_id,
                        "[ROAD] No actors/targets identified in findings; skipping blast-radius query",
                        "info",
                    )
        except Exception as ex:
            add_log_to_run(run_id, f"[ROAD] Enrichment phase raised: {ex}", "warning")
        phase_end("enrichment")

        # =====================================================================
        # Phase 5: LLM Analysis (if enabled)
        # =====================================================================
        analysis_results = {}
        if enable_llm and findings:
            add_log_to_run(run_id, "[AZURE] Phase 5: Running LLM analysis...", "info")
            _set_progress(run_id, 75)
            phase_start("analysis")

            try:
                # Analyze findings (not raw logs).
                # pipeline_kind="azure" enables the single-pass timeline mode
                # for small runs — events here are chronological log entries,
                # unlike the on-prem Velociraptor flow which keeps fan-out.
                # extra_context carries blast-radius facts from ROADtools
                # (when available) so the LLM can prioritize remediation by
                # tenant reach rather than just observed events.
                analysis_results = analyze_artifacts(
                    run_id=run_id,
                    all_results=findings,
                    llm_config=llm_config,
                    anonymizer=options.get('anonymizer'),
                    pipeline_kind="azure",
                    extra_context={"blast_radius": result.get("blast_radius")} if result.get("blast_radius") else None,
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
            phase_end("analysis")
        else:
            skip_reason = "LLM disabled" if not enable_llm else "no findings"
            result['phases']['analysis'] = {'status': 'skipped', 'reason': skip_reason}
            add_log_to_run(run_id, f"[AZURE] LLM analysis skipped: {skip_reason}", "warning")

        result['analysis'] = analysis_results
        _set_progress(run_id, 90)

        if is_cancelled(run_id):
            return result

        # =====================================================================
        # Phase 6: Report Generation (always, even without LLM)
        # =====================================================================
        if findings:
            add_log_to_run(run_id, "[AZURE] Phase 6: Generating reports...", "info")
            _set_progress(run_id, 95)
            phase_start("reporting")

            try:
                if enable_llm and analysis_results:
                    # Full LLM-narrated report
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
                        blast_radius=result.get('blast_radius'),
                    )
                else:
                    # Structured findings list (no LLM tokens spent)
                    reports = {
                        'technical': _build_findings_report(
                            blueprint=blueprint,
                            collected_data=collected_data,
                            findings=findings,
                            time_filter=options.get('time_filter', {}),
                        )
                    }

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
            phase_end("reporting")
        else:
            result['phases']['reporting'] = {'status': 'skipped', 'reason': 'no findings'}
            add_log_to_run(run_id, "[AZURE] Report generation skipped: no findings", "warning")

        # =====================================================================
        # Phase 7: IRIS Import (if configured)
        # =====================================================================
        iris_config = options.get('iris_config')
        # Pinpoint *why* IRIS didn't run so the operator can read the workflow
        # log and tell at a glance whether they need to fix config, an
        # unreachable URL, a missing key, or just enable the toggle.
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
            phase_end("iris")
        else:
            result['phases']['iris'] = {'status': 'skipped', 'reason': iris_skip_reason}
            add_log_to_run(run_id, f"[AZURE] IRIS import skipped: {iris_skip_reason}", "warning")

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
        # Offline-uploaded data is treated as tenant_wide (we don't know
        # what scope the operator pulled the upload at).
        findings, detection_status = run_sigma_rules(
            logs=uploaded_data,
            min_level=min_severity,
            scope_mode=options.get('scope_mode', 'tenant_wide'),
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
