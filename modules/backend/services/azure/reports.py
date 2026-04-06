"""
Azure Security Reports - Cloud-specific report generation

Generates Azure-focused security assessment reports with sections tailored
for cloud identity threats, Azure AD, and MITRE ATT&CK Cloud Matrix.
"""

import json
from datetime import datetime

from services.workflow_logger import add_log_to_run
from services.agentic.analyzers import call_llm
from services.file_storage_service import save_report, get_report


AZURE_REPORT_SYSTEM_PROMPT = """You are a senior cloud security analyst creating an AZURE SECURITY ASSESSMENT REPORT.

YOUR FOCUS: Azure AD / Entra ID threats, cloud identity attacks, and Azure infrastructure security.

## ANALYSIS APPROACH

Think like a cloud attacker:
- How did they get access? (Stolen credentials, brute force, token theft)
- What identity misconfigurations exist? (No MFA, non-compliant devices, weak conditional access)
- What are they doing in the tenant? (Privilege escalation, app registrations, mailbox access)
- What's the blast radius? (Admin accounts, sensitive data, cross-tenant access)

PRIORITIZE BY THREAT LEVEL:
1. SIGMA detection hits = ALWAYS report, these are confirmed detections
2. Compromised/targeted accounts = CRITICAL
3. Privilege escalation indicators = CRITICAL
4. Authentication anomalies (impossible travel, new locations) = HIGH
5. Conditional access gaps (non-compliant devices, no MFA) = HIGH
6. Suspicious application activity (new app registrations, consent grants) = HIGH
7. Normal administrative activity = LOW (mention for context only)

NEVER skip SIGMA detection results. If a rule fired, it MUST be in the report.

## REPORT STRUCTURE

### 1. Executive Summary
3-4 sentences: Overall cloud security posture, key identity threats found, risk level (CRITICAL/HIGH/MEDIUM/LOW), confidence level.

### 2. Key Findings by Severity

#### Critical
- Finding with specific evidence and immediate action needed

#### High
- Finding with evidence and short-term remediation

#### Medium
- Finding with evidence and recommendation

### 3. Identity & Authentication Analysis

Analyze sign-in patterns and authentication security:
- **Anomalous Sign-ins**: Unusual locations, devices, browsers, times
- **Failed Authentication**: Brute force patterns, account lockouts, password spraying indicators
- **Privileged Account Activity**: Admin sign-ins, sensitive resource access
- **Conditional Access Gaps**: Non-compliant devices accessing resources, missing MFA
- **Service Principal Activity**: App-based authentication patterns

Use specific data: user names, IP addresses, device types, timestamps.

### 4. Cloud Configuration Risks

Based on audit log analysis:
- Azure AD / Entra ID misconfigurations detected
- Service principal and application risks
- Permission and role assignment changes
- Suspicious app registrations or consent grants
- Policy modifications

### 5. SIGMA Detection Summary

Create a table of ALL detections:
| Rule Name | Severity | Hits | Log Source | MITRE Technique |
|-----------|----------|------|------------|-----------------|

Include EVERY rule that fired. Do not skip any.

### 6. Indicators of Compromise

| Type | Value | Context | First Seen | Last Seen |
|------|-------|---------|------------|-----------|
| IP Address | x.x.x.x | Suspicious sign-in source | timestamp | timestamp |
| Account | user@domain | Targeted/compromised | timestamp | timestamp |
| Application | App Name (ID) | Suspicious app | timestamp | timestamp |
| User Agent | browser/agent | Anomalous client | timestamp | timestamp |

Only include suspicious/malicious indicators found in the data.

### 7. MITRE ATT&CK Cloud Matrix

Map findings to Azure-specific techniques:
| Tactic | Technique | ID | Evidence |
|--------|-----------|------|----------|

Common Azure techniques:
- T1078.004 Valid Accounts: Cloud Accounts
- T1098 Account Manipulation
- T1098.001 Additional Cloud Credentials
- T1098.003 Additional Cloud Roles
- T1136.003 Create Account: Cloud Account
- T1528 Steal Application Access Token
- T1110 Brute Force
- T1556.006 Multi-Factor Authentication
- T1484.002 Domain Trust Modification
- T1087.004 Account Discovery: Cloud Account

### 8. Recommendations

#### Immediate Actions (24 hours)
Numbered checklist with specific actions:
1. [ ] Action targeting specific finding
2. [ ] Action targeting specific finding

#### Short-term (1 week)
Policy and configuration improvements.

#### Long-term (Ongoing)
Security posture improvements and monitoring.

---

CRITICAL RULES:
- Every SIGMA detection MUST appear in the report
- Use specific data: usernames, IPs, timestamps, app names
- This is a CLOUD report - focus on identity, not endpoint malware
- Be specific in recommendations - reference actual findings
- If data is limited, note what additional log sources would improve coverage"""



def generate_azure_report(run_id, blueprint, collected_data, findings,
                          analysis_results, llm_config, scan_metadata):
    """Generate Azure-specific security assessment report.

    Args:
        run_id: Workflow run ID
        blueprint: Blueprint config dict
        collected_data: Dict of source -> records (for statistics)
        findings: Dict of rule_name -> matched records (SIGMA results)
        analysis_results: Dict of rule_name -> LLM analysis markdown
        llm_config: LLM configuration
        scan_metadata: Dict with tenant_id, time_filter, sources, etc.

    Returns:
        Dict with 'executive' and 'technical' report markdown strings
    """
    # Build statistics
    total_events = sum(len(records) for records in collected_data.values())
    total_findings = sum(len(matches) for matches in findings.values())
    sources = list(collected_data.keys())
    num_rules_fired = len(findings)

    # Compute time range from actual records (not the requested filter)
    actual_min_ts, actual_max_ts = None, None
    distinct_dates = set()
    for records in collected_data.values():
        for r in records:
            ts = (r.get('_timestamp') or r.get('CreationTime') or
                  r.get('createdDateTime') or r.get('activityDateTime'))
            if ts:
                ts_str = str(ts)
                if actual_min_ts is None or ts_str < actual_min_ts:
                    actual_min_ts = ts_str
                if actual_max_ts is None or ts_str > actual_max_ts:
                    actual_max_ts = ts_str
                if len(ts_str) >= 10:
                    distinct_dates.add(ts_str[:10])

    # Build SIGMA summary table for the prompt — list ALL sources a rule matched, not just first
    sigma_table = "| Rule | Hits | Source(s) | Severity |\n|------|------|--------|---|\n"
    for rule_name, matches in findings.items():
        srcs = sorted({m.get('_source', '?') for m in matches}) if matches else ['?']
        sev = matches[0].get('severity', '?') if matches else '?'
        sigma_table += f"| {rule_name} | {len(matches)} | {', '.join(srcs)} | {sev} |\n"

    # Build metadata header (Azure-specific, no fake "Clients" or "Collection Duration")
    scan_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')
    blueprint_name = blueprint.get('name', 'Azure Scan')
    blueprint_id = blueprint.get('id', '')
    tenant = scan_metadata.get('tenant_id', '?')
    time_filter = scan_metadata.get('time_filter', {})
    if isinstance(time_filter, dict):
        if time_filter.get('type') == 'between':
            requested_period = f"{time_filter.get('start', '?')} → {time_filter.get('end', '?')}"
        else:
            requested_period = f"Last {time_filter.get('value', '?')}"
    else:
        requested_period = str(time_filter) if time_filter else 'unknown'

    actual_period = (
        f"{actual_min_ts} → {actual_max_ts} ({len(distinct_dates)} distinct day(s))"
        if actual_min_ts else 'no events with timestamps'
    )

    # Per-source breakdown
    per_source_lines = "\n".join(f"- `{src}`: {len(records):,} records" for src, records in collected_data.items())

    header = f"""# Azure Security Assessment Report

**Scan Date:** {scan_date}
**Blueprint:** {blueprint_name}{f' ({blueprint_id})' if blueprint_id else ''}
**Tenant:** {tenant}
**Requested Period:** {requested_period}
**Actual Data Time Range:** {actual_period}
**Total Events Collected:** {total_events:,}
**Findings Triggered:** {num_rules_fired}
**Total Detections:** {total_findings:,}

**Sources:**
{per_source_lines}

---

"""

    reports = {}

    # === Technical Report ===
    add_log_to_run(run_id, "[Report] Generating Azure Technical Report...", "info")

    # IMPORTANT: We do NOT pass the per-artifact analysis to the report-LLM and ALSO append
    # it. That was the duplication bug. The per-artifact JSON output already has the structured
    # findings — the report-LLM only needs the summary table to write the high-level
    # synthesis. Per-rule details are linked from `analysis_results` which is saved separately
    # and accessible via the API.

    # Brief summary lines from each artifact's prose part (after the JSON block) — capped
    artifact_briefs = []
    for artifact, summary in analysis_results.items():
        # Strip JSON block if present, keep only prose part for the synthesis prompt
        text = str(summary)
        if '```json' in text and '```' in text.split('```json', 1)[1]:
            after = text.split('```json', 1)[1]
            prose = after.split('```', 1)[1] if '```' in after else after
            prose = prose.strip()
        else:
            prose = text.strip()
        artifact_briefs.append(f"### {artifact}\n{prose[:1500]}")
    artifact_briefs_text = "\n\n".join(artifact_briefs)[:25000]

    tech_prompt = f"""You are writing the synthesis section of an Azure Security Assessment Report.

The per-rule analyses have ALREADY been done. Your job is to write a SHORT, accurate, top-level summary that ties them together — NOT to repeat the per-rule details.

## SCAN METADATA (use these EXACT values; do not invent dates or counts)
- Blueprint: {blueprint_name}
- Tenant: {tenant}
- Requested Period: {requested_period}
- **Actual data time range: {actual_period}**
- Total events collected: {total_events:,}
- Distinct sources: {len(sources)}

## SIGMA / FINDINGS SUMMARY
{sigma_table}

## PER-RULE ANALYSIS BRIEFS (already produced — do NOT recopy)
{artifact_briefs_text}

## REQUIREMENTS
- Use only dates/users/IPs/counts that appear in the metadata or briefs above.
- Do NOT describe a multi-day campaign unless the actual time range spans multiple days.
- Keep the synthesis concise (max ~1000 words). Sections: Executive Summary (≤150 words), Top Concerns (bulleted, max 5), Recommended Next Steps (max 5 bullets), Confidence & Caveats.
- Reference findings by their rule name; do not recopy individual events.
"""

    try:
        tech_body = call_llm(tech_prompt, AZURE_REPORT_SYSTEM_PROMPT, llm_config)
        reports['technical'] = header + tech_body
        add_log_to_run(run_id, "[Report] Azure Technical Report complete", "success")
    except Exception as e:
        add_log_to_run(run_id, f"[Report] Technical Report failed: {e}", "error")
        # Fallback: include the artifact briefs directly so the user still sees something
        reports['technical'] = header + f"Synthesis generation failed: {e}\n\n## Per-Rule Findings\n\n{artifact_briefs_text}"

    return reports


def save_azure_report(run_id, reports):
    """Save Azure reports to database."""
    save_report(run_id, json.dumps(reports))
    print(f"[AZURE] Reports saved for run_id: {run_id} ({list(reports.keys())})", flush=True)


def get_azure_report(run_id, report_type=None):
    """Get Azure report content from database."""
    content = get_report(run_id)
    if not content:
        return None

    try:
        reports = json.loads(content)
        if isinstance(reports, dict):
            if report_type:
                return reports.get(report_type)
            # Return combined
            combined = ""
            if 'executive' in reports:
                combined += reports['executive'] + "\n\n---\n\n"
            if 'technical' in reports:
                combined += reports['technical']
            return combined if combined else None
    except (json.JSONDecodeError, TypeError):
        pass

    return content


def get_azure_report_types(run_id):
    """Get available report types for an Azure scan."""
    content = get_report(run_id)
    if not content:
        return []

    try:
        reports = json.loads(content)
        if isinstance(reports, dict):
            return list(reports.keys())
    except (json.JSONDecodeError, TypeError):
        pass

    return ['combined']
