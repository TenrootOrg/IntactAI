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

    # Build SIGMA summary table for the prompt
    sigma_table = "| Rule | Hits | Source |\n|------|------|--------|\n"
    for rule_name, matches in findings.items():
        source = matches[0].get('_source', 'Unknown') if matches else 'Unknown'
        sigma_table += f"| {rule_name} | {len(matches)} | {source} |\n"

    # Combine LLM analysis summaries
    summaries_text = "\n\n---\n\n".join([
        f"## {artifact}\n\n{summary}"
        for artifact, summary in analysis_results.items()
    ])

    # Build metadata header
    scan_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    blueprint_name = blueprint.get('name', 'Azure Scan')
    time_filter = scan_metadata.get('time_filter', {})
    period = time_filter.get('value', 'unknown') if isinstance(time_filter, dict) else str(time_filter)

    header = f"""# Azure Security Assessment Report

**Scan Date:** {scan_date}
**Blueprint:** {blueprint_name}
**Period:** {period}
**Log Sources:** {', '.join(sources)}
**Total Events Collected:** {total_events:,}
**SIGMA Rules Triggered:** {num_rules_fired}
**Total Detections:** {total_findings:,}

---

"""

    reports = {}

    # === Technical Report ===
    add_log_to_run(run_id, "[Report] Generating Azure Technical Report...", "info")

    tech_prompt = f"""Create an AZURE SECURITY ASSESSMENT REPORT based on this scan data:

**SCAN METADATA:**
- Blueprint: {blueprint_name}
- Period: {period}
- Log Sources Collected: {', '.join(sources)}
- Total Events: {total_events:,}
- SIGMA Rules Triggered: {num_rules_fired}
- Total Detections: {total_findings:,}

**SIGMA DETECTION SUMMARY:**
{sigma_table}

**DETAILED ANALYSIS PER DETECTION:**
{summaries_text[:30000]}

Generate the full Azure Security Assessment Report with ALL required sections.
Every SIGMA detection must appear in the report. Be specific with usernames, IPs, and timestamps from the data."""

    try:
        tech_body = call_llm(tech_prompt, AZURE_REPORT_SYSTEM_PROMPT, llm_config)

        # Append raw analysis as appendix
        appendix = f"""

---

# Appendix: Detailed Detection Analysis

*Per-rule analysis from SIGMA detections.*

{summaries_text}
"""
        reports['technical'] = header + tech_body + appendix
        add_log_to_run(run_id, "[Report] Azure Technical Report complete", "success")
    except Exception as e:
        add_log_to_run(run_id, f"[Report] Technical Report failed: {e}", "error")
        reports['technical'] = header + f"Report generation failed: {e}\n\n## Detection Analysis\n\n{summaries_text}"


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
