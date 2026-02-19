#!/usr/bin/env python3
"""
Agentic Reports - Report generation functions for forensic analysis
"""

import json
from datetime import datetime

from services.workflow_service import add_log_to_run
from services.file_storage_service import save_report, get_report
from services.agentic.analyzers import call_llm
from services.agentic.utils import extract_timeline_events


def generate_final_report(run_id, blueprint, client_ids, collection_minutes,
                          artifact_summaries, all_results, llm_config, report_types=None, anonymizer=None):
    """Generate report(s) using LLM. Returns dict with 'executive', 'technical', or both.
    If anonymizer is provided, masked values in reports are restored to original."""

    if report_types is None:
        report_types = ['technical']  # Default: both

    # Extract timeline events
    events = extract_timeline_events(all_results)
    timeline_section = _generate_timeline_section(events, llm_config, run_id) if events else ""

    # Build the combined analysis prompt
    summaries_text = "\n\n".join([
        f"### {artifact}\n{summary}"
        for artifact, summary in artifact_summaries.items()
    ])

    total_rows = sum(len(rows) for rows in all_results.values())

    reports = {}

    # Common metadata header
    def get_header(report_title):
        return f"""# {report_title}

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Blueprint:** {blueprint.get('name')}
**Clients:** {len(client_ids)} analyzed
**Collection Duration:** {collection_minutes} minutes
**Artifacts:** {len(artifact_summaries)} analyzed
**Total Data Rows:** {total_rows}
**Events Timeline:** {len(events)} timestamped events

---

"""

    # Generate Executive Report (C-level)
    if 'executive' in report_types:
        add_log_to_run(run_id, "[Report] Generating Executive Report (C-level summary)...", "info")
        exec_system = """You are a senior incident response consultant creating an EXECUTIVE FORENSICS REPORT.
This report is for C-level executives and board members who need substantive technical context without overwhelming detail.

REQUIREMENTS:
- SUBSTANTIVE: Provide real findings, not vague summaries. Be specific about what was found.
- ACCESSIBLE: Explain technical concepts in business terms, but don't oversimplify
- EVIDENCE-BASED: Reference specific artifacts and data that support your conclusions
- RISK-QUANTIFIED: Clear severity ratings with justification

REQUIRED SECTIONS (use markdown headers):

## 1. Threat Assessment Summary
- Overall Risk Level: CRITICAL / HIGH / MEDIUM / LOW (with 1-sentence justification)
- Confidence Level: HIGH / MEDIUM / LOW (based on data quality and coverage)
- Incident Type Classification (e.g., Malware, Unauthorized Access, Data Exfiltration, Insider Threat)

## 2. Situation Overview
3-5 sentences explaining:
- What triggered this investigation
- What systems/data were involved
- Current status of the threat (active, contained, remediated)

## 3. Key Findings
Present 3-6 significant findings as a table:
| Finding | Severity | Systems Affected | Evidence Source |
Include specific hostnames, user accounts, or file paths where relevant (sanitized if needed)

## 4. Timeline Summary
Brief chronological narrative (5-10 key events):
- First suspicious activity detected
- Escalation points
- Lateral movement (if any)
- Most recent activity

## 5. Business Impact Assessment
| Impact Area | Status | Details |
- Data at Risk (types, volume estimates)
- Operational Impact (systems affected, downtime)
- Compliance Implications (GDPR, HIPAA, PCI-DSS if applicable)
- Reputational Risk

## 6. Immediate Actions Required
Prioritized list of 4-6 actions with owners:
| Priority | Action | Responsible Party | Deadline |
(e.g., P1-Critical, P2-High, P3-Medium)

## 7. Next Steps
- Recommended follow-up investigations
- Evidence preservation requirements
- External notification requirements (legal, regulators, customers)

STYLE NOTES:
- Use tables for structured data - executives appreciate scannable formats
- Include specific numbers (e.g., "147 failed login attempts" not "many failed logins")
- Reference artifact names (e.g., "Windows Event Logs", "Browser History") so readers understand data sources
- Avoid raw IOCs, but do mention categories (e.g., "3 suspicious external IP addresses identified")"""

        exec_prompt = f"""Create an EXECUTIVE FORENSICS REPORT based on this investigation data:

**INVESTIGATION METADATA:**
- Systems Analyzed: {len(client_ids)}
- Collection Duration: {collection_minutes} minutes
- Forensic Artifacts Examined: {len(artifact_summaries)}
- Total Data Points Processed: {total_rows:,}
- Timeline Events Identified: {len(events)}

**ARTIFACT ANALYSIS RESULTS:**
{summaries_text[:20000]}

**INVESTIGATION TIMELINE:**
{timeline_section[:8000] if timeline_section else "Timeline data not available - timestamps could not be extracted from collected artifacts."}

Generate the executive forensics report with all required sections. Be specific and substantive - executives need real findings, not generic statements."""

        try:
            exec_body = call_llm(exec_prompt, exec_system, llm_config)
            reports['executive'] = get_header("Executive Forensics Report") + exec_body
            add_log_to_run(run_id, "[Report] Executive Report complete", "success")
        except Exception as e:
            add_log_to_run(run_id, f"[Report] Executive Report failed: {str(e)}", "error")
            reports['executive'] = get_header("Executive Forensics Report") + f"Report generation failed: {str(e)}"

    # Generate Technical Report (Forensics team)
    if 'technical' in report_types:
        add_log_to_run(run_id, "[Report] Generating Technical Report (forensics detail)...", "info")
        tech_system = """You are a senior incident response analyst creating a TECHNICAL FORENSICS REPORT.
This report is for security analysts and forensic investigators who need FULL DETAILS.

Structure:
1. **Executive Summary** (2-3 sentences with risk assessment)
2. **Investigation Timeline** (detailed chronological events with timestamps)
3. **Key Findings by Severity**:
   - CRITICAL: Active threats, malware, unauthorized access
   - HIGH: Credential theft, lateral movement, persistence mechanisms
   - MEDIUM: Suspicious behavior, policy violations, recon activity
   - LOW/INFO: Baseline context, normal activity patterns
4. **Indicators of Compromise (IOCs)**:
   | Type | Value | Context | First Seen |
   Include: IPs, domains, hashes, file paths, registry keys, user agents
5. **MITRE ATT&CK Mapping**:
   | Technique ID | Name | Evidence |
6. **Affected Systems & Accounts** (hostnames, users, IPs with roles)
7. **Attack Chain Reconstruction** (if applicable)
8. **Detailed Artifact Analysis** (per-artifact breakdown)
9. **Remediation Steps** (specific, technical, prioritized)
10. **Appendix: Raw Artifact Summaries**

Be THOROUGH. Include ALL technical details from the artifact summaries."""

        tech_prompt = f"""Create a DETAILED TECHNICAL FORENSICS REPORT:

**Investigation Details:**
- Blueprint: {blueprint.get('name')}
- Artifacts analyzed: {len(artifact_summaries)}
- Clients analyzed: {len(client_ids)}
- Collection duration: {collection_minutes} minutes
- Total data rows: {total_rows}
- Timeline events: {len(events)}

**Detailed Timeline ({len(events)} events):**
{timeline_section if timeline_section else "No timeline events available."}

**Per-Artifact Analysis:**
{summaries_text}

Generate the comprehensive technical forensics report:"""

        try:
            tech_body = call_llm(tech_prompt, tech_system, llm_config)
            # Append raw summaries as appendix
            tech_full = tech_body + f"\n\n---\n\n## Appendix: Raw Artifact Summaries\n\n{summaries_text}"
            reports['technical'] = get_header("Technical Forensics Report") + tech_full
            add_log_to_run(run_id, "[Report] Technical Report complete", "success")
        except Exception as e:
            add_log_to_run(run_id, f"[Report] Technical Report failed: {str(e)}", "error")
            reports['technical'] = get_header("Technical Forensics Report") + f"Report generation failed: {str(e)}\n\n## Artifact Summaries\n\n{summaries_text}"

    # Unmask reports if anonymization was used
    if anonymizer:
        add_log_to_run(run_id, "[Report] Restoring original values from anonymized data...", "info")
        if 'executive' in reports:
            reports['executive'] = anonymizer.unmask_text(reports['executive'])
        if 'technical' in reports:
            reports['technical'] = anonymizer.unmask_text(reports['technical'])
        mapping_summary = anonymizer.get_mapping_summary()
        add_log_to_run(run_id, f"[Report] Restored {mapping_summary['total_mappings']} masked values", "info")

    return reports


def generate_empty_report(blueprint, client_ids, collection_minutes):
    """Generate report when no data was collected"""
    return f"""# Agentic Forensics Report

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Blueprint:** {blueprint.get('name')}
**Clients:** {len(client_ids)} selected
**Collection Duration:** {collection_minutes} minutes

---

## Summary

No data was collected from the selected clients during the {collection_minutes}-minute collection window.

**Possible reasons:**
- Selected clients may be offline or unreachable
- Artifacts may not be applicable to the target operating systems
- Collection time may have been too short for clients to respond

**Recommended actions:**
- Verify that selected clients are online in the Dashboard
- Increase the collection time window
- Check Velociraptor hunt status for errors
"""


def build_fallback_report(blueprint, client_ids, collection_minutes,
                          artifact_summaries, total_rows):
    """Build report without LLM (fallback)"""
    sections = []
    sections.append("## Executive Summary\n")
    sections.append(f"Analyzed {len(artifact_summaries)} artifacts across {len(client_ids)} clients "
                    f"over a {collection_minutes}-minute collection window. "
                    f"Total of {total_rows} data rows processed.\n")

    sections.append("## Findings by Artifact\n")
    for artifact, summary in artifact_summaries.items():
        sections.append(f"### {artifact}\n{summary}\n")

    return "\n".join(sections)


def _generate_timeline_section(events, llm_config, run_id):
    """Generate a human-readable timeline summary from events."""
    if not events:
        return "No timestamped events found in collected artifacts."

    # Limit to most relevant events (first 200 and last 50 for context)
    if len(events) > 250:
        selected_events = events[:200] + events[-50:]
    else:
        selected_events = events

    # Format events for LLM (handle None timestamps for events without time info)
    events_text = "\n".join([
        f"[{ev['timestamp'].strftime('%Y-%m-%d %H:%M:%S') if ev.get('timestamp') else 'UNKNOWN TIME'}] ({ev['source']}) [{ev.get('hostname', 'Unknown')}] {ev.get('description', '')[:200]}"
        for ev in selected_events
    ])

    system_prompt = """You are a forensic analyst creating a timeline narrative.
Given a chronological list of events from various forensic artifacts, create a coherent narrative
that explains what happened on the system(s). Focus on:
- Initial compromise indicators (first suspicious activity)
- Lateral movement and persistence
- Data exfiltration attempts
- Key actions by threat actors or users
- Notable patterns and correlations between events

Format as a timeline with clear timestamps and explanations. Group related events logically."""

    user_prompt = f"""Create a narrative timeline from these {len(selected_events)} forensic events:

{events_text}

Generate a clear, chronological narrative of what occurred:"""

    try:
        add_log_to_run(run_id, f"[Report] Generating timeline narrative from {len(events)} events...", "info")
        timeline = call_llm(user_prompt, system_prompt, llm_config)
        return timeline
    except Exception as e:
        add_log_to_run(run_id, f"[Report] Timeline generation failed: {str(e)}", "warning")
        # Fallback: just list events
        return "**Timeline Events:**\n\n" + events_text[:10000]


def save_report_content(run_id, report_content):
    """Save report(s) to database. Handles both single report (legacy) and dict of reports."""
    if isinstance(report_content, dict):
        # Multiple reports - save as JSON containing both
        save_report(run_id, json.dumps(report_content))
        print(f"[AGENTIC] Reports saved for run_id: {run_id} ({list(report_content.keys())})", flush=True)
    else:
        # Legacy single report
        save_report(run_id, report_content)
        print(f"[AGENTIC] Report saved for run_id: {run_id}", flush=True)


def get_report_content(run_id, report_type=None):
    """Get report content from database.
    Args:
        run_id: The run ID
        report_type: 'executive', 'technical', or None for combined/legacy
    Returns: markdown string or None
    """
    content = get_report(run_id)
    if not content:
        return None

    # Try to parse as JSON (new multi-report format)
    try:
        reports = json.loads(content)
        if isinstance(reports, dict):
            if report_type:
                return reports.get(report_type)
            # Return combined if no type specified
            combined = ""
            if 'executive' in reports:
                combined += reports['executive'] + "\n\n---\n\n"
            if 'technical' in reports:
                combined += reports['technical']
            return combined if combined else None
    except (json.JSONDecodeError, TypeError):
        pass

    # Legacy single report
    return content


def get_available_report_types(run_id):
    """Get list of available report types for a run."""
    content = get_report(run_id)
    if not content:
        return []

    try:
        reports = json.loads(content)
        if isinstance(reports, dict):
            return list(reports.keys())
    except (json.JSONDecodeError, TypeError):
        pass

    return ['combined']  # Legacy format
