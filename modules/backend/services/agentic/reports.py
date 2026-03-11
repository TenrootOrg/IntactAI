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

    # Build the combined analysis prompt with clear artifact headers
    summaries_text = "\n\n---\n\n".join([
        f"## {artifact}\n\n{summary}"
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
        tech_system = """You are a senior DFIR analyst creating a TECHNICAL FORENSICS REPORT.

YOUR MISSION: A DFIR team leader will read this report and must understand 80% of what happened, what's critical, and what to do next.

## ANALYSIS APPROACH

Think like an attacker to understand the attack chain:
- How did they get in? (Initial Access)
- How are they staying? (Persistence)
- What are they doing? (Actions on Objectives)
- What's their goal? (Impact/Exfiltration)

PRIORITIZE BY THREAT LEVEL:
1. Detection rule hits (YARA, Sigma, any rule that fired) = ALWAYS report these
2. Memory anomalies (injection, shellcode, suspicious regions) = CRITICAL
3. Credential access (dumps, LSASS, SAM, browser creds) = CRITICAL
4. Persistence mechanisms (registry, tasks, services, WMI) = HIGH
5. Defense evasion (renamed binaries, encoded commands) = HIGH
6. Suspicious network activity (C2 patterns, unusual DNS) = HIGH
7. Normal system activity = LOW (mention briefly for context)

NEVER skip or summarize away detection hits. If something was flagged by a rule, it MUST be in your report.

## REPORT STRUCTURE

### 1. Critical Findings (TOP OF REPORT)
List the most dangerous findings FIRST, even if timestamps are unknown.
Format:
- **[Timestamp or "Time Unknown"]** What was found
- **Why Critical**: One sentence on why this matters
- **Evidence**: Source artifact/rule that detected it

### 2. Executive Summary
3-4 sentences: What happened, overall risk level (CRITICAL/HIGH/MEDIUM/LOW), threat status (Active/Contained/Unknown), confidence level.

### 3. Attack Narrative Timeline
Tell the STORY of the attack in chronological order:
- What was the likely entry point?
- What did the attacker do to persist?
- What actions did they take?
- What was their apparent objective?

Connect related events. If event A at 10:00 leads to event B at 10:05, explain that relationship.
For events without timestamps, group them logically in a "Time Unknown" section but still integrate them into the narrative.

### 4. Indicators of Compromise
| Type | Value | Context |
Only include IOCs actually found in the data. Include: file paths, hashes, IPs, domains, commands, registry keys.

### 5. MITRE ATT&CK Mapping
| Tactic | Technique | Evidence |
Map only techniques with clear evidence.

### 6. Affected Assets
- **Systems**: List with context (e.g., "DESKTOP-ABC - primary compromised host")
- **Accounts**: List with privilege level (e.g., "admin_user - Domain Admin")
- **Data at Risk**: What sensitive data may be affected

### 7. DFIR Action Plan

#### Immediate Actions (Execute Now)
Numbered checklist of urgent actions:
1. [ ] Isolate [specific system] from network
2. [ ] Disable [specific account]
3. [ ] Block [specific IOCs] at perimeter
4. [ ] Preserve evidence from [specific locations]
(Be specific based on findings - not generic advice)

#### Investigation Priorities (In Order)
1. **FIRST**: What to investigate and why (most urgent)
2. **SECOND**: Next priority
3. **THIRD**: Following priority
Order by: Active threat containment > Scope determination > Root cause > Impact assessment

#### Evidence to Collect
Specific additional artifacts or logs needed for deeper analysis.

#### Escalation Triggers
When to escalate (e.g., "If lateral movement to domain controller confirmed, escalate to executive team")

---

CRITICAL RULES:
- Detection hits are the most important findings - NEVER skip them
- Tell the story, don't just list findings
- Critical items go at the TOP regardless of timestamp
- Be specific in the action plan - use actual hostnames, accounts, IOCs from the data
- If data is ambiguous, say so - don't fabricate details"""

        tech_prompt = f"""Create a TECHNICAL FORENSICS REPORT for a DFIR team leader.

**Investigation Scope:**
- Blueprint: {blueprint.get('name')}
- Systems analyzed: {len(client_ids)}
- Artifacts examined: {len(artifact_summaries)}
- Data points processed: {total_rows:,}
- Timeline events: {len(events)}

**Timeline Data ({len(events)} events):**
{timeline_section if timeline_section else "No timeline events available."}

**Artifact Analysis Results:**
{summaries_text}

IMPORTANT REMINDERS:
- Start with CRITICAL FINDINGS at the top - do not bury them
- Every detection rule hit (YARA, Sigma, etc.) MUST appear in the report
- Tell the attack STORY - connect events into a narrative
- DFIR Action Plan must use SPECIFIC hostnames, accounts, and IOCs from this data
- If you see memory injection, credential access, or C2 indicators - these are CRITICAL

Generate the report now:"""

        try:
            tech_body = call_llm(tech_prompt, tech_system, llm_config)
            # Append artifact findings as appendix with clear formatting
            artifact_findings_section = f"""


---

# Artifact Findings

*Detailed analysis results from each collected artifact.*

{summaries_text}
"""
            tech_full = tech_body + artifact_findings_section
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
