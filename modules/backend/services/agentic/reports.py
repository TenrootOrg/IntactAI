#!/usr/bin/env python3
"""
Agentic Reports - Report generation functions for forensic analysis
"""

import json
import zipfile
import os
from datetime import datetime

from services.workflow_service import add_log_to_run
from services.file_storage_service import save_report, get_report
from services.agentic.analyzers import call_llm
from services.agentic.utils import extract_timeline_events


def filter_results_by_client(all_results, client_id):
    """Filter artifact results to only include rows from a specific client.

    Args:
        all_results: Dict of artifact_name -> list of rows (each row has _client_id)
        client_id: The client ID to filter for

    Returns:
        Dict of artifact_name -> filtered list of rows for this client only
    """
    filtered = {}
    for artifact_name, rows in all_results.items():
        client_rows = [row for row in rows if row.get('_client_id') == client_id]
        if client_rows:
            filtered[artifact_name] = client_rows
    return filtered


def get_client_hostname(client_id, all_results):
    """Extract hostname from results for a client (from any row that has it)."""
    for rows in all_results.values():
        for row in rows:
            if row.get('_client_id') == client_id:
                hostname = row.get('_hostname') or row.get('Hostname') or row.get('hostname')
                if hostname:
                    return hostname
    # Fallback to client_id
    return client_id.replace('C.', 'Client-')


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
- Avoid raw IOCs, but do mention categories (e.g., "3 suspicious external IP addresses identified")
- Do NOT include or invent a "Collection Platform Version" or any tool version numbers - only use the metadata provided"""

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

### 1. Critical Findings
List the most dangerous findings FIRST, even if timestamps are unknown.
For each finding, write a short paragraph with:
- Timestamp (YYYY-MM-DD HH:MM:SS) or "Time Unknown"
- What was found
- Why it matters (one sentence)
- Evidence source (artifact/rule that detected it)

### 2. Executive Summary
3-4 sentences: What happened, overall risk level (CRITICAL/HIGH/MEDIUM/LOW), threat status (Active/Contained/Unknown), confidence level.

### 3. Attack Narrative Timeline
Tell the STORY of the attack in chronological order:
- What was the likely entry point?
- What did the attacker do to persist?
- What actions did they take?
- What was their apparent objective?

Connect related events. ALWAYS use full date+time (YYYY-MM-DD HH:MM:SS) for ALL timestamps - never time-only.
For events without timestamps, group them in a "Time Unknown" section.

### 4. Indicators of Compromise

IOCs are artifacts that can be searched for or blocked across systems. Organize by type:

#### 4.1 Files & Executables
| File | Path | SHA256 | MITRE | Classification |
|------|------|--------|-------|----------------|
(Only include malicious/suspicious files found in the data. Include hash if available, leave empty if not.)

#### 4.2 Network Indicators
| Type | Value | Context | Classification |
|------|-------|---------|----------------|
(IPs, domains, URLs observed in malicious activity. Skip if none found.)

#### 4.3 Registry & Persistence
| Key/Path | Value | MITRE | Classification |
|----------|-------|-------|----------------|
(Registry modifications, scheduled tasks, WMI subscriptions. Skip if none found.)

IOC RULES:
- Only include items you can search for or block: files, hashes, IPs, domains, URLs, registry keys
- Classification = short tag (e.g., "Recon tool", "Credential dumper", "C2 callback", "Privilege escalation")
- DO NOT include: usernames, hostnames, account names, Event IDs, default Windows accounts, or files generated by this analysis platform
- Usernames and hostnames belong in section 6 (Affected Assets), not here
- ONE row per unique indicator, no duplicates
- If a section has no indicators, omit it entirely

### 5. MITRE ATT&CK Mapping
| Tactic | Technique | Evidence |
|--------|-----------|----------|
Map only techniques with clear evidence from the data.

### 6. Affected Assets
- Systems: hostname, role, compromise status
- Accounts: username, privilege level, activity observed
- Data at risk: what sensitive data may be affected

### 7. DFIR Action Plan

Immediate Actions:
1. [ ] Isolate [specific system] from network
2. [ ] Disable [specific account]
3. [ ] Block [specific IOCs] at perimeter
4. [ ] Preserve evidence from [specific locations]

Investigation Priorities (ordered by urgency):
1. Most urgent investigation and why
2. Second priority
3. Third priority

Evidence to Collect:
- Specific additional artifacts or logs needed

Escalation Triggers:
- Conditions that require escalation to management

---

FORMATTING RULES:
- Write clean, professional prose. Minimal use of bold - only for section headers and critical keywords
- Do NOT use bold labels like "**Timestamp:**", "**Severity:**" etc. Just write naturally: "Timestamp: 2026-03-10 15:46:19"
- Use bullet points for lists, short paragraphs for narrative
- Keep descriptions concise - one line per point where possible
- Use tables for structured data, prose for narrative
- ALWAYS use full datetime (YYYY-MM-DD HH:MM:SS) - never time-only, NEVER append UTC or Z after timestamps
- Do NOT repeat sections or findings - each finding appears exactly once
- Do not fabricate details. If data is ambiguous, say so
- Detection rule hits are the most important findings - never skip them
- Do NOT include or invent tool version numbers
- Ignore any files matching "agentic_*_report_*.md" - these are generated by this analysis platform, not attack artifacts
- Do NOT include or invent a "Collection Platform Version" or any tool version numbers - only use the metadata provided"""

        tech_prompt = f"""Write the body of a technical forensics report for a DFIR team leader. Do NOT include a report title or metadata header - that is already provided. Start directly with section 1 (Critical Findings).

Investigation Scope:
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
- Do NOT generate a report title or metadata block - start directly with "## 1. Critical Findings"
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


def generate_per_client_report(run_id, client_id, hostname, client_results, artifact_summaries, llm_config):
    """Generate a detailed report for a single client.

    Args:
        run_id: Workflow run ID
        client_id: Client ID
        hostname: Client hostname
        client_results: Dict of artifact -> rows for this client only
        artifact_summaries: Dict of artifact -> LLM summary (shared across clients)
        llm_config: LLM configuration

    Returns:
        Markdown report string
    """
    total_rows = sum(len(rows) for rows in client_results.values())
    events = extract_timeline_events(client_results)

    # Build summaries text from client-specific data
    client_summaries_text = "\n\n---\n\n".join([
        f"## {artifact}\n\n{artifact_summaries.get(artifact, 'No analysis available')}"
        for artifact in client_results.keys()
    ])

    header = f"""# Forensics Report: {hostname}

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Client ID:** {client_id}
**Hostname:** {hostname}
**Artifacts:** {len(client_results)} analyzed
**Total Data Rows:** {total_rows}
**Timeline Events:** {len(events)} timestamped events

---

"""

    system_prompt = """You are a senior DFIR analyst creating a DETAILED FORENSICS REPORT for a SINGLE CLIENT/HOST.

Focus on this specific system only. Provide:
1. **Critical Findings** - Most dangerous findings for THIS host
2. **Executive Summary** - What happened on THIS system
3. **Attack Timeline** - Chronological events on THIS host
4. **IOCs Found** - Indicators specific to this system
5. **MITRE ATT&CK Mapping** - Techniques observed
6. **Remediation Actions** - Specific steps for THIS host

Be specific and detailed. This is a per-host deep-dive report."""

    user_prompt = f"""Create a detailed forensics report for host: {hostname}

**Data Summary:**
- Artifacts examined: {len(client_results)}
- Data points: {total_rows}
- Timeline events: {len(events)}

**Artifact Analysis:**
{client_summaries_text[:30000]}

Generate the detailed report now:"""

    try:
        report_body = call_llm(user_prompt, system_prompt, llm_config)
        return header + report_body
    except Exception as e:
        return header + f"Report generation failed: {str(e)}\n\n## Raw Analysis\n\n{client_summaries_text}"


def generate_macro_report(run_id, client_ids, hostnames, all_results, artifact_summaries, llm_config):
    """Generate a high-level organizational summary across all clients.

    Args:
        run_id: Workflow run ID
        client_ids: List of client IDs
        hostnames: Dict of client_id -> hostname
        all_results: Full results dict (all clients)
        artifact_summaries: Dict of artifact -> LLM summary
        llm_config: LLM configuration

    Returns:
        Markdown report string
    """
    add_log_to_run(run_id, f"[Report] Generating macro summary for {len(client_ids)} clients...", "info")

    # Build per-client stats
    client_stats = []
    for client_id in client_ids:
        hostname = hostnames.get(client_id, client_id)
        client_results = filter_results_by_client(all_results, client_id)
        row_count = sum(len(rows) for rows in client_results.values())
        artifact_count = len(client_results)

        # Count severity levels (look for Level/Severity fields)
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'informational': 0}
        for rows in client_results.values():
            for row in rows:
                level = str(row.get('Level') or row.get('Severity') or row.get('RuleLevel') or 'informational').lower()
                if 'crit' in level:
                    severity_counts['critical'] += 1
                elif 'high' in level:
                    severity_counts['high'] += 1
                elif 'med' in level:
                    severity_counts['medium'] += 1
                elif 'low' in level:
                    severity_counts['low'] += 1
                else:
                    severity_counts['informational'] += 1

        client_stats.append({
            'client_id': client_id,
            'hostname': hostname,
            'rows': row_count,
            'artifacts': artifact_count,
            'severity': severity_counts
        })

    # Build stats table
    stats_table = "| Hostname | Artifacts | Findings | Critical | High | Medium |\n"
    stats_table += "|----------|----------:|---------:|---------:|-----:|-------:|\n"
    for stat in client_stats:
        total_findings = stat['rows']
        stats_table += f"| {stat['hostname']} | {stat['artifacts']} | {total_findings} | {stat['severity']['critical']} | {stat['severity']['high']} | {stat['severity']['medium']} |\n"

    total_rows = sum(len(rows) for rows in all_results.values())
    total_critical = sum(s['severity']['critical'] for s in client_stats)
    total_high = sum(s['severity']['high'] for s in client_stats)
    total_medium = sum(s['severity']['medium'] for s in client_stats)

    # Build summaries text
    summaries_text = "\n\n---\n\n".join([
        f"## {artifact}\n\n{summary}"
        for artifact, summary in artifact_summaries.items()
    ])

    header = f"""# Organization Analysis Summary

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Clients Analyzed:** {len(client_ids)}
**Total Findings:** {total_rows}
**Severity Breakdown:** Critical: {total_critical} | High: {total_high} | Medium: {total_medium}

---

## Per-Client Summary

{stats_table}

---

"""

    system_prompt = """You are a senior incident response consultant creating an ORGANIZATIONAL SUMMARY REPORT.

This is a HIGH-LEVEL report covering MULTIPLE hosts/clients. Focus on:

1. **Overall Threat Assessment** - Organization-wide risk level
2. **Cross-Client Patterns** - Findings appearing on multiple hosts (shared IOCs, lateral movement indicators)
3. **Attack Chain Reconstruction** - How the threat spread across systems (if applicable)
4. **Priority Hosts** - Which systems need immediate attention and why
5. **Organization-Wide Recommendations** - Top 5 actions for the security team

DO NOT repeat detailed per-host findings. Keep it macro-level and actionable.
If you see the same IOC on multiple hosts, highlight it as cross-host correlation.
If you see sequential activity suggesting lateral movement, call it out."""

    user_prompt = f"""Create an ORGANIZATIONAL SUMMARY REPORT for {len(client_ids)} clients.

**Clients:** {', '.join(hostnames.values())}

**Combined Artifact Analysis:**
{summaries_text[:40000]}

Focus on:
- Patterns across multiple hosts
- Most critical hosts requiring attention
- Organization-wide remediation priorities

Generate the macro summary now:"""

    try:
        report_body = call_llm(user_prompt, system_prompt, llm_config)
        return header + report_body
    except Exception as e:
        add_log_to_run(run_id, f"[Report] Macro report generation failed: {str(e)}", "error")
        return header + f"Report generation failed: {str(e)}\n\n## Raw Analysis\n\n{summaries_text}"


def generate_multi_client_reports(run_id, blueprint, client_ids, collection_minutes,
                                   artifact_summaries, all_results, llm_config, anonymizer=None):
    """Generate per-client reports + macro summary for multi-client analysis.

    Args:
        run_id: Workflow run ID
        blueprint: Blueprint dict
        client_ids: List of client IDs
        collection_minutes: Collection duration
        artifact_summaries: Dict of artifact -> LLM summary
        all_results: Full results dict (all clients)
        llm_config: LLM configuration
        anonymizer: Optional anonymizer instance

    Returns:
        Dict with:
            - 'per_client': Dict of client_id -> report markdown
            - 'macro': Macro summary markdown
            - 'hostnames': Dict of client_id -> hostname
    """
    add_log_to_run(run_id, f"[Report] Generating reports for {len(client_ids)} clients...", "info")

    # Build hostname mapping
    hostnames = {}
    for client_id in client_ids:
        hostnames[client_id] = get_client_hostname(client_id, all_results)

    # Generate per-client reports
    per_client_reports = {}
    for i, client_id in enumerate(client_ids):
        hostname = hostnames[client_id]
        add_log_to_run(run_id, f"[Report] Generating report for {hostname} ({i+1}/{len(client_ids)})...", "info")

        client_results = filter_results_by_client(all_results, client_id)
        if not client_results:
            per_client_reports[client_id] = f"# {hostname}\n\nNo data collected from this client."
            continue

        report = generate_per_client_report(
            run_id, client_id, hostname, client_results, artifact_summaries, llm_config
        )
        per_client_reports[client_id] = report

    # Generate macro summary
    add_log_to_run(run_id, "[Report] Generating organization summary...", "info")
    macro_report = generate_macro_report(
        run_id, client_ids, hostnames, all_results, artifact_summaries, llm_config
    )

    # Unmask if anonymization was used
    if anonymizer:
        add_log_to_run(run_id, "[Report] Restoring original values from anonymized data...", "info")
        macro_report = anonymizer.unmask_text(macro_report)
        for client_id in per_client_reports:
            per_client_reports[client_id] = anonymizer.unmask_text(per_client_reports[client_id])

    add_log_to_run(run_id, f"[Report] Generated {len(per_client_reports)} client reports + 1 summary", "success")

    return {
        'per_client': per_client_reports,
        'macro': macro_report,
        'hostnames': hostnames
    }


def create_report_package(run_id, multi_reports):
    """Create a ZIP package containing all reports.

    Args:
        run_id: Workflow run ID
        multi_reports: Dict from generate_multi_client_reports()

    Returns:
        Path to the created ZIP file
    """
    # Ensure downloads directory exists
    downloads_dir = f"/data/downloads/{run_id}"
    os.makedirs(downloads_dir, exist_ok=True)

    zip_path = f"{downloads_dir}/reports.zip"
    hostnames = multi_reports.get('hostnames', {})

    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
        # Add macro summary first (00_ prefix for sorting)
        zf.writestr("00_ORGANIZATION_SUMMARY.md", multi_reports['macro'])

        # Add per-client reports
        for client_id, report in multi_reports['per_client'].items():
            hostname = hostnames.get(client_id, client_id)
            # Clean hostname for filename
            safe_hostname = "".join(c if c.isalnum() or c in '-_' else '_' for c in hostname)
            zf.writestr(f"{safe_hostname}_report.md", report)

    return zip_path
