#!/usr/bin/env python3
"""
Agentic Reports - Report generation functions for forensic analysis
"""

import json
import re
import textwrap
import zipfile
import os
from datetime import datetime

from services.workflow_service import add_log_to_run
from services.file_storage_service import save_report, get_report
from services.agentic.analyzers import call_llm
from services.agentic.utils import extract_timeline_events
from services.agentic.reports._base import *  # noqa: F401,F403
from services.agentic.reports._base import (_LIST_MARKER_RE, _format_clients_label, _generate_timeline_section, _safe_hostname)  # underscore members not covered by import *

def generate_final_report(run_id, blueprint, client_ids, collection_minutes,
                          artifact_summaries, all_results, llm_config, report_types=None,
                          anonymizer=None, hostnames=None, master_prompt=None):
    """Generate report(s) using LLM. Returns dict with 'executive', 'technical', or both.
    If anonymizer is provided, masked values in reports are restored to original.

    `hostnames` is an optional dict[client_id -> hostname] used to render the
    Clients header line with names (e.g. "2 (NofLaptop, DESKTOP-566AT85)").
    When omitted, the header falls back to the bare count ("2 analyzed").
    The agentic route stashes this dict in workflow details at run-create
    time; the pipeline passes it through to here."""

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
    clients_label = _format_clients_label(client_ids, hostnames)

    def get_header(report_title):
        return f"""# {report_title}

> **All timestamps in this report are in UTC.**

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} UTC
**Blueprint:** {blueprint.get('name')}
**Clients:** {clients_label}
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

        # Interactive-mode master prompt — see analyzers.py for full
        # rationale. Same prepend pattern across all report builders.
        exec_system_final = exec_system
        if master_prompt:
            exec_system_final = (
                "## OPERATOR CONTEXT (from interactive validation)\n"
                "The analyst has reviewed a prior version of this report and "
                "supplied the following corrections + investigation priorities. "
                "Treat them as ground truth and adjust the executive summary "
                "accordingly.\n\n"
                f"{master_prompt.strip()}\n\n---\n\n"
            ) + exec_system
        try:
            exec_body = call_llm(exec_prompt, exec_system_final, llm_config)
            reports['executive'] = get_header("Executive Forensics Report") + exec_body
            add_log_to_run(run_id, "[Report] Executive Report complete", "success")
        except Exception as e:
            add_log_to_run(run_id, f"[Report] Executive Report failed: {str(e)}", "error")
            reports['executive'] = get_header("Executive Forensics Report") + f"Report generation failed: {str(e)}"

    # Generate Technical Report (Forensics team)
    if 'technical' in report_types:
        add_log_to_run(run_id, "[Report] Generating Technical Report (forensics detail)...", "info")

        # Single fixed macro for the report writer: a DFIR investigation
        # playbook that explicitly covers timeline reconstruction. Selection
        # logic was deliberately removed — the report writer's job is the
        # same shape every run (look at it as a DFIR professional, build a
        # timeline), so a stable macro is preferable to dynamic scoring
        # that sometimes picked tooling-reference playbooks (timesketch,
        # YARA triage) over investigation methodology.
        _REPORT_MACRO = "performing-endpoint-forensics-investigation"
        macro_preamble = ""
        try:
            from services.agentic.skills import get_macro_body
            body = get_macro_body(_REPORT_MACRO) or ""
            if body:
                macro_preamble = f"\n\n## DOMAIN PLAYBOOK ({_REPORT_MACRO})\n{body.strip()}\n"
                add_log_to_run(run_id, f"[Skill] Technical report -> {_REPORT_MACRO}", "info")
            else:
                add_log_to_run(run_id, f"[Skill] Technical report -> macro '{_REPORT_MACRO}' has no body (using base prompt only)", "warning")
        except Exception as _skill_err:  # noqa: BLE001 — never block report generation
            add_log_to_run(run_id, f"[Skill] Technical report macro load skipped: {_skill_err}", "warning")

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
7. Normal system activity = OMIT — see REPORT-WIDE DISCIPLINE below.

NEVER skip or summarize away detection hits. If something was flagged by a rule, it MUST be in your report.

## REPORT-WIDE DISCIPLINE

This report is for a DFIR team leader who will ACT on what's in it. Every section
must answer "is this attacker activity, with high confidence?" — if not, drop it.

- Section 1 (Critical Findings): ONLY high-severity, high-confidence threats. If the
  data has none, write "No high-confidence attacker activity identified in the analyzed
  window." DO NOT lower the bar to fill the section.
- Section 3 (Attack Narrative): ONLY the chain of suspicious actions. Skip normal
  user activity, vendor RMM the org uses, default scheduled tasks, expected logons —
  even when chronologically interesting.
- Section 4 (IOCs): see per-section rules below. EXCLUDE vendor/SaaS brand domains
  unless there's specific attacker abuse evidence. EXCLUDE authentication providers
  (AzureAD, NT AUTHORITY) and internal hostnames (DESKTOP-*) entirely.
- Section 5 (MITRE Mapping): map a technique only when the records show evidence
  *specific to attacker use* of that technique. "PowerShell observed" is not T1059.001
  unless the PowerShell was suspicious (encoded, downloads, lateral movement).
- Section 7 (DFIR Action Plan): every action must tie to a finding in section 1.
  No action items for benign activity.

A SHORT, HONEST report is correct when the data is benign. Padding with normal-activity
prose to fill sections is failure mode — it dilutes signal and erodes SOC trust.

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
| File | Path | Hash | MITRE | Classification |
|------|------|------|-------|----------------|
(Hash cell MUST be type-prefixed: "SHA256:<hex>", "MD5:<hex>", "SHA1:<hex>".
 Multiple hash types for the same file: join with "; " — e.g. "MD5:abc; SHA256:def".
 Use "Not provided" only when no hash exists in the source data.
 Only include malicious/suspicious files found in the data — not benign software.

 IMPORTANT: ANY file with a hash (or where one would meaningfully apply) goes
 here, even if the activity is "registry-related" or "configuration tampering"
 (e.g., a tampered Sysmon config). The entity's identity is still a file —
 put it in 4.1 so it can be hash-searched. Section 4.3 is for registry KEYS,
 scheduled TASKS, services, and WMI subscriptions — NOT for files.)

#### 4.2 Network Indicators
| Type | Value | Context | Classification |
|------|-------|---------|----------------|
(Only domains / IPs / URLs observed in ATTACKER activity:
 C2 communication, exfiltration, staging downloads, malicious tooling fetched, detection-rule hits.
 EXCLUDE these even if they appear in the data — they are NOT IOCs:
 - Vendor / SaaS brand domains (anydesk.com, crowdstrike.com, openai.com, github.com, gmail.com,
   facebook.com, splashtop.com, microsoft.com, googleusercontent.com, cloudflare.com, etc.)
   unless there is SPECIFIC evidence of attacker abuse of that service.
 - Authentication-provider names (AzureAD, NT AUTHORITY, NT VIRTUAL MACHINE) — these are not domains.
 - Internal hostnames or local resource names (DESKTOP-*, local-*, *.local, *.lan, *.corp).
   Those belong in section 6 Affected Assets.
 If a value is in your data but doesn't meet the bar above, omit it. Skip the section entirely
 if no IOCs qualify.)

#### 4.3 Registry & Persistence
| Key/Path | Value | MITRE | Classification |
|----------|-------|-------|----------------|
(Registry KEYS (HKLM\..., HKCU\...), scheduled TASKS, SERVICES, WMI event
 subscriptions ONLY. Do NOT put files in this section — even tampered config
 files / config XML / .reg files belong in 4.1 (so they get a hash IOC).
 Skip the section entirely if no registry/task/service/WMI items qualify.)

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

        # Master prompt prepended (same rationale as elsewhere). Note we
        # build the full system string from the existing concatenation
        # (tech_system + macro_preamble) and prepend operator context to
        # that, so the order is: OPERATOR CONTEXT → base system → macro
        # preamble.
        tech_system_full = tech_system + macro_preamble
        if master_prompt:
            tech_system_full = (
                "## OPERATOR CONTEXT (from interactive validation)\n"
                "The analyst has reviewed a prior version of this technical "
                "report and supplied the following corrections + investigation "
                "priorities. Treat them as ground truth: downweight or remove "
                "findings they marked as false-positive / known-legitimate, "
                "and deepen any areas they asked you to investigate further.\n\n"
                f"{master_prompt.strip()}\n\n---\n\n"
            ) + tech_system_full
        try:
            tech_body = call_llm(tech_prompt, tech_system_full, llm_config)
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

    # Hard-wrap paragraph text so the saved .md is readable in raw editors
    # (the LLM returns paragraphs as single very long logical lines).
    for _key in ('executive', 'technical'):
        if _key in reports and reports[_key]:
            reports[_key] = wrap_markdown_paragraphs(reports[_key], width=100)

    return reports



def generate_per_client_report(run_id, client_id, hostname, client_results, artifact_summaries,
                                llm_config, master_prompt=None):
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

    # Interactive-mode master prompt (see analyzers.py for the same
    # injection rationale). Operator-supplied corrections + investigation
    # priorities take priority over the base instructions.
    if master_prompt:
        system_prompt = (
            "## OPERATOR CONTEXT (from interactive validation)\n"
            "The analyst has reviewed a prior version of this per-host report "
            "and supplied the following corrections + investigation priorities. "
            "Treat them as ground truth: downweight or remove findings they "
            "marked as false-positive / known-legitimate, and deepen any areas "
            "they asked you to investigate further.\n\n"
            f"{master_prompt.strip()}\n\n---\n\n"
        ) + system_prompt

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


def generate_macro_report(run_id, client_ids, hostnames, all_results, artifact_summaries,
                          llm_config, per_client_reports=None, master_prompt=None):
    """Generate an organization-grade DFIR synthesis across all clients.

    The LLM is fed the FULL per-host markdown reports (when supplied) plus
    the per-artifact summaries as a backstop, and is prompted to produce a
    structured report matching the OMC reference
    (/home/tenroot/OMC_Incident_Macro.md): numbered Critical Findings with
    evidence-source pointers, attack-narrative timeline, cross-host
    indicators, MITRE mapping, per-host role matrix, data impact, open
    questions, and tiered recommendations.

    Args:
        run_id: Workflow run ID
        client_ids: List of client IDs
        hostnames: Dict of client_id -> hostname
        all_results: Full results dict (all clients)
        artifact_summaries: Dict of artifact -> LLM summary
        llm_config: LLM configuration
        per_client_reports: Optional dict of client_id -> per-host markdown.
            When omitted, the macro pass falls back to artifact summaries
            only (much weaker output). The new-collection pipeline passes
            this; the analyze-existing pipeline should too.

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

    # Build artifact-summary backstop (used when no per-host reports are
    # available, e.g. very old analyze-existing runs).
    summaries_text = "\n\n---\n\n".join([
        f"## {artifact}\n\n{summary}"
        for artifact, summary in artifact_summaries.items()
    ])

    header = f"""# Organization Analysis Summary

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Clients Analyzed:** {_format_clients_label(client_ids, hostnames)}
**Total Findings:** {total_rows}
**Severity Breakdown:** Critical: {total_critical} | High: {total_high} | Medium: {total_medium}

---

## Per-Client Summary

{stats_table}

---

"""

    # ---- Evidence package for the LLM ---------------------------------
    # The OMC reference report (/home/tenroot/OMC_Incident_Macro.md) was
    # produced by feeding the LLM EVERY per-host report verbatim and asking
    # for a cross-host synthesis. We do the same here.
    #
    # Budget: most modern providers handle 200k+ tokens, but per-host
    # reports can be large. Soft cap the TOTAL evidence at 300k chars;
    # when exceeded, truncate each per-host report proportionally rather
    # than dropping hosts entirely.
    EVIDENCE_BUDGET_CHARS = 300_000
    evidence_blocks = []
    if per_client_reports:
        # Compute target per-host length if total exceeds budget.
        total_chars = sum(len(r or "") for r in per_client_reports.values())
        if total_chars > EVIDENCE_BUDGET_CHARS:
            per_host_target = EVIDENCE_BUDGET_CHARS // max(1, len(per_client_reports))
            add_log_to_run(
                run_id,
                f"[Report] Per-host reports total {total_chars} chars > {EVIDENCE_BUDGET_CHARS} budget — "
                f"truncating each to ~{per_host_target} chars for macro synthesis",
                "warning",
            )
        else:
            per_host_target = None  # no truncation needed

        for cid in client_ids:
            hostname = hostnames.get(cid, cid)
            body = per_client_reports.get(cid) or ""
            if per_host_target and len(body) > per_host_target:
                # Keep the most useful prefix (header + first chunks of
                # findings/timeline). Mark the truncation explicitly.
                body = body[:per_host_target] + "\n\n*[…truncated for macro synthesis context budget…]*"
            evidence_blocks.append(f"### {hostname}\n\n{body}")
        evidence_section = "\n\n---\n\n".join(evidence_blocks)
        evidence_kind = "PER-HOST REPORTS"
    else:
        # Fallback: artifact summaries only. Weaker but better than nothing.
        evidence_section = summaries_text[:EVIDENCE_BUDGET_CHARS]
        evidence_kind = "PER-ARTIFACT SUMMARIES (per-host reports not available)"

    system_prompt = """You are a senior DFIR lead writing an ORGANIZATION-WIDE INCIDENT REPORT for a SOC.

You will receive the per-host investigation reports below. Synthesise them into a single
cross-host narrative that an IR team can hand to executives and use to drive containment.

## REQUIRED STRUCTURE
Output the following sections, in this order, with these exact level-2 headings:

## 1. Critical Findings
Numbered F-1, F-2, …. Each finding has:
- A one-line title with the host(s) involved.
- Timestamp (or window) and what concretely happened.
- An evidence pointer: "Evidence source: <hostname> §<N>" referencing the per-host report.

## 2. Executive Summary
Plain language, ≤ 6 paragraphs. What happened, who was compromised, when, current status,
overall risk level (CRITICAL / HIGH / MEDIUM / LOW), confidence (HIGH / MEDIUM / LOW), and the
single most-suspicious host or IP.

## 3. Attack Narrative Timeline
Phased: Phase 0 — Pre-positioning, Phase 1 — First Foothold, Phase 2 — Lateral Movement, …
Each phase has timestamped bullets; bullets tag the host inline (e.g. "**WS1** — 13:05:04 …").
If the data is small/benign, write fewer phases — do not invent activity to fill the template.

## 4. Cross-Host Indicators
- **Attacker-controlled / unmanaged IPs** — table: IP / role / first seen / hosts touched.
- **External C2 / staging infrastructure** — table: domain or IP / role / observed on.
- **Tooling** — table: tool / purpose / hosts.
- **Compromised accounts** — list.
- **Persistence mechanisms** — table: mechanism / host / MITRE technique.

## 5. Per-Host Role Matrix
Table: hostname / IP (if known) / role in attack / earliest event / key accounts / data touched.

## 6. MITRE ATT&CK Mapping
Table: tactic / technique / evidence (host tags).

## 7. Data Impact
What was confirmed staged or accessed; what's suspected but unconfirmed.

## 8. Open Questions / Unresolved Items
Numbered list of questions the IR team still needs to answer.

## 9. Recommendations
Tiered: Immediate Containment / Eradication / Hardening.

## DISCIPLINE
- Synthesise ONLY suspicious or malicious activity. If the per-host reports describe normal
  baseline activity, the right macro is "no cross-host attacker activity identified" — NOT a
  padded story about benign behaviour.
- Stay GROUNDED in the per-host reports. Do NOT invent IPs, tools, accounts, timestamps, or
  attacker tradecraft not present in the evidence below. Every claim must be traceable to a
  per-host source.
- If the evidence is thin (small org, mostly benign), produce a SHORT report. A 1-page
  honest macro beats a 10-page fabricated one.
- Calibrate confidence honestly. "HIGH" requires multiple independent artifact classes converging.
"""

    # Interactive-mode master prompt — see analyzers.py for full rationale.
    # Prepended so operator corrections take priority over the base
    # synthesis instructions.
    if master_prompt:
        system_prompt = (
            "## OPERATOR CONTEXT (from interactive validation)\n"
            "The analyst has reviewed a prior version of this organization-wide "
            "synthesis and supplied the following corrections + investigation "
            "priorities. Treat them as ground truth: downweight or remove "
            "Critical Findings they marked as false-positive / known-legitimate, "
            "and deepen any areas they asked you to investigate further.\n\n"
            f"{master_prompt.strip()}\n\n---\n\n"
        ) + system_prompt

    user_prompt = f"""# ORGANIZATION-WIDE INCIDENT SYNTHESIS

**Hosts analyzed:** {len(client_ids)} ({', '.join(hostnames.get(cid, cid) for cid in client_ids)})
**Severity totals across all hosts:** Critical={total_critical}, High={total_high}, Medium={total_medium}
**Total findings:** {total_rows}

## {evidence_kind}
(Cite by hostname tag in your Critical Findings, e.g. "Evidence source: NofLaptop §3")

{evidence_section}

---

Now produce the organization-wide synthesis following the required structure above.
"""

    try:
        report_body = call_llm(user_prompt, system_prompt, llm_config)
        if not report_body or not isinstance(report_body, str):
            # call_llm should always return a string; if it returns None or
            # something exotic, fall through to the except branch instead of
            # crashing with a confusing TypeError further down.
            raise RuntimeError(
                f"call_llm returned {type(report_body).__name__!r} "
                f"(expected str); LLM provider may be misconfigured."
            )
        return header + report_body
    except Exception as e:
        # Full traceback to docker logs — the old "NoneType is not
        # subscriptable" with no context was un-debuggable.
        import traceback as _tb
        tb_text = _tb.format_exc()
        print(f"[MACRO] generation error:\n{tb_text}", flush=True)
        add_log_to_run(
            run_id,
            f"[Report] Macro report generation failed ({type(e).__name__}): {str(e)[:300]}",
            "error",
        )
        # Always return SOMETHING — the per-host reports are intact in the
        # ZIP either way, and the header + per-host table + raw summaries
        # are still a usable degraded output.
        return header + (
            f"_Macro synthesis failed: {type(e).__name__}: {str(e)[:200]}._\n\n"
            f"The per-host reports in this ZIP are intact. Raw per-artifact "
            f"summaries below.\n\n## Raw Analysis\n\n{summaries_text}"
        )


def generate_multi_client_reports(run_id, blueprint, client_ids, collection_minutes,
                                   artifact_summaries, all_results, llm_config, anonymizer=None,
                                   hostnames=None, generate_macro=False, master_prompt=None):
    """Generate per-client reports + (optionally) macro summary for
    multi-client analysis.

    Args:
        run_id: Workflow run ID
        blueprint: Blueprint dict
        client_ids: List of client IDs
        collection_minutes: Collection duration
        artifact_summaries: Dict of artifact -> LLM summary
        all_results: Full results dict (all clients)
        llm_config: LLM configuration
        anonymizer: Optional anonymizer instance
        hostnames: Optional pre-resolved dict[client_id -> hostname]. When
            omitted, falls back to deriving from collected rows via
            get_client_hostname() (used by the analyze-existing path).
        generate_macro: when True, produces the org-wide macro synthesis
            (`00_ORGANIZATION_SUMMARY.md` in the ZIP). Off by default —
            operators opt in via the dashboard checkbox. The extra LLM
            call is meaningful spend on large hosts, and on a small run
            the macro often adds noise; per-client reports are always
            generated regardless.

    Returns:
        Dict with:
            - 'per_client': Dict of client_id -> report markdown
            - 'macro': Macro summary markdown (None when generate_macro=False)
            - 'hostnames': Dict of client_id -> hostname
    """
    add_log_to_run(run_id, f"[Report] Generating reports for {len(client_ids)} clients...", "info")

    # Use the pre-resolved hostname map if the caller supplied one (route
    # stashes it at run-create time via resolve_hostnames). Otherwise fall
    # back to row-derived hostnames — works for analyze-existing runs
    # where the rows already carry `_hostname` from the original collection.
    if hostnames:
        hostnames = dict(hostnames)  # defensive copy
        for cid in client_ids:
            if not hostnames.get(cid):
                hostnames[cid] = get_client_hostname(cid, all_results)
    else:
        hostnames = {}
        for client_id in client_ids:
            hostnames[client_id] = get_client_hostname(client_id, all_results)

    # Generate per-client reports IN PARALLEL. Each per-client report is
    # an independent LLM call (no shared mutable state), so running them
    # concurrently cuts wall-clock from N×latency to ~1×latency. For 5
    # clients with a 30s LLM call that's 2.5min -> 30s.
    #
    # Cap concurrency at the same `max_concurrent_requests` we use for
    # the per-artifact analyzer pool, so we don't blow past the provider's
    # rate limit.
    from concurrent.futures import ThreadPoolExecutor, as_completed
    max_workers = max(1, int((llm_config.get('agentic', {}) or {}).get('max_concurrent_requests', 5)))
    max_workers = min(max_workers, len(client_ids))  # never spawn more than needed

    per_client_reports = {}

    def _build_one(client_id):
        hostname = hostnames[client_id]
        client_results = filter_results_by_client(all_results, client_id)
        if not client_results:
            return client_id, hostname, f"# {hostname}\n\nNo data collected from this client."
        try:
            report = generate_per_client_report(
                run_id, client_id, hostname, client_results, artifact_summaries, llm_config,
                master_prompt=master_prompt,
            )
            return client_id, hostname, report
        except Exception as e:
            # Don't let one client's failure abort the others. Drop a stub
            # so the macro pass still has SOMETHING to cite for this host.
            import traceback as _tb
            print(f"[REPORT] Per-client report for {hostname} failed:\n{_tb.format_exc()}", flush=True)
            return client_id, hostname, (
                f"# {hostname}\n\n"
                f"_Per-host report generation failed: {type(e).__name__}: {str(e)[:200]}_"
            )

    add_log_to_run(
        run_id,
        f"[Report] Generating {len(client_ids)} per-client reports in parallel (max_workers={max_workers})...",
        "info",
    )
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(_build_one, cid): cid for cid in client_ids}
        completed = 0
        for fut in as_completed(futures):
            cid, hostname, report = fut.result()
            per_client_reports[cid] = report
            completed += 1
            add_log_to_run(
                run_id,
                f"[Report] [{hostname}] per-host report ready ({completed}/{len(client_ids)})",
                "info",
            )

    # Generate macro summary ONLY when the operator opted in (UI checkbox
    # `forensics-cross-client-toggle`). Off by default — saves one LLM
    # call and avoids adding a cross-host narrative to the ZIP when the
    # operator just wanted per-host reports. The operator can still get
    # the macro later by re-running the same flow IDs via analyze-existing
    # with the flag flipped on.
    macro_report = None
    if generate_macro:
        add_log_to_run(run_id, "[Report] Generating organization-wide synthesis (opt-in)...", "info")
        macro_report = generate_macro_report(
            run_id, client_ids, hostnames, all_results, artifact_summaries, llm_config,
            per_client_reports=per_client_reports,
            master_prompt=master_prompt,
        )
    else:
        add_log_to_run(
            run_id,
            "[Report] Skipping organization-wide synthesis (checkbox off). "
            "Per-client reports were still generated.",
            "info",
        )

    # Unmask if anonymization was used
    if anonymizer:
        add_log_to_run(run_id, "[Report] Restoring original values from anonymized data...", "info")
        if macro_report:
            macro_report = anonymizer.unmask_text(macro_report)
        for client_id in per_client_reports:
            per_client_reports[client_id] = anonymizer.unmask_text(per_client_reports[client_id])

    # Hard-wrap paragraph text so the saved .md is readable in raw editors.
    if macro_report:
        macro_report = wrap_markdown_paragraphs(macro_report, width=100)
    for _cid in per_client_reports:
        if per_client_reports[_cid]:
            per_client_reports[_cid] = wrap_markdown_paragraphs(per_client_reports[_cid], width=100)

    macro_suffix = " + 1 summary" if macro_report else " (no org summary)"
    add_log_to_run(run_id, f"[Report] Generated {len(per_client_reports)} client reports{macro_suffix}", "success")

    return {
        'per_client': per_client_reports,
        'macro': macro_report,
        'hostnames': hostnames
    }


