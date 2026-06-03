"""
AWS Security Reports — Cloud-specific report generation.

Mirrors `services.azure.reports`, with the system prompt re-written
around AWS-native primitives (CloudTrail events, IAM principals,
GuardDuty finding types, AssumeRole chains, MITRE ATT&CK Cloud Matrix
for AWS).
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Dict, List

from services.workflow_logger import add_log_to_run
from services.agentic.analyzers import call_llm
from services.file_storage_service import save_report, get_report


AWS_REPORT_SYSTEM_PROMPT = """You are a senior cloud security analyst creating an AWS SECURITY ASSESSMENT REPORT.

YOUR FOCUS: AWS identity (IAM users / roles / SAML / federation), CloudTrail events, S3 / EC2 / Lambda data planes, and GuardDuty / AccessAnalyzer findings.

## ANALYSIS APPROACH

Think like an AWS-focused attacker:
- How did they get in? (Long-lived access-key compromise, console-login without MFA, federated-identity abuse, AssumeRole chain from a compromised role)
- What privilege did they escalate to? (AttachUserPolicy of AdministratorAccess, CreateAccessKey for another user, iam:PassRole, role-trust modification)
- What persistence did they establish? (New IAM users, new access keys on existing users, new SAML providers, new federated identity providers)
- What defense evasion did they attempt? (StopLogging on the trail, DeleteTrail, modify trail to single-region, disable GuardDuty, delete CloudWatch alarms)
- What's the blast radius? (Which data planes can the principal touch — S3 buckets, RDS, Lambda, KMS keys, ECR repos)

PRIORITIZE BY THREAT LEVEL:
1. SIGMA detection hits = ALWAYS report — these are confirmed pattern matches
2. GuardDuty findings (especially UnauthorizedAccess:* and CryptoCurrency:*) = CRITICAL
3. Privilege-escalation events (AttachUserPolicy, PutUserPolicy, CreateAccessKey for-another-user) = CRITICAL
4. Defense evasion events (StopLogging, DeleteTrail, DeleteFlowLogs, DisableSecurityHub) = CRITICAL
5. Anomalous console logins (no MFA, unusual source IP / country) = HIGH
6. AssumeRole patterns from unexpected source IPs or principal chains = HIGH
7. Public S3 / Resource exposure (PutBucketPolicy with `Principal: *`, AccessAnalyzer findings) = HIGH
8. Old / unrotated access keys, IAM-without-MFA = MEDIUM
9. Normal administrative activity = LOW (context only)

NEVER skip SIGMA detection results. If a rule fired, it MUST be in the report.

## REPORT STRUCTURE

### 1. Executive Summary
3-4 sentences: Overall AWS account posture, key threats found, risk level (CRITICAL/HIGH/MEDIUM/LOW), confidence level.

### 2. Key Findings by Severity

#### Critical
- Finding with specific evidence (event name, principal ARN, source IP, timestamp) + immediate action.

#### High
- Finding with evidence and short-term remediation.

#### Medium
- Finding with evidence and recommendation.

### 3. Identity & Authentication Analysis

Analyze CloudTrail console + IAM events:
- **Console logins**: success / failure, MFA presence, unusual source IPs or geographies, off-hours patterns
- **API-key compromise indicators**: `CreateAccessKey` for another user, suddenly-active old keys, keys used from new countries
- **AssumeRole chains**: cross-principal role assumption, especially from external accounts
- **Federated identity changes**: `CreateSAMLProvider`, `UpdateSAMLProvider`, `DeleteSAMLProvider`
- **Privileged-principal activity**: any action under the root account, admin-policy attachments

Use specific data: principal ARNs, source IPs, timestamps, event names.

### 4. Resource & Data-Plane Risks

Based on CloudTrail + AccessAnalyzer + Prowler findings:
- S3 bucket policy changes that allow `Principal: *` or unfamiliar accounts
- EC2 instances launched in unexpected regions / with unusual instance types (e.g. p3.* off-hours = potential crypto mining)
- Lambda / Step Functions privilege changes
- KMS key policy widening
- Resource-policy drift from AccessAnalyzer (`Active` findings)
- Posture failures from Prowler (`status_code: FAIL`)

### 5. SIGMA Detection Summary

| Rule Name | Severity | Hits | Log Source | MITRE Technique |
|-----------|----------|------|------------|-----------------|

Include EVERY rule that fired.

### 6. Indicators of Compromise

| Type | Value | Context | First Seen | Last Seen |
|------|-------|---------|------------|-----------|
| IP Address | x.x.x.x | Suspicious sign-in source / API caller | timestamp | timestamp |
| IAM Principal | arn:aws:iam::...:user/X | Targeted or attacker-controlled | timestamp | timestamp |
| Access Key | AKIA... | Created during incident window | timestamp | timestamp |
| Role | arn:aws:iam::...:role/X | Assumed in suspicious chain | timestamp | timestamp |
| Bucket / Resource | arn:aws:s3:::... | Exposed / accessed by attacker | timestamp | timestamp |

Only suspicious / malicious indicators found in the data.

### 7. MITRE ATT&CK Cloud Matrix (AWS-flavoured)

| Tactic | Technique | ID | Evidence |
|--------|-----------|------|----------|

Common AWS techniques to consider:
- T1078.004 Valid Accounts: Cloud Accounts
- T1098 Account Manipulation
- T1098.001 Additional Cloud Credentials (CreateAccessKey for another user)
- T1098.003 Additional Cloud Roles (AttachUserPolicy of AdministratorAccess)
- T1136.003 Create Account: Cloud Account (CreateUser)
- T1078.004 Valid Accounts: Cloud Accounts
- T1562.008 Impair Defenses: Disable Cloud Logs (StopLogging / DeleteTrail / DisableSecurityHub)
- T1580 Cloud Infrastructure Discovery
- T1526 Cloud Service Discovery
- T1530 Data from Cloud Storage Object (GetObject on a newly-public bucket)
- T1199 Trusted Relationship (SAML provider / cross-account role abuse)
- T1110 Brute Force (failed console logins from one IP)
- T1496 Resource Hijacking (crypto-mining EC2 instances)

### 8. Recommendations

#### Immediate Actions (24 hours)
1. [ ] Action targeting a specific finding (rotate the access key, detach the admin policy, etc.)
2. [ ] …

#### Short-term (1 week)
Policy and configuration improvements.

#### Long-term (Ongoing)
Posture improvements: SCP guardrails, enable Hardware MFA on root, enable multi-region CloudTrail, enable GuardDuty in every active region.

---

CRITICAL RULES:
- Every SIGMA detection MUST appear in the report.
- Use specific data: principal ARNs, source IPs, timestamps, event names, region.
- This is a CLOUD report — focus on AWS-native identity / API / IAM events, not endpoint malware.
- Be specific in recommendations — reference actual findings.
- If data is limited, note what additional log sources (e.g. VPC flow logs, CloudWatch Logs, Athena queries over CloudTrail) would improve coverage."""


# =============================================================================
# Report generation
# =============================================================================


def generate_aws_report(
    run_id: str,
    blueprint: Dict[str, Any],
    collected_data: Dict[str, List[Dict]],
    findings: Dict[str, List[Dict]],
    analysis_results: Dict[str, str],
    llm_config: Dict[str, Any],
    scan_metadata: Dict[str, Any],
    master_prompt: str = None,
) -> Dict[str, str]:
    """Generate AWS-specific assessment report. Returns {'technical': markdown}.

    `master_prompt` (optional) is the operator's distilled chat context
    from interactive mode. When set, it's prepended to the synthesis
    system prompt so the LLM treats it as ground truth — same pattern
    as the agentic report builders."""

    total_events = sum(len(records) for records in collected_data.values())
    total_findings = sum(len(matches) for matches in findings.values())
    sources = list(collected_data.keys())
    num_rules_fired = len(findings)

    actual_min_ts, actual_max_ts = None, None
    distinct_dates = set()
    for records in collected_data.values():
        for r in records:
            ts = (
                r.get('_timestamp')
                or r.get('eventTime')
                or r.get('EventTime')
                or r.get('CreatedAt')
                or r.get('createdAt')
                or r.get('analyzedAt')
            )
            if ts:
                ts_str = str(ts)
                if actual_min_ts is None or ts_str < actual_min_ts:
                    actual_min_ts = ts_str
                if actual_max_ts is None or ts_str > actual_max_ts:
                    actual_max_ts = ts_str
                if len(ts_str) >= 10:
                    distinct_dates.add(ts_str[:10])

    sigma_table = "| Rule | Hits | Source(s) | Severity |\n|------|------|--------|---|\n"
    for rule_name, matches in findings.items():
        srcs = sorted({m.get('_source', '?') for m in matches}) if matches else ['?']
        sev = matches[0].get('severity', '?') if matches else '?'
        sigma_table += f"| {rule_name} | {len(matches)} | {', '.join(srcs)} | {sev} |\n"

    scan_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')
    blueprint_name = blueprint.get('name', 'AWS Scan')
    blueprint_id = blueprint.get('id', '')
    account = scan_metadata.get('account_id', '?')
    region = scan_metadata.get('region', '?')
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

    per_source_lines = "\n".join(
        f"- `{src}`: {len(records):,} records" for src, records in collected_data.items()
    )

    header = f"""# AWS Security Assessment Report

> **All timestamps in this report are in UTC.**

**Scan Date:** {scan_date}
**Blueprint:** {blueprint_name}{f' ({blueprint_id})' if blueprint_id else ''}
**Account:** {account}
**Region(s):** {region}
**Requested Period:** {requested_period}
**Actual Data Time Range:** {actual_period}
**Total Events Collected:** {total_events:,}
**Findings Triggered:** {num_rules_fired}
**Total Detections:** {total_findings:,}

**Sources:**
{per_source_lines}

---

"""

    reports: Dict[str, str] = {}

    # Per-artifact briefs for the synthesis prompt (mirrors Azure)
    artifact_briefs: List[str] = []
    for artifact, summary in analysis_results.items():
        text = str(summary)
        if '```json' in text and '```' in text.split('```json', 1)[1]:
            after = text.split('```json', 1)[1]
            prose = after.split('```', 1)[1] if '```' in after else after
            prose = prose.strip()
        else:
            prose = text.strip()
        artifact_briefs.append(f"### {artifact}\n{prose[:1500]}")
    artifact_briefs_text = "\n\n".join(artifact_briefs)[:25000]

    tech_prompt = f"""You are writing the synthesis section of an AWS Security Assessment Report.

The per-rule analyses have ALREADY been done. Your job is to write a SHORT, accurate, top-level summary that ties them together — NOT to repeat the per-rule details.

## SCAN METADATA (use these EXACT values; do not invent dates or counts)
- Blueprint: {blueprint_name}
- Account: {account}
- Region(s): {region}
- Requested Period: {requested_period}
- **Actual data time range: {actual_period}**
- Total events collected: {total_events:,}
- Distinct sources: {len(sources)}

## SIGMA / FINDINGS SUMMARY
{sigma_table}

## PER-RULE ANALYSIS BRIEFS (already produced — do NOT recopy)
{artifact_briefs_text}

## REQUIREMENTS
- Use only dates / principal ARNs / IPs / counts that appear in the metadata or briefs above.
- Do NOT describe a multi-day campaign unless the actual time range spans multiple days.
- Keep the synthesis concise (max ~1000 words). Sections: Executive Summary (≤150 words), Top Concerns (max 5 bullets), Recommended Next Steps (max 5 bullets), Confidence & Caveats.
- Reference findings by their rule name; do not recopy individual events.
"""

    add_log_to_run(run_id, "[Report] Generating AWS Technical Report...", "info")
    # Prepend interactive-mode operator context to the system prompt
    # when present. Same shape as the agentic report builders so the
    # LLM treats the operator's notes as ground truth.
    system_prompt = AWS_REPORT_SYSTEM_PROMPT
    if master_prompt:
        system_prompt = (
            "## OPERATOR CONTEXT (from interactive validation)\n"
            "The following corrections + investigation priorities have been "
            "supplied by the analyst after reviewing a prior version of this "
            "report. Treat them as ground truth and adjust your analysis "
            "accordingly — downweight or remove findings the analyst marked "
            "as false-positive / known-legitimate, surface and deepen any "
            "areas they asked you to investigate further.\n\n"
            f"{master_prompt.strip()}\n\n---\n\n"
        ) + system_prompt
        add_log_to_run(run_id, "[Pipeline] master prompt applied to AWS report", "info")
    try:
        tech_body = call_llm(tech_prompt, system_prompt, llm_config)
        appendix = _build_artifact_appendix(analysis_results)
        reports['technical'] = header + tech_body + appendix
        add_log_to_run(run_id, "[Report] AWS Technical Report complete", "success")
    except Exception as e:
        add_log_to_run(run_id, f"[Report] Technical Report failed: {e}", "error")
        appendix = _build_artifact_appendix(analysis_results)
        reports['technical'] = header + f"Synthesis generation failed: {e}\n" + appendix

    return reports


def get_aws_report_content(run_id: str):
    """Return the AWS scan's stored markdown report, or a best-effort
    fallback for the interactive chat to feed the assistant as system
    context.

    Resolution order:
      1. DB-stored markdown report (the normal pipeline finish path).
      2. The `reports.technical` field in
         `/app/data/aws_runs/<run_id>.json` (covers runs that wrote
         the JSON but failed to commit to the DB).
      3. A synthesised digest of the persisted `analysis` dict —
         per-rule LLM summaries glued together with rule-name
         headings. Lets the assistant still discuss findings on
         older runs that never produced a full report.
    """
    import os as _os
    # 1. DB
    raw = get_report(run_id)
    if raw:
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                body = parsed.get('technical') or parsed.get('executive')
                if body:
                    return body
            return str(parsed)
        except (ValueError, TypeError):
            return raw
    # 2 + 3. Fall back to the persisted JSON dump.
    persisted = f"/app/data/aws_runs/{run_id}.json"
    if not _os.path.exists(persisted):
        return None
    try:
        with open(persisted) as f:
            data = json.load(f)
    except Exception:
        return None
    reps = data.get('reports') or {}
    if isinstance(reps, dict):
        body = reps.get('technical') or reps.get('executive')
        if body:
            return body
    # 3. Glue per-rule analyses into a single markdown blob so the
    # assistant has something concrete to discuss.
    analysis = data.get('analysis') or {}
    if not isinstance(analysis, dict) or not analysis:
        return None
    parts = ["# AWS scan — per-rule findings (digest)", ""]
    for rule, summary in analysis.items():
        parts.append(f"## {rule}\n\n{summary}\n")
    return "\n".join(parts)


def _build_artifact_appendix(analysis_results: dict) -> str:
    """Per-rule findings appendix. Identical shape to azure._build_artifact_appendix."""
    if not analysis_results:
        return ""

    parts: List[str] = [
        "\n\n---\n\n# Detailed Findings\n",
        "*Per-rule analysis with evidence, severity, and recommended actions.*\n",
    ]
    for artifact, summary in analysis_results.items():
        parts.append(f"\n## {artifact}\n")
        text = str(summary)

        findings_data = None
        if '```json' in text:
            try:
                json_part = text.split('```json', 1)[1].split('```', 1)[0]
                findings_data = json.loads(json_part)
            except (json.JSONDecodeError, IndexError):
                findings_data = None

        if findings_data:
            if findings_data.get('summary'):
                parts.append(f"**Summary:** {findings_data['summary']}\n")
            if findings_data.get('scan_scope_acknowledged'):
                parts.append(f"\n*Scope: {findings_data['scan_scope_acknowledged']}*\n")
            findings_list = findings_data.get('findings', [])
            if findings_list:
                parts.append(f"\n### Findings ({len(findings_list)})\n")
                for f in findings_list:
                    sev = f.get('severity', '?').upper()
                    conf = f.get('confidence', '?')
                    sev_emoji = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🔵', 'INFORMATIONAL': '⚪'}.get(sev, '•')
                    parts.append(f"\n#### {sev_emoji} {f.get('id', '')} — {f.get('title', 'Untitled')}")
                    parts.append(f"\n- **Severity:** {sev} (confidence: {conf})")
                    if f.get('evidence_count'):
                        parts.append(f"\n- **Evidence count:** {f['evidence_count']}")
                    if f.get('evidence'):
                        parts.append(f"\n- **Evidence (FACT):** {f['evidence']}")
                    if f.get('interpretation'):
                        parts.append(f"\n- **Interpretation (INFERENCE):** {f['interpretation']}")
                    if f.get('sample_users'):
                        parts.append(f"\n- **Principals:** `{', '.join(f['sample_users'])}`")
                    if f.get('sample_ips'):
                        parts.append(f"\n- **IPs:** `{', '.join(f['sample_ips'])}`")
                    if f.get('sample_timestamps'):
                        parts.append(f"\n- **Sample timestamps:** `{', '.join(f['sample_timestamps'][:3])}`")
                    if f.get('mitre'):
                        parts.append(f"\n- **MITRE:** {', '.join(f['mitre'])}")
                    if f.get('recommended_action'):
                        parts.append(f"\n- **Recommended action:** {f['recommended_action']}")
                    parts.append("\n")
            iocs = findings_data.get('iocs', {})
            if any(iocs.values()):
                parts.append("\n### IOCs\n")
                for k, v in iocs.items():
                    if v:
                        parts.append(f"- **{k}:** `{', '.join(v)}`\n")
            if '```' in text:
                after_json = text.split('```json', 1)[1].split('```', 1)
                if len(after_json) > 1 and after_json[1].strip():
                    parts.append(f"\n**Analyst note:**\n{after_json[1].strip()}\n")
        else:
            parts.append(f"\n{text}\n")
        parts.append("\n---\n")
    return "".join(parts)


# =============================================================================
# Persistence — wrappers around services.file_storage_service
# =============================================================================


def save_aws_report(run_id: str, reports: Dict[str, str]) -> None:
    save_report(run_id, json.dumps(reports))
    print(f"[AWS] Reports saved for run_id: {run_id} ({list(reports.keys())})", flush=True)


def get_aws_report(run_id: str, report_type: str = None):
    content = get_report(run_id)
    if not content:
        return None
    try:
        reports = json.loads(content)
        if isinstance(reports, dict):
            if report_type:
                return reports.get(report_type)
            combined = ""
            if 'executive' in reports:
                combined += reports['executive'] + "\n\n---\n\n"
            if 'technical' in reports:
                combined += reports['technical']
            return combined if combined else None
    except (json.JSONDecodeError, TypeError):
        pass
    return content


def get_aws_report_types(run_id: str) -> List[str]:
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
