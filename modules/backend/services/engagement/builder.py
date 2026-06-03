"""Engagement Report builder.

Combines completed agentic / aws_scan / azure_scan workflow reports
into a single IR-firm-style markdown deliverable. One LLM call
produces the executive layer; everything else is plain markdown
assembly.

Public surface:
  run_engagement_build(run_id, sources, notes, llm_config)
  _run_engagement_reanalyze(run_id, master_prompt, llm_config, scope)
"""
from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from services.workflow_service import update_run_status, add_log_to_run
from services.file_storage_service import get_workflow, save_workflow
from services.storage.report_store import save_report, get_report
from services.agentic.analyzers import call_llm

from .templates import (
    ENGAGEMENT_SYSTEM_PROMPT,
    SOURCE_EVIDENCE_CHAR_BUDGET,
    SOURCE_INLINE_CHAR_BUDGET,
    CANONICAL_SECTIONS,
    cover_block,
    section_heading,
    ioc_table_header,
    appendix_heading,
    audience_language_directive,
)


def _load_source_report(run_id: str, automation_type: str) -> Optional[str]:
    """Dispatch to the per-module accessor we already use in chat.py.
    Returns the source's markdown, or None when nothing's on file."""
    try:
        if automation_type == 'agentic':
            from services.agentic.reports import get_report_content
            return get_report_content(run_id)
        if automation_type == 'aws_scan':
            from services.aws.reports import get_aws_report_content
            return get_aws_report_content(run_id)
        if automation_type == 'azure_scan':
            from services.azure.reports import get_azure_report_content
            return get_azure_report_content(run_id)
        if automation_type == 'cve_scan':
            # CVE Scan stores its short markdown summary via the same
            # save_report accessor AWS / Azure use. Pull it the same way.
            from services.storage.report_store import get_report
            raw = get_report(run_id)
            if not raw:
                return None
            try:
                payload = json.loads(raw)
                return payload.get('technical') or None
            except Exception:
                return raw  # treat as bare markdown if the row wasn't JSON
    except Exception as e:
        print(f"[ENGAGEMENT] Failed to load report for {run_id}: {e}", flush=True)
    return None


def _load_cve_findings(run_id: str) -> List[Dict]:
    """Read the CVE Scan run's `findings.json` — the structured form
    of `combined_cves.csv`. Returns a list of dicts in CVSS-descending
    order, vulnerable findings only.

    Returns [] when the file is missing (e.g. the CVE run pre-dated
    the findings.json write, or its downloads dir was purged)."""
    path = Path(f"/data/downloads/{run_id}/findings.json")
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding='utf-8'))
    except Exception:
        return []
    vulns = [r for r in (data or []) if (r.get('status') or '').lower() == 'vulnerable']
    # Sort by CVSS desc, then by host + product for stable output.
    vulns.sort(key=lambda r: (-float(r.get('cvss_score') or 0),
                              r.get('hostname') or '',
                              r.get('product') or ''))
    return vulns


def _top_vulnerable_products(raw_findings, top_n=20):
    """Aggregate raw CVE findings by `(product, cve_id)` and count
    distinct hostnames per pair. Returns the top N rows sorted by
    CVSS desc then host-count desc — the exec-friendly view of
    "what software needs patching across how many machines" without
    listing every host by name.

    Each row dict: {product, cve_id, cvss_score, severity_bucket,
    cve_link, host_count}.
    """
    by_pair = {}
    for r in raw_findings or []:
        prod = (r.get('product') or '').strip()
        cve = (r.get('cve_id') or '').strip()
        host = (r.get('hostname') or '(unknown)').strip()
        if not prod or not cve:
            continue
        key = (prod, cve)
        score = float(r.get('cvss_score') or 0)
        if key not in by_pair:
            by_pair[key] = {
                'product': prod,
                'cve_id': cve,
                'cvss_score': score,
                'severity_bucket': r.get('severity_bucket') or '',
                'cve_link': r.get('cve_link') or (f'https://nvd.nist.gov/vuln/detail/{cve}' if cve else ''),
                'hosts': set(),
            }
        else:
            # Defensive — same CVE rarely varies in CVSS across rows,
            # but keep the highest if it does.
            if score > by_pair[key]['cvss_score']:
                by_pair[key]['cvss_score'] = score
                by_pair[key]['severity_bucket'] = r.get('severity_bucket') or by_pair[key]['severity_bucket']
        by_pair[key]['hosts'].add(host)
    rows = []
    for r in by_pair.values():
        r['host_count'] = len(r['hosts'])
        # Drop the set — JSON-unfriendly + we don't need the names downstream.
        r.pop('hosts', None)
        rows.append(r)
    rows.sort(key=lambda r: (-r['cvss_score'], -r['host_count'], r['product']))
    return rows[:top_n]



def _condense(markdown: Optional[str], budget: int) -> str:
    """Trim to `budget` chars + a truncation marker. Used for the
    evidence block we feed the synthesis LLM (we'd blow the context
    window if we shovelled in every source's full report)."""
    if not markdown:
        return "*(no report content available)*"
    if len(markdown) <= budget:
        return markdown
    return markdown[:budget] + "\n\n*[…trimmed for synthesis budget; full text in Appendix A…]*"


def _build_synthesis_prompt(name, notes, loaded_sources):
    """The user-prompt body fed alongside ENGAGEMENT_SYSTEM_PROMPT.

    `loaded_sources` = list of dicts {section, run_id, name, markdown,
    metadata}. We give the LLM the section label + condensed excerpts
    grouped by section so it knows which environment each piece of
    evidence came from."""
    parts = [
        f"# Engagement: {name}",
        "",
    ]
    if (notes or '').strip():
        parts += ["## Operator notes", "", notes.strip(), ""]

    # Group by section so the LLM sees a clean per-environment view.
    by_section = {}
    for s in loaded_sources:
        by_section.setdefault(s['section'], []).append(s)

    for section in sorted(by_section.keys()):
        parts.append(f"## Source evidence: {section}")
        parts.append("")
        for s in by_section[section]:
            meta_bits = []
            md = s.get('metadata') or {}
            hostnames = md.get('hostnames') or {}
            if hostnames:
                meta_bits.append("hosts: " + ", ".join(sorted(hostnames.values()))[:200])
            sm = md.get('scan_metadata') or {}
            if sm.get('tenant_id'):
                meta_bits.append(f"tenant_id: {sm['tenant_id']}")
            if sm.get('account_id'):
                meta_bits.append(f"account_id: {sm['account_id']}")
            if md.get('time_filter'):
                meta_bits.append(f"time_filter: {md.get('time_filter')}")
            meta_line = " | ".join(meta_bits) if meta_bits else "(no extra metadata)"

            parts.append(
                f"### Source `{s['run_id']}` — {s.get('name') or '(unnamed)'}"
            )
            parts.append(f"*{meta_line}*")
            parts.append("")
            parts.append(_condense(s.get('markdown'), SOURCE_EVIDENCE_CHAR_BUDGET))
            parts.append("")
            parts.append("---")
            parts.append("")

    parts += [
        "## Your task",
        "",
        "Following the rules in the system prompt, write sections 1–4 "
        "(Executive Summary, Engagement Scope, Key Findings, Timeline of "
        "Events) plus section 9 (Recommended Next Steps) and section 10 "
        "(MITRE ATT&CK Mapping, only if any source mentioned techniques). "
        "Do not write the per-environment sections (5–7) or the IOC "
        "table (8) — those will be assembled mechanically from the "
        "source material.",
        "",
    ]
    return "\n".join(parts)


# Common public TLDs we'll accept for "Domain" IOCs. Limits false
# positives like `bob.smith` (username) or `responseElements.name`
# (JSON keypath). Easily extensible — add niche TLDs the customer
# uses if real ones get dropped.
_COMMON_TLDS = {
    # generic
    'com', 'net', 'org', 'edu', 'gov', 'mil', 'int', 'info', 'biz',
    'name', 'pro', 'aero', 'jobs', 'museum', 'travel', 'cat',
    # tech-y
    'io', 'co', 'ai', 'app', 'dev', 'cloud', 'tech', 'systems', 'tools',
    'host', 'page', 'site', 'online', 'xyz', 'me', 'sh', 'st', 'tv',
    'us', 'uk', 'eu', 'de', 'fr', 'es', 'it', 'nl', 'ch', 'se', 'no',
    'fi', 'pl', 'ru', 'br', 'mx', 'au', 'nz', 'jp', 'kr', 'cn', 'tw',
    'hk', 'sg', 'in', 'il', 'tr', 'za', 'ca', 'ar', 'cl', 'ie', 'pt',
    # cloud SaaS
    'amazonaws', 'azure', 'azurewebsites', 'cloudfront', 'cloudflare',
    # extras
    'club', 'shop', 'store', 'studio', 'agency', 'design', 'media',
    'news', 'tv', 'wiki', 'blog', 'top', 'vip',
}


# Regex tuned for the kind of indicators forensic reports typically
# mention. v1 — simple union extraction with no LLM. Sources column
# tracks which workflow(s) emitted each indicator so the IOC table
# stays auditable.
_IOC_PATTERNS = {
    'IPv4': re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
    'SHA256': re.compile(r'\b[a-fA-F0-9]{64}\b'),
    'SHA1': re.compile(r'\b[a-fA-F0-9]{40}\b'),
    'MD5': re.compile(r'\b[a-fA-F0-9]{32}\b'),
    'Domain': re.compile(r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b', re.I),
    'Email': re.compile(r'\b[\w.+-]+@[\w-]+\.[\w.-]+\b'),
}

# Indicators that would otherwise fire but are noisy garbage in the
# context of these reports (placeholder IPs, intacti.ai's own
# infrastructure, etc.). Tune as we encounter false positives.
_IOC_BLOCKLIST = {
    'IPv4': {'0.0.0.0', '127.0.0.1', '255.255.255.255', '1.1.1.1', '8.8.8.8', '169.254.169.254'},
    'Domain': {'example.com', 'localhost', 'localdomain'},
    'Email': set(),
    'SHA256': set(),
    'SHA1': set(),
    'MD5': set(),
}


def _is_obvious_pseudo_ip(ip):
    """True for IPs that are clearly network-range placeholders or
    documentation/test addresses rather than real IOCs.

    - Anything ending `.0.0.0` (network mask placeholder like
      `147.0.0.0`).
    - The RFC 5737 documentation ranges (192.0.2.0/24, 198.51.100.0/24,
      203.0.113.0/24).
    - RFC 3849 / loopback / link-local addresses (handled in the
      static blocklist above).
    """
    parts = (ip or '').split('.')
    if len(parts) != 4:
        return True
    if parts[-3:] == ['0', '0', '0']:
        return True
    if not all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return True
    # RFC 5737 documentation prefixes.
    p1, p2 = int(parts[0]), int(parts[1])
    p3 = int(parts[2])
    if (p1, p2, p3) in [(192, 0, 2), (198, 51, 100), (203, 0, 113)]:
        return True
    return False


# Domains that are cloud-service control-plane endpoints rather than
# real IOCs. Every CloudTrail log mentions these — including them in
# the engagement's IOC table is noise.
_CLOUD_DOMAIN_SUFFIXES = (
    '.amazonaws.com',
    '.cloudfront.net',
    '.azure.com',
    '.azurewebsites.net',
    '.windows.net',
    '.microsoft.com',
    '.microsoftonline.com',
    '.office.com',
    '.office365.com',
    '.outlook.com',
    '.googleapis.com',
    '.googleusercontent.com',
)

# Heading text in source reports that marks "this is a finding /
# concern / IOC block" — IOC extraction only counts indicators that
# appear under one of these headings. Skips metadata blocks where
# the same indicator might appear as noise.
_FINDING_HEADING_RE = None


def _findings_subsections(md):
    """Yield (heading_text, body) for each H2/H3 section in `md`
    whose heading looks like a finding / IOC / concern / attack
    chain block. Falls back to yielding the entire document when
    no such heading is found (rather than emitting zero IOCs for
    a source that just happens not to use those header words)."""
    import re as _re
    global _FINDING_HEADING_RE
    if _FINDING_HEADING_RE is None:
        _FINDING_HEADING_RE = _re.compile(
            r'(?im)^[ \t]*#{2,3}[ \t]+.*?\b('
            r'finding|concern|attack|indicator|ioc|detection|chain'
            r'|sigma|alert|incident|compromise|backdoor'
            r')\b',
        )
    matches = list(_FINDING_HEADING_RE.finditer(md or ''))
    if not matches:
        yield ('(entire document)', md or '')
        return
    for i, m in enumerate(matches):
        start = m.start()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(md)
        # Section text spans from this heading line to the next
        # matched heading.
        yield (m.group(0).strip(), md[start:end])


# Words that, when they appear close to an IP / hash / domain in
# the source report, signal "this indicator is attacker-attributed
# rather than infrastructure noise". An IP that only shows up in a
# CloudTrail event row without any of these nearby is probably an
# AWS service endpoint and shouldn't land in the IOC table.
_IOC_CONTEXT_KEYWORDS = (
    'attacker', 'compromise', 'compromised', 'backdoor', 'malicious',
    'suspicious', 'anomalous', 'unauthorized', 'unauthorised',
    'persistence', 'evasion', 'exfiltrat', 'lateral', 'breach',
    'phishing', 'c2', 'command and control', 'tor exit',
    'threat', 'adversary', 'intruder', 'attack chain',
    'indicator of compromise', 'ioc:', 'kill chain', 'tactic',
    # SIGMA rule names tend to include strong context too
    'sigma rule', 'rule triggered', 'detection fired',
)

# Number of characters around each indicator match we scan for
# context keywords. ~250 chars covers a typical paragraph either
# side without going so wide that unrelated text bleeds in.
_IOC_CONTEXT_WINDOW = 250


def _has_attacker_context(md_lower, match_start, match_end):
    """True iff a context keyword appears within ~250 chars of the
    indicator match. Used to filter out infrastructure IPs / domains
    that the source report mentions in routine event records but
    didn't actually flag as malicious."""
    window_start = max(0, match_start - _IOC_CONTEXT_WINDOW)
    window_end = min(len(md_lower), match_end + _IOC_CONTEXT_WINDOW)
    window = md_lower[window_start:window_end]
    return any(kw in window for kw in _IOC_CONTEXT_KEYWORDS)


def _extract_iocs(loaded_sources):
    """Regex-union over every source's markdown — but only inside
    finding-style sections of each report, AND only when the
    indicator sits near attacker-context keywords. Returns a list
    of `(type, indicator, [source_run_ids])` tuples deduped per
    (type, indicator).

    Two-layer filter: section scope (drop metadata + appendix
    blocks) + proximity to keywords like "attacker", "compromise",
    "backdoor". A CloudTrail event row that just happens to
    include an AWS infrastructure IP won't satisfy either layer.
    """
    found = {}  # (type, indicator) -> set of run_ids
    for s in loaded_sources:
        full_md = s.get('markdown') or ''
        rid = s.get('run_id', '?')
        # Concatenate every findings/IOC subsection into a single
        # text blob and run the regexes against THAT, not the whole
        # report. Falls back to the whole doc when no such sections
        # exist (better than emitting zero IOCs).
        md = "\n\n".join(body for _, body in _findings_subsections(full_md))
        md_lower = md.lower()
        for kind, pat in _IOC_PATTERNS.items():
            for m in pat.finditer(md):
                ind = m.group(0).strip()
                if ind.lower() in _IOC_BLOCKLIST.get(kind, set()):
                    continue
                # Filter out things that *look* like domains but
                # aren't (usernames like "bob.smith", SDK paths like
                # "AWS.CloudTrail", JSON keypaths like
                # "responseElements.accessKey.status"):
                #   - Require the last segment to be a known TLD.
                #     That's the strongest signal we have a real
                #     hostname vs an identifier with a dot in it.
                if kind == 'Domain':
                    tld_raw = ind.rsplit('.', 1)[-1].lower()
                    if tld_raw not in _COMMON_TLDS:
                        continue
                    # And the rest of the domain must be all-lowercase
                    # — code identifiers tend to have CamelCase
                    # segments (Application.AppId, AWS.CloudTrail).
                    if not ind.islower():
                        continue
                    # Cloud control-plane endpoints aren't IOCs.
                    # CloudTrail logs mention them in every record;
                    # treating them as indicators is pure noise.
                    ind_lower = ind.lower()
                    if any(ind_lower.endswith(sfx) for sfx in _CLOUD_DOMAIN_SUFFIXES):
                        continue

                # IPv4: drop documentation / network-range placeholders.
                if kind == 'IPv4' and _is_obvious_pseudo_ip(ind):
                    continue

                # Hash IOCs are hex strings — normalise to lowercase
                # so the same hash mentioned in upper- AND lowercase
                # in different parts of the source report dedupes
                # into one row.
                if kind in ('SHA256', 'SHA1', 'MD5'):
                    ind = ind.lower()

                # Final filter: indicator must sit near attacker-
                # context language (attacker, compromise, backdoor,
                # suspicious, …). Drops AWS infra IPs that appear
                # only inside routine event records, while keeping
                # IPs cited in the attack-chain narrative.
                if not _has_attacker_context(md_lower, m.start(), m.end()):
                    continue

                key = (kind, ind)
                found.setdefault(key, set()).add(rid)
    # Stable ordering: by type, then by indicator alphabetically.
    return sorted(
        [(k[0], k[1], sorted(rids)) for k, rids in found.items()],
        key=lambda t: (t[0], t[1]),
    )


# Regex matching the `**Severity:** Critical` style severity lines the
# per-module pipelines emit (AWS / Azure / agentic / CVE all do).
# Captures the level, case-insensitive.
_SEVERITY_LINE_RE = re.compile(
    r"\*\*Severity:\*\*\s*(critical|high|medium|low|info(?:rmational)?)",
    re.IGNORECASE,
)


def _tally_findings_severity(loaded_sources):
    """Count Critical/High/Medium/Low findings across every source's
    markdown by scanning for `**Severity:** <level>` lines (the shared
    convention the per-module pipelines emit). Returns
    {'Critical': N, 'High': N, 'Medium': N, 'Low': N, 'Informational': N}.

    Conservative — a source that uses different wording for severity
    won't contribute, but won't crash either. False positives are
    unlikely because the literal "**Severity:**" string is reserved
    for finding records by every emitter."""
    counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Informational': 0}
    for s in loaded_sources or []:
        md = s.get('markdown') or ''
        for m in _SEVERITY_LINE_RE.finditer(md):
            level = m.group(1).lower()
            if level in ('info', 'informational'):
                counts['Informational'] += 1
            else:
                counts[level.capitalize()] += 1
    return counts


def _format_severity_rollup(counts):
    """Render the tally as a one-line markdown string for the cover
    metadata, e.g. `🟥 2 · 🟧 5 · 🟨 12 · 🟩 3`. Informational is
    only shown when non-zero (most reports skip it). Returns empty
    string when every count is zero — caller can omit the row in
    that case."""
    total = sum(counts.values())
    if total == 0:
        return ''
    parts = [
        f"🟥 Critical: {counts['Critical']}",
        f"🟧 High: {counts['High']}",
        f"🟨 Medium: {counts['Medium']}",
        f"🟩 Low: {counts['Low']}",
    ]
    if counts.get('Informational', 0) > 0:
        parts.append(f"⬜ Informational: {counts['Informational']}")
    return "  ·  ".join(parts)


# Regex finding the title line that immediately precedes a Severity
# row inside a finding block. Walks back to the nearest preceding
# `### <title>` or `#### <title>` H3/H4 heading.
_FINDING_TITLE_RE = re.compile(r"(?m)^[ \t]*#{3,4}[ \t]+(.+?)\s*$")

# Captures the body of `**Evidence (FACT):** <fact text>` lines that
# per-module pipelines emit under each finding. Used by the Appendix A
# facts extractor — the "fact" body is the customer-facing nugget; the
# Interpretation / Recommended-action / Principals lines that follow
# it inside the same finding block are deliberately dropped.
_EVIDENCE_FACT_RE = re.compile(
    r"\*\*Evidence\s*(?:\(\s*FACT\s*\))?\s*:?\s*\*\*\s*(.+?)(?=\n\s*[-*]\s|\n\s*\*\*|\n{2,}|\Z)",
    re.IGNORECASE | re.DOTALL,
)
# Leading "F1 — " / "F12 — " / emoji prefix on finding titles. Stripped
# for the appendix's customer-facing rendering (the operator doesn't
# need to see internal finding IDs).
_FINDING_ID_PREFIX_RE = re.compile(r"^[^\w]*F\d+\s*[—\-:]\s*", re.UNICODE)


_AGENTIC_FINDING_RE = re.compile(
    r"\*\*Finding:\*\*\s*(?P<title>.+?)(?=\n\s*[-*]|\n{2,}|\Z)",
    re.IGNORECASE | re.DOTALL,
)
_AGENTIC_EVIDENCE_RE = re.compile(
    r"\*\*Evidence(?:\s+Source)?:?\*\*\s*(?P<evidence>.+?)(?=\n\s*[-*]\s|\n\s*\*\*|\n{2,}|\Z)",
    re.IGNORECASE | re.DOTALL,
)
_AGENTIC_SECTION_RE = re.compile(
    r"^##\s+\d+\.\s+(Critical|High|Medium|Low)\s+Findings",
    re.IGNORECASE | re.MULTILINE,
)


def _extract_source_facts(markdown: str, limit: int = 12):
    """For one source workflow's markdown, yield up to `limit` tuples of
    `(severity, finding_title, evidence_fact)` — exactly the three
    fields a customer-facing appendix should show. Everything else
    (Interpretation / Recommended action / MITRE IDs / IOCs blocks /
    Analyst notes / JSON payloads / internal section headings like
    `## __timeline__` and `## INV.*`) is dropped.

    Two source formats are handled:

    1. **Structured** (AWS / Azure / CVE pipelines): each finding has a
       `**Severity:** <level>` anchor with a nearest-preceding H3/H4
       title and a following `**Evidence (FACT):**` line. The walk
       anchors on the severity line.

    2. **Narrative** (agentic / endpoint forensics): findings live as
       bullet-list items under `## <N>. Critical|High|Medium|Low
       Findings` section headings, with `**Finding:** <title>` and
       `**Evidence Source:** <source>` sub-bullets. Severity is taken
       from the enclosing section heading.
    """
    if not markdown:
        return []
    out = []

    # --- Structured pipelines ---
    title_positions = [(m.start(), m.group(1).strip()) for m in _FINDING_TITLE_RE.finditer(markdown)]
    for sev_match in _SEVERITY_LINE_RE.finditer(markdown):
        title = ''
        for pos, t in reversed(title_positions):
            if pos < sev_match.start():
                title = t
                break
        if not title:
            continue
        clean_title = _FINDING_ID_PREFIX_RE.sub('', title).strip()
        clean_title = re.sub(r"^[\U0001F300-\U0001FAFF☀-➿⬀-⯿]\s*", '', clean_title).strip()
        window = markdown[sev_match.end(): sev_match.end() + 800]
        m_ev = _EVIDENCE_FACT_RE.search(window)
        evidence = ''
        if m_ev:
            evidence = re.sub(r"\s+", " ", m_ev.group(1)).strip()
            if len(evidence) > 320:
                evidence = evidence[:320].rstrip() + '…'
        out.append({
            'title': clean_title or title,
            'severity': sev_match.group(1).strip().capitalize(),
            'evidence': evidence,
        })
        if len(out) >= limit:
            return out

    # --- Narrative (agentic) ---
    # Walk each "Critical|High|Medium|Low Findings" section and pluck
    # the `**Finding:** <title>` + `**Evidence Source:** <src>` bullets
    # inside it. Skip if the structured walk already produced results
    # for this source — the two formats are mutually exclusive in
    # practice.
    if not out:
        section_bounds = [(m.start(), m.group(1).capitalize()) for m in _AGENTIC_SECTION_RE.finditer(markdown)]
        section_bounds.append((len(markdown), ''))
        for i, (start, sev_label) in enumerate(section_bounds[:-1]):
            end = section_bounds[i + 1][0]
            section_md = markdown[start:end]
            for f_match in _AGENTIC_FINDING_RE.finditer(section_md):
                raw_title = re.sub(r"\s+", " ", f_match.group('title')).strip().rstrip('.')
                # Look ahead ~600 chars for the Evidence Source / Evidence line.
                window = section_md[f_match.end(): f_match.end() + 600]
                evidence = ''
                m_ev = _AGENTIC_EVIDENCE_RE.search(window)
                if m_ev:
                    evidence = re.sub(r"\s+", " ", m_ev.group('evidence')).strip()
                    if len(evidence) > 320:
                        evidence = evidence[:320].rstrip() + '…'
                out.append({
                    'title': raw_title,
                    'severity': sev_label,
                    'evidence': evidence,
                })
                if len(out) >= limit:
                    return out
    return out


def _dedupe_findings_index(loaded_sources):
    """Build a cross-source finding index: for every finding-like block
    (one with a `**Severity:** X` line), capture the nearest preceding
    H3/H4 heading as the title, then merge by `(severity, title-stem)`
    across all source workflows.

    Returns a list of `(title, severity, source_run_ids, count)`
    tuples sorted by severity desc → title asc, deduped so the same
    finding hitting 5 hosts in different sources collapses to one row
    with `Seen in N sources`. Useful as a "Findings at a Glance" table
    in the engagement deliverable — the customer scans one list
    instead of paging through every source appendix."""
    SEV_RANK = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'informational': 0, 'info': 0}
    bucket = {}  # (severity, title_stem) -> set of run_ids
    for s in loaded_sources or []:
        md = s.get('markdown') or ''
        rid = s.get('run_id', '?')
        title_positions = [(m.start(), m.group(1).strip()) for m in _FINDING_TITLE_RE.finditer(md)]
        for sev_match in _SEVERITY_LINE_RE.finditer(md):
            # Walk backwards to find the nearest H3/H4 title before
            # this severity line.
            title = ''
            for pos, t in reversed(title_positions):
                if pos < sev_match.start():
                    title = t
                    break
            if not title:
                continue
            sev = sev_match.group(1).lower()
            if sev in ('info', 'informational'):
                sev = 'informational'
            # Stem the title — drop trailing source/host identifiers in
            # parens / brackets so the same rule fired on different
            # hosts dedupes ("Suspicious LSASS Access (host-a)" ==
            # "Suspicious LSASS Access (host-b)").
            stem = re.sub(r'[\(\[][^)\]]*[\)\]]\s*$', '', title).strip().lower()
            if not stem:
                continue
            bucket.setdefault((sev, stem), set()).add(rid)
    out = []
    for (sev, stem), rids in bucket.items():
        out.append((stem, sev.capitalize(), sorted(rids), len(rids)))
    out.sort(key=lambda t: (-SEV_RANK.get(t[1].lower(), 0), t[0]))
    return out


_HEAD_NUMBERED_HEADINGS = (
    ('Executive Summary',              '## 1. Executive Summary'),
    ('Engagement Scope & Methodology', '## 2. Engagement Scope & Methodology'),
    ('Engagement Scope and Methodology', '## 2. Engagement Scope & Methodology'),
    ('Engagement Scope',               '## 2. Engagement Scope & Methodology'),
    ('Attack Narrative',               '## 3. Attack Narrative'),
    ('Timeline of Events',             '## 4. Timeline of Events'),
    ('Key Findings',                   '## 5. Key Findings'),
)


def _tail_headings_for(next_ordinal):
    """Build the tail-block numbered-heading map dynamically.

    The tail contains "Recommended Next Steps" + "MITRE ATT&CK
    Mapping" — but their section numbers depend on how many
    per-environment sections preceded them (plus the §IOC section).
    On a 1-env build the tail is §8 / §9; on a 3-env build it's
    §10 / §11. Pass the starting ordinal in so the assembler can
    pin the numbers to reality."""
    rec_n = next_ordinal
    mitre_n = next_ordinal + 1
    return (
        ('Recommended Next Steps', f'## {rec_n}. Recommended Next Steps'),
        ('MITRE ATT&CK Mapping',   f'## {mitre_n}. MITRE ATT&CK Mapping'),
        ('MITRE ATT&CK',           f'## {mitre_n}. MITRE ATT&CK Mapping'),
    )


def _clean_llm_block(md, expected_headings):
    """Post-process one half of the LLM synthesis output:

    1. Strip any level-1 heading the LLM emitted (the cover page
       owns the document's only H1).
    2. For each expected H2 heading in `expected_headings`, if the
       LLM dropped the section number ("## Executive Summary"
       instead of "## 1. Executive Summary"), rewrite to the
       numbered form. Case-insensitive match, exact-ish text.

    The LLM is instructed in the system prompt to follow the
    format, but this defensive post-process means a single stray
    output doesn't make the assembled document look broken.
    """
    import re as _re
    if not md:
        return ''
    lines = md.splitlines()
    out_lines = []
    for line in lines:
        # Strip h1s outright.
        if line.lstrip().startswith('# ') and not line.lstrip().startswith('## '):
            continue
        out_lines.append(line)
    cleaned = "\n".join(out_lines).strip()
    # Replace existing H2 headings with our numbered form. The
    # heading might come with no number ("## Recommended Next
    # Steps") OR with a stale number ("## 9. Recommended Next
    # Steps" when we want §7 because only 1 env section was
    # included). Either way, replace the whole line.
    for needle, replacement in expected_headings:
        # Optional "N. " or "N) " prefix before the heading text,
        # optional bold wrapper, optional trailing colon.
        pattern = _re.compile(
            r'(?im)^[ \t]*##[ \t]+(?:\d+[.)][ \t]+)?\**' + _re.escape(needle) + r'\**[ \t]*:?[ \t]*$',
        )
        if pattern.search(cleaned):
            cleaned = pattern.sub(replacement, cleaned, count=1)
    return cleaned.strip()


def _split_synthesis(synthesis_md):
    """Split the LLM output on the `<!-- BREAK -->` marker so we can
    place §1-§4 before the per-environment sections and §9-§10 after
    the IOC table. Then post-process each half: strip H1s the LLM
    sometimes adds, and renumber any H2 the LLM forgot to prefix
    with `1. ` / `2. ` / ... so the document numbering stays
    consistent regardless of how well the model behaved."""
    md = (synthesis_md or '').strip()
    marker = '<!-- BREAK -->'
    if marker in md:
        head, tail = md.split(marker, 1)
    else:
        head, tail = md, ''
    head = _clean_llm_block(head, _HEAD_NUMBERED_HEADINGS)
    # Tail is renumbered later by `_renumber_tail` once the
    # assembler knows the actual ordinal — different number of
    # env sections changes the numbering. Just strip H1s + drop
    # bogus MITRE here.
    tail = _clean_llm_block(tail, ())
    tail, _dropped = _validate_mitre_table(tail)
    return (head, tail)


def _renumber_tail(tail_md, next_ordinal):
    """Apply the dynamic numbered-heading replacements to the tail
    block, using the ordinal that follows the last assembler-added
    section (per-env + IOCs). Called from `_assemble_markdown`."""
    return _clean_llm_block(tail_md, _tail_headings_for(next_ordinal))


# Small allowlist of MITRE ATT&CK Enterprise technique IDs the LLM
# is most likely to cite for engagements that mix endpoint + cloud
# work. Covers the techniques referenced by the agentic skill index
# + common cloud-attack techniques. Hallucinated IDs (e.g.
# T1136.003, which doesn't exist) get stripped from the §10 table
# before the report is saved, with a footnote explaining why.
#
# Keep this list pragmatic, not exhaustive — when an operator hits
# a legitimate technique we don't list, they'll see the footnote
# saying "row removed" and can extend this set.
_MITRE_ALLOWLIST = {
    # Initial Access
    'T1078', 'T1078.001', 'T1078.002', 'T1078.003', 'T1078.004',
    'T1190', 'T1133', 'T1566', 'T1566.001', 'T1566.002',
    # Execution
    'T1059', 'T1059.001', 'T1059.003', 'T1059.005', 'T1059.006',
    'T1059.007', 'T1106', 'T1204', 'T1053', 'T1053.005',
    # Persistence
    'T1136', 'T1136.001', 'T1136.002', 'T1098', 'T1098.001',
    'T1098.003', 'T1098.004', 'T1547', 'T1547.001', 'T1543',
    'T1543.003', 'T1574',
    # Privilege Escalation
    'T1068', 'T1078', 'T1548', 'T1134',
    # Defense Evasion
    'T1562', 'T1562.001', 'T1562.002', 'T1562.004', 'T1562.007',
    'T1562.008', 'T1070', 'T1070.001', 'T1070.004', 'T1027',
    'T1140', 'T1556', 'T1218', 'T1218.011',
    # Credential Access
    'T1003', 'T1003.001', 'T1003.002', 'T1003.003', 'T1003.006',
    'T1110', 'T1110.003', 'T1110.004', 'T1552', 'T1552.001',
    'T1552.004', 'T1555', 'T1539',
    # Discovery
    'T1087', 'T1087.001', 'T1087.002', 'T1087.004', 'T1018',
    'T1057', 'T1082', 'T1083', 'T1518', 'T1518.001', 'T1069',
    'T1069.001', 'T1069.002',
    # Lateral Movement
    'T1021', 'T1021.001', 'T1021.002', 'T1021.006', 'T1550',
    'T1550.001', 'T1550.002', 'T1550.003', 'T1550.004',
    # Collection
    'T1005', 'T1039', 'T1213', 'T1530',
    # Command & Control
    'T1071', 'T1071.001', 'T1071.004', 'T1573', 'T1573.001',
    'T1090', 'T1572', 'T1219',
    # Exfiltration
    'T1041', 'T1048', 'T1537',
    # Impact
    'T1486', 'T1490', 'T1485', 'T1489',
}


def _validate_mitre_table(md):
    """Walk a markdown blob and rewrite any MITRE ATT&CK table rows
    whose technique-ID column references an unknown ID. Unknown
    rows are dropped (the LLM hallucinates these often — passing
    fake IDs to the customer would be embarrassing).

    Returns (cleaned_markdown, dropped_count).

    Heuristic: any line that looks like a markdown table row
    `| ... | ... | T1xxx | ... |` and whose 3rd cell parses as a
    plausible technique ID gets validated. If invalid, the row is
    removed. If at least one row was dropped, a small note is
    appended to the §10 section.
    """
    import re as _re
    if not md or 'T1' not in md:
        return md, 0

    # Match lines that look like MITRE table rows with a T-id in
    # any cell. Keep it loose so different column orderings still
    # work.
    id_re = _re.compile(r'\bT(\d{4})(?:\.(\d{3}))?\b')
    dropped = 0
    out_lines = []
    in_mitre_table = False
    for line in md.splitlines():
        stripped = line.strip()
        if stripped.startswith('## ') and 'mitre' in stripped.lower():
            in_mitre_table = True
            out_lines.append(line)
            continue
        # Once we hit the next H2 we're out of the MITRE block.
        if in_mitre_table and stripped.startswith('## ') and 'mitre' not in stripped.lower():
            in_mitre_table = False
        if in_mitre_table and stripped.startswith('|') and 'T1' in stripped:
            # Skip table header + separator rows (no technique ID).
            ids_in_row = id_re.findall(stripped)
            if ids_in_row:
                # Reconstruct the full technique IDs we found.
                row_ids = []
                for major, sub in ids_in_row:
                    full = f"T{major}.{sub}" if sub else f"T{major}"
                    row_ids.append(full)
                # Row is valid if ALL the IDs it mentions are in the
                # allowlist. If any is bogus we drop the whole row
                # rather than risk leaking a partial fake to the
                # customer.
                if all(rid in _MITRE_ALLOWLIST for rid in row_ids):
                    out_lines.append(line)
                else:
                    dropped += 1
                continue
        out_lines.append(line)

    cleaned = "\n".join(out_lines)
    if dropped:
        cleaned = cleaned.rstrip() + (
            f"\n\n*Note: {dropped} MITRE row(s) removed because the "
            f"technique ID didn't validate against the ATT&CK Enterprise "
            f"matrix (typically a model hallucination — the analyst can "
            f"re-add them by hand or extend the allowlist in "
            f"`services/engagement/builder.py:_MITRE_ALLOWLIST`).*\n"
        )
    return cleaned, dropped


def _maybe_containment_block(notes):
    """If the operator notes describe past-tense containment actions
    (specific things the IR team / customer already did), surface
    those verbatim as the §Containment body. Otherwise return falsy
    so the assembler uses its operator-direction placeholder.

    Two-signal heuristic to avoid false positives on chatter that
    just mentions the word "containment":
    - At least TWO distinct past-tense action verbs (revoked, blocked,
      rotated, isolated, etc.).
    - At least one specific noun-anchored phrase (an account name,
      IP, host, time stamp, key, etc.) so we know the operator was
      naming concrete actions rather than discussing the concept.
    """
    if not notes:
        return ''
    lower = notes.lower()
    action_verbs = (
        ' revoked ', ' rotated ', ' blocked ', ' isolated ', ' quarantined ',
        ' reimaged ', ' restored ', ' re-enabled ', ' deleted ', ' disabled ',
        ' reset ', ' contained ',
    )
    hits = sum(1 for v in action_verbs if v in f' {lower} ')
    if hits < 2:
        return ''
    # Also require at least one specific anchor (timestamp, account
    # name, IP fragment, etc.). Loose check.
    import re as _re
    has_specific = bool(_re.search(
        r'\b(?:\d{4}-\d{2}-\d{2}|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|@|access key|user|host|tenant)\b',
        lower,
    ))
    if not has_specific:
        return ''
    return notes.strip()


def _build_source_metadata_summary(s):
    """A short one-sentence description of what's in this source's
    report — used as the body of §5/§6/§7. Pulls from the source
    workflow's `details` so it's grounded in facts, not regurgitating
    the LLM's §1 narrative.

    The aim is "metadata, not summary": the reader sees what was
    investigated by this source workflow (assets, time window, data
    types, counts) and a clear pointer to Appendix A for the full
    text. Eliminates the §1 / §3 / §5 / Appendix overlap the
    previous preview extractor created.
    """
    atype = s.get('automation_type')
    meta = s.get('metadata') or {}
    bits = []

    if atype == 'agentic':
        client_count = meta.get('client_count') or len(meta.get('client_ids') or []) or None
        hostnames = list((meta.get('hostnames') or {}).values())
        if client_count == 1 and hostnames:
            bits.append(f"endpoint forensics on `{hostnames[0]}`")
        elif client_count:
            host_list = ', '.join(f"`{h}`" for h in hostnames[:5])
            if hostnames[5:]:
                host_list += f" (+{len(hostnames) - 5} more)"
            bits.append(f"endpoint forensics across {client_count} host(s): {host_list or 'unnamed clients'}")
        else:
            bits.append("endpoint forensics")
        collection_min = meta.get('collection_minutes')
        if collection_min:
            bits.append(f"collected over a {collection_min}-minute window")
        flow_id = meta.get('flow_id') or meta.get('hunt_id')
        if flow_id:
            if isinstance(flow_id, list):
                bits.append(f"source flows: {', '.join(f'`{f}`' for f in flow_id[:3])}")
            else:
                bits.append(f"source flow: `{flow_id}`")
        blueprint = meta.get('blueprint') or meta.get('blueprint_id')
        if blueprint:
            bits.append(f"blueprint: `{blueprint}`")
        # Fallback: when none of the structured fields gave us
        # anything substantive, lean on the workflow's name so the
        # blurb doesn't read as "Scope: endpoint forensics." in
        # isolation.
        if len(bits) == 1:  # only the generic 'endpoint forensics' tag
            wf_name = (s.get('name') or '').strip()
            if wf_name:
                bits.append(f"workflow: `{wf_name}`")

    elif atype == 'aws_scan':
        sm = meta.get('scan_metadata') or {}
        acct = sm.get('account_id') or meta.get('account_id') or '(account not recorded)'
        bits.append(f"AWS account `{acct}`")
        sources = list((sm.get('sources') or meta.get('sources') or []))
        if sources:
            bits.append(f"data sources: {', '.join(sources[:6])}")
        tf = meta.get('time_filter') or sm.get('time_filter') or {}
        if isinstance(tf, dict) and tf.get('enabled'):
            mode = tf.get('mode', 'relative')
            if mode == 'between':
                bits.append(f"time range: {tf.get('start_datetime', '?')} → {tf.get('end_datetime', 'now')}")
            else:
                bits.append(f"time range: last {tf.get('relative_range', '7d')}")
        blueprint = meta.get('blueprint') or meta.get('blueprint_id')
        if blueprint:
            bits.append(f"blueprint: `{blueprint}`")

    elif atype == 'azure_scan':
        sm = meta.get('scan_metadata') or {}
        tenant = sm.get('tenant_id') or '(tenant not recorded)'
        bits.append(f"Azure tenant `{tenant}`")
        sources = list((sm.get('sources') or meta.get('sources') or []))
        if sources:
            bits.append(f"data sources: {', '.join(sources[:6])}")
        tf = meta.get('time_filter') or sm.get('time_filter') or {}
        if isinstance(tf, dict) and tf.get('enabled'):
            mode = tf.get('mode', 'relative')
            if mode == 'between':
                bits.append(f"time range: {tf.get('start_datetime', '?')} → {tf.get('end_datetime', 'now')}")
            else:
                bits.append(f"time range: last {tf.get('relative_range', '7d')}")
        blueprint = meta.get('blueprint') or meta.get('blueprint_id')
        if blueprint:
            bits.append(f"blueprint: `{blueprint}`")

    elif atype == 'cve_scan':
        # Findings counts come from the cve_scan workflow row's stash;
        # see services/cve_scan/pipeline.py which writes
        # findings_count / patched_count / unknown_count / unique_pairs.
        unique = meta.get('unique_pairs')
        vuln = meta.get('findings_count')
        patched = meta.get('patched_count')
        unknown = meta.get('unknown_count')
        inputs = meta.get('inputs_processed') or []
        bits.append("software-inventory CVE scan")
        if isinstance(vuln, int):
            counts = [f"{vuln} vulnerable"]
            if isinstance(patched, int):
                counts.append(f"{patched} patched")
            if isinstance(unknown, int):
                counts.append(f"{unknown} unknown")
            bits.append(", ".join(counts))
        if isinstance(unique, int):
            bits.append(f"{unique} unique (product, version) pairs scanned")
        if inputs:
            bits.append(f"inputs: {', '.join(inputs[:4])}")

    if not bits:
        return ''
    return "*Scope: " + "; ".join(bits) + ".*"


def _collapse_findings_by_host_cve(findings: List[Dict]) -> List[Dict]:
    """Collapse rows that share `(hostname, cve_id)` into one display
    row. This catches:
      - Sub-components of the same parent product on the same host
        that all hit the same CVE (e.g. Office Click-to-Run's
        Extensibility / Licensing / Localization Component rows all
        mapped to CVE-2025-53766 on DC1).
      - Near-duplicate inventory rows differing only by punctuation
        ("ASP.NET Core 8.0.14 - Shared Framework" vs "… Shared
        Framework") from overlapping inputs (system_programs.csv vs
        detectraptor_applications.csv).

    The remediation for both cases is identical ("patch CVE-X on host
    Y"), so showing them as N rows just inflates the table without
    adding actionable signal. Raw row-level data is preserved in
    `combined_cves.csv` from the workflow download for anyone who
    needs to audit the underlying inventory."""
    if not findings:
        return []
    groups: Dict[tuple, List[Dict]] = {}
    order: List[tuple] = []
    for f in findings:
        key = (f.get('hostname') or '(unknown)', f.get('cve_id') or '')
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(f)

    collapsed: List[Dict] = []
    for key in order:
        rows = groups[key]
        if len(rows) == 1:
            collapsed.append(rows[0])
            continue
        # Pick the highest-CVSS row as representative for severity /
        # link metadata (they're nearly always identical inside a group
        # since the CVE itself drives those fields).
        rep = max(rows, key=lambda r: float(r.get('cvss_score') or 0))
        products = [r.get('product') or '' for r in rows]
        # Longest common prefix as the display name. Strip trailing
        # whitespace and dangling punctuation so we don't show
        # "Microsoft Office 16 -" with a hanging hyphen.
        prefix = products[0]
        for p in products[1:]:
            i = 0
            limit = min(len(prefix), len(p))
            while i < limit and prefix[i] == p[i]:
                i += 1
            prefix = prefix[:i]
        display_prod = prefix.rstrip(" -–—_/.,:").strip()
        # If the prefix collapsed too aggressively (one product had
        # nothing in common with the rest), fall back to the shortest
        # full product name in the group.
        if len(display_prod) < 4:
            display_prod = min(products, key=len)
        merged = dict(rep)
        extras = len(rows) - 1
        merged['product'] = f"{display_prod} (+{extras} variant{'' if extras == 1 else 's'})"
        versions = sorted({(r.get('version') or '') for r in rows})
        merged['version'] = versions[0] if len(versions) == 1 else f"{versions[0]} (+{len(versions) - 1} more)"
        merged['_group_size'] = len(rows)
        collapsed.append(merged)

    # Re-sort by CVSS desc for stable display (groups may have shifted
    # things around if the representative wasn't the original head).
    collapsed.sort(key=lambda r: (-float(r.get('cvss_score') or 0),
                                  r.get('hostname') or '',
                                  r.get('product') or ''))
    return collapsed


def _build_vulnerabilities_section(cve_sources: List[Dict]) -> List[str]:
    """Render the Vulnerabilities table body. Reads findings.json for
    each cve_scan source and produces a per-source breakdown + a
    consolidated top-50 table. The list is bounded so a hunt with
    1000 vulnerable rows doesn't dominate the PDF — the operator can
    still pull the full CSV from the source workflow's downloads.

    Rows are collapsed by `(hostname, cve_id)` first so sibling
    sub-components of a parent product (Office Click-to-Run's
    Extensibility / Licensing / Localization Components, etc.) appear
    as a single actionable row."""
    out: List[str] = []
    severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}

    for src in cve_sources:
        raw_findings = _load_cve_findings(src['run_id'])
        meta = src.get('metadata') or {}
        out.append(f"### From `{src['run_id']}` — {src.get('name') or '(unnamed)'}")
        out.append("")
        if not raw_findings:
            out.append(
                "*No `findings.json` is on file for this scan (the run may "
                "pre-date the structured-output write, or its downloads "
                "directory was purged). Re-run the scan to regenerate.*"
            )
            out.append("")
            continue

        findings = _collapse_findings_by_host_cve(raw_findings)
        collapsed_delta = len(raw_findings) - len(findings)

        # Severity breakdown counts the COLLAPSED set so it lines up
        # with the table the operator actually sees below.
        buckets: Dict[str, int] = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        for f in findings:
            sev = (f.get('severity_bucket') or '').title()
            if sev in buckets:
                buckets[sev] += 1
        out.append("**Severity breakdown:**")
        out.append("")
        for sev in ('Critical', 'High', 'Medium', 'Low'):
            n = buckets[sev]
            if n:
                out.append(f"- {sev}: {n}")
        # Total hosts that surfaced any vulnerable finding — useful
        # one-liner without naming the hosts (per the customer-facing
        # aggregation policy: counts, not roll-call).
        host_set = {(f.get('hostname') or '(unknown)') for f in findings}
        out.append("")
        out.append(f"**Vulnerable hosts:** {len(host_set)}")

        if collapsed_delta:
            out.append("")
            out.append(
                f"*{collapsed_delta} sub-component / near-duplicate row(s) "
                f"collapsed into the {len(findings)} actionable findings before "
                f"aggregation (grouped by host + CVE).*"
            )

        # Aggregated top-N table: one row per (product, CVE) pair with
        # the count of distinct hosts that have it. Exec-friendly — the
        # operator sees what to patch + how widespread without per-host
        # noise (which is in `combined_cves.csv` if needed).
        TOP_PRODUCTS = 20
        top_rows = _top_vulnerable_products(raw_findings, top_n=TOP_PRODUCTS)
        out.append("")
        if not top_rows:
            out.append("*No (product, CVE) pairs to display.*")
            out.append("")
            continue
        out.append(f"**Top {min(TOP_PRODUCTS, len(top_rows))} vulnerable products (sorted by CVSS desc, host count tiebreaker):**")
        out.append("")
        out.append("| Hosts | Product | CVSS | CVE |")
        out.append("|---|---|---|---|")
        pipe_esc = "\\|"
        for r in top_rows:
            n_hosts = r.get('host_count', 0)
            prod = (r.get('product') or '').replace('|', pipe_esc)
            score = r.get('cvss_score') or 0
            sev = r.get('severity_bucket') or ''
            cve = r.get('cve_id') or ''
            link = r.get('cve_link') or ''
            cve_cell = f"[{cve}]({link})" if (cve and link) else (cve or '—')
            out.append(f"| {n_hosts} | {prod} | {score} {sev} | {cve_cell} |")
        out.append("")
        out.append(
            "*Full per-host detail is in `combined_cves.csv` from the CVE "
            "Scan workflow row.*"
        )
        out.append("")
    return out


def _assemble_markdown(name, notes, loaded_sources, synthesis_md, *, tlp='AMBER', version=1, customer_name='', audience='both'):
    """Glue the LLM-written synthesis layer together with the
    mechanically-assembled per-environment sections, IOC table, and
    appendix.

    `customer_name` is rendered into the cover block ("Prepared for: …").
    `audience='executive'` skips the verbatim source-reports appendix
    since exec-only readers won't need the rule-by-rule output."""
    generated_at = datetime.now().strftime('%Y-%m-%d %H:%M UTC')
    severity_counts = _tally_findings_severity(loaded_sources)
    severity_summary = _format_severity_rollup(severity_counts)
    body = [cover_block(
        name, generated_at, loaded_sources,
        tlp=tlp, version=version, customer_name=customer_name,
        severity_summary=severity_summary,
    )]

    if (notes or '').strip():
        body += ["", "## Engagement notes (operator-supplied)", "", notes.strip(), ""]

    # §1-4 from the LLM (the executive layer).
    head, tail = _split_synthesis(synthesis_md)
    body += [head, ""]

    # §5–7 (and any "Other" sections) — per-environment, in canonical
    # order. Only included when the operator picked at least one
    # source for the section. The body is the source's report
    # markdown, capped + appendix-pointered if it's enormous.
    #
    # cve_scan sources are excluded here: they get their own dedicated
    # Vulnerabilities section later (with the per-host CVE table from
    # findings.json). Otherwise they'd render twice — once as a thin
    # metadata blurb here, once with the actual table.
    by_section = {}
    for s in loaded_sources:
        if s.get('automation_type') == 'cve_scan':
            continue
        by_section.setdefault(s['section'], []).append(s)

    section_order = list(CANONICAL_SECTIONS)
    # Tack on any sections the operator named that aren't canonical.
    for sec in by_section.keys():
        if sec not in section_order:
            section_order.append(sec)

    # Track each source's Appendix A position so the per-environment
    # section can point at it rather than duplicating the full text
    # inline. cve_scan sources are skipped (their data is rendered in
    # §8 Vulnerabilities, not Appendix A) so we index over the same
    # filtered list the appendix renderer below uses.
    appendix_index = {
        s['run_id']: idx + 1
        for idx, s in enumerate(s for s in loaded_sources if s.get('automation_type') != 'cve_scan')
    }

    # Per-environment sections start at §6 in the new layout (§1-§5
    # are the LLM-written executive layer: Exec, Scope, Attack
    # Narrative, Timeline, Findings).
    ordinal = 6
    for section in section_order:
        if section not in by_section:
            continue
        body.append(section_heading(section, ordinal))
        ordinal += 1
        for s in by_section[section]:
            body.append(f"### {s.get('name') or s['run_id']}")
            body.append(f"*Source: `{s['run_id']}` — full report in Appendix A.{appendix_index.get(s['run_id'], '?')}.*")
            body.append("")
            # Use a metadata blurb (assets, time window, data sources)
            # rather than a regurgitated executive summary — the §1
            # Executive Summary already covered the findings, so a
            # second prose paragraph here would just repeat. The
            # metadata answers "what does this source workflow cover?"
            # not "what did it find?".
            meta_summary = _build_source_metadata_summary(s)
            if meta_summary:
                body.append(meta_summary)
                body.append("")

    # Indicators of Compromise — sub-categorised into Network / Host
    # / Email so each table is short enough to scan at a glance
    # (matches how professional IR firms format their IOC sections).
    iocs = _extract_iocs(loaded_sources)
    body.append(f"## {ordinal}. Indicators of Compromise")
    ordinal += 1
    body.append("")
    if not iocs:
        body.append(
            "*No indicators of compromise were extracted from the source "
            "reports. This may mean the sources don't surface raw IP / "
            "hash / domain values in findings sections, or that the "
            "incident was contained entirely at the credential / "
            "configuration layer.*"
        )
    else:
        # Group by category. Each indicator's `kind` maps to one of
        # three buckets per the typical IR firm convention.
        network_kinds = {'IPv4', 'IPv6', 'Domain', 'URL'}
        host_kinds    = {'SHA256', 'SHA1', 'MD5', 'Filename', 'Registry', 'Path'}
        email_kinds   = {'Email'}
        groups = {'Network': [], 'Host': [], 'Email': [], 'Other': []}
        for kind, ind, sources in iocs:
            if kind in network_kinds:
                groups['Network'].append((kind, ind, sources))
            elif kind in host_kinds:
                groups['Host'].append((kind, ind, sources))
            elif kind in email_kinds:
                groups['Email'].append((kind, ind, sources))
            else:
                groups['Other'].append((kind, ind, sources))

        for label, rows in groups.items():
            if not rows:
                continue
            body.append(f"### {label} indicators")
            body.append("")
            body.append("| Type | Indicator | Sources |")
            body.append("|---|---|---|")
            for kind, ind, sources in rows:
                srcs = ", ".join(f"`{r}`" for r in sources)
                ind_escaped = ind.replace('|', '\\|')
                body.append(f"| {kind} | `{ind_escaped}` | {srcs} |")
            body.append("")
    body.append("")

    # Cross-source Finding Index — same finding hitting multiple
    # sources collapses to one row with `Seen in N sources` so the
    # customer can scan one list instead of paging through every
    # appendix.
    finding_index = _dedupe_findings_index(loaded_sources)
    if finding_index:
        body.append(f"## {ordinal}. Cross-Source Finding Index")
        ordinal += 1
        body.append("")
        body.append(
            "*Findings collapsed across source workflows by (severity, "
            "title). When the same rule fired in multiple sources the "
            "row's `Sources` count reflects every workflow that "
            "surfaced it — drill into the source appendices for the "
            "per-host detail.*"
        )
        body.append("")
        body.append("| # | Severity | Finding | Sources |")
        body.append("|---|---|---|---|")
        for idx, (title, severity, sources, count) in enumerate(finding_index, 1):
            srcs = ", ".join(f"`{r}`" for r in sources)
            title_safe = (title or '').replace('|', '\\|').strip().capitalize()
            body.append(f"| {idx} | {severity} | {title_safe} | {count} ({srcs}) |")
        body.append("")

    # Containment Actions Taken — what the IR team and the customer
    # did during the engagement (separate from future
    # recommendations). Default body is a placeholder that the
    # operator fills via the Interactive chat refinement loop;
    # synthesised master prompts that mention containment work
    # will land in the next rebuild's body via the LLM's natural
    # phrasing.
    containment_body = ((notes or '').strip() and _maybe_containment_block(notes)) or (
        "*No containment actions have been documented yet. Use the "
        "Interactive chat on this engagement to add what the IR team "
        "and the customer did during the engagement — credential "
        "revocations, host isolations, logging restorations, etc. — "
        "and click Re-run to regenerate this report with those actions "
        "in scope.*"
    )
    body.append(f"## {ordinal}. Containment Actions Taken")
    body.append("")
    body.append(containment_body)
    body.append("")
    ordinal += 1

    # Vulnerabilities — software-inventory CVE table built mechanically
    # from each cve_scan source's findings.json. Sits AFTER Containment
    # but BEFORE the LLM tail so the operator sees concrete vulnerable
    # products before reading "Recommended Next Steps". Only renders
    # when at least one cve_scan source was selected for the engagement.
    cve_sources = [s for s in loaded_sources if s.get('automation_type') == 'cve_scan']
    if cve_sources:
        body.append(f"## {ordinal}. Vulnerabilities")
        ordinal += 1
        body.append("")
        body.append(
            "*Software-inventory CVE scan results (NVD matches against installed "
            "software on each host). Findings sorted by CVSS desc. Full per-row "
            "data with all severities — including patched + unknown — is in the "
            "downloadable `combined_cves.csv` from the source workflow.*"
        )
        body.append("")
        body.extend(_build_vulnerabilities_section(cve_sources))
        body.append("")

    # Renumber + append the LLM-written tail block (Recommended
    # Next Steps + MITRE Mapping). Their ordinals follow the
    # Containment section's ordinal.
    if tail:
        body += [_renumber_tail(tail, ordinal), ""]

    # Appendix A — Source workflow citations.
    #
    # Default: a tight citation table (one row per source workflow) so
    # the reader knows which runs back the analysis without us dumping
    # 700 lines of raw analyst-internal markdown into a customer-facing
    # deliverable. The full source reports remain a click away on the
    # workflow row's Report button.
    #
    # cve_scan sources are excluded from the citation list since their
    # output is already fully rendered in §12 Vulnerabilities (top
    # vulnerable products + counts).
    #
    # `audience='technical'` is the one case where we still ship the
    # verbatim raw markdown — a DFIR / SOC reader explicitly opted in
    # to the per-rule detail. Exec + Mixed audiences get the clean
    # citation table.
    appendix_sources = [s for s in loaded_sources if s.get('automation_type') != 'cve_scan']
    audience_lc = (audience or 'both').lower()
    if appendix_sources:
        if audience_lc == 'technical':
            body.append(appendix_heading())
            body.append("")
            for idx, s in enumerate(appendix_sources, 1):
                body.append(f"### A.{idx} — `{s['run_id']}` — {s.get('name') or '(unnamed)'}  *({s.get('section')})*")
                body.append("")
                body.append(s.get('markdown') or '*(no content on file)*')
                body.append("")
                body.append("---")
                body.append("")
        else:
            # Customer-facing appendix: per-source list of facts only.
            # Each finding renders as a small block with severity + the
            # title + the Evidence (FACT) line. Interpretation,
            # Recommended action, MITRE IDs, raw IOC dumps, JSON
            # payloads, Analyst notes — all dropped. The full
            # analyst-internal source markdown is one click away on the
            # workflow row in the dashboard.
            body.append("\n---\n")
            body.append("## Appendix A — Findings by Source")
            body.append("")
            body.append(
                "*Per-source list of findings: severity, title, and the "
                "evidentiary fact behind each. Interpretation, "
                "recommended actions, and raw evidence dumps live on the "
                "source workflow's full report (one click from the row "
                "on the dashboard) — they're omitted here to keep this "
                "deliverable focused on what was found, not how it was "
                "analysed.*"
            )
            body.append("")
            type_pretty = {
                'aws_scan': 'AWS Scan',
                'azure_scan': 'Azure Scan',
                'agentic': 'Endpoint Forensics',
                'timesketch': 'TimeSketch',
            }
            pipe_esc = "\\|"
            for idx, s in enumerate(appendix_sources, 1):
                rid = s.get('run_id', '?')
                name = (s.get('name') or '(unnamed)').strip()
                at = s.get('automation_type') or '?'
                at_disp = type_pretty.get(at, at)
                sec = s.get('section') or '?'
                # Avoid "AWS Scan: AWS Scan: foo" — the workflow name
                # often already starts with the type prefix.
                lowered = name.lower()
                if lowered.startswith(f"{at_disp.lower()}:") or lowered.startswith(f"{at_disp.lower()} "):
                    heading = f"### A.{idx} — {name}"
                else:
                    heading = f"### A.{idx} — {at_disp}: {name}"
                body.append(heading)
                body.append(f"*Source: `{rid}` · Section: {sec}*")
                body.append("")
                facts = _extract_source_facts(s.get('markdown') or '')
                if not facts:
                    body.append(
                        "*No structured findings extracted from this source — "
                        "see the workflow row's full report for narrative-only output.*"
                    )
                    body.append("")
                    continue
                body.append("| Severity | Finding | Evidence (Fact) |")
                body.append("|---|---|---|")
                for f in facts:
                    sev = f.get('severity') or '—'
                    title = (f.get('title') or '').replace('|', pipe_esc)
                    ev = (f.get('evidence') or '—').replace('|', pipe_esc)
                    body.append(f"| {sev} | {title} | {ev} |")
                body.append("")

    # Appendix B — Tools Used. One row per source workflow with what
    # ran. Helps the customer reproduce or audit the analysis later.
    body.append("## Appendix B — Tools & Methods")
    body.append("")
    body.append(
        "*Each source workflow's automated tooling, blueprint, and "
        "the analyst-grade detection pack(s) that ran during "
        "collection / analysis.*"
    )
    body.append("")
    body.append("| Source workflow | Tool / Pipeline | Blueprint | Notes |")
    body.append("|---|---|---|---|")
    for s in loaded_sources:
        meta = s.get('metadata') or {}
        atype = s.get('automation_type') or '?'
        if atype == 'agentic':
            tool = "IntactAI Agentic Pipeline (Velociraptor + Hayabusa + LLM analysis)"
        elif atype == 'aws_scan':
            tool = "IntactAI AWS Scan (CloudTrail + Prowler + GuardDuty + LLM)"
        elif atype == 'azure_scan':
            tool = "IntactAI Azure Scan (DFIR-O365RC + SIGMA + LLM analysis)"
        elif atype == 'cve_scan':
            tool = "IntactAI CVE Scan (Velociraptor inventory + local NVD mirror + CPE/Publisher resolver)"
        else:
            tool = "IntactAI workflow"
        blueprint = meta.get('blueprint') or meta.get('blueprint_id') or '—'
        note_bits = []
        if meta.get('anonymize_data'):
            note_bits.append("PII masking on")
        if meta.get('min_severity') and meta.get('min_severity') != 'informational':
            note_bits.append(f"min severity {meta.get('min_severity')}")
        if meta.get('cross_client_synthesis'):
            note_bits.append("cross-client macro on")
        note = "; ".join(note_bits) if note_bits else "default settings"
        body.append(f"| `{s['run_id']}` | {tool} | `{blueprint}` | {note} |")
    body.append("")

    return "\n".join(body)


def _load_all_sources(sources, log_func):
    """Resolve each source's automation_type + workflow name + load
    its markdown. Returns the enriched list ready for synthesis +
    assembly.

    Sources whose accessor returns no usable markdown (None, empty,
    or recognisable "no-report" sentinels like `{"technical": null}`)
    are dropped completely — they used to be injected with a
    placeholder string that ended up visible in the final document.
    Better to skip and emit a warning the operator can see in the
    workflow log.
    """
    loaded = []
    for src in sources:
        rid = src.get('run_id')
        section = src.get('section') or 'Other'
        if not rid:
            continue
        wf = get_workflow(rid) or {}
        atype = wf.get('automation_type') or 'unknown'
        wf_name = wf.get('name') or rid
        markdown = _load_source_report(rid, atype)
        # Defensive: even if an accessor missed a corner case and
        # returned a stringified JSON null marker, reject it here.
        if markdown and isinstance(markdown, str):
            stripped = markdown.strip()
            if stripped in ('{}', '[]', 'null', '""') or '"technical": null' in stripped or '"technical":null' in stripped:
                markdown = None
        if not markdown:
            log_func(
                f"[Engagement] Source {rid} ({atype}) has no usable report "
                f"content — skipping (the operator may want to re-run that "
                f"workflow before regenerating this engagement).",
                "warning",
            )
            continue
        loaded.append({
            'run_id': rid,
            'name': wf_name,
            'section': section,
            'automation_type': atype,
            'markdown': markdown,
            'metadata': wf.get('details') or {},
        })
    return loaded


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------


def run_engagement_build(run_id, sources, notes, llm_config):
    """Background-thread worker for `POST /api/engagement/generate`.

    `sources`: [{'run_id': str, 'section': str}, ...]
    `notes`: operator-supplied free-form engagement context (str).
    `llm_config`: shared LLM config dict.

    Mutates the workflow row's status + progress + logs throughout."""
    try:
        update_run_status(run_id, 'running', progress=5)
        add_log_to_run(run_id, f"[Engagement] Loading {len(sources)} source report(s)…", "info")
        # Enumerate the chosen sources up front so the workflow log shows
        # exactly which runs are being bundled. Useful when triaging a
        # build later — the dispatched selection is visible in the log
        # alongside the (eventual) per-source load result.
        for s in sources:
            rid = s.get('run_id', '?')
            sec = s.get('section', '?')
            add_log_to_run(run_id, f"[Engagement]   - {rid}  ({sec})", "info")
        loaded = _load_all_sources(sources, lambda m, l: add_log_to_run(run_id, m, l))
        add_log_to_run(run_id, f"[Engagement] Loaded {len(loaded)} source(s):", "info")
        # And again with the resolved automation_type + name now that
        # the loader has filled them in — confirms which inputs actually
        # produced usable markdown.
        for s in loaded:
            at = s.get('automation_type', '?')
            rid = s.get('run_id', '?')
            sec = s.get('section', '?')
            name = (s.get('name') or '').strip() or '(unnamed)'
            add_log_to_run(run_id, f"[Engagement]   - {at}  {rid}  →  {sec}  ·  {name}", "info")
        if not loaded:
            raise RuntimeError("No usable source workflows — every selected run had empty or unreadable reports.")
        update_run_status(run_id, 'running', progress=25)

        # Pull operator-supplied master prompt (set by interactive chat)
        # if there is one. On a brand-new engagement build it's None;
        # on a re-run via the chat, it's the synthesised brief.
        wf = get_workflow(run_id) or {}
        details = wf.get('details') or {}
        master_prompt = (details.get('master_prompt') or '').strip() or None
        audience = (details.get('audience') or 'both').lower()
        language = (details.get('language') or 'en').lower()
        customer_name = (details.get('customer_name') or '').strip()

        add_log_to_run(run_id, "[Engagement] Synthesising executive narrative with LLM…", "info")
        update_run_status(run_id, 'running', progress=40)
        synthesis_md = _synthesise_executive(
            run_id, sources_data=loaded, notes=notes, llm_config=llm_config,
            master_prompt=master_prompt, audience=audience, language=language,
        )
        update_run_status(run_id, 'running', progress=80)

        # Engagement name comes from the workflow row's name (the user
        # entered it when creating the build).
        name = (wf.get('name') or 'Engagement Report')
        tlp = details.get('tlp') or 'AMBER'
        version = int(details.get('report_version') or 1)
        add_log_to_run(run_id, "[Engagement] Assembling final markdown document…", "info")
        final_md = _assemble_markdown(
            name, notes, loaded, synthesis_md,
            tlp=tlp, version=version, customer_name=customer_name, audience=audience,
        )
        update_run_status(run_id, 'running', progress=95)

        # Save under the same shape the AWS/Azure download endpoint
        # expects: a JSON blob with a 'technical' key.
        save_report(run_id, json.dumps({'technical': final_md}))

        # Stash per-engagement details so the UI can show them later
        # without re-loading sources.
        _wf = get_workflow(run_id)
        if _wf:
            _wf_details = _wf.get('details') or {}
            _wf_details['sources'] = [{'run_id': s['run_id'], 'section': s['section'], 'automation_type': s['automation_type']} for s in loaded]
            _wf_details['notes'] = notes or ''
            _wf_details['has_report'] = True
            _wf_details['llm_enabled'] = True
            _wf['details'] = _wf_details
            save_workflow(_wf)

        update_run_status(run_id, 'completed', progress=100, force=True)
        add_log_to_run(run_id, "[Engagement] Complete.", "success")
    except Exception as e:
        import traceback as _tb
        _tb.print_exc()
        add_log_to_run(run_id, f"[Engagement] Build failed: {e}", "error")
        update_run_status(run_id, 'failed', error=str(e))


def _synthesise_executive(run_id, sources_data, notes, llm_config, master_prompt=None, audience='both', language='en'):
    """One LLM call producing the executive layer (§1–§4 + §9 + §10).

    When `master_prompt` is set (operator used the chat refinement
    loop), it's prepended to the system prompt so the LLM treats the
    operator's notes as ground truth. Same pattern the agentic /
    AWS / Azure pipelines use for chat-driven re-runs.

    `audience` and `language` append a small tailoring directive
    (audience: executive/technical/both; language: en/he). Defaults
    preserve the previous behaviour for back-compat with old runs."""
    system_prompt = ENGAGEMENT_SYSTEM_PROMPT
    directive = audience_language_directive(audience=audience, language=language)
    if directive:
        system_prompt = system_prompt + "\n\n" + directive
    if master_prompt:
        system_prompt = (
            "## OPERATOR CONTEXT (from interactive validation)\n"
            "The analyst has reviewed a prior version of this engagement "
            "report and provided the following corrections + priorities. "
            "Treat them as ground truth and adjust your writing "
            "accordingly — downweight or remove findings the analyst "
            "marked as false-positive / known-legitimate, surface and "
            "deepen any areas they asked you to focus on, incorporate "
            "any environment context they shared.\n\n"
            f"{master_prompt.strip()}\n\n---\n\n"
        ) + system_prompt
        add_log_to_run(run_id, "[Engagement] Master prompt applied to synthesis", "info")

    user_prompt = _build_synthesis_prompt(
        name=(get_workflow(run_id) or {}).get('name') or 'Engagement',
        notes=notes,
        loaded_sources=sources_data,
    )

    body = call_llm(user_prompt, system_prompt, llm_config, run_id=run_id)
    if not body or not isinstance(body, str):
        raise RuntimeError(f"Engagement synthesis LLM returned unexpected type: {type(body).__name__}")
    return body.strip()


def run_engagement_reanalyze(run_id, master_prompt, llm_config, scope='reports_only'):
    """Rebuild the engagement report with the operator's master prompt
    threaded into the synthesis LLM. Reuses the sources stored on the
    workflow row from the original build — no source-picker UX during
    a re-run.

    For engagement reports the two scopes collapse: there's only one
    LLM call (the synthesis), so `reports_only` and `full` both
    regenerate the same thing. We accept the param for symmetry with
    AWS/Azure but ignore it.
    """
    wf = get_workflow(run_id) or {}
    details = wf.get('details') or {}
    sources_meta = details.get('sources') or []
    notes = details.get('notes') or ''
    if not sources_meta:
        raise RuntimeError("No source workflows on file for this engagement — cannot re-run.")

    add_log_to_run(run_id, f"[Engagement] Re-running with master prompt ({len(sources_meta)} source(s))", "info")
    for s in sources_meta:
        at = s.get('automation_type', '?')
        rid = s.get('run_id', '?')
        sec = s.get('section', '?')
        add_log_to_run(run_id, f"[Engagement]   - {at}  {rid}  →  {sec}", "info")
    update_run_status(run_id, 'running', progress=15)

    # Reload sources fresh — the operator may have re-run one of them
    # between the original build and this re-run.
    src_list = [{'run_id': s['run_id'], 'section': s['section']} for s in sources_meta]
    loaded = _load_all_sources(src_list, lambda m, l: add_log_to_run(run_id, m, l))
    if not loaded:
        raise RuntimeError("All source workflows became unreadable since the original build.")
    add_log_to_run(run_id, f"[Engagement] Reloaded {len(loaded)} source(s):", "info")
    for s in loaded:
        at = s.get('automation_type', '?')
        rid = s.get('run_id', '?')
        sec = s.get('section', '?')
        name = (s.get('name') or '').strip() or '(unnamed)'
        add_log_to_run(run_id, f"[Engagement]   - {at}  {rid}  →  {sec}  ·  {name}", "info")

    update_run_status(run_id, 'running', progress=40)
    audience = (details.get('audience') or 'both').lower()
    language = (details.get('language') or 'en').lower()
    customer_name = (details.get('customer_name') or '').strip()
    synthesis_md = _synthesise_executive(
        run_id, sources_data=loaded, notes=notes, llm_config=llm_config,
        master_prompt=master_prompt, audience=audience, language=language,
    )
    update_run_status(run_id, 'running', progress=80)

    name = wf.get('name') or 'Engagement Report'
    tlp = details.get('tlp') or 'AMBER'
    # On a re-run, bump the version so the Document History row
    # reads as a revision rather than the initial build.
    prior_version = int((wf.get('details') or {}).get('report_version') or 1)
    version = prior_version + 1
    # Persist the bumped version back so subsequent reads (UI,
    # next re-run) see the new number.
    try:
        from services.file_storage_service import get_workflow as _get_wf, save_workflow as _save_wf
        _wf_bump = _get_wf(run_id)
        if _wf_bump:
            _wfd = _wf_bump.get('details') or {}
            _wfd['report_version'] = version
            _wf_bump['details'] = _wfd
            _save_wf(_wf_bump)
    except Exception:
        pass
    add_log_to_run(run_id, f"[Engagement] Reassembling final markdown (v{version})…", "info")
    final_md = _assemble_markdown(
        name, notes, loaded, synthesis_md,
        tlp=tlp, version=version, customer_name=customer_name, audience=audience,
    )
    save_report(run_id, json.dumps({'technical': final_md}))
    update_run_status(run_id, 'running', progress=95)
