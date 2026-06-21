#!/usr/bin/env python3
"""
IRIS Service - DFIR-IRIS integration for case management, timeline, and IOC import.

Integrates with DFIR-IRIS v2.x API for:
- Creating cases
- Importing timeline events
- Importing IOCs extracted from reports

Note: IRIS v2.x uses /manage/ prefix for API endpoints and API key authentication.
"""

import os
import re
import json
import traceback
import requests
import urllib3
from datetime import datetime
from typing import Dict, List, Any, Optional, Callable

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def extract_ioc_context(report_content: str, ioc_value: str, ioc_type: str = None) -> str:
    """Extract context explaining WHY this IOC is malicious and WHERE it was found.

    Searches for the IOC in the report and finds:
    1. The section/artifact header it appears under
    2. Any analysis text near it explaining why it's suspicious

    Args:
        report_content: Full technical report text
        ioc_value: The IOC value (IP, hash, domain)
        ioc_type: Type of IOC (ip, md5, sha1, sha256, domain)

    Returns:
        Detailed description or None if no context found
    """
    # Split report into lines for easier section detection
    lines = report_content.split('\n')
    ioc_lower = ioc_value.lower()

    # Find all lines containing this IOC
    ioc_line_indices = []
    for i, line in enumerate(lines):
        if ioc_lower in line.lower():
            ioc_line_indices.append(i)

    if not ioc_line_indices:
        return None

    best_context_parts = []
    found_section = None
    found_artifact = None

    for line_idx in ioc_line_indices:
        # Search backwards for nearest header (section context)
        for i in range(line_idx, max(0, line_idx - 30), -1):
            line = lines[i]
            if line.startswith('#'):
                # Found a header - extract section name
                header = line.lstrip('#').strip()
                if not found_section:
                    found_section = header
                # Check if it's an artifact name
                artifact_keywords = ['amcache', 'prefetch', 'browser', 'persistence',
                                   'detection', 'hayabusa', 'network', 'rdp', 'registry',
                                   'event', 'lnk', 'scheduled', 'dns']
                for kw in artifact_keywords:
                    if kw in header.lower():
                        found_artifact = header
                        break
                break

        # Get the line containing the IOC and surrounding lines
        start_idx = max(0, line_idx - 2)
        end_idx = min(len(lines), line_idx + 3)
        context_lines = lines[start_idx:end_idx]

        # Look for analysis keywords in nearby lines
        analysis_keywords = ['suspicious', 'malicious', 'indicates', 'suggests',
                           'evidence', 'executed', 'connected', 'downloaded',
                           'attack', 'compromise', 'threat', 'C2', 'callback']

        for ctx_line in context_lines:
            # Skip table rows and empty lines
            stripped = ctx_line.strip()
            if not stripped or stripped.startswith('|') or stripped.startswith('---'):
                continue

            ctx_lower = ctx_line.lower()
            if any(kw in ctx_lower for kw in analysis_keywords):
                # Found analysis text
                cleaned = stripped.lstrip('-•*').strip()
                if cleaned and len(cleaned) > 20 and cleaned not in best_context_parts:
                    best_context_parts.append(cleaned)

    # Build description
    description_parts = []

    if found_artifact:
        description_parts.append(f"Source: {found_artifact}.")
    elif found_section:
        description_parts.append(f"Found in: {found_section}.")

    if best_context_parts:
        # Join context parts, limit total length
        context_text = ' '.join(best_context_parts)
        # Clean markdown
        context_text = context_text.replace('**', '').replace('`', '').replace('*', '')
        if len(context_text) > 350:
            truncate_at = context_text.rfind('. ', 0, 350)
            if truncate_at > 150:
                context_text = context_text[:truncate_at + 1]
            else:
                context_text = context_text[:347] + '...'
        description_parts.append(context_text)

    if description_parts:
        return ' '.join(description_parts)

    return None


def parse_iocs_from_report(report_content: str) -> List[dict]:
    """Extract IOCs from technical report content.

    First parses the "Indicators of Compromise" table which has Context descriptions.
    Then falls back to regex extraction for any IOCs not in the table.

    Args:
        report_content: Markdown report text

    Returns:
        List of IOC dicts with type, value, and description
    """
    iocs = []
    seen = set()  # Avoid duplicates

    # Skip well-known safe IPs only. Domain filtering is intentionally NOT
    # done here — if a domain made it into the LLM's IOC table, the LLM
    # (or upstream Velociraptor detection rules) flagged it for a reason.
    # Second-guessing those signals leads to discarding real findings.
    SAFE_IPS = {'127.0.0.1', '0.0.0.0', '8.8.8.8', '1.1.1.1', '255.255.255.255'}

    # IOC type mapping to IRIS type IDs
    TYPE_MAP = {
        'ip': 76, 'ip address': 76, 'ipv4': 76,
        'md5': 90, 'md5 hash': 90,
        'sha1': 111, 'sha1 hash': 111,
        'sha256': 113, 'sha256 hash': 113,
        'domain': 20, 'fqdn': 20,
        'hash': 90,  # Default to MD5 for generic "hash"
        'file path': 118, 'path': 118, 'filepath': 118,
        'url': 141,
        'command': 1, 'cmd': 1,
        'registry': 118, 'registry key': 118,
    }

    # STEP 0: Parse consolidated IOC table (new format)
    # Format: | Name | Details | Hashes | Source | Why Suspicious |
    # Example: | AdFind.exe | Path: C:\path\ | MD5:abc SHA1:def SHA256:ghi | DetectRaptor | AD tool |
    # Example: | svchost.exe | PID: 1234 | N/A | Netstat | Suspicious connection |

    in_ioc_section = False
    ioc_section_depth = 0
    for line in report_content.split('\n'):
        line_lower = line.lower()
        if 'indicator' in line_lower and 'compromise' in line_lower:
            in_ioc_section = True
            # remember the depth (number of leading #) so we only close on a
            # sibling/parent heading. Sub-sections like "### 4.1 Files &
            # Executables" sit under "## 4. Indicators of Compromise" — those
            # are part of the IOC tables, not a section break.
            stripped = line.lstrip()
            ioc_section_depth = len(stripped) - len(stripped.lstrip('#'))
            continue
        if in_ioc_section and line.startswith('#'):
            stripped = line.lstrip()
            depth = len(stripped) - len(stripped.lstrip('#'))
            # Close only on a heading at the same depth or shallower than the
            # opening "## 4. Indicators..." heading. Deeper sub-headings stay
            # inside.
            if depth <= ioc_section_depth and 'indicator' not in line_lower:
                in_ioc_section = False

        if in_ioc_section and '|' in line:
            parts = [p.strip() for p in line.split('|')]
            parts = [p for p in parts if p]

            # Check for consolidated format: | Name | Details | Hashes | Source | Why |
            # Detect by: has 4+ columns AND (has hash pattern in col 3 OR has "N/A" in col 3)
            if len(parts) >= 4:
                name = re.sub(r'[`*]', '', parts[0]).strip()
                # Strip URL prefixes the LLM may have included. Markdown
                # rendering / IRIS UI mangles ":/" into "--" downstream so
                # values arrive looking like "https--track.example.com".
                # Normalise both shapes to the bare hostname so the dedup
                # key + safe-domain check work.
                name = re.sub(r'^https?(://|--)', '', name, flags=re.IGNORECASE).strip()
                # Drop any trailing path so "wolt.com/track" -> "wolt.com"
                name = name.split('/', 1)[0]
                details = re.sub(r'[`*]', '', parts[1]).strip() if len(parts) > 1 else ''
                hashes_str = parts[2] if len(parts) > 2 else ''
                source = re.sub(r'[`*]', '', parts[3]).strip() if len(parts) > 3 else ''
                why = re.sub(r'[`*]', '', parts[4]).strip() if len(parts) > 4 else ''

                # Skip header rows
                if name.lower() in ('name', 'file name', 'type', '---', ''):
                    continue
                if 'details' in details.lower() and 'hashes' in hashes_str.lower():
                    continue

                # A row counts as a consolidated file IOC if its hash column:
                #   - has labelled hashes ("SHA256: <hash>") — original format
                #   - is a bare hash (32/40/64 hex chars) — what the report writer
                #     actually emits in section 4.1's SHA256 column
                #   - is the literal "N/A" / "Not provided" / "(not provided)" —
                #     row is still useful (filename + path + MITRE) even without
                #     a hash; we'll pull it through with no SHA256 component.
                has_labelled = re.search(r'(MD5|SHA1|SHA256):', hashes_str, re.I)
                bare_hash_match = re.search(r'\b([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})\b',
                                            hashes_str, re.I)
                hashes_norm = hashes_str.strip().upper().strip('()').strip()
                is_missing = hashes_norm in ('N/A', 'NOT PROVIDED', '-', '')
                is_consolidated = bool(has_labelled or bare_hash_match or is_missing)

                if is_consolidated and name and len(name) > 2:
                    # Parse hashes from "MD5:xxx SHA1:yyy SHA256:zzz"
                    md5_match = re.search(r'MD5:([a-f0-9]{32})', hashes_str, re.I)
                    sha1_match = re.search(r'SHA1:([a-f0-9]{40})', hashes_str, re.I)
                    sha256_match = re.search(r'SHA256:([a-f0-9]{64})', hashes_str, re.I)
                    # Fall back to bare hashes (no inline label) — the report
                    # writer's section 4.1 emits "<hash>" not "SHA256:<hash>".
                    if not (md5_match or sha1_match or sha256_match) and bare_hash_match:
                        bare = bare_hash_match.group(1).lower()
                        if len(bare) == 32:
                            md5_match = re.match(r'(.+)', bare)
                        elif len(bare) == 40:
                            sha1_match = re.match(r'(.+)', bare)
                        elif len(bare) == 64:
                            sha256_match = re.match(r'(.+)', bare)

                    # Surface the additional hash variants (md5/sha1) in
                    # Evidence so an analyst sees them next to the row even
                    # though only sha256 ends up in the IOC value (composite
                    # filename|sha256). The IOC's primary identity is the
                    # composite or the bare name; this is supporting context.
                    extra_hashes = []
                    if md5_match:
                        extra_hashes.append(f"MD5={md5_match.group(1).lower()}")
                    if sha1_match:
                        extra_hashes.append(f"SHA1={sha1_match.group(1).lower()}")
                    if sha256_match:
                        extra_hashes.append(f"SHA256={sha256_match.group(1).lower()}")

                    why_clean = why if (why and why.upper() != 'N/A') else None
                    details_clean = details if (details and details.upper() != 'N/A') else None
                    # Path / file-system location goes into Evidence; MITRE
                    # technique IDs (column 4 in section 4.1) get their own
                    # canonical field. The analyst sees "where was this seen"
                    # without us inventing custom fields.
                    evidence_bits = []
                    if details_clean:
                        evidence_bits.append(f"path={details_clean}")
                    evidence_bits.extend(extra_hashes)
                    # MITRE column may be "T1003.001" or "T1003.001, T1059.001"
                    # or "N/A" / blank — extract any T#### IDs the LLM emitted.
                    mitre_ids = re.findall(r'\bT\d{4}(?:\.\d{3})?\b',
                                           source if source else '')
                    # One Why sentence that explains why this is an IOC.
                    # The classification (why_clean) is the analyst's label
                    # ("Monitoring evasion", "Credential dumper"); we add
                    # MITRE/path context so the row is self-contained.
                    why_bits = [why_clean] if why_clean else [
                        "Surfaced in the report's curated IOC table"
                    ]
                    if mitre_ids:
                        why_bits.append("MITRE " + ", ".join(mitre_ids))
                    if details_clean:
                        why_bits.append(f"observed at {details_clean}")
                    why_text = " — ".join(why_bits)

                    canonical_desc = _format_ioc_description(
                        artifact="Forensic Analysis Report",
                        why=why_text,
                        evidence="; ".join(evidence_bits) if evidence_bits else None,
                        mitre=mitre_ids if mitre_ids else None,
                    )

                    # Determine IOC type - use filename|sha256 composite when we have SHA256
                    name_lower = name.lower()

                    # File-like extensions — extended set so "sysmonconfig.xml",
                    # "config.json", etc. don't get mis-classified as domains
                    # by the trailing-dot regex.
                    is_file_ioc = re.search(
                        r'\.(exe|dll|ps1|bat|cmd|vbs|js|msi|scr|sys|zip|rar|7z|'
                        r'xml|json|yaml|yml|conf|cfg|ini|reg|hive|evtx|log|'
                        r'dmp|raw|bin|dat|tmp|lnk|hta|chm|jar|py|sh)$',
                        name_lower,
                    )
                    is_domain = re.match(r'^[a-z0-9.-]+\.[a-z]{2,}$', name_lower) and not is_file_ioc
                    is_ip = re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', name)

                    # Build dedup key
                    if sha256_match:
                        dedup_key = f"{name}|{sha256_match.group(1)}".lower()
                    else:
                        dedup_key = name_lower

                    if dedup_key not in seen:
                        seen.add(dedup_key)

                        # Use filename|sha256 composite type when we have SHA256 for files
                        if sha256_match and (is_file_ioc or (not is_domain and not is_ip)):
                            sha256_hash = sha256_match.group(1).lower()
                            composite_value = f"{name}|{sha256_hash}"
                            iocs.append({
                                'type': 'filename|sha256',
                                'type_id': 46,
                                'value': composite_value,
                                'description': canonical_desc
                            })
                        elif is_domain:
                            # NO safe-domain filtering on the LLM-curated
                            # path. If the LLM (or Velociraptor's detection
                            # rules upstream) flagged this domain, it has
                            # context we don't — trust it and push.
                            iocs.append({
                                'type': 'domain',
                                'type_id': 20,
                                'value': name,
                                'description': canonical_desc
                            })
                        elif is_ip:
                            iocs.append({
                                'type': 'ip',
                                'type_id': 76,
                                'value': name,
                                'description': canonical_desc
                            })
                        # Skip plain filenames without SHA256 - they would create duplicates

                        # Add all hashes and filename to seen to prevent duplicates
                        seen.add(name_lower)
                        if md5_match:
                            seen.add(md5_match.group(1).lower())
                        if sha1_match:
                            seen.add(sha1_match.group(1).lower())
                        if sha256_match:
                            seen.add(sha256_match.group(1).lower())

                    continue  # Skip to next line, don't process with old parser

    # STEP 1: Parse the IOC table from the report (legacy format)
    # Format: | Type | Value | Artifact Source | Timestamp | Why IOC |
    # Or old: | Type | Value | Context | Severity | (still supported)

    in_ioc_section = False
    ioc_section_depth = 0
    for line in report_content.split('\n'):
        line_lower = line.lower()
        if 'indicator' in line_lower and 'compromise' in line_lower:
            in_ioc_section = True
            stripped = line.lstrip()
            ioc_section_depth = len(stripped) - len(stripped.lstrip('#'))
            continue
        # Same depth-aware close logic as STEP 0 — sub-headings stay inside.
        if in_ioc_section and line.startswith('#'):
            stripped = line.lstrip()
            depth = len(stripped) - len(stripped.lstrip('#'))
            if depth <= ioc_section_depth and 'indicator' not in line_lower:
                in_ioc_section = False

        if in_ioc_section and '|' in line:
            # Split by pipe and clean up
            parts = [p.strip() for p in line.split('|')]
            parts = [p for p in parts if p]  # Remove empty parts

            if len(parts) >= 3:
                ioc_type_raw = parts[0].lower()
                ioc_value = parts[1]

                # Skip header row and separator
                if 'type' in ioc_type_raw and ('value' in parts[1].lower() or 'artifact' in str(parts).lower()):
                    continue
                if '---' in ioc_type_raw or '---' in ioc_value:
                    continue

                # Clean up markdown formatting: **text**, `text`, *text*
                ioc_type_raw = re.sub(r'\*+', '', ioc_type_raw).strip()
                ioc_value = re.sub(r'[`*]', '', ioc_value).strip()

                # Extract columns based on format (new 5-col or old 4-col)
                artifact_source = ''
                timestamp = ''
                why_ioc = ''
                context = ''

                if len(parts) >= 5:
                    # New format: Type | Value | Artifact Source | Timestamp | Why IOC
                    artifact_source = re.sub(r'[`*]', '', parts[2]).strip()
                    timestamp = re.sub(r'[`*]', '', parts[3]).strip()
                    why_ioc = re.sub(r'[`*]', '', parts[4]).strip()
                elif len(parts) >= 4:
                    # 4-col format: Type | Value | Context | <Classification|Severity>
                    # Classification (e.g. "C2/Staging") and Severity (e.g.
                    # "HIGH") both land here; we don't know which without
                    # reading the LLM's mind, so just join with a separator.
                    context = re.sub(r'[`*]', '', parts[2]).strip()
                    tail = re.sub(r'[`*]', '', parts[3]).strip()
                    why_ioc = f"{context} — {tail}" if (context and tail) else (context or tail)
                elif len(parts) >= 3:
                    context = re.sub(r'[`*]', '', parts[2]).strip()
                    why_ioc = context

                # Determine IOC type - MUST match a known type.
                # Word-bounded match so "script" doesn't match key "ip"
                # (the substring 'ip' inside 'script' bit us — produced
                # `In-memory execution` as a type=ip IOC). Lower-cased
                # because the report writer emits "Domain" / "IP" with
                # capitalisation while TYPE_MAP keys are lowercase.
                ioc_type = None
                type_id = None
                ioc_type_lower = ioc_type_raw.lower()
                for key, tid in TYPE_MAP.items():
                    if re.search(rf'\b{re.escape(key)}\b', ioc_type_lower):
                        ioc_type = key.split()[0]  # Get first word (ip, md5, etc.)
                        type_id = tid
                        break

                # Skip if no recognized IOC type (prevents trash entries)
                if type_id is None:
                    continue

                # Skip individual hash rows - hashes should be in consolidated file IOCs
                if ioc_type in ('md5', 'sha1', 'sha256', 'hash'):
                    continue

                # Skip file path IOCs - we use filename|sha256 composite instead
                # File paths create duplicates and type_id 118 may not exist in IRIS
                if ioc_type in ('file', 'path', 'filepath', 'registry'):
                    continue

                # Validate and add IOC
                if ioc_value and ioc_value.lower() not in seen and len(ioc_value) > 3:
                    # Skip if it looks like a header
                    if ioc_value.lower() in ('value', 'context', 'type', 'severity', 'artifact', 'timestamp', 'why'):
                        continue
                    seen.add(ioc_value.lower())

                    # Canonical description shape — see _format_ioc_description.
                    junk = ('artifact source', 'source', 'timestamp', 'why ioc',
                            'why', '-', 'n/a', '')
                    artifact_clean = (artifact_source if artifact_source and
                                      artifact_source.lower() not in junk else None)
                    timestamp_clean = (timestamp if timestamp and
                                       timestamp.lower() not in junk else None)
                    why_clean = (why_ioc if why_ioc and
                                 why_ioc.lower() not in junk else None)

                    iocs.append({
                        'type': ioc_type or 'other',
                        'type_id': type_id,
                        'value': ioc_value,
                        'description': _format_ioc_description(
                            artifact=(artifact_clean or "Forensic Analysis Report"),
                            why=(why_clean
                                 or "Surfaced in the report's network-indicators table"),
                            found=timestamp_clean,
                        ),
                    })

    # STEP 2: Regex-fallback extraction is INTENTIONALLY DISABLED.
    #
    # The previous regex-fallback walked the LLM's narrative report text and
    # pattern-matched anything `.com/.io/.org`-shaped (or four dotted octets).
    # In production runs this pulled in:
    #   - .NET namespace text:  "system.io"
    #   - version numbers:      "1.0.31.15"  (Lenovo update version)
    #   - mangled URL prefixes: "https--track.wolt.com"
    #   - background brand mentions: facebook.com, win-rar.com, crowdstrike.com
    # Filtering these via SAFE_DOMAINS / SAFE_IPS is whack-a-mole and the
    # noise dwarfs the signal. The LLM-curated structured IOC table (parsed
    # in STEP 0 above) and the timeline-derived IOCs from
    # extract_iocs_from_timeline are the only paths that have intent behind
    # them. Trust those; abandon the regex scrape.
    #
    # If a future workload needs regex IOCs, gate them behind an explicit
    # flag and add a strong "appears in a network-context line" filter
    # (e.g., near "GET ", "POST ", "Connection to", or an explicit IP field
    # name). Until then, the consolidated table is the source of truth.

    # Hash regex extraction was already disabled — kept the comment for
    # historical reference.
    # # MD5 hashes (32 hex chars)
    # md5_pattern = r'\b[a-fA-F0-9]{32}\b'
    # for match in re.finditer(md5_pattern, report_content):
    #     hash_val = match.group().lower()
    #     if hash_val not in seen:
    #         seen.add(hash_val)
    #         iocs.append({'type': 'md5', 'type_id': 90, 'value': hash_val, 'description': 'MD5 hash from forensic analysis'})

    # Disabled — see STEP 2 comment above.
    if False:
        # IPv4 addresses
        ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        for match in re.finditer(ip_pattern, report_content):
            ip = match.group()
            if ip not in seen and ip not in SAFE_IPS:
                # Skip internal/private ranges for IOCs
                if not (ip.startswith('10.') or ip.startswith('192.168.') or
                        ip.startswith('172.16.') or ip.startswith('172.17.') or
                        ip.startswith('169.254.')):
                    seen.add(ip)
                    context = extract_ioc_context(report_content, ip, 'ip')
                    iocs.append({
                        'type': 'ip',
                        'type_id': 76,
                        'value': ip,
                        'description': context or 'External IP address identified in network/connection artifacts during forensic analysis'
                    })
        # Domains (basic pattern - look for domain-like strings)
        domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|ru|cn|tk|xyz|top|info|biz|cc|pw)\b'
        for match in re.finditer(domain_pattern, report_content, re.IGNORECASE):
            domain = match.group().lower()
            if domain in seen:  # _is_safe_domain removed — dead code path anyway
                continue
            seen.add(domain)
            context = extract_ioc_context(report_content, domain, 'domain')
            if not context:
                desc_parts = [f"**Domain:** {domain}"]
                lines = report_content.split('\n')
                for i, line in enumerate(lines):
                    if domain in line.lower():
                        context_window = '\n'.join(lines[max(0,i-3):min(len(lines),i+4)])
                        tool_refs = re.findall(r'(\w+\.exe|\w+\.dll)', context_window, re.I)
                        if tool_refs:
                            desc_parts.append(f"**Associated with:** {', '.join(set(tool_refs))}")
                        break
                desc_parts.append("**Action:** Check reputation on VirusTotal, URLhaus, or threat feeds")
                context = '\n'.join(desc_parts)
            iocs.append({
                'type': 'domain',
                'type_id': 20,
                'value': domain,
                'description': context
            })

    return iocs


# ---------------------------------------------------------------------------
# Per-artifact LLM JSON IOC extraction
#
# The atomic-phase analyzer attaches a structured JSON block to each
# per-artifact summary (see services/agentic/analyzers.py). It's the
# highest-fidelity IOC source we have: each finding carries severity,
# confidence, evidence text, and MITRE tags, and bare iocs.* lists what
# the model considered noteworthy beyond the enumerated findings.
# ---------------------------------------------------------------------------

_IRIS_TYPE_IDS = {"ip": 76, "domain": 20, "md5": 90, "sha1": 111, "sha256": 113}


def _format_ioc_description(
    *,
    artifact,                       # str | list[str] | tuple — rendered comma-joined
    why: Optional[str],
    severity: Optional[str] = None,
    confidence: Optional[str] = None,
    evidence: Optional[str] = None,
    mitre=None,
    found: Optional[str] = None,
    # Accepted-and-ignored for backward compat with callers that still
    # pass `source=` or `reason=`. Both used to render a separate line;
    # we collapsed source into the **Source:** artifact list and folded
    # reason into **Why:**, so neither has a render path now.
    source: Optional[str] = None,
    reason: Optional[str] = None,
) -> str:
    """Canonical IOC description shape used by every IOC extractor.

    The IOC's "source" is the **artifact(s)** that flagged it — when an
    IOC is corroborated by multiple sources the merge layer extends the
    same **Source:** line into a comma-separated list, e.g.:

        **Source:** Windows.Forensics.Prefetch, Forensic Analysis Report

    There is NO separate **Reason:** line — its content is folded into
    **Why:**, which is the single sentence explaining why the value is
    suspicious or malicious. There is NO **Also seen in:** marker either;
    multi-source corroboration is communicated by the comma list above.

    Fields are joined with a blank line so IRIS's markdown renderer puts
    each on its own visible line. Optional fields (Severity, Confidence,
    Evidence, MITRE, Found) are omitted when the source has no data.
    """
    _ = source  # tolerated for backward-compat
    _ = reason  # tolerated for backward-compat (folded into why upstream)

    if isinstance(artifact, (list, tuple)):
        # Dedupe while preserving order of first appearance.
        seen = set()
        ordered = []
        for a in artifact:
            a = (a or "").strip()
            if a and a not in seen:
                ordered.append(a)
                seen.add(a)
        artifact_render = ", ".join(ordered) if ordered else "(unknown artifact)"
    else:
        artifact_render = (artifact or "(unknown artifact)").strip()
        if not artifact_render:
            artifact_render = "(unknown artifact)"

    parts = [f"**Source:** {artifact_render}"]
    why = (why or "").strip()
    if why:
        parts.append(f"**Why:** {why}")
    if severity:
        parts.append(f"**Severity:** {severity}")
    if confidence:
        parts.append(f"**Confidence:** {confidence}")
    if evidence:
        # Keep evidence to a single rendered line — long quotes get
        # truncated to keep IRIS rows scannable.
        ev = str(evidence).strip()
        if ev:
            parts.append(f"**Evidence:** {ev[:600]}")
    if mitre:
        rendered = ", ".join(mitre) if isinstance(mitre, (list, tuple)) else str(mitre)
        rendered = rendered.strip()
        if rendered:
            parts.append(f"**MITRE:** {rendered}")
    if found:
        f = str(found).strip()
        if f and f.lower() not in ("-", "n/a", "unknown", ""):
            parts.append(f"**Found:** {f}")
    return "\n\n".join(parts)


_HASH_PREFIX_RE = re.compile(
    r'^\s*(?:md5|sha1|sha256|sha-?256|sha-?1|hash)\s*[:=]\s*',
    flags=re.IGNORECASE,
)


def _coerce_ioc_value(item) -> str:
    """LLM JSON blocks sometimes emit IOCs as objects instead of bare strings,
    and sometimes prefix hash values with their type label (e.g.
    "SHA256=abc..." in iocs.hashes). Normalise both shapes so the IRIS dedup
    key is the underlying value, not a labelled wrapper.

    Returns "" if no usable value can be extracted (caller should skip
    falsy returns).
    """
    if item is None:
        return ""
    if isinstance(item, str):
        s = item.strip()
        # Strip "SHA256=", "md5: ", "Hash:" etc. — LLM occasionally emits
        # hashes with their type labelled inline. Without this, IRIS treats
        # "SHA256=abc..." as a different IOC than the bare "abc..." it
        # already has from the timeline, and cross-case dedup misses too.
        s = _HASH_PREFIX_RE.sub('', s)
        return s.strip()
    if isinstance(item, dict):
        for key in ("value", "ioc", "ip", "domain", "hash", "sha256", "sha1", "md5"):
            v = item.get(key)
            if isinstance(v, str) and v.strip():
                return _HASH_PREFIX_RE.sub('', v.strip()).strip()
        return ""
    # numbers, etc. -- best-effort string conversion
    try:
        return _HASH_PREFIX_RE.sub('', str(item).strip()).strip()
    except Exception:
        return ""


def _strip_url_prefix(s) -> str:
    """Drop "http(s)://", "http(s)--" and any trailing path so a value
    like "https--track.example.com/path" becomes "track.example.com".
    Mirrors the regex inlined in parse_iocs_from_report. Tolerates dicts
    (LLM sometimes nests the domain under a "value"/"domain" key).
    """
    s = _coerce_ioc_value(s)
    s = re.sub(r'^https?(://|--)', '', s, flags=re.IGNORECASE).strip()
    return s.split('/', 1)[0]


def _hash_type(h) -> str:
    """Return md5 / sha1 / sha256 based on hex length. Falls back to sha256
    for anything unrecognised — IRIS will accept it and the analyst can
    correct manually if needed. Tolerates dicts (LLM occasionally returns
    structured hash objects)."""
    h = _coerce_ioc_value(h)
    return {32: "md5", 40: "sha1", 64: "sha256"}.get(len(h), "sha256")


def _mk_ioc(ioc_type: str, value, description: str) -> dict:
    """Build an IOC record in the shape add_iocs expects. value may arrive
    as a string or a dict from the LLM JSON; coerce to str."""
    return {
        "type": ioc_type,
        "type_id": _IRIS_TYPE_IDS.get(ioc_type, 1),
        "value": _coerce_ioc_value(value),
        "description": description,
    }


def _format_finding_desc(artifact: str, idx: int, f: dict) -> str:
    title = (f.get("title") or "(untitled finding)").strip()
    interpretation = (f.get("interpretation") or "").strip()
    # Fold title + interpretation into one Why sentence. Title is always
    # short (a label); interpretation carries the analyst-style reasoning.
    if interpretation:
        why = f"[F{idx}] {title} — {interpretation}"
    else:
        why = f"[F{idx}] {title}"
    return _format_ioc_description(
        artifact=artifact,
        why=why,
        severity=f.get("severity"),
        confidence=f.get("confidence"),
        evidence=f.get("evidence"),
        mitre=f.get("mitre"),
    )


def _find_value_context_in_summary(summary_text: str, value: str, max_len: int = 320) -> str:
    """Return the sentence in `summary_text` containing `value`, so a bare
    IOC from `iocs.*` carries the LLM's actual reasoning instead of a
    generic placeholder. Returns "" when not found or value is too short
    to be meaningful (avoids matching common substrings).

    Searches the prose portion only — strips fenced code blocks first so
    we don't surface raw JSON snippets to the analyst.
    """
    if not summary_text or not value or len(value) < 6:
        return ""
    prose = re.sub(r"```.*?```", "", summary_text, flags=re.DOTALL)
    idx = prose.lower().find(value.lower())
    if idx == -1:
        return ""
    # Sentence boundaries — back to nearest sentence-end before idx,
    # forward to nearest one after.
    start = max(prose.rfind('.', 0, idx),
                prose.rfind('!', 0, idx),
                prose.rfind('?', 0, idx),
                prose.rfind('\n\n', 0, idx))
    start = (start + 1) if start >= 0 else 0
    end_candidates = [prose.find(c, idx + len(value)) for c in '.!?']
    end_candidates = [e for e in end_candidates if e != -1]
    end = min(end_candidates) + 1 if end_candidates else len(prose)
    sentence = prose[start:end].strip()
    # Strip leading bullet/markdown noise
    sentence = re.sub(r'^[-*#>\s]+', '', sentence)
    return sentence[:max_len]


def extract_iocs_from_summaries(
    artifact_summaries: dict,
    min_severity: Optional[str] = None,
) -> List[dict]:
    """Pull IOCs out of the per-artifact LLM JSON blocks.

    artifact_summaries: {artifact_name: raw_summary_string} as returned by
    analyze_artifacts(). Each summary contains a fenced ```json``` block
    holding findings[*] and iocs.{ips, hashes, domains, users}. We walk
    both, attach the artifact name and finding evidence to each IOC's
    description, and emit one record per (value, type) pair.

    min_severity: optional gate ("low"|"medium"|"high"|"critical"). When
    set, IOCs from findings below the threshold are dropped. Bare iocs.*
    entries (no enclosing finding) bypass the gate — those are the LLM's
    "noteworthy regardless of severity" channel.

    Returns IOCs in the same shape as parse_iocs_from_report. Users from
    iocs.users are intentionally skipped — IRIS already adds analyzed
    users as case assets, so re-pushing them as IOCs duplicates and
    pollutes. No safe-domain allowlist (explicit user constraint).
    """
    # Lazy import to avoid a hard dependency at module load (services.agentic
    # is optional in some deployments).
    from services.agentic.analyzers import _extract_findings_from_summary

    sev_rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    threshold = sev_rank.get((min_severity or "").lower(), 0)

    out: List[dict] = []
    for artifact, summary in (artifact_summaries or {}).items():
        block = _extract_findings_from_summary(summary)
        if not block:
            continue

        # 1a. Per-finding IOCs — richest, carry severity + evidence.
        for idx, f in enumerate(block.get("findings", []) or [], 1):
            sev = (f.get("severity") or "").lower()
            if sev_rank.get(sev, 0) < threshold:
                continue
            base_desc = _format_finding_desc(artifact, idx, f)
            for raw in f.get("sample_ips", []) or []:
                v = _coerce_ioc_value(raw)
                if v:
                    out.append(_mk_ioc("ip", v, base_desc))
            for raw in f.get("sample_hashes", []) or []:
                v = _coerce_ioc_value(raw)
                if v:
                    out.append(_mk_ioc(_hash_type(v), v, base_desc))
            # users intentionally skipped — see docstring
            # timestamps are not IOCs

        # 1b. Bare iocs.* — no enclosing finding, bypass severity gate.
        # Try to lift the LLM's actual rationale by finding the value in
        # the artifact's prose summary and using the surrounding sentence.
        # When that fails, fall back to a less-generic placeholder that
        # at least names the artifact.
        bare = block.get("iocs", {}) or {}

        def _bare_desc_for(value: str) -> str:
            ctx = _find_value_context_in_summary(summary, value)
            why = ctx or (
                f"Listed in the {artifact} analyzer's `iocs.*` channel — "
                f"flagged as noteworthy alongside the structured findings, "
                f"but no per-finding severity/evidence was attached. Treat "
                f"as a triage lead and correlate with surrounding events."
            )
            return _format_ioc_description(artifact=artifact, why=why)

        for raw in bare.get("ips", []) or []:
            v = _coerce_ioc_value(raw)
            if v:
                out.append(_mk_ioc("ip", v, _bare_desc_for(v)))
        for raw in bare.get("domains", []) or []:
            v = _strip_url_prefix(raw)
            if v:
                out.append(_mk_ioc("domain", v, _bare_desc_for(v)))
        for raw in bare.get("hashes", []) or []:
            v = _coerce_ioc_value(raw)
            if v:
                out.append(_mk_ioc(_hash_type(v), v, _bare_desc_for(v)))

    return out


# Match the Source line WITHOUT consuming the trailing newline. `\s` would
# match `\n` and the regex.sub would eat the blank line that separates
# Source from Why, collapsing them into one rendered line.
_ARTIFACT_LINE_RE = re.compile(r'^\*\*Source:\*\*[ \t]*(.+?)[ \t]*$', flags=re.MULTILINE)


def _ioc_artifacts_from_desc(desc: str) -> List[str]:
    """Pull the artifact name(s) out of an IOC description's `**Source:**`
    line. Returns the comma-separated list as a Python list (order
    preserved). Empty list when the description doesn't follow the
    canonical shape."""
    if not desc:
        return []
    m = _ARTIFACT_LINE_RE.search(desc)
    if not m:
        return []
    raw = m.group(1).strip()
    if not raw or raw == "(unknown artifact)":
        return []
    return [a.strip() for a in raw.split(",") if a.strip()]


def _merge_artifact_into_source(target_ioc: dict, new_artifacts: List[str]) -> None:
    """Append `new_artifacts` to the `**Source:**` line of target_ioc's
    description, deduplicated and order-preserving. Mutates in place.
    Used by _merge_ioc_sets when a collision adds a new corroborating
    artifact to an already-merged IOC."""
    desc = target_ioc.get("description") or ""
    existing = _ioc_artifacts_from_desc(desc)
    seen = set(existing)
    extended = list(existing)
    for a in new_artifacts:
        if a and a not in seen:
            extended.append(a)
            seen.add(a)
    if extended == existing:
        return
    rendered = ", ".join(extended)
    target_ioc["description"] = _ARTIFACT_LINE_RE.sub(
        lambda _m: f"**Source:** {rendered}", desc, count=1
    )


def _merge_ioc_sets(*sources, pre_seen: Optional[set] = None) -> List[dict]:
    """Dedupe IOCs across sources. On collision, fold the colliding IOC's
    artifact into the kept IOC's `**Source:**` comma-separated list —
    no separate "Also seen in" marker.

    Composite values (`filename|sha256`) are processed BEFORE bare
    values, regardless of source order. This way a richer composite
    from the report-IOC parser wins over a bare hash from a per-artifact
    analyzer and the analyst sees `filename|hash` in IRIS rather than a
    context-less hash.

    Each `source` is a (iocs_list, _label_unused) tuple. The label
    parameter is kept for caller compatibility but no longer used.

    pre_seen: optional lowercased values to suppress without producing an
    IOC record. Used by import_to_iris for hashes/filenames embedded in
    a timeline IOC's evidence line.
    """
    merged: Dict[str, dict] = {}
    seen_value: set = set(pre_seen or ())

    # Sort composites ahead of bare values so the richer description wins.
    flat: List[dict] = []
    for iocs, _label in sources:
        for ioc in iocs or []:
            flat.append(ioc)
    flat.sort(key=lambda i: 0 if "|" in (i.get("value") or "") else 1)

    for ioc in flat:
        v = (ioc.get("value") or "").strip().lower()
        if not v:
            continue

        collision_target = None
        if "|" in v:
            fn, _, hsh = v.partition("|")
            if v in merged:
                collision_target = merged[v]
            elif fn and fn in seen_value:
                collision_target = next(
                    (merged[k] for k in merged if k == fn or k.startswith(fn + "|")), None
                )
            elif hsh and hsh in seen_value:
                collision_target = next(
                    (merged[k] for k in merged if k == hsh or k.endswith("|" + hsh)), None
                )
        elif v in seen_value:
            collision_target = merged.get(v)
            if collision_target is None:
                # Bare hash arrived after a composite that contains it.
                collision_target = next(
                    (merged[k] for k in merged
                     if "|" in k and k.endswith("|" + v)),
                    None,
                )

        if collision_target is not None:
            new_artifacts = _ioc_artifacts_from_desc(ioc.get("description") or "")
            if new_artifacts:
                _merge_artifact_into_source(collision_target, new_artifacts)
            continue

        entry = dict(ioc)
        merged[v] = entry
        seen_value.add(v)
        if "|" in v:
            fn, _, hsh = v.partition("|")
            if fn:
                seen_value.add(fn)
            if hsh:
                seen_value.add(hsh)

    return list(merged.values())


def extract_iocs_from_timeline(timeline_events: List[dict]) -> List[dict]:
    """Extract IOCs from timeline events - uses the same rich descriptions.

    Scans each timeline event's raw data for IOC values (hashes, IPs, domains)
    and uses the event's description as the IOC description.

    Args:
        timeline_events: List of timeline event dicts with 'raw', 'description', 'source'

    Returns:
        List of IOC dicts with type, value, and description from the timeline event
    """
    iocs = []
    seen = set()

    # IOC patterns
    patterns = {
        'md5': (r'\b[a-fA-F0-9]{32}\b', 90),
        'sha1': (r'\b[a-fA-F0-9]{40}\b', 111),
        'sha256': (r'\b[a-fA-F0-9]{64}\b', 113),
        'ip': (r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', 76),
    }

    # Safe values to skip
    SAFE_IPS = {'127.0.0.1', '0.0.0.0', '8.8.8.8', '1.1.1.1', '255.255.255.255'}

    # Hash field names to look for in raw data
    hash_fields = ['SHA1', 'SHA256', 'MD5', 'Hash', 'FileHash', 'sha1', 'sha256', 'md5']
    ip_fields = ['SourceIP', 'DestIP', 'RemoteAddress', 'IpAddress', 'Raddr', 'IP']

    for event in timeline_events:
        raw = event.get('raw', {})
        description = event.get('description', '')
        source = event.get('source', 'Unknown')
        timestamp = event.get('timestamp', '')
        title = event.get('title', '')

        if not raw:
            continue

        # Extract context from raw data for richer IOC descriptions
        filename = raw.get('Name') or raw.get('FileName') or raw.get('Process') or ''
        filepath = raw.get('FullPath') or raw.get('Path') or raw.get('FilePath') or ''
        user = raw.get('User') or raw.get('UserName') or raw.get('Account') or ''
        process = raw.get('Process') or raw.get('ProcessName') or raw.get('Name') or ''
        cmdline = raw.get('CommandLine') or raw.get('Cmdline') or ''

        # Extract "Why it matters" from the event description
        why_matters = ''
        if '**Why it matters:**' in description:
            why_matters = description.split('**Why it matters:**')[-1].strip()
        elif 'Why it matters:' in description:
            why_matters = description.split('Why it matters:')[-1].strip()

        def build_ip_description(ip_value):
            """Canonical IP description — single Why explains why it's an IOC."""
            evidence_bits = ["External IP address"]
            if process:
                evidence_bits.append(f"process={process}")
            dest_port = raw.get('DestPort') or raw.get('RemotePort') or raw.get('Rport') or ''
            if dest_port:
                evidence_bits.append(f"port={dest_port}")

            base_why = (why_matters
                        or "External connection identified during investigation")
            why_bits = [base_why]
            if process:
                why_bits.append(f"process {process}")
            if dest_port:
                why_bits.append(f"port {dest_port}")
            why_text = " — ".join(why_bits)

            return _format_ioc_description(
                artifact=source,
                why=why_text,
                evidence="; ".join(evidence_bits) if evidence_bits else None,
                found=timestamp,
            )

        # CONSOLIDATE all hashes from this row into ONE IOC entry
        # Instead of creating separate IOCs for MD5, SHA1, SHA256
        hashes_found = {}
        for field in hash_fields:
            if field in raw:
                value = str(raw[field]).lower().strip()
                if value and len(value) in (32, 40, 64):
                    # Determine hash type by length
                    if len(value) == 32:
                        hashes_found['md5'] = value
                    elif len(value) == 40:
                        hashes_found['sha1'] = value
                    elif len(value) == 64:
                        hashes_found['sha256'] = value

        # Also check for nested Hash object (common in DetectRaptor artifacts)
        hash_obj = raw.get('Hash')
        if isinstance(hash_obj, dict):
            for key, value in hash_obj.items():
                if value and isinstance(value, str):
                    value = value.lower().strip()
                    key_lower = key.lower()
                    if 'md5' in key_lower and len(value) == 32:
                        hashes_found['md5'] = value
                    elif 'sha1' in key_lower and len(value) == 40:
                        hashes_found['sha1'] = value
                    elif 'sha256' in key_lower and len(value) == 64:
                        hashes_found['sha256'] = value

        # Create ONE consolidated IOC if hashes found
        if hashes_found:
            # Use filename + source + filepath as dedup key (not individual hash values)
            file_key = f"{source}:{filename}:{filepath}".lower()
            if file_key not in seen:
                seen.add(file_key)

                # Canonical description shape — see _format_ioc_description.
                # Path / user / extra hashes go into Evidence so the file
                # row stays scannable while preserving the supporting
                # context an analyst needs.
                evidence_bits = []
                if filepath:
                    evidence_bits.append(f"path={filepath}")
                if user:
                    evidence_bits.append(f"user={user}")
                for ht in ('md5', 'sha1', 'sha256'):
                    if ht in hashes_found:
                        evidence_bits.append(f"{ht.upper()}={hashes_found[ht]}")

                if why_matters:
                    base_why = why_matters
                elif 'suspicious' in description.lower() or 'malicious' in description.lower():
                    base_why = "Flagged as suspicious in forensic analysis"
                elif filename:
                    base_why = f"File '{filename}' observed in {source}"
                else:
                    base_why = f"Hash observed in {source}"

                why_bits = [base_why]
                if filepath:
                    why_bits.append(f"location {filepath}")
                if user:
                    why_bits.append(f"user {user}")
                why_text = " — ".join(why_bits)

                canonical_desc = _format_ioc_description(
                    artifact=source,
                    why=why_text,
                    evidence="; ".join(evidence_bits) if evidence_bits else None,
                    found=timestamp,
                )

                # Use filename|sha256 composite type when we have both filename and SHA256
                if filename and 'sha256' in hashes_found:
                    sha256_hash = hashes_found['sha256']
                    composite_value = f"{filename}|{sha256_hash}"
                    iocs.append({
                        'type': 'filename|sha256',
                        'type_id': 46,
                        'value': composite_value,
                        'description': canonical_desc,
                    })
                    seen.add(sha256_hash.lower())
                    seen.add(filename.lower())
                elif 'sha256' in hashes_found:
                    iocs.append({
                        'type': 'sha256',
                        'type_id': 113,
                        'value': hashes_found['sha256'],
                        'description': canonical_desc,
                    })
                # Skip if no SHA256 - we only keep SHA256 to reduce data

        # Look for IPs in specific fields
        for field in ip_fields:
            if field in raw:
                value = str(raw[field]).strip()
                if value and value not in seen and value not in SAFE_IPS:
                    # Validate IP format
                    if re.match(patterns['ip'][0], value):
                        # Skip private ranges
                        if not (value.startswith('10.') or value.startswith('192.168.') or
                                value.startswith('172.16.') or value.startswith('172.17.') or
                                value.startswith('169.254.')):
                            seen.add(value)
                            iocs.append({
                                'type': 'ip',
                                'type_id': 76,
                                'value': value,
                                'description': build_ip_description(value)
                            })

    return iocs


