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


def _get_iris_api_key(iris_config: dict, logger: Callable = None) -> Optional[str]:
    """Get IRIS API key from config or database.

    Args:
        iris_config: Configuration dict with api_key or database connection
        logger: Optional callback function(message, level) to log progress

    Returns:
        API key string or None if not available
    """
    def log(message, level="info"):
        print(f"[IRIS] {message}", flush=True)
        if logger:
            try:
                logger(f"[IRIS] {message}", level)
            except:
                pass

    # First check if API key is directly in config
    api_key = iris_config.get('api_key')
    if api_key:
        log("Using API key from configuration")
        return api_key

    # Try to get API key from IRIS database
    try:
        import subprocess
        result = subprocess.run(
            ['docker', 'exec', 'intact_iris_db', 'psql', '-U', 'iris', '-d', 'iris_db', '-t', '-c',
             "SELECT api_key FROM \"user\" WHERE name='administrator';"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0 and result.stdout.strip():
            api_key = result.stdout.strip()
            log("Retrieved API key from IRIS database")
            return api_key
    except Exception as e:
        log(f"Could not retrieve API key from database: {e}", "warning")

    log("No API key available", "error")
    return None


def _make_iris_request(method: str, endpoint: str, iris_config: dict, api_key: str,
                       data: dict = None, logger: Callable = None) -> Optional[dict]:
    """Make an authenticated request to IRIS API.

    Args:
        method: HTTP method (GET, POST, PUT, DELETE)
        endpoint: API endpoint (e.g., '/manage/cases/add')
        iris_config: Configuration dict with host
        api_key: API key for Bearer authentication
        data: Optional JSON data for POST/PUT requests
        logger: Optional callback function

    Returns:
        Response JSON dict or None on failure
    """
    def log(message, level="info"):
        print(f"[IRIS] {message}", flush=True)
        if logger:
            try:
                logger(f"[IRIS] {message}", level)
            except:
                pass

    try:
        # Use HTTP for internal container communication
        host = iris_config.get('host', 'http://intact_iris_app:8000')
        # Convert https to http for internal calls
        if host.startswith('https://'):
            host = host.replace('https://', 'http://')

        url = f"{host}{endpoint}"

        headers = {
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json'
        }

        response = requests.request(
            method=method,
            url=url,
            headers=headers,
            json=data,
            verify=False,
            timeout=30
        )

        if response.status_code in [200, 201]:
            return response.json()
        else:
            log(f"API request failed: {method} {endpoint} -> {response.status_code}", "warning")
            log(f"Response: {response.text[:500]}", "warning")
            return None

    except Exception as e:
        log(f"API request error: {e}", "error")
        return None


def create_iris_case(case_name: str, case_description: str, iris_config: dict,
                     api_key: str, logger: Callable = None) -> Optional[dict]:
    """Create a new IRIS case.

    Args:
        case_name: Name for the new case
        case_description: Description of the case
        iris_config: Configuration dict
        api_key: API key for authentication
        logger: Optional callback function

    Returns:
        Dict with case_id and case details, or None on failure
    """
    def log(message, level="info"):
        print(f"[IRIS] {message}", flush=True)
        if logger:
            try:
                logger(f"[IRIS] {message}", level)
            except:
                pass

    log(f"Creating IRIS case: {case_name}")

    # Generate SOC ID from timestamp
    soc_id = f"Intact.AI-{datetime.now().strftime('%Y%m%d-%H%M%S')}"

    case_data = {
        "case_name": case_name,
        "case_description": case_description,
        "case_customer": 1,  # Default customer (IrisInitialClient)
        "case_soc_id": soc_id,
        "classification_id": None,
        "case_tags": "agentic,automated"
    }

    response = _make_iris_request(
        method="POST",
        endpoint="/manage/cases/add",
        iris_config=iris_config,
        api_key=api_key,
        data=case_data,
        logger=logger
    )

    if response and response.get('status') == 'success':
        case_info = response.get('data', {})
        case_id = case_info.get('case_id')
        log(f"Case created with ID: {case_id}", "success")
        return {
            'case_id': case_id,
            'case_name': case_info.get('case_name'),
            'case_uuid': case_info.get('case_uuid')
        }

    log("Failed to create case", "error")
    return None


def create_or_get_asset(case_id: int, hostname: str, iris_config: dict,
                        api_key: str, asset_cache: dict = None,
                        logger: Callable = None) -> Optional[int]:
    """Create or retrieve an asset (computer) for a hostname.

    Args:
        case_id: IRIS case ID
        hostname: Hostname to create asset for
        iris_config: Configuration dict
        api_key: API key for authentication
        asset_cache: Dict to cache asset_id by hostname (modified in place)
        logger: Optional callback function

    Returns:
        Asset ID or None on failure
    """
    def log(message, level="info"):
        print(f"[IRIS] {message}", flush=True)
        if logger:
            try:
                logger(f"[IRIS] {message}", level)
            except:
                pass

    # Check cache first
    if asset_cache and hostname in asset_cache:
        return asset_cache[hostname]

    # Create new asset
    asset_data = {
        "asset_name": hostname,
        "asset_type_id": 1,  # 1 = Windows - Loss of operation, usually for computers
        "asset_description": f"Host collected by Agentic pipeline",
        "asset_compromise_status_id": 1,  # 1 = Unknown compromise status
        "asset_tags": "agentic,automated"
    }

    response = _make_iris_request(
        method="POST",
        endpoint=f"/case/assets/add?cid={case_id}",
        iris_config=iris_config,
        api_key=api_key,
        data=asset_data,
        logger=None
    )

    if response and response.get('status') == 'success':
        asset_info = response.get('data', {})
        asset_id = asset_info.get('asset_id')
        if asset_id:
            log(f"Created asset for {hostname}: ID {asset_id}")
            if asset_cache is not None:
                asset_cache[hostname] = asset_id
            return asset_id

    # If creation failed (maybe already exists), try to find it
    # List all assets for case
    list_response = _make_iris_request(
        method="GET",
        endpoint=f"/case/assets/list?cid={case_id}",
        iris_config=iris_config,
        api_key=api_key,
        logger=None
    )

    if list_response and list_response.get('status') == 'success':
        assets = list_response.get('data', {}).get('assets', [])
        for asset in assets:
            if asset.get('asset_name') == hostname:
                asset_id = asset.get('asset_id')
                if asset_id:
                    if asset_cache is not None:
                        asset_cache[hostname] = asset_id
                    return asset_id

    return None


def add_timeline_events(case_id: int, events: List[dict], iris_config: dict,
                        api_key: str, logger: Callable = None,
                        asset_cache: dict = None) -> int:
    """Add timeline events to an IRIS case.

    Args:
        case_id: IRIS case ID
        events: List of event dicts with timestamp, source, title, description, hostname
                Events without timestamps are added with a special marker
        iris_config: Configuration dict
        api_key: API key for authentication
        logger: Optional callback function
        asset_cache: Optional dict mapping hostname -> asset_id

    Returns:
        Count of successfully imported events
    """
    def log(message, level="info"):
        print(f"[IRIS] {message}", flush=True)
        if logger:
            try:
                logger(f"[IRIS] {message}", level)
            except:
                pass

    if not events:
        log("No events to import")
        return 0

    log(f"Importing {len(events)} timeline events to case {case_id}...")

    # Build asset cache if not provided
    if asset_cache is not None and asset_cache:
        log(f"Using provided asset cache with {len(asset_cache)} entries: {list(asset_cache.keys())}")
    elif asset_cache is None:
        asset_cache = {}
        # Get existing assets from case
        list_response = _make_iris_request(
            method="GET",
            endpoint=f"/case/assets/list?cid={case_id}",
            iris_config=iris_config,
            api_key=api_key,
            logger=None
        )
        if list_response and list_response.get('status') == 'success':
            assets = list_response.get('data', {}).get('assets', [])
            for asset in assets:
                name = asset.get('asset_name')
                aid = asset.get('asset_id')
                if name and aid:
                    asset_cache[name] = aid
            if asset_cache:
                log(f"Found {len(asset_cache)} existing assets to link")

    imported_count = 0
    errors = 0

    for i, event in enumerate(events):
        # Skip None or non-dict events
        if not event or not isinstance(event, dict):
            errors += 1
            continue

        try:
            # Parse timestamp - IRIS requires format with microseconds
            timestamp = event.get('timestamp')
            no_timestamp = event.get('no_timestamp', False)

            if no_timestamp or not timestamp:
                # Use epoch time for events without timestamps - will appear at top of timeline
                event_date = "1970-01-01T00:00:00.000000"
            elif isinstance(timestamp, datetime):
                event_date = timestamp.strftime('%Y-%m-%dT%H:%M:%S.000000')
            else:
                # Convert string timestamp to proper format
                ts_str = str(timestamp)[:19]  # Get YYYY-MM-DDTHH:MM:SS
                if not ts_str or len(ts_str) < 10:
                    # Use epoch for invalid timestamps
                    event_date = "1970-01-01T00:00:00.000000"
                    no_timestamp = True
                else:
                    if 'T' not in ts_str and ' ' in ts_str:
                        ts_str = ts_str.replace(' ', 'T')
                    event_date = f"{ts_str}.000000"

            # Get clean title from event (or fall back to description)
            event_title_raw = event.get('title') or event.get('description', 'Event')
            description = event.get('description') or str(event)
            source = event.get('source', 'Unknown Artifact')
            hostname = event.get('hostname', '')

            # Handle events without timestamps
            if no_timestamp:
                title_prefix = "[INVESTIGATE] "
                content_prefix = f"⚠️ **NO TIMESTAMP - REQUIRES INVESTIGATION**\n\n"
                description = content_prefix + description
            else:
                title_prefix = ""

            # Truncate description if too long
            if len(description) > 2000:
                description = description[:1997] + "..."

            # Create clean title (short and meaningful)
            event_title = f"{title_prefix}{event_title_raw[:80]}"

            # Get asset ID for this hostname
            event_assets = []
            if hostname and hostname in asset_cache:
                event_assets = [asset_cache[hostname]]
            elif hostname and i == 0:
                # Log first event's hostname lookup for debugging
                log(f"  Debug: Event hostname='{hostname}' not in asset_cache. Cache keys: {list(asset_cache.keys())[:5]}")

            event_data = {
                "event_title": event_title,
                "event_date": event_date,
                "event_content": description,
                "event_raw": json.dumps(event.get('raw', {}), default=str)[:5000] if event.get('raw') else "",
                "event_source": source,
                "event_tz": "+00:00",
                "event_category_id": 1,  # Default category (Unspecified)
                "event_assets": event_assets,
                "event_iocs": []
            }

            response = _make_iris_request(
                method="POST",
                endpoint=f"/case/timeline/events/add?cid={case_id}",
                iris_config=iris_config,
                api_key=api_key,
                data=event_data,
                logger=None  # Don't log each event
            )

            if response and response.get('status') == 'success':
                imported_count += 1
            else:
                errors += 1

            # Log progress every 100 events
            if (i + 1) % 100 == 0:
                log(f"  Progress: {i + 1}/{len(events)} events processed")

        except Exception as e:
            errors += 1
            if errors <= 3:  # Only log first few errors
                log(f"  Error importing event: {e}", "warning")

    log(f"Imported {imported_count}/{len(events)} events ({errors} errors)",
        "success" if errors == 0 else "warning")

    return imported_count


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

    # Skip well-known safe values
    SAFE_IPS = {'127.0.0.1', '0.0.0.0', '8.8.8.8', '1.1.1.1', '255.255.255.255'}
    SAFE_DOMAINS = {'localhost', 'example.com', 'example.org', 'microsoft.com', 'windows.com'}

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
    for line in report_content.split('\n'):
        line_lower = line.lower()
        if 'indicator' in line_lower and 'compromise' in line_lower:
            in_ioc_section = True
            continue
        if in_ioc_section and line.startswith('#') and 'indicator' not in line_lower:
            in_ioc_section = False

        if in_ioc_section and '|' in line:
            parts = [p.strip() for p in line.split('|')]
            parts = [p for p in parts if p]

            # Check for consolidated format: | Name | Details | Hashes | Source | Why |
            # Detect by: has 4+ columns AND (has hash pattern in col 3 OR has "N/A" in col 3)
            if len(parts) >= 4:
                name = re.sub(r'[`*]', '', parts[0]).strip()
                details = re.sub(r'[`*]', '', parts[1]).strip() if len(parts) > 1 else ''
                hashes_str = parts[2] if len(parts) > 2 else ''
                source = re.sub(r'[`*]', '', parts[3]).strip() if len(parts) > 3 else ''
                why = re.sub(r'[`*]', '', parts[4]).strip() if len(parts) > 4 else ''

                # Skip header rows
                if name.lower() in ('name', 'file name', 'type', '---', ''):
                    continue
                if 'details' in details.lower() and 'hashes' in hashes_str.lower():
                    continue

                # Check if this is consolidated format (has hashes OR has N/A in hash column)
                has_hashes = re.search(r'(MD5|SHA1|SHA256):', hashes_str, re.I)
                is_consolidated = has_hashes or hashes_str.strip().upper() == 'N/A'

                if is_consolidated and name and len(name) > 2:
                    # Parse hashes from "MD5:xxx SHA1:yyy SHA256:zzz"
                    md5_match = re.search(r'MD5:([a-f0-9]{32})', hashes_str, re.I)
                    sha1_match = re.search(r'SHA1:([a-f0-9]{40})', hashes_str, re.I)
                    sha256_match = re.search(r'SHA256:([a-f0-9]{64})', hashes_str, re.I)

                    # Build consolidated description
                    desc_parts = [f"**Name:** {name}"]
                    if details and details.upper() != 'N/A':
                        desc_parts.append(f"**Details:** {details}")
                    if md5_match:
                        desc_parts.append(f"**MD5:** {md5_match.group(1).lower()}")
                    if sha1_match:
                        desc_parts.append(f"**SHA1:** {sha1_match.group(1).lower()}")
                    if sha256_match:
                        desc_parts.append(f"**SHA256:** {sha256_match.group(1).lower()}")
                    if source and source.upper() != 'N/A':
                        desc_parts.append(f"**Source:** {source}")
                    if why and why.upper() != 'N/A':
                        desc_parts.append(f"**Why IOC:** {why}")

                    # Determine IOC type - use filename|sha256 composite when we have SHA256
                    name_lower = name.lower()

                    # Check if this is a file-like IOC (has extension or has SHA256)
                    is_file_ioc = re.search(r'\.(exe|dll|ps1|bat|cmd|vbs|js|msi|scr)$', name_lower)
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
                                'description': '\n'.join(desc_parts)
                            })
                        elif is_domain:
                            iocs.append({
                                'type': 'domain',
                                'type_id': 20,
                                'value': name,
                                'description': '\n'.join(desc_parts)
                            })
                        elif is_ip:
                            iocs.append({
                                'type': 'ip',
                                'type_id': 76,
                                'value': name,
                                'description': '\n'.join(desc_parts)
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
    for line in report_content.split('\n'):
        line_lower = line.lower()
        # Detect IOC section
        if 'indicator' in line_lower and 'compromise' in line_lower:
            in_ioc_section = True
            continue
        # Exit IOC section on next major header
        if in_ioc_section and line.startswith('#') and 'indicator' not in line_lower:
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
                    # Old format: Type | Value | Context | Severity
                    context = re.sub(r'[`*]', '', parts[2]).strip()
                    severity = re.sub(r'[`*]', '', parts[3]).strip()
                    why_ioc = f"{context} (Severity: {severity})" if severity else context
                elif len(parts) >= 3:
                    context = re.sub(r'[`*]', '', parts[2]).strip()
                    why_ioc = context

                # Determine IOC type - MUST match a known type
                ioc_type = None
                type_id = None
                for key, tid in TYPE_MAP.items():
                    if key in ioc_type_raw:
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

                    # Build rich description like timeline format
                    desc_parts = []
                    if artifact_source and artifact_source.lower() not in ('artifact source', 'source', '-', 'n/a', ''):
                        desc_parts.append(f"**Artifact:** {artifact_source}")
                    if timestamp and timestamp.lower() not in ('timestamp', '-', 'n/a', ''):
                        desc_parts.append(f"**Found:** {timestamp}")
                    if why_ioc and why_ioc.lower() not in ('why ioc', 'why', '-', 'n/a', ''):
                        desc_parts.append(f"**Why IOC:** {why_ioc}")

                    description = '\n'.join(desc_parts) if desc_parts else None

                    iocs.append({
                        'type': ioc_type or 'other',
                        'type_id': type_id,
                        'value': ioc_value,
                        'description': description or f'Identified in forensic analysis'
                    })

    # STEP 2: Fall back to regex extraction for IOCs not in the table

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
                    'type_id': 76,  # IRIS type ID for IP
                    'value': ip,
                    'description': context or 'External IP address identified in network/connection artifacts during forensic analysis'
                })

    # DISABLED: Hash regex extraction creates duplicates when consolidated format is used
    # Hashes should be part of consolidated file IOCs, not separate entries
    # If needed, uncomment below for legacy reports without consolidated format
    #
    # # MD5 hashes (32 hex chars)
    # md5_pattern = r'\b[a-fA-F0-9]{32}\b'
    # for match in re.finditer(md5_pattern, report_content):
    #     hash_val = match.group().lower()
    #     if hash_val not in seen:
    #         seen.add(hash_val)
    #         iocs.append({'type': 'md5', 'type_id': 90, 'value': hash_val, 'description': 'MD5 hash from forensic analysis'})
    #
    # # SHA1/SHA256 extraction similarly disabled

    # Domains (basic pattern - look for domain-like strings)
    domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|ru|cn|tk|xyz|top|info|biz|cc|pw)\b'
    for match in re.finditer(domain_pattern, report_content, re.IGNORECASE):
        domain = match.group().lower()
        if domain not in seen and domain not in SAFE_DOMAINS:
            seen.add(domain)
            context = extract_ioc_context(report_content, domain, 'domain')

            # Build a more informative default description if no context found
            if not context:
                # Check if domain is mentioned near any tool/file names
                desc_parts = [f"**Domain:** {domain}"]

                # Search for surrounding context in report
                lines = report_content.split('\n')
                for i, line in enumerate(lines):
                    if domain in line.lower():
                        # Check nearby lines for tool references
                        context_window = '\n'.join(lines[max(0,i-3):min(len(lines),i+4)])
                        tool_refs = re.findall(r'(\w+\.exe|\w+\.dll)', context_window, re.I)
                        if tool_refs:
                            desc_parts.append(f"**Associated with:** {', '.join(set(tool_refs))}")
                        break

                desc_parts.append("**Action:** Check reputation on VirusTotal, URLhaus, or threat feeds")
                context = '\n'.join(desc_parts)

            iocs.append({
                'type': 'domain',
                'type_id': 20,  # IRIS type ID for domain
                'value': domain,
                'description': context
            })

    return iocs


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
            """Build specific description for an IP IOC."""
            parts = []

            # What is this IOC?
            parts.append(f"**What:** External IP address")

            # Connection context
            if process:
                parts.append(f"**Process:** `{process}`")

            dest_port = raw.get('DestPort') or raw.get('RemotePort') or raw.get('Rport') or ''
            if dest_port:
                parts.append(f"**Port:** {dest_port}")

            # How was it found?
            parts.append(f"**Found in:** {source} artifact")

            # When?
            if timestamp:
                parts.append(f"**When:** {timestamp}")

            # Why is it an IOC?
            if why_matters:
                parts.append(f"**Why IOC:** {why_matters}")
            else:
                parts.append(f"**Why IOC:** External connection identified during investigation")

            return '\n'.join(parts)

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

                # Build consolidated description with ALL hashes
                desc_parts = []
                if filename:
                    desc_parts.append(f"**File:** {filename}")
                if filepath:
                    desc_parts.append(f"**Location:** {filepath}")

                # List all hashes
                for ht in ['md5', 'sha1', 'sha256']:
                    if ht in hashes_found:
                        desc_parts.append(f"**{ht.upper()}:** {hashes_found[ht]}")

                desc_parts.append(f"**Found in:** {source}")
                if timestamp:
                    desc_parts.append(f"**When:** {timestamp}")
                if user:
                    desc_parts.append(f"**User:** {user}")
                if why_matters:
                    desc_parts.append(f"**Why IOC:** {why_matters}")
                elif 'suspicious' in description.lower() or 'malicious' in description.lower():
                    desc_parts.append(f"**Why IOC:** Flagged as suspicious in forensic analysis")

                # Use filename|sha256 composite type when we have both filename and SHA256
                if filename and 'sha256' in hashes_found:
                    sha256_hash = hashes_found['sha256']
                    composite_value = f"{filename}|{sha256_hash}"
                    iocs.append({
                        'type': 'filename|sha256',
                        'type_id': 46,
                        'value': composite_value,
                        'description': '\n'.join(desc_parts)
                    })
                    # Add to seen to prevent duplicates
                    seen.add(sha256_hash.lower())
                    seen.add(filename.lower())
                elif 'sha256' in hashes_found:
                    # No filename, just use SHA256 alone
                    iocs.append({
                        'type': 'sha256',
                        'type_id': 113,
                        'value': hashes_found['sha256'],
                        'description': '\n'.join(desc_parts)
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


def add_iocs(case_id: int, iocs: List[dict], iris_config: dict,
             api_key: str, logger: Callable = None) -> int:
    """Add IOCs to an IRIS case.

    Args:
        case_id: IRIS case ID
        iocs: List of IOC dicts from parse_iocs_from_report
        iris_config: Configuration dict
        api_key: API key for authentication
        logger: Optional callback function

    Returns:
        Count of successfully imported IOCs
    """
    def log(message, level="info"):
        print(f"[IRIS] {message}", flush=True)
        if logger:
            try:
                logger(f"[IRIS] {message}", level)
            except:
                pass

    if not iocs:
        log("No IOCs to import")
        return 0

    log(f"Importing {len(iocs)} IOCs to case {case_id}...")

    imported_count = 0

    for ioc in iocs:
        # Skip None or invalid IOCs
        if not ioc or not isinstance(ioc, dict):
            continue

        try:
            # Skip IOCs without a value
            ioc_value = ioc.get('value')
            if not ioc_value:
                continue

            ioc_data = {
                "ioc_value": ioc_value,
                "ioc_type_id": ioc.get('type_id', 1),
                "ioc_description": ioc.get('description', '') or '',
                "ioc_tlp_id": 2,  # AMBER
                "ioc_tags": f"agentic,{ioc.get('type', 'unknown')}"
            }

            response = _make_iris_request(
                method="POST",
                endpoint=f"/case/ioc/add?cid={case_id}",
                iris_config=iris_config,
                api_key=api_key,
                data=ioc_data,
                logger=None  # Don't log each IOC
            )

            if response and response.get('status') == 'success':
                imported_count += 1

        except Exception as e:
            ioc_val = ioc.get('value', 'unknown') if isinstance(ioc, dict) else 'unknown'
            log(f"  Error importing IOC {ioc_val}: {e}", "warning")

    log(f"Imported {imported_count}/{len(iocs)} IOCs", "success" if imported_count > 0 else "warning")

    return imported_count


def add_assets(case_id: int, clients: List[dict], iris_config: dict,
               api_key: str, logger: Callable = None) -> tuple:
    """Add assets (analyzed clients) to an IRIS case.

    Args:
        case_id: IRIS case ID
        clients: List of client dicts with hostname, os, client_id
        iris_config: Configuration dict
        api_key: API key for authentication
        logger: Optional callback function

    Returns:
        Tuple of (count of successfully imported assets, asset_cache dict mapping hostname->asset_id)
    """
    def log(message, level="info"):
        print(f"[IRIS] {message}", flush=True)
        if logger:
            try:
                logger(f"[IRIS] {message}", level)
            except:
                pass

    asset_cache = {}  # Maps hostname -> asset_id

    if not clients:
        log("No clients to add as assets")
        return 0, asset_cache

    log(f"Adding {len(clients)} assets to case {case_id}...")

    imported_count = 0

    for client in clients:
        # Skip None or empty clients
        if not client or not isinstance(client, dict):
            log(f"  Skipping invalid client: {client}", "warning")
            continue

        try:
            # Extract hostname - try multiple paths
            hostname = client.get('hostname') or client.get('os_info', {}).get('hostname')
            if not hostname:
                log(f"  Skipping client with no hostname: {client}", "warning")
                continue

            os_info = str(client.get('os', client.get('os_info', {}).get('system', '')) or '').lower()
            client_id = client.get('client_id', '') or ''

            # Determine asset type based on OS
            if 'windows' in os_info:
                if 'server' in os_info:
                    asset_type_id = 10  # Windows - Server
                else:
                    asset_type_id = 9   # Windows - Computer
            elif 'linux' in os_info:
                if 'server' in os_info:
                    asset_type_id = 3   # Linux - Server
                else:
                    asset_type_id = 4   # Linux - Computer
            elif 'mac' in os_info or 'darwin' in os_info:
                asset_type_id = 6       # Mac - Computer
            else:
                asset_type_id = 9       # Default to Windows - Computer

            # IRIS v2.x asset creation format
            asset_data = {
                "asset_name": hostname,
                "asset_type_id": asset_type_id,
                "asset_description": f"Velociraptor Client ID: {client_id}\nOS: {client.get('os', 'Unknown')}",
                "asset_tags": "agentic,analyzed",
                "analysis_status_id": 1,  # To be determined
                "asset_compromise_status_id": 1  # To be determined
            }

            log(f"  Sending asset: {hostname} (type_id={asset_type_id})")

            response = _make_iris_request(
                method="POST",
                endpoint=f"/case/assets/add?cid={case_id}",
                iris_config=iris_config,
                api_key=api_key,
                data=asset_data,
                logger=logger  # Enable logging to see errors
            )

            if response and response.get('status') == 'success':
                imported_count += 1
                # Extract asset_id from response and store in cache
                asset_data_response = response.get('data', {})
                asset_id = asset_data_response.get('asset_id')
                if asset_id:
                    asset_cache[hostname] = asset_id
                    log(f"  Added asset: {hostname} (id={asset_id})", "success")
                else:
                    log(f"  Added asset: {hostname} (no id returned)", "success")
            else:
                log(f"  Failed to add asset: {hostname} - Response: {response}", "warning")

        except Exception as e:
            hostname = client.get('hostname', 'unknown') if isinstance(client, dict) else 'unknown'
            log(f"  Error adding asset {hostname}: {e}", "warning")
            log(f"  Client data: {client}", "warning")

    log(f"Added {imported_count}/{len(clients)} assets", "success" if imported_count > 0 else "warning")
    log(f"Asset cache contains {len(asset_cache)} entries: {list(asset_cache.keys())}")

    return imported_count, asset_cache


def import_to_iris(run_id: str, case_name: str, timeline_events: List[dict],
                   technical_report: str, iris_config: dict,
                   clients: List[dict] = None, blueprint_name: str = None,
                   all_events_for_iocs: List[dict] = None,
                   logger: Callable = None) -> dict:
    """Main entry point for importing agentic analysis results to IRIS.

    Orchestrates the full import process:
    1. Get API key
    2. Create a new case
    3. Add assets (analyzed clients)
    4. Import timeline events
    5. Parse and import IOCs from technical report

    Args:
        run_id: Agentic pipeline run ID (for reference)
        case_name: Name for the IRIS case
        timeline_events: List of timeline event dicts (filtered for display)
        technical_report: Technical report markdown content
        iris_config: IRIS configuration dict
        clients: List of client dicts (hostname, os, client_id) to add as assets
        blueprint_name: Name of the blueprint used for analysis
        all_events_for_iocs: Unfiltered events for IOC extraction (optional, falls back to timeline_events)
        logger: Optional callback function

    Returns:
        Dict with success status, case_id, case_url, and counts
    """
    def log(message, level="info"):
        print(f"[IRIS] {message}", flush=True)
        if logger:
            try:
                logger(f"[IRIS] {message}", level)
            except:
                pass

    result = {
        'success': False,
        'case_id': None,
        'case_url': None,
        'assets_imported': 0,
        'events_imported': 0,
        'iocs_imported': 0,
        'error': None
    }

    try:
        # 1. Get API key
        log("Starting IRIS import process...")
        api_key = _get_iris_api_key(iris_config, logger)
        if not api_key:
            result['error'] = "Failed to get IRIS API key"
            return result

        # Extract IOCs from ALL events (unfiltered) for better hash coverage
        # Amcache/Prefetch have hashes but may be filtered from timeline_events
        ioc_source_events = all_events_for_iocs if all_events_for_iocs else timeline_events
        timeline_iocs = extract_iocs_from_timeline(ioc_source_events) if ioc_source_events else []

        # Also parse IOCs from report (catches any not in timeline)
        report_iocs = parse_iocs_from_report(technical_report) if technical_report else []

        # Merge IOCs - timeline IOCs first (better descriptions), then report IOCs
        # Extract ALL hashes AND filenames from timeline IOCs to avoid duplicates
        seen_values = set()
        for ioc in timeline_iocs:
            ioc_value = ioc['value'].lower()
            seen_values.add(ioc_value)

            # For composite filename|sha256, also add the parts separately
            if '|' in ioc_value:
                parts = ioc_value.split('|', 1)
                seen_values.add(parts[0])  # Add filename
                if len(parts) > 1:
                    seen_values.add(parts[1])  # Add hash

            # Also extract any hashes mentioned in description (MD5, SHA1, SHA256 lines)
            desc = ioc.get('description', '')
            for line in desc.split('\n'):
                if line.startswith('**MD5:**') or line.startswith('**SHA1:**') or line.startswith('**SHA256:**'):
                    hash_val = line.split(':', 1)[-1].strip().lower()
                    if hash_val:
                        seen_values.add(hash_val)
                # Also extract filename from **File:** line
                if line.startswith('**File:**'):
                    filename = line.split(':', 1)[-1].strip().lower()
                    if filename:
                        seen_values.add(filename)

        iocs = timeline_iocs + [ioc for ioc in report_iocs if ioc['value'].lower() not in seen_values]

        log(f"IOCs found: {len(timeline_iocs)} from timeline, {len(report_iocs)} from report, {len(iocs)} total unique")

        # Build client list for summary
        client_names = []
        if clients:
            for c in clients:
                if c and isinstance(c, dict):
                    hostname = c.get('hostname', c.get('os_info', {}).get('hostname', 'Unknown'))
                    client_names.append(hostname)

        # 2. Create case with comprehensive description
        case_description = f"""## Automated Forensic Analysis

**Analysis Type:** {blueprint_name or 'Agentic Pipeline'}
**Run ID:** {run_id}
**Created:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}

### Scope
- **Systems Analyzed:** {len(clients) if clients else 0} ({', '.join(client_names[:5])}{'...' if len(client_names) > 5 else ''})
- **Timeline Events:** {len(timeline_events)}
- **IOCs Identified:** {len(iocs)}

### Data Sources
This case was automatically created by the Intact.AI Agentic Analysis module using Velociraptor forensic collection.

---
*For detailed findings, see the attached forensic reports.*
"""

        case_result = create_iris_case(case_name, case_description, iris_config, api_key, logger)
        if not case_result:
            result['error'] = "Failed to create IRIS case"
            return result

        case_id = case_result['case_id']
        result['case_id'] = case_id

        # Build case URL
        external_host = iris_config.get('external_host', iris_config.get('host', 'https://localhost:8443'))
        result['case_url'] = f"{external_host}/case?cid={case_id}"

        # 3. Add assets (analyzed clients)
        asset_cache = {}
        if clients:
            result['assets_imported'], asset_cache = add_assets(case_id, clients, iris_config, api_key, logger)
            log(f"Asset cache for linking: {asset_cache}")

        # 4. Import timeline events (pass asset_cache for linking)
        if timeline_events:
            result['events_imported'] = add_timeline_events(
                case_id, timeline_events, iris_config, api_key, logger, asset_cache=asset_cache
            )

        # 5. Import IOCs (already extracted above from timeline + report)
        if iocs:
            result['iocs_imported'] = add_iocs(case_id, iocs, iris_config, api_key, logger)

        result['success'] = True
        log(f"IRIS import complete! Case URL: {result['case_url']}", "success")

    except Exception as e:
        result['error'] = str(e)
        log(f"IRIS import failed: {e}", "error")
        log(traceback.format_exc(), "error")

    return result
