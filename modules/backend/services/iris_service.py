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
            ['docker', 'exec', 'mssp_iris_db', 'psql', '-U', 'iris', '-d', 'iris_db', '-t', '-c',
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
        host = iris_config.get('host', 'http://mssp_iris_app:8000')
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
    soc_id = f"MSSP-{datetime.now().strftime('%Y%m%d-%H%M%S')}"

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


def parse_iocs_from_report(report_content: str) -> List[dict]:
    """Extract IOCs from technical report content.

    Parses for:
    - IP addresses (IPv4)
    - Domains
    - File hashes (MD5, SHA1, SHA256)
    - File paths

    Args:
        report_content: Markdown report text

    Returns:
        List of IOC dicts with type and value
    """
    iocs = []
    seen = set()  # Avoid duplicates

    # Skip well-known safe values
    SAFE_IPS = {'127.0.0.1', '0.0.0.0', '8.8.8.8', '1.1.1.1', '255.255.255.255'}
    SAFE_DOMAINS = {'localhost', 'example.com', 'example.org', 'microsoft.com', 'windows.com'}

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
                iocs.append({
                    'type': 'ip',
                    'type_id': 76,  # IRIS type ID for IP
                    'value': ip,
                    'description': 'Extracted from forensic analysis'
                })

    # MD5 hashes (32 hex chars)
    md5_pattern = r'\b[a-fA-F0-9]{32}\b'
    for match in re.finditer(md5_pattern, report_content):
        hash_val = match.group().lower()
        if hash_val not in seen:
            seen.add(hash_val)
            iocs.append({
                'type': 'md5',
                'type_id': 90,  # IRIS type ID for MD5
                'value': hash_val,
                'description': 'MD5 hash from forensic analysis'
            })

    # SHA1 hashes (40 hex chars)
    sha1_pattern = r'\b[a-fA-F0-9]{40}\b'
    for match in re.finditer(sha1_pattern, report_content):
        hash_val = match.group().lower()
        if hash_val not in seen:
            seen.add(hash_val)
            iocs.append({
                'type': 'sha1',
                'type_id': 111,  # IRIS type ID for SHA1
                'value': hash_val,
                'description': 'SHA1 hash from forensic analysis'
            })

    # SHA256 hashes (64 hex chars)
    sha256_pattern = r'\b[a-fA-F0-9]{64}\b'
    for match in re.finditer(sha256_pattern, report_content):
        hash_val = match.group().lower()
        if hash_val not in seen:
            seen.add(hash_val)
            iocs.append({
                'type': 'sha256',
                'type_id': 113,  # IRIS type ID for SHA256
                'value': hash_val,
                'description': 'SHA256 hash from forensic analysis'
            })

    # Domains (basic pattern - look for domain-like strings)
    domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|ru|cn|tk|xyz|top|info|biz|cc|pw)\b'
    for match in re.finditer(domain_pattern, report_content, re.IGNORECASE):
        domain = match.group().lower()
        if domain not in seen and domain not in SAFE_DOMAINS:
            seen.add(domain)
            iocs.append({
                'type': 'domain',
                'type_id': 20,  # IRIS type ID for domain
                'value': domain,
                'description': 'Domain from forensic analysis'
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
        timeline_events: List of timeline event dicts
        technical_report: Technical report markdown content
        iris_config: IRIS configuration dict
        clients: List of client dicts (hostname, os, client_id) to add as assets
        blueprint_name: Name of the blueprint used for analysis
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

        # Parse IOCs early to include count in description
        iocs = parse_iocs_from_report(technical_report) if technical_report else []

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
This case was automatically created by the MSSP Agentic Analysis module using Velociraptor forensic collection.

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

        # 5. Parse and import IOCs
        if technical_report:
            iocs = parse_iocs_from_report(technical_report)
            if iocs:
                log(f"Found {len(iocs)} IOCs in technical report")
                result['iocs_imported'] = add_iocs(case_id, iocs, iris_config, api_key, logger)

        result['success'] = True
        log(f"IRIS import complete! Case URL: {result['case_url']}", "success")

    except Exception as e:
        result['error'] = str(e)
        log(f"IRIS import failed: {e}", "error")
        log(traceback.format_exc(), "error")

    return result
