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
from services.iris_service._iocs import *  # noqa: F401,F403
from services.iris_service._iocs import _merge_ioc_sets  # underscore helper not covered by import *

def _get_iris_api_key(iris_config: dict, logger: Callable = None) -> Optional[str]:
    """Get IRIS API key. Three-tier resolution.

    1. iris_config['api_key'] — typically populated at backend import time
       by config.py:_load_iris_api_key from the secrets DB.
    2. Fresh secrets-table read — handles the case where install.sh wrote
       the key AFTER the backend started, so the import-time snapshot is
       stale and a backend restart wasn't done. We pick it up live.
       Also self-heals: if we successfully fetch from the iris-db
       fallback (step 3), we persist it back to the secrets table so the
       next call uses the fast path.
    3. docker-exec fallback into intact_iris_db — final safety net if
       nothing else has it.

    Returns the api_key string, or None if every path failed.
    """
    def log(message, level="info"):
        print(f"[IRIS] {message}", flush=True)
        if logger:
            try:
                logger(f"[IRIS] {message}", level)
            except:
                pass

    # 1. Snapshot from backend startup
    api_key = iris_config.get('api_key')
    if api_key:
        log("Using API key from configuration")
        return api_key

    # 2. Fresh DB read — handles "install.sh wrote after backend started"
    try:
        from services.storage.secret_store import get_secret
        api_key = get_secret('iris.administrator.api_key')
        if api_key:
            log("Using API key from secrets table (fresh read)")
            iris_config['api_key'] = api_key  # cache on the config dict
            return api_key
    except Exception as e:
        log(f"Secret store unavailable: {e}", "warning")

    # 3. Last resort: docker-exec into the IRIS Postgres container
    try:
        import subprocess
        result = subprocess.run(
            ['docker', 'exec', 'intact_iris_db', 'psql', '-U', 'iris', '-d', 'iris_db', '-t', '-c',
             "SELECT api_key FROM \"user\" WHERE name='administrator';"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0 and result.stdout.strip():
            api_key = result.stdout.strip()
            log("Retrieved API key from IRIS database (docker-exec fallback)")
            # Self-heal: persist to secrets table so next call hits step 2
            try:
                from services.storage.secret_store import set_secret
                set_secret('iris.administrator.api_key', api_key)
                iris_config['api_key'] = api_key
                log("Cached API key in secrets table for future calls")
            except Exception:
                pass
            return api_key
    except Exception as e:
        log(f"Could not retrieve API key via docker-exec: {e}", "warning")

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
    skipped_empty = 0

    for i, event in enumerate(events):
        # Skip None or non-dict events
        if not event or not isinstance(event, dict):
            errors += 1
            continue

        # Skip events that have no real content. The build_rich_description
        # path can produce "**Finding:** Unknown" + the generic "Why" line
        # when an artifact's row has neither a recognisable Name field nor
        # a Detection.Name nested value (commonly seen in
        # DetectRaptor.Windows.Detection.* artifacts with sparse rows).
        # Combined with no timestamp, these events pollute the IRIS case
        # with "[INVESTIGATE] Detection: Alert" entries the analyst can't
        # act on. Filter them at the gate so they never get pushed.
        no_timestamp_pre = event.get('no_timestamp', False)
        desc_pre = event.get('description', '') or ''
        title_pre = event.get('title', '') or ''
        looks_empty = (
            '**Finding:** Unknown' in desc_pre
            or 'Finding: Unknown' in desc_pre
        )
        looks_generic_title = title_pre.strip() in ('', 'Detection: Alert', 'Alert', 'Event')
        if no_timestamp_pre and looks_empty and looks_generic_title:
            skipped_empty += 1
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
                # Must send an explicit empty string: if omitted, IRIS
                # stores event_tags as NULL, and its own timeline CSV
                # exporter (case.timeline.js timelineToCsv) then calls
                # .replace() on null and the whole "Download as CSV"
                # button throws with no file produced.
                "event_tags": "",
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

    summary = f"Imported {imported_count}/{len(events)} events ({errors} errors"
    if skipped_empty:
        summary += f", {skipped_empty} empty-finding events skipped"
    summary += ")"
    log(summary, "success" if errors == 0 else "warning")

    return imported_count



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
                   artifact_summaries: dict = None,
                   min_ioc_severity: Optional[str] = None,
                   logger: Callable = None) -> dict:
    """Main entry point for importing agentic analysis results to IRIS.

    Orchestrates the full import process:
    1. Get API key
    2. Create a new case
    3. Add assets (analyzed clients)
    4. Import timeline events
    5. Extract IOCs from per-artifact LLM JSON (primary), the raw
       Velociraptor timeline, and the combining LLM report; dedupe
       across sources and import.

    Args:
        run_id: Agentic pipeline run ID (for reference)
        case_name: Name for the IRIS case
        timeline_events: List of timeline event dicts (filtered for display)
        technical_report: Technical report markdown content
        iris_config: IRIS configuration dict
        clients: List of client dicts (hostname, os, client_id) to add as assets
        blueprint_name: Name of the blueprint used for analysis
        all_events_for_iocs: Unfiltered events for IOC extraction (optional, falls back to timeline_events)
        artifact_summaries: {artifact_name: raw_summary_string} from
            analyze_artifacts(). Primary IOC source — each summary holds
            a JSON block with findings/severity/evidence. When None,
            falls back to the timeline + report sources only.
        min_ioc_severity: Optional gate passed to extract_iocs_from_summaries.
            When None (default) every LLM-flagged IOC is pushed.
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

        # IOC extraction — three sources, ranked by signal quality:
        #   1. per-artifact LLM JSON (richest: severity + evidence + MITRE)
        #   2. raw Velociraptor timeline events (rich descriptions, but
        #      hashes/filenames embedded in description text)
        #   3. combining LLM technical report (regex-grade fallback)
        # _merge_ioc_sets dedupes across all three and joins descriptions
        # on collision so the analyst can see every source that flagged
        # a value.
        ioc_source_events = all_events_for_iocs if all_events_for_iocs else timeline_events
        summary_iocs = (
            extract_iocs_from_summaries(artifact_summaries, min_ioc_severity)
            if artifact_summaries else []
        )
        timeline_iocs = extract_iocs_from_timeline(ioc_source_events) if ioc_source_events else []
        report_iocs = parse_iocs_from_report(technical_report) if technical_report else []

        # Pre-seed the dedup with hashes/filenames embedded in timeline IOC
        # descriptions, so a later report-side mention of the same hash is
        # dropped instead of added as a separate record.
        #
        # New canonical shape carries them inside the **Evidence:** line
        # as "MD5=...; SHA1=...; SHA256=...; path=..." — we regex any hex
        # sequence of length 32/40/64 plus any filename-shaped token.
        # Legacy "**MD5:** /**File:**" prefixes are also still scanned for
        # backward-compat with descriptions that pre-date this change.
        pre_seen = set()
        for ioc in timeline_iocs:
            desc = ioc.get("description") or ""
            for m in re.findall(r'\b[a-fA-F0-9]{32,64}\b', desc):
                if len(m) in (32, 40, 64):
                    pre_seen.add(m.lower())
            for m in re.findall(r'(?:^|[\s;=])([\w\-.]+\.(?:exe|dll|ps1|bat|cmd|vbs|js|msi|scr))\b',
                                desc, flags=re.IGNORECASE):
                pre_seen.add(m.lower())
            # Legacy "**MD5:** ...", "**File:** ...", etc. prefixes
            for line in desc.split("\n"):
                for prefix in ("**MD5:**", "**SHA1:**", "**SHA256:**", "**File:**"):
                    if line.startswith(prefix):
                        embedded = line.split(":", 1)[-1].strip().lower()
                        if embedded:
                            pre_seen.add(embedded)

        iocs = _merge_ioc_sets(
            (summary_iocs,  "per-artifact LLM"),
            (timeline_iocs, "Velociraptor timeline"),
            (report_iocs,   "combining LLM report"),
            pre_seen=pre_seen,
        )

        log(
            f"IOCs found: {len(summary_iocs)} from summaries, "
            f"{len(timeline_iocs)} from timeline, {len(report_iocs)} from report, "
            f"{len(iocs)} total unique"
        )

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
