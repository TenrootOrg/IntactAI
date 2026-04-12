"""
Azure Log Collection Module

Collects logs from Microsoft Graph API and supports offline (manual upload) mode.
Automatic license tier detection (Free/P1/P2).
"""

import os
import json
import time
import tempfile
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from pathlib import Path


# =============================================================================
# Constants
# =============================================================================

# Graph API endpoints per source type
GRAPH_ENDPOINTS = {
    'signin_logs': {
        'endpoint': '/auditLogs/signIns',
        'time_field': 'createdDateTime',
        'user_field': 'userPrincipalName',
        'ip_field': 'ipAddress',
    },
    'audit_logs': {
        'endpoint': '/auditLogs/directoryAudits',
        'time_field': 'activityDateTime',
        'user_field': 'initiatedBy/user/userPrincipalName',
        'ip_field': None,
    },
    'risky_signins': {
        'endpoint': '/identityProtection/riskySignIns',
        'time_field': 'riskLastUpdatedDateTime',
        'user_field': 'userPrincipalName',
        'ip_field': 'ipAddress',
    },
    'risk_detections': {
        'endpoint': '/identityProtection/riskDetections',
        'time_field': 'detectedDateTime',
        'user_field': 'userPrincipalName',
        'ip_field': 'ipAddress',
    },
    'security_alerts': {
        'endpoint': '/security/alerts_v2',
        'time_field': 'createdDateTime',
        'user_field': None,
        'ip_field': None,
    },
    # State-snapshot sources (no time_field — current state, not events)
    'ca_policies': {
        'endpoint': '/identity/conditionalAccess/policies',
        'time_field': None,  # state snapshot
        'user_field': None,
        'ip_field': None,
    },
    'federation': {
        'endpoint': '/domains',
        'time_field': None,  # state snapshot
        'user_field': None,
        'ip_field': None,
    },
}

# Log source types with their license requirements and tier
LOG_SOURCES = {
    # Tier 1: Microsoft Detections (low volume, high value)
    'security_alerts': {
        'name': 'Security Alerts',
        'license': 'free',
        'sigma_prefix': 'Azure.SecurityAlert',
        'tier': 1
    },
    'risk_detections': {
        'name': 'Risk Detections',
        'license': 'p2',
        'sigma_prefix': 'Azure.RiskDetection',
        'tier': 1
    },
    'risky_signins': {
        'name': 'Risky Sign-ins',
        'license': 'p2',
        'sigma_prefix': 'Azure.RiskySignIn',
        'tier': 1
    },
    # Tier 2: Targeted queries (filtered by user/IP)
    'signin_logs': {
        'name': 'Sign-in Logs',
        'license': 'free',
        'sigma_prefix': 'Azure.SignIn',
        'tier': 2
    },
    'audit_logs': {
        'name': 'Directory Audit Logs',
        'license': 'free',
        'sigma_prefix': 'Azure.Audit',
        'tier': 2
    },
    # Tier 3: External tools (DFIR-O365RC)
    'unified_audit': {
        'name': 'Unified Audit Log',
        'license': 'free',
        'sigma_prefix': 'Azure.UnifiedAudit',
        'tier': 3
    },
    'activity_logs': {
        'name': 'Azure Activity Logs',
        'license': 'free',
        'sigma_prefix': 'Azure.Activity',
        'tier': 3
    },
    # Tier 4: State / posture snapshots (no event timeline; analyzed for outliers)
    'ca_policies': {
        'name': 'Conditional Access Policies',
        'license': 'p1',
        'sigma_prefix': 'Azure.CAPolicy',
        'tier': 4,
        'is_state': True,
    },
    'federation': {
        'name': 'Federation / Domain Settings',
        'license': 'free',
        'sigma_prefix': 'Azure.Federation',
        'tier': 4,
        'is_state': True,
    }
}

SUPPORTED_FORMATS = ['.json', '.jsonl', '.csv']

GRAPH_BASE_URL = 'https://graph.microsoft.com/v1.0'


# =============================================================================
# Authentication
# =============================================================================

def get_access_token(azure_config: Dict[str, str]) -> str:
    """Get OAuth2 access token using client credentials flow."""
    tenant_id = azure_config.get('tenant_id', '')
    client_id = azure_config.get('client_id', '')
    client_secret = azure_config.get('client_secret', '')

    if not all([tenant_id, client_id, client_secret]):
        raise ValueError("Missing Azure credentials (tenant_id, client_id, or client_secret)")

    token_url = f'https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token'
    token_data = {
        'grant_type': 'client_credentials',
        'client_id': client_id,
        'client_secret': client_secret,
        'scope': 'https://graph.microsoft.com/.default'
    }

    resp = requests.post(token_url, data=token_data, timeout=30)
    if resp.status_code != 200:
        error = resp.json().get('error_description', resp.text[:200])
        raise ValueError(f"Authentication failed: {error}")

    return resp.json()['access_token']


# =============================================================================
# Graph API Collection
# =============================================================================

def graph_request(token: str, endpoint: str, params: Optional[Dict] = None,
                  extra_headers: Optional[Dict] = None) -> requests.Response:
    """Make authenticated request to Microsoft Graph API with retry on 429.

    `extra_headers` is merged into the request headers — used for advanced query
    filters that require `ConsistencyLevel: eventual`.
    """
    url = endpoint if endpoint.startswith('http') else f'{GRAPH_BASE_URL}{endpoint}'
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }
    if extra_headers:
        headers.update(extra_headers)

    for attempt in range(3):
        resp = requests.get(url, headers=headers, params=params, timeout=30)
        if resp.status_code == 429:
            retry_after = int(resp.headers.get('Retry-After', 10))
            print(f"[AZURE] Rate limited, waiting {retry_after}s...")
            time.sleep(retry_after)
            continue
        return resp

    return resp  # Return last response after retries


def collect_with_pagination(token: str, endpoint: str, time_filter: Optional[str] = None,
                           max_records: int = 10000,
                           extra_headers: Optional[Dict] = None,
                           extra_params: Optional[Dict] = None) -> Optional[List[Dict]]:
    """
    Collect records from Graph API with pagination.

    Args:
        extra_headers: Merged into request headers (e.g. `{'ConsistencyLevel': 'eventual'}`
                       for advanced sign-in filters).
        extra_params: Merged into query params (e.g. `{'$count': 'true'}`).

    Returns:
        List of records, or None if 403 (license tier doesn't include this source)
    """
    records = []
    params = {'$top': '999'}
    if time_filter:
        params['$filter'] = time_filter
    if extra_params:
        params.update(extra_params)

    # Allow absolute URLs (e.g. for the beta endpoint) — only prepend the base
    # for relative paths starting with '/'.
    url = endpoint if endpoint.startswith('http') else f'{GRAPH_BASE_URL}{endpoint}'

    while url and len(records) < max_records:
        resp = graph_request(token, url, params, extra_headers=extra_headers)

        if resp.status_code == 403:
            return None  # Source not available at this license tier
        if resp.status_code == 401:
            raise ValueError("Authentication failed - check credentials and API permissions")
        if resp.status_code != 200:
            raise Exception(f"Graph API error {resp.status_code}: {resp.text[:200]}")

        data = resp.json()
        records.extend(data.get('value', []))

        # Follow pagination
        url = data.get('@odata.nextLink')
        params = None  # nextLink already includes query params

    return records


# =============================================================================
# Online Collection
# =============================================================================

def build_odata_filter(time_field: str, start_date: str, end_date: Optional[str] = None,
                       user_field: Optional[str] = None, target_users: Optional[List[str]] = None,
                       ip_field: Optional[str] = None, target_ips: Optional[List[str]] = None) -> str:
    """Build OData $filter string with time, user, and IP filters."""
    filters = [f"{time_field} ge {start_date}"]

    if end_date:
        filters.append(f"{time_field} le {end_date}")

    # User filter (OR across multiple users)
    if target_users and user_field:
        if len(target_users) == 1:
            filters.append(f"{user_field} eq '{target_users[0]}'")
        else:
            user_clauses = ' or '.join(f"{user_field} eq '{u}'" for u in target_users)
            filters.append(f"({user_clauses})")

    # IP filter (OR across multiple IPs)
    if target_ips and ip_field:
        if len(target_ips) == 1:
            filters.append(f"{ip_field} eq '{target_ips[0]}'")
        else:
            ip_clauses = ' or '.join(f"{ip_field} eq '{ip}'" for ip in target_ips)
            filters.append(f"({ip_clauses})")

    return ' and '.join(filters)


def _get_source_fix(source: str) -> str:
    """Get actionable fix message for unavailable sources."""
    from .dfir_o365rc import is_available as dfir_available

    fixes = {
        'security_alerts': 'Missing API permission: SecurityAlert.Read.All (and optionally SecurityIncident.Read.All). Add to App Registration → API permissions.',
        'risk_detections': 'Requires Azure AD P2 license. Upgrade at Azure Portal → Entra ID → Licenses.',
        'risky_signins': 'Requires Azure AD P2 license. Upgrade at Azure Portal → Entra ID → Licenses.',
        'activity_logs': 'Not available via Graph API. Requires Azure CLI or DFIR-O365RC.',
    }

    if source == 'unified_audit':
        status = dfir_available()
        if not status['has_image']:
            return 'DFIR-O365RC not installed. Run: docker pull anssi/dfir-o365rc:latest'
        elif not status['has_certificate']:
            return 'Certificate not generated. Run install.sh or go to Settings → Cloud → Azure.'
        else:
            return 'Certificate not uploaded to Azure App Registration. Go to Settings → Cloud → Azure for instructions.'

    return fixes.get(source, 'Source not available with current license or API permissions.')


def collect_azure_logs(
    azure_config: Dict[str, str],
    sources: List[str],
    time_range_days: int = 7,
    start_date_str: Optional[str] = None,
    end_date_str: Optional[str] = None,
    target_users: Optional[List[str]] = None,
    target_ips: Optional[List[str]] = None,
    pivot_mode: bool = False,
    output_dir: Optional[str] = None,
    logger=None,
    run_id: str = None
) -> Tuple[Dict[str, List[Dict]], Dict[str, str]]:
    """
    Collect Azure/M365 logs from Microsoft Graph API with identity filters.

    Args:
        azure_config: Dict with tenant_id, client_id, client_secret
        sources: List of source types to collect (or ['all'] for all available)
        time_range_days: Number of days to look back (used if start_date_str not provided)
        start_date_str: Explicit start date (ISO format)
        end_date_str: Explicit end date (ISO format)
        target_users: List of email addresses to filter by
        target_ips: List of IP addresses to filter by
        pivot_mode: If True, discover IPs from target users then search all users from those IPs
        output_dir: Directory for output files (unused, kept for API compatibility)

    Returns:
        Tuple of (collected_data dict, status dict)
    """
    log = logger or (lambda msg, level="info": print(f"[AZURE] {msg}"))

    # Authenticate
    log("Authenticating with Microsoft Graph API...", "info")
    token = get_access_token(azure_config)
    log("Authentication successful", "info")

    # Detect license tier
    license_tier = detect_license_tier(token)
    log(f"Detected license tier: {license_tier.upper()}", "info")

    # Filter sources based on license
    available_sources = get_available_sources(sources, license_tier)

    status = {
        'license_tier': license_tier,
        'requested_sources': sources,
        'available_sources': available_sources,
        'skipped_sources': [s for s in sources if s not in available_sources and s != 'all'],
        'collection_start': datetime.utcnow().isoformat(),
        'target_users': target_users or [],
        'target_ips': target_ips or [],
        'pivot_mode': pivot_mode,
        'errors': []
    }

    collected_data = {}

    # Calculate time window
    if start_date_str:
        start_date = start_date_str
    else:
        start_date = (datetime.utcnow() - timedelta(days=time_range_days)).strftime('%Y-%m-%dT%H:%M:%SZ')
    end_date = end_date_str  # None = now

    if target_users:
        log(f"Target users: {', '.join(target_users)}", "info")
    if target_ips:
        log(f"Target IPs: {', '.join(target_ips)}", "info")

    for source in available_sources:
        source_info = LOG_SOURCES.get(source, {})
        source_name = source_info.get('name', source)
        graph_info = GRAPH_ENDPOINTS.get(source)

        if not graph_info:
            # Try DFIR-O365RC for unified_audit
            if source == 'unified_audit':
                from .dfir_o365rc import is_available as dfir_available, collect_unified_audit_log
                dfir_status = dfir_available()
                if dfir_status['available']:
                    log(f"Collecting {source_name} via DFIR-O365RC...", "info")
                    try:
                        ual_result = collect_unified_audit_log(
                            tenant=azure_config.get('tenant_id', ''),
                            app_id=azure_config.get('client_id', ''),
                            start_date=start_date,
                            end_date=end_date or datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),
                            target_users=target_users,
                            logger=log,
                            azure_config=azure_config,
                            run_id=run_id
                        )
                        if ual_result.get('skipped'):
                            log(f"{source_name} skipped: {ual_result.get('reason', 'Exchange Online not available')}", "info")
                        elif ual_result['success'] and ual_result['records']:
                            normalized = normalize_logs(ual_result['records'], source_info.get('sigma_prefix', source))
                            collected_data[source_info['sigma_prefix']] = normalized
                            log(f"Collected {len(normalized)} records from {source_name}", "success")
                        elif ual_result['error']:
                            status['errors'].append(f"{source_name}: {ual_result['error']}")
                            log(f"{source_name}: {ual_result['error'][:200]}", "warning")
                        else:
                            log(f"No records found for {source_name}", "info")
                    except Exception as e:
                        status['errors'].append(f"{source_name}: {str(e)}")
                        log(f"{source_name}: {str(e)[:200]}", "warning")
                    continue

            # Try DFIR-O365RC for activity_logs (Azure RM Activity Logs - no Exchange needed)
            if source == 'activity_logs':
                from .dfir_o365rc import is_available as dfir_available, collect_azure_activity_logs
                dfir_status = dfir_available()
                if dfir_status['available']:
                    log(f"Collecting {source_name} via DFIR-O365RC...", "info")
                    try:
                        act_result = collect_azure_activity_logs(
                            tenant=azure_config.get('tenant_id', ''),
                            app_id=azure_config.get('client_id', ''),
                            start_date=start_date,
                            end_date=end_date or datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),
                            logger=log
                        )
                        if act_result['success'] and act_result['records']:
                            normalized = normalize_logs(act_result['records'], source_info.get('sigma_prefix', source))
                            collected_data[source_info['sigma_prefix']] = normalized
                            log(f"Collected {len(normalized)} records from {source_name}", "success")
                        elif act_result.get('error'):
                            status['errors'].append(f"{source_name}: {act_result['error']}")
                            log(f"{source_name}: {act_result['error'][:200]}", "warning")
                        else:
                            log(f"No records found for {source_name}", "info")
                    except Exception as e:
                        status['errors'].append(f"{source_name}: {str(e)}")
                        log(f"{source_name}: {str(e)[:200]}", "warning")
                    continue

            fix = _get_source_fix(source)
            log(f"Skipped {source_name}: {fix}", "warning")
            status['errors'].append(f"{source_name}: {fix}")
            continue

        log(f"Collecting {source_name}...", "info")

        # State-snapshot sources (current configuration, not events)
        if source_info.get('is_state'):
            try:
                if source == 'ca_policies':
                    records = collect_ca_policies(token, log)
                elif source == 'federation':
                    records = collect_federation(token, log)
                else:
                    records = []

                if records:
                    # Tag with severity per-record (state sources don't go through SIGMA)
                    scored = _score_state_records(source, records)
                    normalized = normalize_logs(scored, source_info.get('sigma_prefix', source))
                    collected_data[source_info['sigma_prefix']] = normalized
                    log(f"Collected {len(normalized)} {source_name} (current state)", "success")
                else:
                    log(f"No {source_name} found", "info")
            except Exception as e:
                error_msg = f"Failed to collect {source_name}: {str(e)}"
                status['errors'].append(error_msg)
                log(f"{error_msg}", "error")
            continue

        try:
            odata_filter = build_odata_filter(
                time_field=graph_info['time_field'],
                start_date=start_date,
                end_date=end_date,
                user_field=graph_info.get('user_field'),
                target_users=target_users,
                ip_field=graph_info.get('ip_field'),
                target_ips=target_ips
            )

            data = collect_with_pagination(token, graph_info['endpoint'], odata_filter)

            if data is None:
                fix = _get_source_fix(source)
                log(f"Skipped {source_name}: {fix}", "warning")
                status['errors'].append(f"{source_name}: {fix}")
                continue

            # For signin_logs, ALSO query FAILED service principal sign-ins.
            #
            # We deliberately do NOT collect:
            #   - successful SP sign-ins (mostly Microsoft first-party app token
            #     refreshes — 99% noise; would add 8000+ records on a typical tenant)
            #   - managed identity sign-ins (almost always Azure RM internal noise)
            #   - non-interactive user sign-ins (token refreshes; the rare attack
            #     case is already covered by risk_detections / risky_signins via
            #     Identity Protection)
            #
            # FAILED service principal sign-ins are the high-signal subset:
            #   - SP credential brute-force / stuffing attempts
            #   - Misconfigured automation (operationally interesting)
            #   - Tiny volume (~0-20 per healthy tenant)
            #
            # Filtering on signInEventTypes requires the Microsoft Graph BETA
            # endpoint + advanced query mode (ConsistencyLevel: eventual +
            # $count=true). The v1.0 endpoint does not expose this property.
            if source == 'signin_logs' and data is not None:
                advanced_headers = {'ConsistencyLevel': 'eventual'}
                advanced_params = {'$count': 'true'}
                beta_endpoint = graph_info['endpoint']  # e.g. /auditLogs/signIns
                try:
                    # SP sign-ins are TENANT-WIDE events (no user). Strip the
                    # target_users clause from the filter — we only want the time
                    # window. SPs don't have userPrincipalName, so combining the
                    # user filter would return 0 results.
                    sp_time_filter = build_odata_filter(
                        time_field=graph_info['time_field'],
                        start_date=start_date,
                        end_date=end_date,
                        user_field=None,        # NOT filtered by user
                        target_users=None,
                        ip_field=None,
                        target_ips=None,
                    )
                    sp_filter = (
                        "signInEventTypes/any(t:t eq 'servicePrincipal') "
                        "and status/errorCode ne 0"
                    )
                    combined = f"({sp_time_filter}) and {sp_filter}" if sp_time_filter else sp_filter
                    beta_url = f'https://graph.microsoft.com/beta{beta_endpoint}'
                    extra = collect_with_pagination(
                        token,
                        beta_url,
                        combined,
                        extra_headers=advanced_headers,
                        extra_params=advanced_params,
                    )
                    if extra:
                        for r in extra:
                            r['_signin_type'] = 'servicePrincipal_failed'
                        data.extend(extra)
                        log(f"  +{len(extra)} failed service principal sign-ins", "info")
                    else:
                        log("  No failed service principal sign-ins", "info")
                except Exception as ext_err:
                    log(f"  Failed to fetch SP sign-ins: {str(ext_err)[:120]}", "warning")

                # Tag the existing interactive sign-ins for clarity
                for r in data:
                    if '_signin_type' not in r:
                        r['_signin_type'] = 'interactiveUser'

            if data:
                normalized = normalize_logs(data, source_info.get('sigma_prefix', source))
                collected_data[source_info['sigma_prefix']] = normalized
                log(f"Collected {len(normalized)} records from {source_name}", "success")
            else:
                log(f"No records found for {source_name}", "info")

        except ValueError as e:
            raise  # Re-raise auth errors
        except Exception as e:
            error_msg = f"Failed to collect {source_name}: {str(e)}"
            status['errors'].append(error_msg)
            log(f"{error_msg}", "error")

    # Pivot Mode: discover IPs from target users, then search for other users from those IPs
    if pivot_mode and target_users and 'Azure.SignIn' in collected_data:
        discovered_ips = set()
        for record in collected_data['Azure.SignIn']:
            ip = record.get('ipAddress')
            if ip and ip not in (target_ips or []):
                discovered_ips.add(ip)

        if discovered_ips:
            log(f"Pivot: Discovered {len(discovered_ips)} IPs from target users: {', '.join(discovered_ips)}", "info")
            status['discovered_ips'] = list(discovered_ips)

            # Search sign-ins from discovered IPs (without user filter = all users)
            try:
                pivot_filter = build_odata_filter(
                    time_field='createdDateTime',
                    start_date=start_date,
                    end_date=end_date,
                    ip_field='ipAddress',
                    target_ips=list(discovered_ips)
                )
                pivot_data = collect_with_pagination(token, '/auditLogs/signIns', pivot_filter)

                if pivot_data:
                    # Filter out records we already have (target users)
                    new_records = [r for r in pivot_data if r.get('userPrincipalName', '').lower() not in
                                   [u.lower() for u in target_users]]
                    if new_records:
                        normalized_pivot = normalize_logs(new_records, 'Azure.SignIn.Pivot')
                        collected_data['Azure.SignIn.Pivot'] = normalized_pivot
                        pivot_users = set(r.get('userPrincipalName', '') for r in new_records)
                        log(f"Pivot: Found {len(new_records)} sign-ins from {len(pivot_users)} other users: {', '.join(pivot_users)}", "info")
                        status['pivot_users'] = list(pivot_users)
                    else:
                        print("[AZURE] Pivot: No other users found from discovered IPs")
            except Exception as e:
                log(f"Pivot search failed: {e}", "error")
                status['errors'].append(f"Pivot search failed: {e}")

    status['collection_end'] = datetime.utcnow().isoformat()
    status['total_records'] = sum(len(v) for v in collected_data.values())

    return collected_data, status


def detect_license_tier(token: str) -> str:
    """
    Detect Azure AD license tier by probing Graph API endpoints.

    Args:
        token: OAuth2 access token (not azure_config - already authenticated)

    Returns: 'free', 'p1', or 'p2'
    """
    # Try P2 endpoint (risky sign-ins)
    resp = graph_request(token, '/identityProtection/riskySignIns', {'$top': '1'})
    if resp.status_code == 200:
        return 'p2'

    # Try sign-in logs (available to P1+, limited on free)
    resp = graph_request(token, '/auditLogs/signIns', {'$top': '1'})
    if resp.status_code == 200:
        return 'p1'

    return 'free'


def get_available_sources(requested: List[str], license_tier: str) -> List[str]:
    """Get sources available for the detected license tier."""
    tier_levels = {'free': 0, 'p1': 1, 'p2': 2}
    current_level = tier_levels.get(license_tier, 0)

    if 'all' in requested:
        return [
            source for source, info in LOG_SOURCES.items()
            if tier_levels.get(info['license'], 0) <= current_level
        ]

    available = []
    for source in requested:
        info = LOG_SOURCES.get(source, {})
        source_level = tier_levels.get(info.get('license', 'free'), 0)
        if source_level <= current_level:
            available.append(source)

    return available


# =============================================================================
# Offline Collection (Manual Upload)
# =============================================================================

def parse_uploaded_logs(
    file_path: str,
    source_type: Optional[str] = None
) -> Tuple[Dict[str, List[Dict]], Dict[str, Any]]:
    """
    Parse uploaded log files (JSON, JSONL, CSV).

    Args:
        file_path: Path to uploaded file
        source_type: Optional source type hint (auto-detected if not provided)

    Returns:
        Tuple of (parsed_data dict, parse_status dict)
    """
    status = {
        'file_path': file_path,
        'file_size': os.path.getsize(file_path),
        'parse_start': datetime.utcnow().isoformat(),
        'errors': []
    }

    ext = Path(file_path).suffix.lower()
    if ext not in SUPPORTED_FORMATS:
        raise ValueError(f"Unsupported file format: {ext}. Supported: {SUPPORTED_FORMATS}")

    try:
        if ext == '.json':
            data = parse_json_file(file_path)
        elif ext == '.jsonl':
            data = parse_jsonl_file(file_path)
        elif ext == '.csv':
            data = parse_csv_file(file_path)
        else:
            data = []
    except Exception as e:
        status['errors'].append(f"Parse error: {str(e)}")
        data = []

    if source_type is None and data:
        source_type = detect_source_type(data[0])

    sigma_prefix = LOG_SOURCES.get(source_type, {}).get('sigma_prefix', 'Azure.Unknown')
    normalized = normalize_logs(data, sigma_prefix)

    status['parse_end'] = datetime.utcnow().isoformat()
    status['record_count'] = len(normalized)
    status['detected_source'] = source_type

    return {sigma_prefix: normalized}, status


def parse_json_file(file_path: str) -> List[Dict]:
    """Parse JSON file (array or object with value/data key)."""
    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    if isinstance(data, list):
        return data
    elif isinstance(data, dict):
        for key in ['value', 'data', 'results', 'records', 'events']:
            if key in data and isinstance(data[key], list):
                return data[key]
        return [data]

    return []


def parse_jsonl_file(file_path: str) -> List[Dict]:
    """Parse JSON Lines file (one JSON object per line)."""
    records = []
    with open(file_path, 'r', encoding='utf-8') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError as e:
                    print(f"[AZURE] Warning: Skipping invalid JSON at line {line_num}: {e}")
    return records


def parse_csv_file(file_path: str) -> List[Dict]:
    """Parse CSV file to list of dicts."""
    import csv

    records = []
    with open(file_path, 'r', encoding='utf-8', newline='') as f:
        sample = f.read(4096)
        f.seek(0)

        try:
            dialect = csv.Sniffer().sniff(sample)
        except:
            dialect = csv.excel

        reader = csv.DictReader(f, dialect=dialect)
        for row in reader:
            cleaned = {k: (v if v != '' else None) for k, v in row.items()}
            records.append(cleaned)

    return records


def detect_source_type(sample_record: Dict) -> Optional[str]:
    """Auto-detect log source type from record fields."""
    fields = set(sample_record.keys())

    signin_fields = {'userPrincipalName', 'ipAddress', 'clientAppUsed', 'conditionalAccessStatus'}
    if signin_fields & fields:
        return 'signin_logs'

    audit_fields = {'activityDisplayName', 'category', 'operationType', 'targetResources'}
    if audit_fields & fields:
        return 'audit_logs'

    risk_fields = {'riskLevel', 'riskState', 'riskDetail', 'riskEventType'}
    if risk_fields & fields:
        return 'risk_detections'

    ual_fields = {'RecordType', 'Operation', 'UserId', 'Workload'}
    if ual_fields & fields:
        return 'unified_audit'

    activity_fields = {'operationName', 'resourceType', 'caller', 'correlationId'}
    if activity_fields & fields:
        return 'activity_logs'

    return None


# =============================================================================
# Data Normalization
# =============================================================================

def normalize_logs(records: List[Dict], source_prefix: str) -> List[Dict]:
    """Normalize log records to standard format for SIGMA processing."""
    normalized = []

    for record in records:
        norm_record = {
            '_source': source_prefix,
            '_original': record.copy()
        }
        norm_record.update(record)

        timestamp = extract_timestamp(record)
        if timestamp:
            norm_record['_timestamp'] = timestamp

        normalized.append(norm_record)

    return normalized


def extract_timestamp(record: Dict) -> Optional[str]:
    """Extract timestamp from record using common Azure timestamp fields."""
    timestamp_fields = [
        'createdDateTime', 'activityDateTime', 'timestamp',
        'TimeGenerated', 'CreationTime', 'eventDateTime',
        'detectedDateTime', 'lastUpdatedDateTime'
    ]

    for field in timestamp_fields:
        for key in record.keys():
            if key.lower() == field.lower():
                value = record[key]
                if value:
                    return str(value)

    return None


# =============================================================================
# State-snapshot collectors (current configuration, not events)
# =============================================================================

def collect_ca_policies(token: str, log_func) -> List[Dict]:
    """Fetch all Conditional Access policies as a state snapshot.

    Returns a list of policy dicts with the relevant fields kept.
    Filters out noise (only the fields the analyst cares about).
    """
    try:
        resp = graph_request(token, '/identity/conditionalAccess/policies')
    except Exception as e:
        log_func(f"  CA policies request failed: {e}", "warning")
        return []

    if resp.status_code != 200:
        try:
            err = resp.json().get('error', {}).get('message', resp.text[:200])
        except Exception:
            err = resp.text[:200]
        log_func(f"  CA policies query failed (HTTP {resp.status_code}): {err}", "warning")
        return []

    policies = resp.json().get('value', [])
    cleaned = []
    for p in policies:
        cleaned.append({
            'id': p.get('id'),
            'displayName': p.get('displayName'),
            'state': p.get('state'),  # enabled / disabled / enabledForReportingButNotEnforced
            'createdDateTime': p.get('createdDateTime'),
            'modifiedDateTime': p.get('modifiedDateTime'),
            'conditions': {
                'users': (p.get('conditions') or {}).get('users') or {},
                'applications': (p.get('conditions') or {}).get('applications') or {},
                'platforms': (p.get('conditions') or {}).get('platforms') or {},
                'locations': (p.get('conditions') or {}).get('locations') or {},
                'clientAppTypes': (p.get('conditions') or {}).get('clientAppTypes') or [],
            },
            'grantControls': p.get('grantControls') or {},
            'sessionControls': p.get('sessionControls') or {},
        })
    return cleaned


def collect_federation(token: str, log_func) -> List[Dict]:
    """Fetch all domains and their federation configuration.

    Returns a list of domain dicts. For federated domains, also includes
    the federationConfiguration (issuer, signing cert, etc).
    """
    try:
        resp = graph_request(token, '/domains')
    except Exception as e:
        log_func(f"  Domains request failed: {e}", "warning")
        return []

    if resp.status_code != 200:
        try:
            err = resp.json().get('error', {}).get('message', resp.text[:200])
        except Exception:
            err = resp.text[:200]
        log_func(f"  Domains query failed (HTTP {resp.status_code}): {err}", "warning")
        return []

    domains = resp.json().get('value', [])
    out = []
    for d in domains:
        entry = {
            'id': d.get('id'),  # the domain name
            'authenticationType': d.get('authenticationType'),  # Managed | Federated
            'isVerified': d.get('isVerified'),
            'isDefault': d.get('isDefault'),
            'isInitial': d.get('isInitial'),
            'supportedServices': d.get('supportedServices') or [],
        }
        # If federated, fetch the federation configuration
        if d.get('authenticationType') == 'Federated':
            try:
                fed_resp = graph_request(token, f"/domains/{d.get('id')}/federationConfiguration")
                if fed_resp.status_code == 200:
                    fed_list = fed_resp.json().get('value', [])
                    if fed_list:
                        f = fed_list[0]
                        entry['federationConfiguration'] = {
                            'issuerUri': f.get('issuerUri'),
                            'passiveSignInUri': f.get('passiveSignInUri'),
                            'activeSignInUri': f.get('activeSignInUri'),
                            'metadataExchangeUri': f.get('metadataExchangeUri'),
                            'preferredAuthenticationProtocol': f.get('preferredAuthenticationProtocol'),
                            'signingCertificate': (f.get('signingCertificate') or '')[:60] + '...' if f.get('signingCertificate') else None,
                            'nextSigningCertificate': (f.get('nextSigningCertificate') or '')[:60] + '...' if f.get('nextSigningCertificate') else None,
                        }
            except Exception as fed_err:
                entry['federationConfigurationError'] = str(fed_err)[:200]
        out.append(entry)
    return out


def _score_state_records(source: str, records: List[Dict]) -> List[Dict]:
    """Tag state-snapshot records with severity / category.

    Mirrors the pattern in dfir_o365rc.filter_and_score_ual_records but for
    inventory data: each item gets a `_severity`, `_category`, `_description`
    so the analyzer can group/filter via the same severity ladder used for
    UAL events. The same `min_severity` UI filter applies.
    """
    out = []

    if source == 'ca_policies':
        # Find which CA policies cover admin roles
        for p in records:
            state = p.get('state')
            name = p.get('displayName', '?')
            grant = p.get('grantControls') or {}
            built_in_controls = grant.get('builtInControls') or []
            users = (p.get('conditions') or {}).get('users') or {}
            include_roles = users.get('includeRoles') or []
            include_users = users.get('includeUsers') or []
            include_groups = users.get('includeGroups') or []

            # Defaults
            severity = 'low'
            category = 'compliance'
            description = f'CA policy "{name}" — {state}'

            # Disabled policies are findings
            if state == 'disabled':
                severity = 'medium'
                description = f'CA policy "{name}" is DISABLED'
                # Disabled and targeting admins → high
                if include_roles or 'All' in include_users:
                    severity = 'high'
                    description = f'CA policy "{name}" is DISABLED — was targeting admins/all users'
            elif state == 'enabledForReportingButNotEnforced':
                severity = 'medium'
                description = f'CA policy "{name}" is in REPORT-ONLY mode (not enforced)'
                if include_roles or 'All' in include_users:
                    severity = 'high'
                    description = f'CA policy "{name}" is REPORT-ONLY — was targeting admins/all users'
            elif state == 'enabled':
                # Enabled = healthy unless missing key controls
                if not built_in_controls:
                    severity = 'medium'
                    description = f'CA policy "{name}" is ENABLED but has no grant controls (allows all)'
                elif 'mfa' in [c.lower() for c in built_in_controls]:
                    severity = 'informational'
                    description = f'CA policy "{name}" enforces MFA'

            p['_severity'] = severity
            p['_category'] = category
            p['_description'] = description
            out.append(p)
        return out

    if source == 'federation':
        for d in records:
            name = d.get('id', '?')
            auth_type = d.get('authenticationType')
            is_verified = d.get('isVerified')

            severity = 'informational'
            category = 'identity_trust'
            description = f'Domain {name} ({auth_type})'

            if auth_type == 'Federated':
                severity = 'medium'  # Federation is always worth noting
                fed_cfg = d.get('federationConfiguration') or {}
                issuer = fed_cfg.get('issuerUri', '')
                description = f'Federated domain {name} → {issuer or "unknown issuer"}'
                # Broken federation = high
                if d.get('federationConfigurationError') or not fed_cfg:
                    severity = 'high'
                    description = f'Federated domain {name} but federation config is missing/unreadable'
                # Unverified federated = critical
                if not is_verified:
                    severity = 'high'
                    description = f'UNVERIFIED federated domain {name} → {issuer or "unknown"}'
            elif auth_type == 'Managed':
                # Managed domains are normal — only flag if unverified
                if not is_verified:
                    severity = 'low'
                    description = f'Unverified managed domain {name}'
                else:
                    severity = 'informational'
                    description = f'Managed domain {name} (verified)'

            d['_severity'] = severity
            d['_category'] = category
            d['_description'] = description
            out.append(d)
        return out

    return records
