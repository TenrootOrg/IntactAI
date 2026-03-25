"""
Azure Log Collection Module

Handles both online (DFIR-O365RC via Docker) and offline (manual upload) collection modes.
Supports automatic license tier detection (Free/P1/P2).
"""

import os
import json
import subprocess
import tempfile
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from pathlib import Path


# =============================================================================
# Constants
# =============================================================================

# Log source types with their license requirements
LOG_SOURCES = {
    'unified_audit': {
        'name': 'Unified Audit Log',
        'license': 'free',
        'dfir_module': 'Get-O365Full',
        'sigma_prefix': 'Azure.UnifiedAudit'
    },
    'signin_logs': {
        'name': 'Sign-in Logs',
        'license': 'free',  # 7 days free, 30 days P1+
        'dfir_module': 'Get-AADSignInLogs',
        'sigma_prefix': 'Azure.SignIn'
    },
    'audit_logs': {
        'name': 'Directory Audit Logs',
        'license': 'free',
        'dfir_module': 'Get-AADAuditLogs',
        'sigma_prefix': 'Azure.Audit'
    },
    'risky_signins': {
        'name': 'Risky Sign-ins',
        'license': 'p2',
        'dfir_module': 'Get-AADRiskySignIns',
        'sigma_prefix': 'Azure.RiskySignIn'
    },
    'risk_detections': {
        'name': 'Risk Detections',
        'license': 'p2',
        'dfir_module': 'Get-AADRiskDetections',
        'sigma_prefix': 'Azure.RiskDetection'
    },
    'activity_logs': {
        'name': 'Azure Activity Logs',
        'license': 'free',
        'dfir_module': 'Get-AzureActivityLogs',
        'sigma_prefix': 'Azure.Activity'
    }
}

# Supported upload formats
SUPPORTED_FORMATS = ['.json', '.jsonl', '.csv']


# =============================================================================
# Online Collection (DFIR-O365RC)
# =============================================================================

def collect_azure_logs(
    azure_config: Dict[str, str],
    sources: List[str],
    time_range_days: int = 7,
    output_dir: Optional[str] = None
) -> Tuple[Dict[str, List[Dict]], Dict[str, str]]:
    """
    Collect Azure/M365 logs using DFIR-O365RC via Docker.

    Args:
        azure_config: Dict with tenant_id, client_id, client_secret
        sources: List of source types to collect (or ['all'] for all available)
        time_range_days: Number of days to look back
        output_dir: Directory for output files (temp dir if not specified)

    Returns:
        Tuple of (collected_data dict, status dict with collection info)
    """
    if output_dir is None:
        output_dir = tempfile.mkdtemp(prefix='azure_collection_')

    # Detect available license tier
    license_tier = detect_license_tier(azure_config)

    # Filter sources based on license
    available_sources = get_available_sources(sources, license_tier)

    status = {
        'license_tier': license_tier,
        'requested_sources': sources,
        'available_sources': available_sources,
        'skipped_sources': [s for s in sources if s not in available_sources and s != 'all'],
        'collection_start': datetime.utcnow().isoformat(),
        'errors': []
    }

    collected_data = {}

    # Create DFIR-O365RC config
    config_path = create_dfir_config(azure_config, output_dir, time_range_days)

    for source in available_sources:
        source_info = LOG_SOURCES.get(source, {})
        print(f"[AZURE] Collecting {source_info.get('name', source)}...")

        try:
            data = run_dfir_collection(
                config_path,
                source_info.get('dfir_module', source),
                output_dir
            )
            if data:
                # Normalize to standard format
                normalized = normalize_logs(data, source_info.get('sigma_prefix', source))
                collected_data[source_info.get('sigma_prefix', source)] = normalized
                print(f"[AZURE] Collected {len(normalized)} records from {source}")
        except Exception as e:
            error_msg = f"Failed to collect {source}: {str(e)}"
            status['errors'].append(error_msg)
            print(f"[AZURE] {error_msg}")

    status['collection_end'] = datetime.utcnow().isoformat()
    status['total_records'] = sum(len(v) for v in collected_data.values())

    return collected_data, status


def detect_license_tier(azure_config: Dict[str, str]) -> str:
    """
    Detect the Azure AD license tier by attempting to access P2 endpoints.

    Returns: 'free', 'p1', or 'p2'
    """
    # For now, attempt to detect by trying endpoints
    # In production, this would make actual API calls

    # Try P2 endpoint (risk detections)
    try:
        # TODO: Implement actual Graph API check
        # For now, default to p1 which is most common
        return 'p1'
    except:
        pass

    return 'free'


def get_available_sources(requested: List[str], license_tier: str) -> List[str]:
    """Get sources available for the detected license tier."""
    tier_levels = {'free': 0, 'p1': 1, 'p2': 2}
    current_level = tier_levels.get(license_tier, 0)

    if 'all' in requested:
        # Return all sources available at this license level
        return [
            source for source, info in LOG_SOURCES.items()
            if tier_levels.get(info['license'], 0) <= current_level
        ]

    # Filter requested sources by license
    available = []
    for source in requested:
        info = LOG_SOURCES.get(source, {})
        source_level = tier_levels.get(info.get('license', 'free'), 0)
        if source_level <= current_level:
            available.append(source)

    return available


def create_dfir_config(
    azure_config: Dict[str, str],
    output_dir: str,
    time_range_days: int
) -> str:
    """Create DFIR-O365RC configuration file."""
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=time_range_days)

    config = {
        'tenant_id': azure_config.get('tenant_id', ''),
        'client_id': azure_config.get('client_id', ''),
        'client_secret': azure_config.get('client_secret', ''),
        'start_date': start_date.strftime('%Y-%m-%d'),
        'end_date': end_date.strftime('%Y-%m-%d'),
        'output_dir': output_dir
    }

    config_path = os.path.join(output_dir, 'dfir_config.json')
    with open(config_path, 'w') as f:
        json.dump(config, f, indent=2)

    return config_path


def run_dfir_collection(config_path: str, module: str, output_dir: str) -> List[Dict]:
    """
    Run DFIR-O365RC collection via Docker.

    Note: This is a placeholder. Actual implementation would run:
    docker run -v {output_dir}:/output dfir-o365rc -ConfigFile /output/config.json -Module {module}
    """
    # TODO: Implement actual Docker execution
    # For now, return empty list - this will be filled when DFIR-O365RC is integrated

    # Check if output file exists
    output_file = os.path.join(output_dir, f'{module}.json')
    if os.path.exists(output_file):
        with open(output_file, 'r') as f:
            return json.load(f)

    return []


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

    # Detect file format
    ext = Path(file_path).suffix.lower()
    if ext not in SUPPORTED_FORMATS:
        raise ValueError(f"Unsupported file format: {ext}. Supported: {SUPPORTED_FORMATS}")

    # Parse based on format
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

    # Auto-detect source type if not provided
    if source_type is None and data:
        source_type = detect_source_type(data[0])

    # Normalize the data
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

    # Handle different JSON structures
    if isinstance(data, list):
        return data
    elif isinstance(data, dict):
        # Common patterns: {value: []}, {data: []}, {results: []}
        for key in ['value', 'data', 'results', 'records', 'events']:
            if key in data and isinstance(data[key], list):
                return data[key]
        # Single record
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
        # Try to detect delimiter
        sample = f.read(4096)
        f.seek(0)

        try:
            dialect = csv.Sniffer().sniff(sample)
        except:
            dialect = csv.excel

        reader = csv.DictReader(f, dialect=dialect)
        for row in reader:
            # Convert empty strings to None
            cleaned = {k: (v if v != '' else None) for k, v in row.items()}
            records.append(cleaned)

    return records


def detect_source_type(sample_record: Dict) -> Optional[str]:
    """Auto-detect log source type from record fields."""
    fields = set(sample_record.keys())

    # Sign-in logs indicators
    signin_fields = {'userPrincipalName', 'ipAddress', 'clientAppUsed', 'conditionalAccessStatus'}
    if signin_fields & fields:
        return 'signin_logs'

    # Audit logs indicators
    audit_fields = {'activityDisplayName', 'category', 'operationType', 'targetResources'}
    if audit_fields & fields:
        return 'audit_logs'

    # Risk detection indicators
    risk_fields = {'riskLevel', 'riskState', 'riskDetail', 'riskEventType'}
    if risk_fields & fields:
        return 'risk_detections'

    # Unified audit log indicators
    ual_fields = {'RecordType', 'Operation', 'UserId', 'Workload'}
    if ual_fields & fields:
        return 'unified_audit'

    # Activity logs indicators
    activity_fields = {'operationName', 'resourceType', 'caller', 'correlationId'}
    if activity_fields & fields:
        return 'activity_logs'

    return None


# =============================================================================
# Data Normalization
# =============================================================================

def normalize_logs(records: List[Dict], source_prefix: str) -> List[Dict]:
    """
    Normalize log records to standard format for SIGMA processing.

    Adds _source and _timestamp fields, preserves original data.
    """
    normalized = []

    for record in records:
        # Create normalized record with metadata
        norm_record = {
            '_source': source_prefix,
            '_original': record.copy()
        }

        # Copy all original fields
        norm_record.update(record)

        # Extract/normalize timestamp
        timestamp = extract_timestamp(record)
        if timestamp:
            norm_record['_timestamp'] = timestamp

        normalized.append(norm_record)

    return normalized


def extract_timestamp(record: Dict) -> Optional[str]:
    """Extract timestamp from record using common Azure timestamp fields."""
    timestamp_fields = [
        'createdDateTime',
        'activityDateTime',
        'timestamp',
        'TimeGenerated',
        'CreationTime',
        'eventDateTime',
        'detectedDateTime',
        'lastUpdatedDateTime'
    ]

    for field in timestamp_fields:
        # Case-insensitive search
        for key in record.keys():
            if key.lower() == field.lower():
                value = record[key]
                if value:
                    return str(value)

    return None
