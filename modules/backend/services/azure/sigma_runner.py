"""
SIGMA Rule Runner for Azure Logs

Executes SIGMA detection rules against collected Azure/M365 logs.
Uses pySigma for rule parsing and matching.
"""

import os
import json
import re
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path

# SIGMA rules directory (cloned from SigmaHQ)
SIGMA_RULES_DIR = os.getenv('SIGMA_RULES_DIR', '/opt/sigma-rules')
AZURE_RULES_PATH = os.path.join(SIGMA_RULES_DIR, 'rules', 'cloud', 'azure')
M365_RULES_PATH = os.path.join(SIGMA_RULES_DIR, 'rules', 'cloud', 'm365')
AWS_RULES_PATH = os.path.join(SIGMA_RULES_DIR, 'rules', 'cloud', 'aws')

# Cloud category → default rule directory set. Used by load_cloud_rules().
CLOUD_RULE_DIRS = {
    'azure': [AZURE_RULES_PATH, M365_RULES_PATH],
    'aws':   [AWS_RULES_PATH],
}


# =============================================================================
# Rule Loading
# =============================================================================

def load_cloud_rules(
    category: str = 'azure',
    rule_dirs: Optional[List[str]] = None,
    categories: Optional[List[str]] = None,
) -> List[Dict]:
    """
    Load SIGMA rules for a cloud provider category ('azure' or 'aws') from
    the SigmaHQ rules directory.

    Args:
        category: 'azure' (default — Azure + M365) or 'aws'. Selects which
            default rule subtrees under /opt/sigma-rules/rules/cloud/ to
            load.
        rule_dirs: Override directories. If provided, `category` is
            ignored.
        categories: Filter loaded rules by tag substring (e.g.
            ['authentication', 'privilege_escalation']).

    Returns:
        List of parsed SIGMA rules as dicts. Each rule has `_file_path` +
        `_file_name` added for downstream provenance.
    """
    if rule_dirs is None:
        rule_dirs = CLOUD_RULE_DIRS.get(category)
        if rule_dirs is None:
            raise ValueError(
                f"Unknown SIGMA cloud category: {category!r}. "
                f"Supported: {list(CLOUD_RULE_DIRS)}"
            )

    rules: List[Dict] = []

    for rule_dir in rule_dirs:
        if not os.path.exists(rule_dir):
            print(f"[SIGMA] Warning: Rule directory not found: {rule_dir}")
            continue

        # Walk directory and load .yml/.yaml files
        for root, _, files in os.walk(rule_dir):
            for filename in files:
                if filename.endswith(('.yml', '.yaml')):
                    rule_path = os.path.join(root, filename)
                    try:
                        rule = load_single_rule(rule_path)
                        if rule:
                            # Filter by category if specified
                            if categories:
                                rule_tags = rule.get('tags', [])
                                if not any(cat in str(rule_tags).lower() for cat in categories):
                                    continue
                            rules.append(rule)
                    except Exception as e:
                        print(f"[SIGMA] Warning: Failed to load {rule_path}: {e}")

    label = {'azure': 'Azure/M365', 'aws': 'AWS'}.get(category, category)
    print(f"[SIGMA] Loaded {len(rules)} {label} detection rules")
    return rules


def load_azure_rules(
    rule_dirs: Optional[List[str]] = None,
    categories: Optional[List[str]] = None
) -> List[Dict]:
    """Back-compat thin wrapper around `load_cloud_rules('azure', …)`."""
    return load_cloud_rules('azure', rule_dirs=rule_dirs, categories=categories)


def load_aws_rules(
    rule_dirs: Optional[List[str]] = None,
    categories: Optional[List[str]] = None
) -> List[Dict]:
    """Convenience wrapper for the AWS rule subtree."""
    return load_cloud_rules('aws', rule_dirs=rule_dirs, categories=categories)


def load_single_rule(rule_path: str) -> Optional[Dict]:
    """Load and parse a single SIGMA rule file."""
    try:
        import yaml
    except ImportError:
        # Fallback to basic YAML parsing
        return parse_yaml_simple(rule_path)

    with open(rule_path, 'r', encoding='utf-8') as f:
        rule = yaml.safe_load(f)

    if rule:
        rule['_file_path'] = rule_path
        rule['_file_name'] = os.path.basename(rule_path)

    return rule


def parse_yaml_simple(rule_path: str) -> Optional[Dict]:
    """Simple YAML parser for basic rule loading (fallback)."""
    # This is a basic fallback - PyYAML should be available
    import yaml
    with open(rule_path, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)


# =============================================================================
# Rule Execution
# =============================================================================

def run_sigma_rules(
    logs: Dict[str, List[Dict]],
    rules: Optional[List[Dict]] = None,
    min_level: str = 'low'
) -> Tuple[Dict[str, List[Dict]], Dict[str, Any]]:
    """
    Execute SIGMA rules against collected logs.

    Args:
        logs: Dict mapping source names to list of log records
        rules: List of SIGMA rules (loaded if not provided)
        min_level: Minimum severity level ('informational', 'low', 'medium', 'high', 'critical')

    Returns:
        Tuple of (findings dict, execution status)
    """
    if rules is None:
        rules = load_azure_rules()

    status = {
        'execution_start': datetime.utcnow().isoformat(),
        'rules_count': len(rules),
        'logs_count': sum(len(v) for v in logs.values()),
        'sources_processed': list(logs.keys()),
        'matches_by_severity': {'informational': 0, 'low': 0, 'medium': 0, 'high': 0, 'critical': 0},
        # rule_tally maps rule_title -> hit_count. Surfaces "rule X fired N times"
        # to the dashboard so the operator sees the shape of detection at a
        # glance instead of just a flat total.
        'rule_tally': {}
    }

    findings = {}
    severity_order = ['informational', 'low', 'medium', 'high', 'critical']
    min_level_idx = severity_order.index(min_level.lower()) if min_level.lower() in severity_order else 0

    # Process each rule
    for rule in rules:
        rule_level = rule.get('level', 'medium').lower()
        if rule_level not in severity_order:
            rule_level = 'medium'

        # Skip rules below minimum severity
        if severity_order.index(rule_level) < min_level_idx:
            continue

        # Match rule against logs
        rule_matches = match_rule(rule, logs)

        if rule_matches:
            # Create finding for each match
            rule_name = rule.get('title', rule.get('_file_name', 'Unknown Rule'))
            source_key = f"SIGMA.{rule_name.replace(' ', '_')}"

            if source_key not in findings:
                findings[source_key] = []

            for match in rule_matches:
                finding = create_finding(rule, match)
                findings[source_key].append(finding)
                status['matches_by_severity'][rule_level] += 1

            status['rule_tally'][rule_name] = status['rule_tally'].get(rule_name, 0) + len(rule_matches)

    status['execution_end'] = datetime.utcnow().isoformat()
    status['total_findings'] = sum(len(v) for v in findings.values())

    return findings, status


def match_rule(rule: Dict, logs: Dict[str, List[Dict]]) -> List[Dict]:
    """
    Match a SIGMA rule against logs.

    Returns list of matching log records.
    """
    matches = []

    # Get detection logic
    detection = rule.get('detection', {})
    if not detection:
        return matches

    # Get the condition and selection criteria
    condition = detection.get('condition', '')
    selections = {k: v for k, v in detection.items() if k != 'condition'}

    if not selections:
        return matches

    # Determine which log sources this rule applies to
    logsource = rule.get('logsource', {})
    product = logsource.get('product', '').lower()
    service = logsource.get('service', '').lower()

    # Match against appropriate log sources
    for source_name, records in logs.items():
        # Check if this source is relevant to the rule
        if not is_source_relevant(source_name, product, service):
            continue

        # Evaluate each record against the rule
        for record in records:
            if evaluate_detection(record, detection, condition, selections):
                matches.append(record)

    return matches


def is_source_relevant(source_name: str, product: str, service: str) -> bool:
    """Check if a log source is relevant to a SIGMA rule's logsource."""
    source_lower = source_name.lower()

    # Azure product matching
    if product in ['azure', 'azuread', 'entra', 'm365', 'office365']:
        if 'azure' in source_lower or 'entra' in source_lower:
            return True

    # AWS product matching — SigmaHQ AWS rules have `logsource.product: aws`
    # and a service like `cloudtrail` / `guardduty`. Records collected by
    # the AWS pipeline are grouped under sigma_prefix keys like
    # `AWS.CloudTrail`, `AWS.GuardDuty`, `AWS.AccessAnalyzer`, `AWS.Prowler`
    # — match any of those when the rule targets AWS.
    if product == 'aws':
        if 'aws' in source_lower:
            return True
        # Service-specific match for AWS even if the prefix doesn't include "aws"
        aws_service_mappings = {
            'cloudtrail':     ['cloudtrail', 'trail'],
            'guardduty':      ['guardduty', 'gd'],
            'iam':            ['iam'],
            's3':             ['s3', 'bucket'],
            'ec2':            ['ec2'],
            'lambda':         ['lambda'],
            'eks':            ['eks'],
            'accessanalyzer': ['accessanalyzer'],
            'sts':            ['sts', 'assumerole'],
        }
        for svc, keywords in aws_service_mappings.items():
            if service == svc and any(kw in source_lower for kw in keywords):
                return True

    # Service-specific matching (Azure)
    service_mappings = {
        'signinlogs': ['signin', 'sign-in', 'authentication'],
        'auditlogs': ['audit', 'directory'],
        'activitylogs': ['activity'],
        'riskdetection': ['risk', 'risky']
    }

    for svc, keywords in service_mappings.items():
        if service == svc or any(kw in source_lower for kw in keywords):
            return True

    # Default: don't match unknown sources
    return False


def evaluate_detection(
    record: Dict,
    detection: Dict,
    condition: str,
    selections: Dict
) -> bool:
    """
    Evaluate a record against SIGMA detection logic.

    Supports basic conditions: selection, selection1 and selection2, selection or filter, not filter
    """
    # Evaluate each selection
    selection_results = {}

    for sel_name, sel_criteria in selections.items():
        if sel_name == 'condition':
            continue
        selection_results[sel_name] = evaluate_selection(record, sel_criteria)

    # Evaluate condition
    return evaluate_condition(condition, selection_results)


def evaluate_selection(record: Dict, criteria: Any) -> bool:
    """
    Evaluate a selection criteria against a record.

    Handles: field|contains, field|startswith, field|endswith, field|re, lists, keywords
    """
    if criteria is None:
        return False

    if isinstance(criteria, dict):
        # All criteria in dict must match (AND)
        for field_spec, value_spec in criteria.items():
            if not match_field(record, field_spec, value_spec):
                return False
        return True

    elif isinstance(criteria, list):
        # Any item in list can match (OR)
        for item in criteria:
            if isinstance(item, dict):
                if evaluate_selection(record, item):
                    return True
            elif isinstance(item, str):
                # Keyword search - check if string appears anywhere in record values
                item_lower = item.lower()
                record_str = json.dumps(record, default=str).lower()
                if item_lower in record_str:
                    return True
        return False

    elif isinstance(criteria, str):
        # Single keyword search
        criteria_lower = criteria.lower()
        record_str = json.dumps(record, default=str).lower()
        return criteria_lower in record_str

    return False


def match_field(record: Dict, field_spec: str, value_spec: Any) -> bool:
    """
    Match a field specification against a record value.

    Supports modifiers: |contains, |startswith, |endswith, |re, |all, |base64
    """
    # Parse field name and modifiers
    parts = field_spec.split('|')
    field_name = parts[0]
    modifiers = parts[1:] if len(parts) > 1 else []

    # Get field value (case-insensitive search)
    field_value = get_field_value(record, field_name)
    if field_value is None:
        return False

    # Convert to string for comparison
    field_value_str = str(field_value).lower()

    # Handle list of values (OR)
    values = value_spec if isinstance(value_spec, list) else [value_spec]

    for value in values:
        if value is None:
            continue

        value_str = str(value).lower()

        # Apply modifiers
        if 'contains' in modifiers:
            if value_str in field_value_str:
                return True
        elif 'startswith' in modifiers:
            if field_value_str.startswith(value_str):
                return True
        elif 'endswith' in modifiers:
            if field_value_str.endswith(value_str):
                return True
        elif 're' in modifiers:
            try:
                if re.search(value_str, field_value_str, re.IGNORECASE):
                    return True
            except re.error:
                pass
        else:
            # Exact match (case-insensitive)
            if field_value_str == value_str:
                return True

    return False


def get_field_value(record: Dict, field_name: str) -> Any:
    """Get field value from record (case-insensitive, supports nested fields)."""
    # Try exact match first
    if field_name in record:
        return record[field_name]

    # Case-insensitive search
    field_lower = field_name.lower()
    for key, value in record.items():
        if key.lower() == field_lower:
            return value

    # Handle nested fields (e.g., 'properties.message')
    if '.' in field_name:
        parts = field_name.split('.')
        current = record
        for part in parts:
            if isinstance(current, dict):
                # Case-insensitive nested search
                found = False
                for key, value in current.items():
                    if key.lower() == part.lower():
                        current = value
                        found = True
                        break
                if not found:
                    return None
            else:
                return None
        return current

    return None


def evaluate_condition(condition: str, selection_results: Dict[str, bool]) -> bool:
    """
    Evaluate a SIGMA condition string.

    Supports: and, or, not, parentheses, 1/all of selection*
    """
    if not condition:
        # Default: all selections must match
        return all(selection_results.values())

    condition = condition.strip().lower()

    # Handle "all of selection*" pattern
    if condition.startswith('all of '):
        pattern = condition[7:].replace('*', '.*')
        matching = [v for k, v in selection_results.items() if re.match(pattern, k)]
        return all(matching) if matching else False

    # Handle "1 of selection*" pattern
    match = re.match(r'(\d+) of (\w+\*?)', condition)
    if match:
        count = int(match.group(1))
        pattern = match.group(2).replace('*', '.*')
        matching = [v for k, v in selection_results.items() if re.match(pattern, k)]
        return sum(matching) >= count

    # Simple cases
    if condition in selection_results:
        return selection_results[condition]

    # Handle "selection and not filter"
    if ' and not ' in condition:
        parts = condition.split(' and not ')
        sel = parts[0].strip()
        filt = parts[1].strip()
        sel_result = selection_results.get(sel, False)
        filt_result = selection_results.get(filt, False)
        return sel_result and not filt_result

    # Handle "selection and filter"
    if ' and ' in condition:
        parts = condition.split(' and ')
        return all(selection_results.get(p.strip(), False) for p in parts)

    # Handle "selection or filter"
    if ' or ' in condition:
        parts = condition.split(' or ')
        return any(selection_results.get(p.strip(), False) for p in parts)

    # Handle "not selection"
    if condition.startswith('not '):
        sel = condition[4:].strip()
        return not selection_results.get(sel, True)

    return selection_results.get(condition, False)


# =============================================================================
# Finding Creation
# =============================================================================

def create_finding(rule: Dict, matched_record: Dict) -> Dict:
    """Create a finding object from a matched rule and record."""
    return {
        # Rule metadata
        'rule_title': rule.get('title', 'Unknown Rule'),
        'rule_id': rule.get('id', ''),
        'rule_description': rule.get('description', ''),
        'severity': rule.get('level', 'medium'),
        'status': rule.get('status', 'experimental'),

        # MITRE ATT&CK mapping
        'mitre_attack': extract_mitre_tags(rule.get('tags', [])),
        'tags': rule.get('tags', []),

        # Detection details
        'logsource': rule.get('logsource', {}),
        'references': rule.get('references', []),
        'falsepositives': rule.get('falsepositives', []),

        # Matched record
        '_timestamp': matched_record.get('_timestamp'),
        '_source': matched_record.get('_source'),
        'matched_record': {k: v for k, v in matched_record.items() if not k.startswith('_original')},

        # Finding metadata
        '_finding_time': datetime.utcnow().isoformat()
    }


def extract_mitre_tags(tags: List[str]) -> List[Dict]:
    """Extract MITRE ATT&CK references from tags."""
    mitre = []

    for tag in tags:
        tag_str = str(tag)
        # Match attack.tXXXX patterns
        if tag_str.startswith('attack.'):
            part = tag_str[7:]  # Remove 'attack.' prefix
            if part.startswith('t'):
                # Technique ID
                mitre.append({'type': 'technique', 'id': part.upper()})
            elif part in ['initial_access', 'execution', 'persistence', 'privilege_escalation',
                          'defense_evasion', 'credential_access', 'discovery', 'lateral_movement',
                          'collection', 'command_and_control', 'exfiltration', 'impact']:
                # Tactic
                mitre.append({'type': 'tactic', 'name': part.replace('_', ' ').title()})

    return mitre


# =============================================================================
# Utility Functions
# =============================================================================

def get_available_rules_count() -> Dict[str, int]:
    """Get count of available rules by category."""
    rules = load_azure_rules()

    counts = {
        'total': len(rules),
        'by_level': {},
        'by_status': {}
    }

    for rule in rules:
        level = rule.get('level', 'unknown')
        status = rule.get('status', 'unknown')

        counts['by_level'][level] = counts['by_level'].get(level, 0) + 1
        counts['by_status'][status] = counts['by_status'].get(status, 0) + 1

    return counts


def validate_rules_directory() -> Tuple[bool, str]:
    """Validate that SIGMA rules are available."""
    if not os.path.exists(SIGMA_RULES_DIR):
        return False, f"SIGMA rules directory not found: {SIGMA_RULES_DIR}"

    if not os.path.exists(AZURE_RULES_PATH):
        return False, f"Azure rules not found: {AZURE_RULES_PATH}"

    rule_count = len(list(Path(AZURE_RULES_PATH).rglob('*.yml')))
    if rule_count == 0:
        return False, "No SIGMA rules found in Azure directory"

    return True, f"Found {rule_count} Azure SIGMA rules"
