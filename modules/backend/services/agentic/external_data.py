#!/usr/bin/env python3
"""
External Data Parser - Parse uploaded CSV/JSON/JSONL files for agentic analysis
"""

import os
import csv
import json


def parse_external_file(file_path, filename):
    """Parse external log file into list of dicts.

    Args:
        file_path: Path to the uploaded file
        filename: Original filename (used to determine format)

    Returns:
        List of dicts, each representing a row/record

    Raises:
        ValueError: If file format is unsupported or parsing fails
    """
    ext = os.path.splitext(filename)[1].lower()

    if not os.path.exists(file_path):
        raise ValueError(f"File not found: {file_path}")

    file_size = os.path.getsize(file_path)
    if file_size == 0:
        return []

    if ext == '.csv':
        return parse_csv(file_path)
    elif ext == '.tsv':
        return parse_tsv(file_path)
    elif ext == '.json':
        return parse_json(file_path)
    elif ext == '.jsonl':
        return parse_jsonl(file_path)
    elif ext == '.xml':
        return parse_xml(file_path)
    elif ext in ['.log', '.txt', '.syslog', '.evtx']:
        return parse_text_lines(file_path)
    else:
        # Default: try to parse as text lines
        return parse_text_lines(file_path)


def parse_csv(file_path):
    """Parse CSV file into list of dicts."""
    rows = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            # Try to detect delimiter
            sample = f.read(8192)
            f.seek(0)

            # Use Sniffer to detect delimiter
            try:
                dialect = csv.Sniffer().sniff(sample, delimiters=',;\t|')
            except csv.Error:
                dialect = 'excel'

            reader = csv.DictReader(f, dialect=dialect)
            for row in reader:
                # Clean up None keys
                clean_row = {k: v for k, v in row.items() if k is not None}
                if clean_row:
                    rows.append(clean_row)
    except Exception as e:
        raise ValueError(f"Failed to parse CSV: {str(e)}")

    return rows


def parse_tsv(file_path):
    """Parse TSV (tab-separated) file into list of dicts."""
    rows = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            reader = csv.DictReader(f, delimiter='\t')
            for row in reader:
                clean_row = {k: v for k, v in row.items() if k is not None}
                if clean_row:
                    rows.append(clean_row)
    except Exception as e:
        raise ValueError(f"Failed to parse TSV: {str(e)}")

    return rows


def parse_text_lines(file_path):
    """Parse text/log file - each non-empty line becomes a record."""
    rows = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            for line_num, line in enumerate(f, 1):
                line = line.rstrip('\n\r')
                if line.strip():  # Skip empty lines
                    rows.append({
                        'line_number': line_num,
                        'content': line
                    })
    except Exception as e:
        raise ValueError(f"Failed to parse text file: {str(e)}")

    return rows


def parse_xml(file_path):
    """Parse XML file - extract elements as records."""
    rows = []
    try:
        import xml.etree.ElementTree as ET
        tree = ET.parse(file_path)
        root = tree.getroot()

        # Try to find repeating elements (common in log exports)
        # Look for direct children that repeat
        child_tags = {}
        for child in root:
            tag = child.tag.split('}')[-1] if '}' in child.tag else child.tag  # Handle namespaces
            child_tags[tag] = child_tags.get(tag, 0) + 1

        # Find the most common repeating element
        if child_tags:
            main_tag = max(child_tags, key=child_tags.get)
            for elem in root.iter():
                tag = elem.tag.split('}')[-1] if '}' in elem.tag else elem.tag
                if tag == main_tag or child_tags.get(tag, 0) > 1:
                    row = {}
                    # Get attributes
                    for k, v in elem.attrib.items():
                        row[k] = v
                    # Get text content
                    if elem.text and elem.text.strip():
                        row['text'] = elem.text.strip()
                    # Get child elements as fields
                    for child in elem:
                        child_tag = child.tag.split('}')[-1] if '}' in child.tag else child.tag
                        if child.text and child.text.strip():
                            row[child_tag] = child.text.strip()
                    if row:
                        rows.append(row)

        # If no repeating elements found, just extract all text content
        if not rows:
            all_text = ET.tostring(root, encoding='unicode', method='text')
            if all_text.strip():
                rows.append({'content': all_text.strip()})

    except Exception as e:
        raise ValueError(f"Failed to parse XML: {str(e)}")

    return rows


def parse_json(file_path):
    """Parse JSON file into list of dicts.

    Handles:
    - Array of objects: [{"a": 1}, {"a": 2}]
    - Single object: {"a": 1} -> [{"a": 1}]
    - Nested "data" or "results" arrays: {"data": [{"a": 1}]} -> [{"a": 1}]
    """
    try:
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON format: {str(e)}")
    except Exception as e:
        raise ValueError(f"Failed to read JSON: {str(e)}")

    if isinstance(data, list):
        # Filter to only include dict items
        return [item for item in data if isinstance(item, dict)]

    if isinstance(data, dict):
        # Check for common nested array keys
        for key in ['data', 'results', 'records', 'items', 'events', 'logs', 'rows']:
            if key in data and isinstance(data[key], list):
                return [item for item in data[key] if isinstance(item, dict)]

        # Single object -> list of one object
        return [data]

    raise ValueError(f"Unexpected JSON structure: expected array or object, got {type(data).__name__}")


def parse_jsonl(file_path):
    """Parse JSONL (JSON Lines) file - one JSON object per line."""
    rows = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    if isinstance(obj, dict):
                        rows.append(obj)
                except json.JSONDecodeError as e:
                    # Log warning but continue parsing
                    print(f"[External] JSONL line {line_num} parse error: {e}", flush=True)
                    continue
    except Exception as e:
        raise ValueError(f"Failed to read JSONL: {str(e)}")

    return rows


def get_source_hint(filename):
    """Extract source hint from filename for LLM context.

    Examples:
        crowdstrike_detections.csv -> "Crowdstrike Detections"
        fortinet_fw_logs.json -> "Fortinet Fw Logs"
        siem_alerts_march.jsonl -> "Siem Alerts March"
    """
    # Remove extension
    base = os.path.splitext(filename)[0]

    # Replace separators with spaces
    result = base.replace('_', ' ').replace('-', ' ')

    # Title case each word
    result = result.title()

    return result


def validate_external_file(filename):
    """Validate that file extension is supported.

    Returns:
        True if valid, raises ValueError if invalid
    """
    ext = os.path.splitext(filename)[1].lower()
    allowed = ['.csv', '.json', '.jsonl', '.log', '.txt', '.xml', '.tsv', '.syslog', '.evtx']

    if ext not in allowed:
        raise ValueError(f"Invalid file type '{ext}'. Allowed: {', '.join(allowed)}")

    return True
