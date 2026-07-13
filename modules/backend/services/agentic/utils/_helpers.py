#!/usr/bin/env python3
"""
Agentic Utils - Timeline extraction and data formatting helpers
"""

from datetime import datetime

# Timestamp field names ordered by FORENSIC PRIORITY (most relevant first)
# Used for time filtering - first match wins, so order matters!
#
# Priority order rationale:
#   1. CREATION timestamps - When artifacts were created (find new attacker artifacts)
#   2. EVENT timestamps - When activity occurred (detections, alerts)
#   3. MODIFICATION timestamps - When things changed (tampering, persistence)
#   4. EXECUTION timestamps - When things ran (can be noisy)
#   5. ACCESS timestamps - Least reliable, often disabled
#   6. INTERNAL timestamps - Collection/metadata timestamps
#
TIMESTAMP_FIELDS = [
    # ─── PRIORITY 1: CREATION TIMESTAMPS (when artifacts were created) ───
    # Best for: Finding NEW attacker artifacts - malware dropped, persistence created
    'Created', 'CreateTime', 'CreatedTime', 'CreationTime', 'CreationTimeUTC',
    'ProcessCreateTime', 'Created0x10', 'Created0x30',
    'SourceCreated', 'InstallDate', 'FirstSeen', 'Firstseen',
    'CopiedOnTimestamp', 'ZipTimestamp', 'RegistrationDate', 'RegistrationTime',
    'LastLoginDate', 'PasswordResetDate',

    # ─── PRIORITY 2: EVENT TIMESTAMPS (when activity occurred) ───
    # Best for: Hayabusa, EventLogs, Detections - "When did this happen?"
    'Timestamp', 'timestamp', 'EventTime', 'event_time',
    'TimeCreated', 'TimeGenerated', 'RecordTime', 'LogTime',
    'Time', 'time', 'DateTime', 'datetime', 'Date', 'date',
    'SystemTime',
    # Azure/M365 timestamps
    'createdDateTime', 'CreatedDateTime', 'activityDateTime', 'ActivityDateTime',
    'detectedDateTime', 'DetectedDateTime', 'eventDateTime', 'EventDateTime',
    'riskLastUpdatedDateTime', 'RiskLastUpdatedDateTime',

    # ─── PRIORITY 3: MODIFICATION TIMESTAMPS (when things changed) ───
    # Best for: TaskScheduler, config files, registry - "When was this modified?"
    'Modified', 'ModifiedTime', 'ModificationTime', 'ModTime',
    'Mtime', 'mtime', 'MTime', 'FileMtime', 'KeyMTime',
    'LastModified', 'LastMod', 'LastModified0x10', 'LastModified0x30',
    'SourceModified', 'LastWriteTime', 'KeyLastWriteTimestamp',
    'LastRecordChange0x10', 'LastRecordChange0x30',
    'SI_LastModified0x10', 'FN_LastModified0x30',

    # ─── PRIORITY 4: EXECUTION TIMESTAMPS (when things ran) ───
    # Caution: Can be noisy - system tasks run constantly
    'StartTime', 'EndTime', 'Runtime',
    'LastRunTimes', 'LastExecutionTime', 'CompletionTimeUTC',
    'LastUsedTimeStart', 'LastUsedTimeStop', 'DateLastUsed',
    'VisitTime', 'LastActivated', 'LastActivityView', 'LastSeen',

    # ─── PRIORITY 5: ACCESS TIMESTAMPS (least reliable) ───
    # Often disabled on modern Windows, can be misleading
    'Accessed', 'AccessedTime', 'LastAccessTime',
    'LastAccess0x10', 'LastAccess0x30', 'SI_LastAccess0x10',
    'Atime', 'atime', 'SourceAccessed',

    # ─── PRIORITY 6: INTERNAL/METADATA TIMESTAMPS ───
    # Velociraptor collection timestamps, birth time, etc.
    '_time', '_ts', 'AttrSystemTime', 'AttrTime', 'ExpiryTime',
    'Ctime', 'ctime', 'Btime', 'btime',

    # ─── PRIORITY 7: PIPELINE-ADDED INTERNAL TIMESTAMPS ───
    # Set by both Azure and on-prem collectors as they tag rows / wrap
    # findings. Putting them here keeps every LLM prompt's timestamp
    # format consistent across both pipelines.
    '_timestamp', '_finding_time',

    # ─── PRIORITY 8: MICROSOFT GRAPH / ENTRA cloud timestamps ───
    # Names observed in `auditLogs/*`, `signIns`, `directoryAudits`, CA
    # policy state, federation configs, identity protection. These don't
    # appear in Velociraptor data so adding them is a no-op for the
    # on-prem flow.
    'lastModifiedDateTime', 'LastModifiedDateTime',
    'modifiedDateTime', 'ModifiedDateTime',
    'lastSignInDateTime', 'LastSignInDateTime',
    'signInDateTime', 'SignInDateTime',
    'lastNonInteractiveSignInDateTime', 'LastNonInteractiveSignInDateTime',
    'lastPasswordChangeDateTime', 'LastPasswordChangeDateTime',
    'lastUpdatedDateTime', 'LastUpdatedDateTime',
    'expirationDateTime', 'ExpirationDateTime',
    'deletedDateTime', 'DeletedDateTime',
    'startDateTime', 'StartDateTime',
    'endDateTime', 'EndDateTime',
    'requestedDateTime', 'RequestedDateTime',
    'tokenIssuedAtDateTime', 'TokenIssuedAtDateTime',
    'validFrom', 'ValidFrom', 'validTo', 'ValidTo',
    'effectiveDateTime', 'EffectiveDateTime',
    'completedDateTime', 'CompletedDateTime',
    'lastDirSyncTime', 'LastDirSyncTime',

    # ─── PRIORITY 9: OFFICE 365 Management API nested timestamps ───
    # Common in DFIR-O365RC's UAL pulls: AppAccessContext, Teams meeting
    # events, SharePoint share sessions. Nested inside list elements,
    # which `normalize_timestamps_recursive` walks via the list-recursion
    # branch.
    'TokenIssuedAtTime', 'IssuedAtTime', 'AuthTime',
    'JoinTime', 'LeaveTime',
    'StartTimestamp', 'EndTimestamp',
]

def find_field_recursive(row, field_names, parent_path=''):
    """Recursively find a field in row, prioritizing field_names order.

    Args:
        row: Dict to search
        field_names: List of field names to look for (in priority order)
        parent_path: Current path (for nested fields)

    Returns:
        (field_path, value) or (None, None)
    """
    if not isinstance(row, dict):
        return None, None

    # First pass: check top-level keys in PRIORITY ORDER (field_names list order)
    # This ensures Timestamp/EventTime are preferred over StartTime/Created
    for field_name in field_names:
        if field_name in row:
            full_path = f"{parent_path}.{field_name}" if parent_path else field_name
            return full_path, row[field_name]

    # Second pass: recurse into nested dicts
    for key, value in row.items():
        if isinstance(value, dict):
            full_path = f"{parent_path}.{key}" if parent_path else key
            nested_path, nested_val = find_field_recursive(value, field_names, full_path)
            if nested_path:
                return nested_path, nested_val

    return None, None


def parse_timestamp(ts_value):
    """Try to parse various timestamp formats. Returns datetime or None."""
    if not ts_value:
        return None
    if isinstance(ts_value, (int, float)):
        try:
            # Detect milliseconds (13 digits) vs seconds (10 digits)
            if ts_value > 1e12:
                ts_value = ts_value / 1000  # Convert milliseconds to seconds
            return datetime.fromtimestamp(ts_value)
        except:
            return None
    if isinstance(ts_value, str):
        formats = [
            '%Y-%m-%dT%H:%M:%S.%fZ', '%Y-%m-%dT%H:%M:%SZ', '%Y-%m-%dT%H:%M:%S',
            '%Y-%m-%d %H:%M:%S', '%Y/%m/%d %H:%M:%S', '%d/%m/%Y %H:%M:%S',
            '%Y-%m-%dT%H:%M:%S.%f', '%Y-%m-%d %H:%M:%S.%f'
        ]
        for fmt in formats:
            try:
                return datetime.strptime(ts_value[:26], fmt)
            except:
                continue
        try:
            return datetime.fromisoformat(ts_value.replace('Z', '+00:00'))
        except:
            pass
    return None


# Standard timestamp output format for consistent reports
TIMESTAMP_FORMAT = '%Y-%m-%d %H:%M:%S'


def normalize_timestamp(value):
    """Convert any timestamp format to standard 'YYYY-MM-DD HH:MM:SS' string."""
    if not value:
        return value

    # Already in target format (19 chars: YYYY-MM-DD HH:MM:SS)
    if isinstance(value, str) and len(value) == 19 and value[4] == '-' and value[10] == ' ':
        return value

    # Parse and reformat
    dt = parse_timestamp(value)
    if dt:
        return dt.strftime(TIMESTAMP_FORMAT)

    return value  # Return original if unparseable


def normalize_timestamps_recursive(row):
    """Normalize all timestamp fields in a row (including nested objects + lists).
    Modifies row in-place and returns it.

    Walks both dict values AND list elements that are dicts. Without the
    list-walk Azure data with `targetResources[].StartTimestamp` or
    `ArtifactShareSessions[].EndTimestamp` keep their raw ISO format and
    leak into the LLM prompt.
    """
    if isinstance(row, dict):
        for key, value in list(row.items()):
            if key in TIMESTAMP_FIELDS:
                row[key] = normalize_timestamp(value)
            elif isinstance(value, dict):
                normalize_timestamps_recursive(value)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, (dict, list)):
                        normalize_timestamps_recursive(item)
    elif isinstance(row, list):
        for item in row:
            if isinstance(item, (dict, list)):
                normalize_timestamps_recursive(item)
    return row


def normalize_all_results(all_results):
    """Normalize timestamps in all artifact results.
    Modifies results in-place for efficiency."""
    for artifact, rows in all_results.items():
        for row in rows:
            normalize_timestamps_recursive(row)
    return all_results



def create_time_filter_func(time_filter):
    """Create a row-level time filter function from time_filter config.

    Returns a function that takes a row and returns True if it passes the filter.
    Returns None if time filtering is not enabled.
    """
    if not time_filter or not time_filter.get('enabled'):
        return None

    from datetime import timedelta

    mode = time_filter.get('mode', 'relative')
    now = datetime.utcnow()

    if mode == 'between':
        start_str = time_filter.get('start_datetime')
        end_str = time_filter.get('end_datetime')
        try:
            start_time = datetime.fromisoformat(start_str.replace('Z', '+00:00').replace('+00:00', '')) if start_str else None
            end_time = datetime.fromisoformat(end_str.replace('Z', '+00:00').replace('+00:00', '')) if end_str else now
        except Exception:
            return None
    else:
        # Relative mode
        range_str = time_filter.get('relative_range') or time_filter.get('default_range', '7d')
        end_time = now
        if range_str.endswith('h'):
            hours = int(range_str[:-1])
            start_time = now - timedelta(hours=hours)
        elif range_str.endswith('d'):
            days = int(range_str[:-1])
            start_time = now - timedelta(days=days)
        else:
            start_time = now - timedelta(days=7)

    def is_row_in_range(row):
        """Check if row's timestamp falls within the time range."""
        field_path, value = find_field_recursive(row, TIMESTAMP_FIELDS)
        if not field_path:
            return True  # No timestamp field - include by default

        ts = parse_timestamp(value)
        if not ts:
            return True  # Unparseable - include

        # Make timezone-naive for comparison
        if hasattr(ts, 'tzinfo') and ts.tzinfo is not None:
            ts = ts.replace(tzinfo=None)

        if start_time and ts < start_time:
            return False
        if end_time and ts > end_time:
            return False
        return True

    return is_row_in_range


def filter_results_by_time(all_results, time_filter, run_id=None):
    """Filter artifact results by timestamp for post-collection filtering.

    Used when analyzing existing flows/hunts where collection already happened.
    Filters each artifact's rows based on timestamp fields.

    Args:
        all_results: Dict of artifact_name -> [rows]
        time_filter: Time filter config with enabled, mode, relative_range/start_datetime/end_datetime
        run_id: Optional run_id for logging

    Returns:
        Filtered all_results dict
    """
    from datetime import timedelta
    from services.workflow_service import add_log_to_run

    def log(msg, level="info"):
        if run_id:
            add_log_to_run(run_id, msg, level)
        print(f"[TIME-FILTER] {msg}", flush=True)

    if not time_filter or not time_filter.get('enabled'):
        return all_results

    # Calculate time range
    mode = time_filter.get('mode', 'relative')
    now = datetime.utcnow()

    if mode == 'between':
        start_str = time_filter.get('start_datetime')
        end_str = time_filter.get('end_datetime')
        try:
            start_time = datetime.fromisoformat(start_str.replace('Z', '+00:00').replace('+00:00', '')) if start_str else None
            end_time = datetime.fromisoformat(end_str.replace('Z', '+00:00').replace('+00:00', '')) if end_str else now
        except Exception as e:
            log(f"Error parsing between dates: {e}", "warning")
            return all_results
    else:
        # Relative mode
        range_str = time_filter.get('relative_range', '7d')
        end_time = now
        if range_str.endswith('h'):
            hours = int(range_str[:-1])
            start_time = now - timedelta(hours=hours)
        elif range_str.endswith('d'):
            days = int(range_str[:-1])
            start_time = now - timedelta(days=days)
        else:
            start_time = now - timedelta(days=7)

    # Calculate total rows before filtering
    total_before = sum(len(rows) for rows in all_results.values())

    def is_in_range(row):
        """Check if row's timestamp falls within the time range (recursive)."""
        # Find time field recursively (handles nested objects)
        field_path, value = find_field_recursive(row, TIMESTAMP_FIELDS)
        if not field_path:
            return True  # No timestamp - include by default

        ts = parse_timestamp(value)
        if not ts:
            return True  # Unparseable timestamp - include

        # Make ts timezone-naive for comparison
        if hasattr(ts, 'tzinfo') and ts.tzinfo is not None:
            ts = ts.replace(tzinfo=None)

        if start_time and ts < start_time:
            return False
        if end_time and ts > end_time:
            return False
        return True

    # Filter each artifact's rows and track stats
    filtered_results = {}
    filter_stats = []  # [(artifact, before, after, field_used)]

    for artifact, rows in all_results.items():
        before = len(rows)
        # Detect which field is being used (from first row)
        field_used = None
        if rows:
            field_path, _ = find_field_recursive(rows[0], TIMESTAMP_FIELDS)
            field_used = field_path
        filtered_rows = [row for row in rows if is_in_range(row)]
        after = len(filtered_rows)
        filtered_results[artifact] = filtered_rows
        filter_stats.append((artifact, before, after, field_used))

    # Calculate totals
    total_after = sum(len(rows) for rows in filtered_results.values())
    total_removed = total_before - total_after

    # Log header
    mode_str = f"last {time_filter.get('relative_range', '7d')} ({start_time.strftime('%Y-%m-%d %H:%M')} to {end_time.strftime('%Y-%m-%d %H:%M')})" if mode == 'relative' else f"{start_time.strftime('%Y-%m-%d %H:%M')} to {end_time.strftime('%Y-%m-%d %H:%M')}"
    log(f"[Filter] Time filter: {mode_str}", "info")
    log(f"[Filter] ─────────────────────────────────────────────", "info")

    # Log per-artifact stats with field used
    for artifact, before, after, field_used in filter_stats:
        removed = before - after
        field_info = f" [{field_used}]" if field_used else " [no timestamp]"
        if removed > 0:
            pct = (removed / before * 100) if before > 0 else 0
            log(f"[Filter] {artifact}{field_info}: {before} → {after} (-{removed}, {pct:.0f}%)", "info")
        elif before > 0:
            log(f"[Filter] {artifact}{field_info}: {before} (no change)", "info")

    # Log total summary
    log(f"[Filter] ─────────────────────────────────────────────", "info")
    pct_total = (total_removed / total_before * 100) if total_before > 0 else 0
    log(f"[Filter] TOTAL: {total_before} → {total_after} (-{total_removed} rows, {pct_total:.0f}% removed)", "success" if total_removed > 0 else "info")

    # Normalize all timestamps to consistent format (YYYY-MM-DD HH:MM:SS)
    normalize_all_results(filtered_results)
    log(f"[Pipeline] Timestamps normalized to {TIMESTAMP_FORMAT} format")

    return filtered_results
