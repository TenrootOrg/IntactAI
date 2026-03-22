#!/usr/bin/env python3
"""
Agentic Utils - Timeline extraction and data formatting helpers
"""

from datetime import datetime

# Common timestamp field names across Velociraptor artifacts
TIMESTAMP_FIELDS = [
    'Timestamp', 'timestamp', 'Time', 'time', 'CreationTime', 'ModificationTime',
    'LastAccessTime', 'EventTime', 'event_time', 'Created', 'Modified', 'Accessed',
    '_time', 'StartTime', 'EndTime', 'LastWriteTime', 'SourceCreated', 'SourceModified',
    'SourceAccessed', 'SI_LastModified0x10', 'SI_LastAccess0x10', 'FN_LastModified0x30',
    'mtime', 'atime', 'ctime', 'btime', 'LastExecutionTime', 'LastRun'
]

# Fields that indicate important/interesting findings
IMPORTANT_FIELDS = [
    'Level', 'Severity', 'Detection', 'Alert', 'Match', 'Hit', 'Finding',
    'Suspicious', 'Malicious', 'Risk', 'Score', 'Status', 'RuleTitle', 'RuleLevel'
]


def parse_timestamp(ts_value):
    """Try to parse various timestamp formats. Returns datetime or None."""
    if not ts_value:
        return None
    if isinstance(ts_value, (int, float)):
        try:
            if ts_value > 1e12:
                ts_value = ts_value / 1e6
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


def extract_timeline_events(all_results, include_no_timestamp=True):
    """Extract events from artifact data for timeline generation.
    Returns list of event dicts with: timestamp, source, description, hostname, raw, no_timestamp.

    Creates rich descriptions explaining what was found and why it matters."""

    events = []
    no_timestamp_events = []

    # Use module-level constants
    timestamp_fields = TIMESTAMP_FIELDS
    important_fields = IMPORTANT_FIELDS

    def get_short_title(row, artifact):
        """Get a short, clean title for the event (max 60 chars)."""
        def extract_str(val):
            """Extract string from value, handling dicts properly."""
            if val is None:
                return None
            if isinstance(val, str):
                return val
            if isinstance(val, dict):
                # Try common keys for nested dicts
                for key in ['Path', 'Name', 'Target', 'LinkTarget', 'Value']:
                    if key in val and val[key] and isinstance(val[key], str):
                        return val[key]
                return None
            return str(val)

        def get_filename(path):
            """Extract filename from path."""
            if not path:
                return None
            path_str = extract_str(path)
            if not path_str:
                return None
            # Split by backslash and get last part
            parts = path_str.replace('/', '\\').split('\\')
            return parts[-1] if parts else path_str

        if 'Amcache' in artifact:
            name = extract_str(row.get('Name')) or get_filename(row.get('FullPath')) or 'Unknown'
            return f"Program Executed: {name[:45]}"
        elif 'RDPAuth' in artifact:
            user = extract_str(row.get('UserName')) or extract_str(row.get('User')) or 'Unknown'
            return f"RDP Login: {user[:50]}"
        elif 'Netstat' in artifact or 'Network' in artifact:
            proc = extract_str(row.get('Name')) or extract_str(row.get('Process')) or 'Unknown'
            remote = extract_str(row.get('Raddr')) or extract_str(row.get('RemoteAddress'))
            if remote:
                return f"Network: {proc} -> {remote}"[:60]
            return f"Network: {proc[:50]}"
        elif 'Lnk' in artifact or 'Forensics.Lnk' in artifact:
            # Get the target filename, not the full path or dict
            target = row.get('LinkTarget') or row.get('TargetPath')
            filename = get_filename(target)
            if filename:
                return f"File Accessed: {filename[:45]}"
            return "Recent File Access"
        elif 'Hayabusa' in artifact:
            level = extract_str(row.get('Level')) or extract_str(row.get('RuleLevel')) or 'INFO'
            title = extract_str(row.get('RuleTitle')) or extract_str(row.get('Title')) or 'Detection'
            return f"[{level.upper()}] {title[:50]}"
        elif 'Persistence' in artifact or 'PersistenceSniper' in artifact:
            technique = extract_str(row.get('Technique')) or extract_str(row.get('Name')) or 'Unknown'
            return f"Persistence: {technique[:45]}"
        elif 'Detection' in artifact:
            name = extract_str(row.get('Name')) or extract_str(row.get('Detection')) or 'Alert'
            return f"Detection: {name[:50]}"
        else:
            # Generic - extract first meaningful field
            for field in ['Name', 'FullPath', 'Message', 'CommandLine']:
                val = extract_str(row.get(field))
                if val:
                    return val[:60]
            return artifact.split('.')[-1][:60]

    def safe_str(val, default=''):
        """Safely convert value to string, handling dicts."""
        if val is None:
            return default
        if isinstance(val, dict):
            return str(val.get('Path') or val.get('Name') or val.get('Value') or val)[:200]
        return str(val)

    def build_rich_description(row, artifact):
        """Build structured description: Artifact, Finding, Why it matters."""
        # Artifact-specific findings
        if 'Amcache' in artifact:
            name = safe_str(row.get('Name')) or safe_str(row.get('FullPath'), 'Unknown').split('\\')[-1]
            path = safe_str(row.get('FullPath'))
            sha1 = safe_str(row.get('SHA1'))
            finding = name
            if path:
                finding += f" at {path}"
            if sha1:
                finding += f" (SHA1: {sha1[:16]}...)"
            # Make why more specific based on path
            if path:
                path_lower = path.lower()
                if any(x in path_lower for x in ['temp', 'tmp', 'download', 'appdata\\local\\temp']):
                    why = "Executed from suspicious temp/download location - common malware staging area. Check file hash against threat intel."
                elif any(x in path_lower for x in ['system32', 'syswow64', 'windows']):
                    why = "Executed from Windows directory - verify this is a legitimate system binary, not a masquerading threat."
                elif 'programdata' in path_lower:
                    why = "Executed from ProgramData - check for unexpected binaries as this location is writable by most users."
                elif 'users' in path_lower:
                    why = "Executed from user profile - correlate with user activity and check if software is authorized."
                else:
                    why = "Program execution recorded in Amcache. Cross-reference with authorized software list."
            else:
                why = "Program executed - Amcache records all binary executions. Verify this is expected software."

        elif 'RDPAuth' in artifact:
            user = safe_str(row.get('UserName')) or safe_str(row.get('User'), 'Unknown')
            source_ip = safe_str(row.get('SourceIP')) or safe_str(row.get('IpAddress'))
            event_type = safe_str(row.get('EventType')) or safe_str(row.get('Description'))
            finding = f"User: {user}"
            if source_ip:
                finding += f" from {source_ip}"
            if event_type:
                finding += f" ({event_type})"
            # Make why more specific
            if source_ip:
                if source_ip.startswith(('10.', '192.168.', '172.16.', '172.17.', '172.18.', '172.19.')):
                    why = f"Internal RDP session from {source_ip}. Verify if this user should have RDP access and if timing matches normal work hours."
                else:
                    why = f"EXTERNAL RDP from {source_ip}! Verify this IP is authorized. Check for brute-force attempts before this login."
            else:
                why = "RDP authentication event - verify user authorization and correlate with other activity from this session."

        elif 'Netstat' in artifact or 'Network' in artifact:
            proc = safe_str(row.get('Name')) or safe_str(row.get('Process'), 'Unknown')
            pid = safe_str(row.get('Pid'))
            remote = safe_str(row.get('Raddr')) or safe_str(row.get('RemoteAddress'))
            local = safe_str(row.get('Laddr')) or safe_str(row.get('LocalAddress'))
            status = safe_str(row.get('Status')) or safe_str(row.get('State'))
            finding = f"{proc} (PID:{pid})"
            if remote:
                finding += f" -> {remote}"
            elif local:
                finding += f" on {local}"
            if status:
                finding += f" [{status}]"
            # Make why more specific
            proc_lower = proc.lower()
            if any(x in proc_lower for x in ['powershell', 'cmd', 'wscript', 'cscript', 'mshta']):
                why = f"Shell/scripting process with network activity - commonly abused for C2. Verify command line arguments."
            elif any(x in proc_lower for x in ['svchost', 'services', 'system']):
                why = f"System process network connection - usually legitimate but verify remote IP is expected."
            elif remote:
                why = f"Active outbound connection to {remote.split(':')[0] if remote else 'unknown'}. Check if destination is known/trusted."
            else:
                why = f"Network activity by {proc}. Review if this process should have network access."

        elif 'Lnk' in artifact or 'Forensics.Lnk' in artifact:
            target = safe_str(row.get('LinkTarget')) or safe_str(row.get('TargetPath'))
            source = safe_str(row.get('SourceFile')) or safe_str(row.get('Name'))
            working_dir = safe_str(row.get('WorkingDir'))
            finding = target or source or "Unknown target"
            if working_dir:
                finding += f" (WorkDir: {working_dir[:50]})"
            # Make why more specific
            if target:
                target_lower = target.lower()
                if any(x in target_lower for x in ['powershell', 'cmd.exe', 'wscript', 'cscript']):
                    why = "LNK pointing to scripting engine - commonly used in phishing attacks. Review full command line."
                elif any(x in target_lower for x in ['temp', 'tmp', 'download']):
                    why = "LNK to temp/download location - may indicate recently downloaded malicious file execution."
                elif '.exe' in target_lower and 'program files' not in target_lower:
                    why = "LNK to executable outside Program Files - verify this is not a dropped malware binary."
                else:
                    why = "Recently accessed file/folder. LNK files in Recent folder show user activity patterns."
            else:
                why = "LNK file records user/attacker file access. Useful for reconstructing activity timeline."

        elif 'Hayabusa' in artifact:
            level = row.get('Level') or row.get('RuleLevel', 'Unknown')
            title = row.get('RuleTitle') or row.get('Title') or row.get('Message', 'Detection')
            details = safe_str(row.get('Details')) or ''
            mitre = safe_str(row.get('MitreAttack')) or safe_str(row.get('MITRE')) or ''
            finding = f"{title}"
            if details:
                finding += f" - {details[:100]}"
            if mitre:
                finding += f" [MITRE: {mitre}]"
            # Make why more specific based on level
            level_upper = str(level).upper()
            if level_upper in ['CRITICAL', 'HIGH']:
                why = f"{level_upper} PRIORITY: This detection indicates likely malicious activity. Correlate with other events and investigate immediately."
            elif level_upper == 'MEDIUM':
                why = f"{level_upper}: Suspicious activity that warrants investigation. May be benign but requires verification."
            else:
                why = f"{level_upper}: Lower priority but adds context to the investigation. Review in conjunction with other findings."

        elif 'Persistence' in artifact or 'PersistenceSniper' in artifact:
            technique = row.get('Technique') or row.get('Name', 'Unknown')
            path = row.get('Path') or row.get('FullPath', '')
            author = safe_str(row.get('Author')) or safe_str(row.get('Publisher'))
            finding = technique
            if path:
                finding += f" at {path[:80]}"
            if author:
                finding += f" (by {author[:30]})"
            # Make why more specific
            technique_lower = str(technique).lower()
            if any(x in technique_lower for x in ['run', 'startup', 'logon']):
                why = "Auto-start persistence - executes on every boot/login. Verify this is authorized software, not malware maintaining access."
            elif 'service' in technique_lower:
                why = "Service-based persistence - runs with system privileges. Check if service is legitimate and properly signed."
            elif 'scheduled' in technique_lower or 'task' in technique_lower:
                why = "Scheduled task persistence - runs automatically at specified intervals. Review task actions and creation time."
            else:
                why = "Persistence mechanism detected - allows attacker to maintain access after reboot. Verify legitimacy."

        elif 'Detection' in artifact:
            name = row.get('Name') or row.get('Detection', 'Unknown')
            reason = row.get('Reason') or row.get('Message', '')
            severity = row.get('Severity') or row.get('Level', '')
            finding = name
            if reason:
                finding += f" - {reason[:80]}"
            # Make why more specific
            if severity:
                why = f"Detection triggered ({severity} severity). Review detection context and correlate with timeline."
            else:
                why = "Security detection fired. Investigate the triggering activity and related events."

        else:
            # Generic - try to provide more context based on common fields
            finding_parts = []
            for field in ['Name', 'FullPath', 'Message', 'CommandLine', 'Description']:
                if field in row and row[field]:
                    finding_parts.append(str(row[field])[:100])
                    if len(finding_parts) >= 2:
                        break
            finding = " | ".join(finding_parts) if finding_parts else "See raw data"
            # Try to provide artifact-specific why
            artifact_lower = artifact.lower()
            if 'event' in artifact_lower or 'evtx' in artifact_lower:
                why = "Windows Event Log entry - provides audit trail of system/security events. Correlate with timeline."
            elif 'registry' in artifact_lower:
                why = "Registry artifact - may indicate configuration changes, persistence, or malware traces."
            elif 'prefetch' in artifact_lower:
                why = "Prefetch data shows program execution history. Useful for proving execution even if binary deleted."
            elif 'browser' in artifact_lower or 'history' in artifact_lower:
                why = "Browser artifact - may reveal phishing links, download sources, or C2 URLs."
            else:
                why = f"Data from {artifact.split('.')[-1]} artifact. Review for indicators relevant to investigation."

        return f"**Artifact:** {artifact}\n**Finding:** {finding}\n**Why it matters:** {why}"

    def is_interesting_finding(row):
        """Check if a row appears to be an interesting/important finding."""
        for field in important_fields:
            if field in row:
                val = str(row.get(field, '')).lower()
                if val and val not in ('', 'none', 'null', '0', 'false', 'informational', 'info'):
                    return True
        # Also include rows with significant data
        if row.get('Name') or row.get('FullPath') or row.get('CommandLine'):
            return True
        return False

    # Process each artifact
    for artifact, rows in all_results.items():
        if not rows:
            continue

        # Determine which timestamp field this artifact uses
        sample_row = rows[0]
        ts_field = None
        for field in timestamp_fields:
            if field in sample_row:
                ts_field = field
                break

        for row in rows:
            hostname = row.get('_hostname', 'Unknown')
            client_id = row.get('_client_id', '')
            title = get_short_title(row, artifact)
            description = build_rich_description(row, artifact)

            if ts_field:
                ts_value = row.get(ts_field)
                parsed_ts = parse_timestamp(ts_value)
                if parsed_ts:
                    events.append({
                        'timestamp': parsed_ts,
                        'source': artifact,
                        'title': title,
                        'description': description,
                        'hostname': hostname,
                        'client_id': client_id,
                        'raw': {k: v for k, v in row.items() if not k.startswith('_')},
                        'no_timestamp': False
                    })
            elif include_no_timestamp and is_interesting_finding(row):
                no_timestamp_events.append({
                    'timestamp': None,
                    'source': artifact,
                    'title': title,
                    'description': description,
                    'hostname': hostname,
                    'client_id': client_id,
                    'raw': {k: v for k, v in row.items() if not k.startswith('_')},
                    'no_timestamp': True
                })

    # Sort timestamped events by timestamp
    events.sort(key=lambda x: x['timestamp'])

    # Add no-timestamp events at the beginning (limit per artifact)
    if no_timestamp_events:
        artifact_counts = {}
        limited_no_ts = []
        for ev in no_timestamp_events:
            artifact = ev['source']
            count = artifact_counts.get(artifact, 0)
            if count < 50:
                limited_no_ts.append(ev)
                artifact_counts[artifact] = count + 1
        events = limited_no_ts + events

    return events


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
        """Check if row's timestamp falls within the time range."""
        for field in TIMESTAMP_FIELDS:
            if field in row:
                ts = parse_timestamp(row[field])
                if ts:
                    # Make ts timezone-naive for comparison
                    if hasattr(ts, 'tzinfo') and ts.tzinfo is not None:
                        ts = ts.replace(tzinfo=None)
                    if start_time and ts < start_time:
                        return False
                    if end_time and ts > end_time:
                        return False
                    return True  # Found a valid timestamp in range
        # No timestamp found - include by default (better to include than exclude)
        return True

    # Filter each artifact's rows
    filtered_results = {}
    artifacts_filtered = []
    for artifact, rows in all_results.items():
        filtered_rows = [row for row in rows if is_in_range(row)]
        filtered_results[artifact] = filtered_rows
        if len(filtered_rows) != len(rows):
            artifacts_filtered.append(f"{artifact}: {len(filtered_rows)}/{len(rows)}")

    # Calculate total rows after filtering
    total_after = sum(len(rows) for rows in filtered_results.values())

    # Log summary to pipeline
    mode_str = f"relative ({time_filter.get('relative_range', '7d')})" if mode == 'relative' else "between dates"
    log(f"[Pipeline] Time filter ({mode_str}): {total_before} rows → {total_after} rows ({total_before - total_after} filtered out)")

    if artifacts_filtered:
        log(f"[Pipeline] Artifacts affected: {', '.join(artifacts_filtered[:5])}" + (f" (+{len(artifacts_filtered)-5} more)" if len(artifacts_filtered) > 5 else ""))

    return filtered_results


def _event_dedup_key(event, include_timestamp=True):
    """Generate a deduplication key for an event.

    For events WITH timestamps: include timestamp so different times = different events
    For events WITHOUT timestamps: dedupe based on source, title, and key fields only
    """
    source = event.get('source', '')
    title = event.get('title', '')
    raw = event.get('raw', {})

    # For timestamped events, include timestamp in key (different times = different events)
    timestamp_part = ''
    if include_timestamp and not event.get('no_timestamp', False):
        ts = event.get('timestamp')
        if ts:
            timestamp_part = str(ts)

    # Include key identifying fields from raw data
    key_fields = []
    for field in ['Name', 'Process', 'ProcessName', 'Exe', 'Path', 'FullPath',
                  'Command', 'CommandLine', 'RuleTitle', 'Finding', 'Detection',
                  'User', 'SourceAddress', 'LogonType', 'Description']:
        if field in raw:
            key_fields.append(str(raw[field]))

    return f"{source}|{title}|{timestamp_part}|{'|'.join(key_fields)}"


def filter_malicious_events(events, max_events=2000, min_severity='informational'):
    """Filter events for IRIS import with severity filtering and deduplication.

    When min_severity > informational:
    - Hayabusa/detection events: filter by Level/RuleLevel field
    - High-value artifacts (Persistence, Detection): always include
    - Low-value artifacts (Amcache, LNK, etc.): exclude when severity >= medium

    Events without timestamps are placed at top as important findings.
    """
    included = []
    no_ts_included = []
    seen_keys = set()  # Track seen events for deduplication

    # Severity filtering setup
    SEVERITY_ORDER = ['informational', 'low', 'medium', 'high', 'critical']
    min_idx = SEVERITY_ORDER.index(min_severity) if min_severity in SEVERITY_ORDER else 0

    # High-value sources always included regardless of severity filter
    HIGH_VALUE_SOURCES = ['persistence', 'detection', 'alert', 'sigma', 'malware', 'threat']

    # Low-value sources excluded when severity >= medium
    LOW_VALUE_SOURCES = ['amcache', 'lnk', 'prefetch', 'userassist', 'shimcache', 'recent', 'jumplist']

    # Skip only these verbose sources
    skip_sources = ['pstree', 'netstat']

    for event in events:
        source = str(event.get('source', '')).lower()
        no_timestamp = event.get('no_timestamp', False)
        raw = event.get('raw', {})

        # Skip only verbose sources (pstree, netstat)
        if any(skip in source for skip in skip_sources):
            continue

        # Severity filtering
        if min_idx > 0:  # If filtering is active
            # Check if event has severity info (Hayabusa, detections)
            event_severity = None
            for field in ['Level', 'level', 'RuleLevel', 'Severity', 'severity']:
                if field in raw:
                    event_severity = str(raw[field]).lower().strip()
                    break

            if event_severity:
                # Map common severity names
                severity_map = {'info': 'informational', 'informational': 'informational',
                                'low': 'low', 'medium': 'medium', 'med': 'medium',
                                'high': 'high', 'critical': 'critical', 'crit': 'critical'}
                normalized = severity_map.get(event_severity, event_severity)
                event_idx = SEVERITY_ORDER.index(normalized) if normalized in SEVERITY_ORDER else 0
                if event_idx < min_idx:
                    continue  # Skip - below threshold
            else:
                # No severity field - check if high-value or low-value source
                is_high_value = any(hv in source for hv in HIGH_VALUE_SOURCES)
                is_low_value = any(lv in source for lv in LOW_VALUE_SOURCES)

                # When severity >= medium, skip low-value artifacts
                if min_idx >= 2 and is_low_value and not is_high_value:
                    continue  # Skip low-value artifact

        # Generate dedup key (includes timestamp for timestamped events)
        dedup_key = _event_dedup_key(event)

        # Skip duplicates
        if dedup_key in seen_keys:
            continue
        seen_keys.add(dedup_key)

        # Add to appropriate list
        if no_timestamp:
            no_ts_included.append(event)
        else:
            included.append(event)

    # Sort timestamped events by timestamp
    included.sort(key=lambda x: x.get('timestamp') or datetime.min)

    # Put no-timestamp findings at the TOP (most important)
    result = no_ts_included + included

    # Limit total events
    if len(result) > max_events:
        result = result[:max_events]

    return result
