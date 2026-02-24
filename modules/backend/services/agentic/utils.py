#!/usr/bin/env python3
"""
Agentic Utils - Timeline extraction and data formatting helpers
"""

from datetime import datetime


def extract_timeline_events(all_results, include_no_timestamp=True):
    """Extract events from artifact data for timeline generation.
    Returns list of event dicts with: timestamp, source, description, hostname, raw, no_timestamp.

    Creates rich descriptions explaining what was found and why it matters."""

    events = []
    no_timestamp_events = []

    # Common timestamp field names across Velociraptor artifacts
    timestamp_fields = [
        'Timestamp', 'timestamp', 'Time', 'time', 'CreationTime', 'ModificationTime',
        'LastAccessTime', 'EventTime', 'event_time', 'Created', 'Modified', 'Accessed',
        '_time', 'StartTime', 'EndTime', 'LastWriteTime', 'SourceCreated', 'SourceModified',
        'SourceAccessed', 'SI_LastModified0x10', 'SI_LastAccess0x10', 'FN_LastModified0x30',
        'mtime', 'atime', 'ctime', 'btime', 'LastExecutionTime', 'LastRun'
    ]

    # Fields that indicate important/interesting findings
    important_fields = [
        'Level', 'Severity', 'Detection', 'Alert', 'Match', 'Hit', 'Finding',
        'Suspicious', 'Malicious', 'Risk', 'Score', 'Status', 'RuleTitle', 'RuleLevel'
    ]

    def parse_timestamp(ts_value):
        """Try to parse various timestamp formats."""
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
            details = row.get('Details') or ''
            mitre = row.get('MitreAttack') or row.get('MITRE') or ''
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


def filter_high_severity_events(events, max_events=500):
    """Filter events for IRIS import - generic logic, not artifact-specific.

    Includes events that have:
    - Any severity/level/priority field (detection results)
    - No timestamp (detection findings without time context)
    - Suspicious keywords in title/description
    - Any raw data fields indicating findings

    Excludes:
    - Events marked as 'trusted', 'clean', 'benign'
    - Events with only baseline/info severity
    - Truncates to max_events to avoid IRIS overload
    """
    filtered = []

    # Fields that indicate a detection/finding
    detection_fields = ['Level', 'Severity', 'RuleLevel', 'Priority', 'Detection',
                        'Alert', 'Hit', 'Match', 'Finding', 'Score', 'Risk',
                        'RuleTitle', 'Technique', 'Status']

    # Values that indicate NOT a finding (skip these)
    skip_values = ['trusted', 'clean', 'benign', 'normal', 'informational',
                   'info', 'none', 'null', '0', 'false', 'n/a', 'baseline']

    # Keywords that indicate interesting findings
    interesting_keywords = ['suspicious', 'malicious', 'threat', 'attack', 'exploit',
                           'injection', 'backdoor', 'persistence', 'credential',
                           'lateral', 'exfil', 'c2', 'command', 'control',
                           'shell', 'payload', 'encoded', 'obfuscated', 'critical',
                           'high', 'medium', 'warning', 'alert', 'detection']

    for event in events:
        raw = event.get('raw', {})
        title = str(event.get('title', '')).lower()
        description = str(event.get('description', '')).lower()
        no_timestamp = event.get('no_timestamp', False)

        # Always include events without timestamps (they represent findings)
        if no_timestamp:
            filtered.append(event)
            continue

        # Check if event has any detection/finding fields
        has_finding = False
        is_clean = False

        for field in detection_fields:
            if field in raw:
                val = str(raw[field]).lower().strip()
                if val:
                    # Check if it's a "clean" value to skip
                    if val in skip_values:
                        is_clean = True
                    else:
                        has_finding = True
                    break

        # Skip events explicitly marked as clean/trusted
        if is_clean and not has_finding:
            continue

        # Include if has a detection field with value
        if has_finding:
            filtered.append(event)
            continue

        # Check for interesting keywords in title/description
        combined_text = f"{title} {description}"
        if any(keyword in combined_text for keyword in interesting_keywords):
            filtered.append(event)
            continue

        # Include if raw data has meaningful content (not just metadata)
        meaningful_fields = ['Name', 'FullPath', 'CommandLine', 'Message', 'Description',
                            'Target', 'Path', 'Hash', 'SHA256', 'MD5', 'Process']
        for field in meaningful_fields:
            if field in raw and raw[field]:
                val = str(raw[field]).lower()
                # Include if the value contains suspicious content
                if any(keyword in val for keyword in interesting_keywords):
                    filtered.append(event)
                    break

    # Limit total events to prevent IRIS overload
    if len(filtered) > max_events:
        filtered = filtered[:max_events]

    return filtered
