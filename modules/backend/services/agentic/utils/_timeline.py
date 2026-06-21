#!/usr/bin/env python3
"""
Agentic Utils - Timeline extraction and data formatting helpers
"""
from datetime import datetime  # noqa: F401
from services.agentic.utils._helpers import *  # noqa: F401,F403

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
            # Title only — severity belongs in the Why-it-matters body, not
            # in the event name. Keeps timeline names clean and consistent
            # with the other artifact branches.
            title = extract_str(row.get('RuleTitle')) or extract_str(row.get('Title')) or 'Detection'
            return title[:60]
        elif 'Persistence' in artifact or 'PersistenceSniper' in artifact:
            technique = extract_str(row.get('Technique')) or extract_str(row.get('Name')) or 'Unknown'
            return f"Persistence: {technique[:45]}"
        elif 'Detection' in artifact:
            detection = row.get('Detection') if isinstance(row.get('Detection'), dict) else None
            name = extract_str((detection or {}).get('Name')) or extract_str(row.get('Name')) or 'Alert'
            # Add the affected file/path so multiple detections of the same
            # rule on different files render as distinct events (the IRIS
            # timeline was showing four identical "Detection: Credential
            # Theft" rows in a row because only `name` was used).
            target = (extract_str(row.get('FullPath'))
                      or extract_str(row.get('FilePath'))
                      or extract_str(row.get('Path'))
                      or extract_str(row.get('FileName'))
                      or extract_str(row.get('Source')))
            target_short = get_filename(target) if target else None
            if target_short and target_short != name:
                return f"Detection: {str(name)[:32]} — {target_short[:28]}"
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

    def clean_multiline_details(details_str: str) -> str:
        """Clean up YAML multiline content for inline display.

        Converts:
            '|\\nNewEngineState=Available\\nPreviousEngineState=None'
        To:
            'NewEngineState=Available, PreviousEngineState=None'

        No truncation - IRIS handles the 2000 char limit at import time.
        """
        if not details_str:
            return ''
        cleaned = details_str.strip()
        # Remove YAML multiline indicators (| or >)
        if cleaned.startswith('|') or cleaned.startswith('>'):
            cleaned = cleaned[1:].strip()
        # Replace newlines with comma-space for inline display
        cleaned = ', '.join(
            part.strip()
            for part in cleaned.split('\n')
            if part.strip()
        )
        return cleaned

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
            level = safe_str(row.get('Level') or row.get('RuleLevel', 'Unknown'))
            title = safe_str(row.get('RuleTitle') or row.get('Title') or row.get('Message', 'Detection'))
            details = safe_str(row.get('Details')) or ''
            mitre = safe_str(row.get('MitreAttack')) or safe_str(row.get('MITRE')) or ''
            channel = safe_str(row.get('Channel'))
            eid = safe_str(row.get('EID')) or safe_str(row.get('EventID'))

            # Parse the pipe-separated Details field that Hayabusa emits
            # ("Threat: ... | Severity: ... | User: ... | Path: ... | Proc: ...")
            # so we can weave specific fields into the Why text.
            detail_fields = {}
            if details:
                for piece in details.split('|'):
                    if ':' in piece:
                        k, _, v = piece.partition(':')
                        detail_fields[k.strip().lower()] = v.strip()

            user = detail_fields.get('user') or safe_str(row.get('Username'))
            path = detail_fields.get('path') or safe_str(row.get('OSPath'))
            proc = detail_fields.get('proc') or detail_fields.get('process')
            threat = detail_fields.get('threat')

            finding = title
            if threat:
                finding += f" — {threat}"
            elif details:
                finding += f" — {clean_multiline_details(details)}"
            if mitre:
                finding += f" [MITRE: {mitre}]"

            # Build a concrete Why grounded in the Sigma rule title +
            # the actual user / path / process / threat fields. Keyword
            # matching on title catches the common attack-chain stages.
            sev_prefix = f"{level}-severity. " if level and level.lower() not in ('unknown', 'info', 'informational') else ""
            text = f"{title} {threat or ''} {channel} {details}".lower()
            target_clip = (path[:160] + "…") if path and len(path) > 160 else (path or "")

            if 'log' in text and ('clear' in text or 'cleared' in text):
                why = (sev_prefix +
                       f"Windows event log was cleared"
                       + (f" — channel: {channel}" if channel else "")
                       + (f", initiated by {user}" if user else "")
                       + ". Log clearance is a defense-evasion TTP (T1070.001) "
                       "— attacker may be hiding earlier activity. Restore "
                       "from backups if possible and audit what executed "
                       "before the clearance.")
            elif 'defender' in text and ('disabled' in text or 'turned off' in text or 'tamper' in text):
                why = (sev_prefix +
                       f"Windows Defender was disabled or tampered with"
                       + (f" by {user}" if user else "")
                       + ". Adversary likely staging follow-on activity "
                       "(T1562.001). Re-enable AV immediately and check "
                       "what executed during the disabled window.")
            elif 'hosts' in text and ('hijack' in text or 'modif' in text):
                why = (sev_prefix +
                       f"Hosts file modification detected"
                       + (f" at {target_clip}" if target_clip else "")
                       + (f" by {user}" if user else "")
                       + ". Adversaries edit the hosts file to redirect DNS "
                       "for credential harvesting, ad-block bypass, or C2 "
                       "indirection (T1557.002 / T1565.001). Inspect current "
                       "hosts contents for added entries and identify the "
                       "process that wrote it.")
            elif 'lsass' in text or 'credential' in text or 'mimikatz' in text:
                why = (sev_prefix +
                       f"Credential-access activity"
                       + (f" — {threat}" if threat else "")
                       + (f" — process: {proc}" if proc else "")
                       + ". Likely credential dumping (T1003). Isolate the "
                       "host, identify parent process, rotate any account "
                       "whose hash may have been read.")
            elif 'powershell' in text or 'script' in text or 'encoded' in text:
                why = (sev_prefix +
                       f"Suspicious PowerShell / script activity"
                       + (f" by {user}" if user else "")
                       + ". Review command line, parent process, and "
                       "downstream behaviour. Encoded / downloaded scripts "
                       "are common loaders (T1059.001).")
            elif ('persistence' in text or 'autorun' in text
                  or 'scheduled' in text or 'service creation' in text):
                why = (sev_prefix +
                       f"Persistence mechanism detected"
                       + (f" at {target_clip}" if target_clip else "")
                       + (f" by {user}" if user else "")
                       + ". Attacker is configuring the host to re-establish "
                       "access. Verify legitimacy and remove if unauthorised "
                       "(T1547 / T1053 / T1543).")
            elif 'rdp' in text or 'lateral' in text or 'remote' in text and 'logon' in text:
                why = (sev_prefix +
                       f"Lateral-movement / remote-logon signal"
                       + (f" — user {user}" if user else "")
                       + ". Review source/destination accounts and isolate "
                       "affected systems (T1021).")
            elif 'process injection' in text or 'hollow' in text or 'inject' in text:
                why = (sev_prefix +
                       f"Process-injection / hollowing detected"
                       + (f" — {threat}" if threat else "")
                       + ". In-memory tradecraft used to evade AV and run "
                       "code in trusted process context (T1055). Capture a "
                       "memory dump before reboot.")
            elif details:
                # Fallback: surface the threat/details verbatim so the
                # analyst at least sees the rule's own description.
                why = (sev_prefix +
                       f"Sigma rule fired: {title}"
                       + (f" — {threat or details[:200]}")
                       + (f" — user {user}" if user else "")
                       + (f" — path {target_clip}" if target_clip else "")
                       + ". Investigate the triggering activity and correlate "
                       "with surrounding events.")
            else:
                why = (sev_prefix +
                       f"Sigma rule '{title}' fired"
                       + (f" on event {eid}/{channel}" if eid or channel else "")
                       + ". Investigate the triggering activity.")

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

        elif 'BinaryRename' in artifact:
            # Detection fires when current filename != PE OriginalFilename.
            # Embed both names + the file description from PE metadata so
            # the analyst sees exactly what tool is masquerading as what.
            current = safe_str(row.get('Name')) or safe_str(row.get('OSPath'))
            path = safe_str(row.get('OSPath'))
            ver = row.get('VersionInformation') or {}
            original = safe_str(ver.get('OriginalFilename'))
            description = safe_str(ver.get('FileDescription'))
            company = safe_str(ver.get('CompanyName'))
            sha256 = safe_str((row.get('Hash') or {}).get('SHA256')) if isinstance(row.get('Hash'), dict) else ''

            finding = f"{current} (renamed)"
            if original and original.lower() not in current.lower():
                finding += f" — original: {original}"
            if path:
                finding += f" at {path[:120]}"

            # Concrete Why citing the actual binary identity
            tool_hint = ""
            tool_lower = (original or current or "").lower()
            if 'procdump' in tool_lower:
                tool_hint = " ProcDump is commonly abused to dump LSASS memory for credential theft (T1003.001)."
            elif 'mimikatz' in tool_lower:
                tool_hint = " Mimikatz is a credential-dumping toolkit (T1003)."
            elif 'psexec' in tool_lower:
                tool_hint = " PsExec is commonly used for lateral movement (T1021.002)."
            elif 'nmap' in tool_lower or 'masscan' in tool_lower:
                tool_hint = " Network scanner — possible lateral-movement reconnaissance (T1046)."
            why = (
                f"Binary on disk has been renamed: file is named '{current}' but "
                f"the embedded PE OriginalFilename says '{original or 'unknown'}'"
                + (f" ({description})" if description else "")
                + (f", signed/published by {company}" if company else "")
                + ".{tool_hint} Adversaries rename tools to defeat name-based "
                "detection (T1036.005). Hash this file (SHA256: "
                f"{sha256 or 'n/a'}), check execution events tied to this path, "
                "and verify business legitimacy."
            ).format(tool_hint=tool_hint)

        elif 'Detection' in artifact:
            # Handle nested Detection dict (DetectRaptor artifacts)
            detection = row.get('Detection', {})
            if isinstance(detection, dict):
                name = detection.get('Name') or row.get('Name', 'Unknown')
                severity = detection.get('Criticality') or detection.get('Severity') or row.get('Level', '')
                reason = (detection.get('Reason') or row.get('Reason')
                          or row.get('Message', ''))
                string_hit = detection.get('StringHit') or ''
                keyword_regex = detection.get('KeywordRegex') or ''
            else:
                name = row.get('Name') or (str(detection) if detection else 'Unknown')
                severity = row.get('Severity') or row.get('Level', '')
                reason = row.get('Reason') or row.get('Message', '')
                string_hit = ''
                keyword_regex = ''

            # Affected target — file/path/event-id/event-message
            target = (row.get('OSPath') or row.get('FullPath') or row.get('FilePath')
                      or row.get('Path') or row.get('FileName')
                      or row.get('Source'))
            if isinstance(target, dict):
                target = target.get('Path') or target.get('Name') or target.get('Value')
            event_id = row.get('EventID') or row.get('EventId') or ''
            channel = safe_str(row.get('Channel'))
            user = safe_str(row.get('Username')) or safe_str(row.get('User'))
            msg = safe_str(row.get('Message'))

            finding_bits = [str(name)]
            if string_hit:
                finding_bits.append(f"matched: {string_hit}")
            if target:
                finding_bits.append(f"on {str(target)[:200]}")
            if event_id:
                finding_bits.append(f"EID {event_id}" + (f" / {channel}" if channel else ""))
            if user:
                finding_bits.append(f"user {user}")
            if reason and isinstance(reason, str):
                finding_bits.append(clean_multiline_details(reason)[:240])
            finding = " — ".join(finding_bits)

            # Build a concrete Why that cites the actual finding's data.
            # Combine artifact name (e.g., "BinaryRename", "Evtx") + detection
            # name keyword matching so the analyst gets attack-chain context
            # tied to THIS row, not boilerplate.
            search_text = f"{artifact} {name}".lower()
            sev_prefix = f"{severity}-severity. " if severity else ""
            target_clip = (str(target)[:120] + "…") if target and len(str(target)) > 120 else (target or "")

            if 'credential' in search_text or 'mimikatz' in search_text or 'lsass' in search_text:
                why = (sev_prefix +
                       f"Credential-access activity detected"
                       + (f" on {target_clip}" if target_clip else "")
                       + (f" by user {user}" if user else "")
                       + ". Likely credential dumping (LSASS, SAM, browser stores) — "
                       "T1003. Isolate the host, identify the parent process, and "
                       "rotate any account whose hash may have been exposed.")
            elif ('persistence' in search_text or 'autorun' in search_text
                  or 'scheduledtask' in search_text or 'wmi' in search_text):
                why = (sev_prefix +
                       f"Persistence mechanism detected"
                       + (f" at {target_clip}" if target_clip else "")
                       + ". Attacker is configuring this host to re-establish access "
                       "after reboot/logoff. Verify legitimacy of the entry and "
                       "remove if unauthorised (T1547 / T1053 / T1546).")
            elif 'lateral' in search_text or 'rdp' in search_text or 'smb' in search_text:
                why = (sev_prefix +
                       "Lateral-movement signal — adversary may be pivoting between "
                       "hosts (T1021). Review source/destination accounts, network "
                       "logs, and isolate affected systems.")
            elif ('defender' in search_text or 'evasion' in search_text
                  or 'tamper' in search_text or 'disable' in search_text
                  or 'log file cleared' in search_text or 'cleared' in search_text):
                why = (sev_prefix +
                       f"Defense-evasion event"
                       + (f" affecting {target_clip}" if target_clip else "")
                       + (f" — initiated by {user}" if user else "")
                       + ". Adversary is disabling monitoring or wiping evidence "
                       "(T1562 / T1070). Restore the disabled control immediately "
                       "and audit what activity occurred during the blind window.")
            elif ('rename' in search_text or 'masquerad' in search_text
                  or 'binaryrename' in search_text):
                why = (sev_prefix +
                       f"Renamed/masquerading binary detected"
                       + (f" at {target_clip}" if target_clip else "")
                       + ". Adversary disguised a tool as a legitimate binary "
                       "(T1036.005). Hash the file, check the PE OriginalFilename, "
                       "and look for execution events tied to this path.")
            elif ('powershell' in search_text or 'script' in search_text
                  or 'execution' in search_text or 'cmdline' in search_text):
                why = (sev_prefix +
                       f"Suspicious script/process execution"
                       + (f" — {target_clip}" if target_clip else "")
                       + (f" by {user}" if user else "")
                       + ". Review command line, parent process, and downstream "
                       "behaviour for credential access, lateral movement, or C2 "
                       "(T1059).")
            elif ('rmm' in search_text or 'remote' in search_text and 'support' in search_text):
                why = (sev_prefix +
                       f"RMM tool detected"
                       + (f" — {target_clip}" if target_clip else "")
                       + ". Remote-management software is commonly abused for "
                       "lateral movement and persistence (T1219). Verify business "
                       "legitimacy and review remote-session activity.")
            elif 'cloud' in search_text or 'transfer' in search_text or 'onedrive' in search_text or 'dropbox' in search_text:
                why = (sev_prefix +
                       f"Cloud-sync application observed"
                       + (f" — {target_clip}" if target_clip else "")
                       + ". Cloud-storage clients can be abused for exfiltration "
                       "(T1567.002). Verify business need and check synced data "
                       "volume / destination account.")
            elif 'archive' in search_text:
                why = (sev_prefix +
                       f"Archive utility observed"
                       + (f" — {target_clip}" if target_clip else "")
                       + ". Adversaries stage data into archives prior to "
                       "exfiltration (T1560). Review what files were compressed "
                       "and where the archive went next.")
            elif msg and len(msg) < 250:
                # No keyword match but we have a message — surface it directly
                why = (sev_prefix +
                       f"Detection '{name}' fired"
                       + (f" on {target_clip}" if target_clip else "")
                       + (f" — {msg}" if msg else "")
                       + ". Investigate the triggering activity and correlate "
                       "with surrounding events.")
            elif severity:
                why = (f"{severity}-severity detection '{name}'"
                       + (f" on {target_clip}" if target_clip else "")
                       + (f" by {user}" if user else "")
                       + ". Investigate triggering activity, correlate with "
                       "surrounding events, and assess scope.")
            else:
                why = (f"Detection '{name}' fired"
                       + (f" on {target_clip}" if target_clip else "")
                       + ". Investigate the triggering activity and related events.")

        elif 'SAM/Parsed' in artifact or 'SAM/CreateTimes' in artifact or 'SAM' in artifact:
            user = safe_str(row.get('Username')) or safe_str(row.get('Name'))
            created = safe_str(row.get('CreatedTime'))
            key = safe_str(row.get('Key'))
            finding_bits = []
            if user:
                finding_bits.append(f"user {user}")
            if created:
                finding_bits.append(f"created {created}")
            if key:
                finding_bits.append(f"key {key[:80]}")
            finding = " — ".join(finding_bits) or "SAM hive entry"
            why = (
                f"SAM hive entry"
                + (f" for local account '{user}'" if user else "")
                + (f", account created at {created}" if created else "")
                + ". Review whether the account was authorised; adversaries "
                "create local accounts for persistence (T1136.001) and the "
                "SAM hive itself can be exfiltrated for offline credential "
                "cracking (T1003.002)."
            )

        elif 'UntrustedBinaries' in artifact:
            filename = safe_str(row.get('Filename'))
            issuer = safe_str(row.get('Issuer'))
            subject = safe_str(row.get('Subject'))
            trusted = safe_str(row.get('Trusted'))
            finding = f"{filename} [{trusted or 'unknown trust'}]"
            if trusted and trusted.lower() == 'trusted':
                why = (
                    f"Trusted binary {filename}"
                    + (f" signed by {subject[:120]}" if subject else "")
                    + ". Listed for completeness — typically benign. Useful as "
                    "context only when correlating with anomalous execution."
                )
            else:
                why = (
                    f"Binary {filename} has an UNTRUSTED or missing code "
                    "signature"
                    + (f" (issuer: {issuer[:120]})" if issuer else "")
                    + ". Adversaries replace signed binaries with malware to "
                    "evade signature-based defences (T1553). Hash-compare "
                    "against a known-good copy and treat as suspicious until "
                    "verified."
                )

        elif 'Pstree' in artifact or 'Process' in artifact:
            proc_name = safe_str(row.get('Name'))
            pid = safe_str(row.get('Pid'))
            ppid = safe_str(row.get('Ppid'))
            user = safe_str(row.get('Username'))
            cmdline = safe_str(row.get('CommandLine'))
            exe = safe_str(row.get('Exe'))
            call_chain = safe_str(row.get('CallChain'))
            finding = f"{proc_name} (PID {pid}, parent {ppid})"
            if exe:
                finding += f" — {exe[:140]}"
            if cmdline and cmdline != exe:
                finding += f" cmd: {cmdline[:200]}"
            if call_chain:
                finding += f" — chain: {call_chain[:120]}"
            cmd_lower = cmdline.lower()
            proc_lower = proc_name.lower()
            if 'powershell' in proc_lower or 'powershell' in cmd_lower:
                why = (
                    f"PowerShell process running as {user or 'unknown'}"
                    + (f" (call chain: {call_chain})" if call_chain else "")
                    + f". Command: {cmdline[:240] or '(none)'}. Review for "
                    "encoded payloads, downloads, AMSI bypass, or LOLBin "
                    "abuse (T1059.001)."
                )
            elif any(x in proc_lower for x in ('cmd.exe', 'wscript', 'cscript', 'mshta')):
                why = (
                    f"Scripting host process {proc_name} as "
                    f"{user or 'unknown'}, parent PID {ppid}. Scripting hosts "
                    "are common LOLBins (T1059). Review the parent process "
                    "and the command line for suspicious arguments."
                )
            elif 'svchost' in proc_lower or 'services' in proc_lower:
                why = (
                    f"Service-host process {proc_name} (PID {pid}, parent "
                    f"{ppid}) running as {user or 'SYSTEM'}. Usually "
                    "legitimate; verify the -k group / parent and look for "
                    "anomalous DLLs or non-system parents."
                )
            elif user and user.lower() not in ('system', 'nt authority\\system', 'local service', 'network service'):
                why = (
                    f"User-context process {proc_name} (PID {pid}) by "
                    f"{user}. Verify the executable path is expected and the "
                    "command line looks normal for that user."
                )
            else:
                why = (
                    f"Process {proc_name} (PID {pid}, parent {ppid}) — "
                    f"{exe or '(no exe)'}. Review parent lineage and command "
                    "line for unusual patterns."
                )

        elif 'Detection.Applications' in artifact or 'Applications' in artifact:
            display_name = safe_str(row.get('DisplayName')) or safe_str(row.get('KeyName'))
            version = safe_str(row.get('DisplayVersion'))
            publisher = safe_str(row.get('Publisher'))
            category = safe_str(row.get('Category'))
            install_loc = safe_str(row.get('InstallLocation')) or safe_str(row.get('InstallSource'))
            finding = f"{display_name} {version}".strip()
            if publisher:
                finding += f" by {publisher}"
            if category:
                finding += f" ({category})"
            why = (
                f"Installed application '{display_name}'"
                + (f" v{version}" if version else "")
                + (f" by {publisher}" if publisher else "")
                + (f" — category: {category}" if category else "")
                + ". Cataloged for context. If the category is data-transfer / "
                "RMM / archive / scripting, verify business legitimacy and "
                "review related file/network activity."
            )

        else:
            # Generic - surface ALL meaningful fields by name=value pairs so
            # the analyst sees the actual data rather than "See raw data".
            field_priority = ['Name', 'FullPath', 'OSPath', 'FilePath', 'Path',
                              'CommandLine', 'Exe', 'Message', 'Description',
                              'Username', 'User', 'Computer', 'Hostname',
                              'EventID', 'Channel', 'Title']
            field_bits = []
            for field in field_priority:
                v = row.get(field)
                if v in (None, '', [], {}):
                    continue
                v_str = clean_multiline_details(str(v)) if isinstance(v, str) else str(v)
                if v_str:
                    field_bits.append(f"{field}={v_str[:140]}")
                if len(field_bits) >= 4:
                    break
            finding = " | ".join(field_bits) if field_bits else "See raw data"

            artifact_lower = artifact.lower()
            short = artifact.split('.')[-1]
            if 'event' in artifact_lower or 'evtx' in artifact_lower:
                eid = safe_str(row.get('EventID')) or safe_str(row.get('EventId'))
                channel = safe_str(row.get('Channel'))
                user = safe_str(row.get('Username')) or safe_str(row.get('User'))
                why = (
                    f"Windows Event"
                    + (f" {eid}" if eid else "")
                    + (f" on {channel}" if channel else "")
                    + (f" by {user}" if user else "")
                    + ". Audit-trail entry — correlate timestamps with "
                    "surrounding events, especially execution / logon / "
                    "policy changes."
                )
            elif 'registry' in artifact_lower:
                key = safe_str(row.get('Key')) or safe_str(row.get('KeyPath')) or safe_str(row.get('Path'))
                why = (
                    f"Registry entry"
                    + (f" at {key[:160]}" if key else "")
                    + ". Persistence (Run keys, services), configuration "
                    "tampering, or malware-trace candidates live here. Verify "
                    "the value against a known-good baseline."
                )
            elif 'prefetch' in artifact_lower:
                exe = safe_str(row.get('Executable')) or safe_str(row.get('Name'))
                why = (
                    f"Prefetch entry"
                    + (f" for {exe}" if exe else "")
                    + ". Proves the binary executed even if it was later "
                    "deleted (T1059). Useful for reconstructing attacker "
                    "actions."
                )
            elif 'browser' in artifact_lower or 'history' in artifact_lower:
                url = safe_str(row.get('Url')) or safe_str(row.get('URL'))
                why = (
                    f"Browser artifact"
                    + (f" — visit to {url[:200]}" if url else "")
                    + ". May reveal phishing landing pages, malware download "
                    "sources, or C2 panels (T1071.001)."
                )
            else:
                why = (
                    f"Data from {short} artifact — review the highlighted "
                    "fields above and correlate with surrounding events for "
                    "investigative context."
                )

        # IRIS has 2000 char limit - ensure "Why it matters" is always included
        artifact_line = f"**Artifact:** {artifact}\n"
        why_line = f"\n**Why it matters:** {why}"
        reserved = len(artifact_line) + len(why_line) + len("**Finding:** ")
        max_finding_len = 1900 - reserved  # Leave buffer

        if len(finding) > max_finding_len:
            # Truncate finding at word boundary
            truncate_at = finding.rfind(' ', 0, max_finding_len - 3)
            if truncate_at > max_finding_len // 2:
                finding = finding[:truncate_at] + '...'
            else:
                finding = finding[:max_finding_len - 3] + '...'

        return f"{artifact_line}**Finding:** {finding}{why_line}"

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

        # Find timestamp field - may be nested in sub-objects (e.g., MFT SI_Lt_Mod.Created0x10)
        sample_row = rows[0]
        ts_path, _ = find_field_recursive(sample_row, timestamp_fields)

        for row in rows:
            hostname = row.get('_hostname', 'Unknown')
            client_id = row.get('_client_id', '')
            title = get_short_title(row, artifact)
            description = build_rich_description(row, artifact)

            if ts_path:
                _, ts_value = find_field_recursive(row, timestamp_fields)
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

    # Dedupe: events sharing (source, title) are the same logical detection
    # firing repeatedly. Keep the earliest, append an occurrence count and
    # time range to the description so the analyst still sees the volume.
    # Now that titles include the affected file/path, this only collapses
    # *true* repeats (same rule on same file at multiple MFT timestamps).
    deduped: list[dict] = []
    keys: dict[tuple, dict] = {}
    for ev in events:
        key = (ev.get('source'), ev.get('title'))
        if key in keys:
            primary = keys[key]
            primary['_dup_count'] = primary.get('_dup_count', 1) + 1
            ts = ev.get('timestamp')
            if ts and (primary.get('_last_ts') is None or ts > primary['_last_ts']):
                primary['_last_ts'] = ts
        else:
            ev['_dup_count'] = 1
            ev['_last_ts'] = ev.get('timestamp')
            keys[key] = ev
            deduped.append(ev)

    for ev in deduped:
        n = ev.pop('_dup_count', 1)
        last_ts = ev.pop('_last_ts', None)
        if n > 1:
            first = ev.get('timestamp')
            ev['description'] = (
                (ev.get('description') or '')
                + f"\n\n**Occurrences:** {n} firings between {first} and {last_ts}"
            )
    events = deduped

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


