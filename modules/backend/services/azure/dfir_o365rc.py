"""
DFIR-O365RC Integration - Unified Audit Log collection via Docker

Uses the ANSSI DFIR-O365RC tool (PowerShell in Docker) to collect
Unified Audit Log data that Graph API cannot access.

Requires:
- Docker image: anssi/dfir-o365rc:latest
- PFX certificate at /data/db/azure_cert.pfx
- Public key uploaded to Azure App Registration
"""

import os
import json
import glob
import shutil
import time
import subprocess
import threading
from typing import Dict, List, Optional, Callable

from services.upgrade.base import run_command, HOST_PATH

CERT_PATH = "/app/data/azure_cert.pfx"
CERT_PUBLIC_PATH = "/app/data/azure_cert_public.pem"


def _docker_image() -> str:
    """DFIR-O365RC image ref, version-pinned via config.yaml -> backend .env.
    Upstream only ships ':latest'; read fresh so an upgrade (re-pull of
    latest) applies without a backend restart."""
    try:
        from config import get_dfir_o365rc_image
        return get_dfir_o365rc_image()
    except Exception:
        return f"anssi/dfir-o365rc:{os.environ.get('DFIR_O365RC_VERSION', 'latest')}"


def _cleanup_container(container_name: str):
    """Remove a DFIR-O365RC container if it exists (prevent orphans)."""
    try:
        subprocess.run(
            f"docker rm -f {container_name}",
            shell=True, capture_output=True, timeout=10
        )
    except Exception:
        pass


def cleanup_orphan_containers():
    """Remove any leftover DFIR-O365RC containers (called on startup or purge)."""
    try:
        result = subprocess.run(
            "docker ps -a --filter name=dfir_o365rc_ -q",
            shell=True, capture_output=True, text=True, timeout=10
        )
        if result.stdout.strip():
            containers = result.stdout.strip().split('\n')
            for cid in containers:
                subprocess.run(f"docker rm -f {cid}", shell=True, capture_output=True, timeout=10)
            return len(containers)
    except Exception:
        pass
    return 0


def is_available() -> Dict[str, any]:
    """Check if DFIR-O365RC is available and configured."""
    result = {
        'available': False,
        'has_image': False,
        'has_certificate': False,
        'message': ''
    }

    # Check Docker image
    check = run_command(f"docker image inspect {_docker_image()}", logger=None)
    result['has_image'] = check.get('success', False)

    # Check certificate
    result['has_certificate'] = os.path.exists(CERT_PATH)

    if not result['has_image']:
        result['message'] = 'DFIR-O365RC Docker image not found. Run: docker pull anssi/dfir-o365rc:latest'
    elif not result['has_certificate']:
        result['message'] = 'Azure certificate not generated. Run install.sh or generate manually.'
    else:
        result['available'] = True
        result['message'] = 'Ready. Ensure public key is uploaded to Azure App Registration.'

    return result


def get_public_certificate() -> Optional[str]:
    """Read the public certificate content for display in Settings UI."""
    if os.path.exists(CERT_PUBLIC_PATH):
        with open(CERT_PUBLIC_PATH, 'r') as f:
            return f.read()
    return None


def check_exchange_online_available(azure_config: Dict[str, str]) -> Dict[str, any]:
    """Check if the tenant has an active Exchange Online subscription.

    DFIR-O365RC requires active (non-expired) Exchange Online for UAL collection.
    Checks both SKU presence AND capabilityStatus (Enabled vs Suspended/Warning/Deleted).
    Also tries to fetch mailbox settings to verify Exchange Online is actually responding.
    Returns a dict with 'available' (bool) and 'message' (str).
    """
    try:
        from .collectors import get_access_token, graph_request

        token = get_access_token(azure_config)

        # Real Exchange Online plans (excluding EXCHANGE_S_FOUNDATION which is shared/bundled)
        real_exchange_plans = {
            'EXCHANGE_S_STANDARD',
            'EXCHANGE_S_ENTERPRISE',
            'EXCHANGE_S_DESKLESS',
            'EXCHANGE_S_ARCHIVE',
            'EXCHANGE_B_STANDARD',
            'EXCHANGE_DESKLESS',
        }

        resp = graph_request(token, '/subscribedSkus')
        if resp.status_code != 200:
            return {'available': False, 'message': f'Failed to query subscribed SKUs (HTTP {resp.status_code})'}

        # Check for an ENABLED Exchange Online SKU
        skus = resp.json().get('value', [])
        active_exchange_sku = None
        suspended_exchange = False

        for sku in skus:
            sku_capability = sku.get('capabilityStatus', '')
            for plan in sku.get('servicePlans', []):
                plan_name = plan.get('servicePlanName', '').upper()
                if plan_name in real_exchange_plans:
                    if sku_capability == 'Enabled' and plan.get('provisioningStatus') == 'Success':
                        active_exchange_sku = plan_name
                        break
                    else:
                        suspended_exchange = True
            if active_exchange_sku:
                break

        if not active_exchange_sku:
            if suspended_exchange:
                return {'available': False, 'message': 'Exchange Online SKU exists but is suspended/expired (likely trial expired)'}
            return {'available': False, 'message': 'No active Exchange Online subscription in tenant'}

        # Definitive test: try to fetch mailboxSettings for any user
        # This will fail if Exchange Online is suspended even if SKU shows Enabled
        users_resp = graph_request(token, '/users', params={'$select': 'id,mail', '$top': '10'})
        if users_resp.status_code == 200:
            users = users_resp.json().get('value', [])
            for user in users:
                if not user.get('mail'):
                    continue
                mb_resp = graph_request(token, f"/users/{user['id']}/mailboxSettings")
                if mb_resp.status_code == 200:
                    return {'available': True, 'message': f'Exchange Online active and responding ({active_exchange_sku})'}
                elif mb_resp.status_code in (403, 404):
                    err = mb_resp.json().get('error', {}).get('code', '') if mb_resp.text else ''
                    if 'MailboxNotEnabled' in err or 'NotFound' in err:
                        continue
                    # Other errors mean Exchange is responding but blocking us
                    return {'available': False, 'message': f'Exchange Online not accessible: {err}'}

            return {'available': False, 'message': 'Exchange Online SKU active but no functional mailboxes found (likely expired/suspended)'}

        return {'available': True, 'message': f'Exchange Online available ({active_exchange_sku})'}

    except Exception as e:
        return {'available': False, 'message': f'Exchange check failed: {str(e)[:200]}'}


# =============================================================================
# UAL collection-mode profiles
# =============================================================================
#
# `ual_mode` selects which UAL records DFIR-O365RC pulls from Microsoft.
# Big tenants generate millions of low-signal events (PowerBI activity,
# Yammer, Sway, etc.) that bury the forensically interesting ones and
# blow up collection time + LLM analysis cost. The two profiles are:
#
#   * "full"  — `-requestType Unfiltered`. Every record type. Default —
#               matches behaviour before the dropdown was introduced.
#               Right choice for small tenants and "I don't know what
#               happened" hunts. Slow on large tenants (15-60+ min).
#
#   * "light" — `-requestType RecordTypes` filtered to a curated list of
#               high-signal types covering the main initial-access /
#               persistence / identity-takeover vectors. Skips PowerBI,
#               Sway, Yammer, Stream, MicrosoftFlow, etc. Typically
#               5-10x smaller dataset; matches the use case the operator
#               flagged: "big organizations need light to avoid waiting".
#
# Identity filters (target_users / target_ips) take precedence over both
# — they're more targeted than any RecordTypes filter — so the user/IP
# scope wins and `ual_mode` is ignored when a filter is set. The mode
# only changes the path when no identity filter is in play.
LIGHT_RECORD_TYPES = [
    # Identity / auth — the must-have core
    "AzureActiveDirectory",            # Generic Azure AD events
    "AzureActiveDirectoryStsLogon",    # STS logon events (interactive + non-interactive)
    "AzureActiveDirectoryAccountLogon",# Account logon outcomes

    # Persistence vectors
    "ExchangeAdmin",                   # Mailbox config changes (forwarding rules, etc.)
    "ApplicationAudit",                # OAuth app consent grants

    # Threat-intel signals
    "ThreatIntelligenceUrl",           # Malicious URL hits

    # Compliance / security tooling activity (rare but high-signal)
    "SecurityComplianceCenterEOPCmdlet",
]


def collect_unified_audit_log(
    tenant: str,
    app_id: str,
    start_date: str,
    end_date: str,
    target_users: Optional[List[str]] = None,
    logger=None,
    azure_config: Optional[Dict[str, str]] = None,
    run_id: str = None,
    ual_mode: str = "full",
) -> Dict:
    """
    Collect Unified Audit Log via DFIR-O365RC Docker container.

    Args:
        tenant: Azure tenant ID or domain
        app_id: Azure App Registration client ID
        start_date: Start date (ISO format or MM/DD/YYYY)
        end_date: End date (ISO format or MM/DD/YYYY)
        target_users: Optional list of user emails to filter
        logger: Logging function
        ual_mode: "full" (every record type, default) or "light" (curated
            high-signal record types only — recommended for large tenants).
            Ignored when target_users or target_ips is set; identity
            filters take precedence as they're more targeted.

    Returns:
        Dict with 'success', 'records' list, and 'error' if failed
    """
    log = logger or (lambda msg, level="info": print(f"[DFIR-O365RC] [{level}] {msg}"))

    # Validate prerequisites
    status = is_available()
    if not status['available']:
        return {'success': False, 'records': [], 'error': status['message']}

    # Create temp output directory in mounted volume (/app/data is mounted from host's data/)
    # Container path: /app/data/tmp/dfir-o365rc-*
    # Host path: {HOST_PATH}/data/tmp/dfir-o365rc-* (used for docker -v mount)
    timestamp = int(time.time())
    output_dir = f"/app/data/tmp/dfir-o365rc-{timestamp}"
    os.makedirs(output_dir, exist_ok=True)

    # Translate to host path for docker volume mount
    from services.upgrade.base import HOST_PATH
    host_output_dir = f"{HOST_PATH}/data/tmp/dfir-o365rc-{timestamp}"

    # Format dates for PowerShell (MM/DD/YYYY HH:mm:ss)
    ps_start = _format_date_for_powershell(start_date)
    ps_end = _format_date_for_powershell(end_date)

    # Use Get-UnifiedAuditLogPurview which uses the modern Graph Audit Log Query API
    # (requires AuditLogsQuery.Read.All permission - no Exchange Online needed!)
    session_name = f"intact_session_{timestamp}"
    log_file = f"/mnt/host/output/{session_name}.log"
    output_file = f"/mnt/host/output/{session_name}.json"

    # Decide cmdlet invocation flags. When the operator scoped the scan to
    # specific users, push that filter to Microsoft instead of pulling the
    # whole tenant and discarding most of it client-side.
    #
    # Get-UnifiedAuditLogPurview's -requestType is one-of:
    #   Unfiltered | Operations | RecordTypes | FreeText | IPAddresses | UserIds
    # Each requestType carries its own scope parameter (e.g. UserIds takes
    # -UserIds, IPAddresses takes -IPAddresses). You can only pick ONE
    # dimension per call — there's no combined "Targeted" mode (we tried).
    # Strategy: prefer user filter when both users and IPs are set; IP filter
    # otherwise; fall back to Unfiltered when neither is set.
    target_ips = None
    if azure_config and azure_config.get('target_ips'):
        target_ips = azure_config.get('target_ips')

    if target_users:
        users_arr = ",".join(f"'{u}'" for u in target_users)
        scope_clause = f"-requestType UserIds -UserIds @({users_arr})"
        scope_label = f"users={','.join(target_users)}"
    elif target_ips:
        ips_arr = ",".join(f"'{ip}'" for ip in target_ips)
        scope_clause = f"-requestType IPAddresses -IPAddresses @({ips_arr})"
        scope_label = f"ips={','.join(target_ips)}"
    elif (ual_mode or "full").lower() == "light":
        rec_arr = ",".join(f"'{r}'" for r in LIGHT_RECORD_TYPES)
        scope_clause = f"-requestType RecordTypes -recordTypes @({rec_arr})"
        scope_label = f"light:{len(LIGHT_RECORD_TYPES)} record types"
    else:
        scope_clause = "-requestType Unfiltered"
        scope_label = None

    verbose_flag = "" if os.environ.get("INTACT_DFIR_VERBOSE") == "0" else "-Verbose"

    # Build the PowerShell command to run in the container.
    # We run the cmdlet in a background job and use Get-Content -Wait to stream
    # the log file to stdout in real-time. This ensures docker logs -f captures
    # everything immediately.
    ps_cmd = (
        f"\\$log = '{log_file}'; "
        f"\\$job = Start-Job -ScriptBlock {{ "
        f"  try {{ "
        f"    Import-Module DFIR-O365RC; "
        f"    \\$cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new('/mnt/cert/azure_cert.pfx', '', 'Exportable,PersistKeySet'); "
        f"    Get-UnifiedAuditLogPurview {scope_clause} -sessionName '{session_name}' -startDate '{ps_start}' -endDate '{ps_end}' -certificate \\$cert -appId '{app_id}' -tenant '{tenant}' -logFile \\$args[0] -outputFile '{output_file}' {verbose_flag} *>&1 "
        f"  }} catch {{ "
        f"    Write-Host \"[FATAL ERROR] \$_ \"; "
        f"    throw \$_; "
        f"  }} "
        f"}} -ArgumentList \\$log; "
        f"\\$jobId = \\$job.Id; "
        f"\\$lastLine = 0; "
        f"while ((Get-Job -Id \\$jobId).State -eq 'Running') {{ "
        f"  if (Test-Path \\$log) {{ "
        f"    \\$lines = @(Get-Content -Path \\$log -ErrorAction SilentlyContinue); "
        f"    if (\\$lines.Count -gt \\$lastLine) {{ "
        f"      \\$lines | Select-Object -Skip \\$lastLine | ForEach-Object {{ "
        f"        \\$l = \$_; "
        f"        if (\\$l -like '*status \"notStarted\"*' -and \\$notStartedTip -ne \\$true) {{ "
        f"           Write-Host '[AZURE] [TIP] Microsoft is queuing the query. This \"notStarted\" phase can take 5-15 minutes.'; "
        f"           \\$notStartedTip = \\$true; "
        f"        }} "
        f"        \\$l "
        f"      }}; "
        f"      \\$lastLine = \\$lines.Count; "
        f"    }} "
        f"  }} "
        f"  Start-Sleep -Seconds 1; "
        f"}}; "
        f"if (Test-Path \\$log) {{ "
        f"  \\$lines = @(Get-Content -Path \\$log -ErrorAction SilentlyContinue); "
        f"  if (\\$lines.Count -gt \\$lastLine) {{ \\$lines | Select-Object -Skip \\$lastLine | ForEach-Object {{ \$_ }} }} "
        f"}}; "
        f"Receive-Job -Id \\$jobId"
    )

    if scope_label:
        log(
            f"Collecting UAL via Purview (server-side filter: {scope_label}) "
            f"- expected to be much faster than Unfiltered",
            "info",
        )
        if target_users and target_ips:
            log(
                "Note: Purview UAL accepts only one filter dimension per call; "
                "applying user filter (IP filter omitted in this run).",
                "warning",
            )
    else:
        log("Collecting UAL (all events, no user/IP scope) via Purview API", "info")

    # Run DFIR-O365RC in Docker container with live log streaming
    host_data_dir = f"{HOST_PATH}/data"
    container_name = f"dfir_o365rc_{timestamp}"
    timeout_seconds = 1800  # 30 minutes - Purview audit log queries can take significant time to cold-start

    log("Starting DFIR-O365RC container...", "info")

    # Run container detached, then stream logs with timeout
    try:
        # Start container detached (use host_output_dir for -v since docker daemon runs on host)
        start_result = subprocess.run(
            f'docker run -d --name {container_name} '
            f'-v {host_output_dir}:/mnt/host/output '
            f'-v {host_data_dir}:/mnt/cert:ro '
            f'{_docker_image()} '
            f'pwsh -NonInteractive -Command "{ps_cmd}"',
            shell=True, capture_output=True, text=True, timeout=30
        )

        if start_result.returncode != 0:
            error = start_result.stderr[:300]
            log(f"Failed to start container: {error}", "error")
            _cleanup_container(container_name)
            shutil.rmtree(output_dir, ignore_errors=True)
            return {'success': False, 'records': [], 'error': f'Container start failed: {error}'}

        # Register cleanup so stop can kill the container
        if run_id:
            from services.workflow_service import register_cleanup
            register_cleanup(run_id, lambda: _cleanup_container(container_name))

        # Stream logs with timeout using a separate thread for reading
        start_time = time.time()
        timed_out = False
        last_log_time = time.time()

        log_process = subprocess.Popen(
            f'docker logs -f {container_name}',
            shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
        )

        # Register cleanup for the docker-logs subprocess too. The container
        # cleanup above kills the actual work; this kills the orphaned log
        # streamer so it doesn't hang reading from a dead container.
        if run_id:
            from services.workflow_service import terminate_subprocess
            register_cleanup(run_id, lambda p=log_process: terminate_subprocess(p))

        import select
        import fcntl

        # Make stdout non-blocking
        fd = log_process.stdout.fileno()
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

        # Fatal error patterns — when we see these in container output, the
        # operation will NEVER recover (auth failure, access denied, etc.).
        # Kill immediately instead of waiting for the full timeout.
        FATAL_ERROR_PATTERNS = (
            'AADSTS',                          # Azure AD auth failure
            'unauthorized_client',
            'invalid_client',
            'ErrorAccessDenied',
            'access_denied',
            'MsalServiceException',
            'MsalClientException',
            'is not a valid application identifier',
            'Cannot validate argument',
            'MissingGraphAuthenticationType',
            'AuthenticationFailedException',
            'No connection could be made',
            'The remote certificate is invalid',
            'Forbidden',
            'application is not authorized',
            'TooManyRequests',
            '429',
        )
        fatal_error_seen = False
        fatal_error_message = None  # Stores the exact container line that triggered the fatal error

        # Recoverable patterns: errors that DFIR-O365RC's internal retry harness
        # is allowed to recover from. We track them so we can emit a clear
        # "↳ retry succeeded" line when the next forward-progress line arrives.
        # Without this the operator sees ERROR ... ERROR ... and can't tell at
        # a glance whether the run actually recovered or stayed stuck.
        RECOVERABLE_ERROR_PATTERNS = (
            'Authentication needed. Please call Connect-MgGraph',
            'Query status check failed',
            'Connection reset by peer',
            'A task was canceled',
        )
        # Forward-progress markers — any of these after a recoverable error
        # means we recovered. "succeeded" is the Purview job state, "Connected"
        # is the MgGraph reconnect signal, "Records collected" is the EXO
        # path's progress line.
        RECOVERY_PATTERNS = (
            'status "succeeded"',
            'Connected to Microsoft Graph',
            'Connected.',
            'Records collected',
            'Successfully retrieved',
        )
        last_recoverable_err = None  # the recoverable pattern we last saw

        while True:
            elapsed = time.time() - start_time

            # Check timeout
            if elapsed > timeout_seconds:
                timed_out = True
                log(f"DFIR-O365RC timed out after {timeout_seconds}s - killing container", "error")
                subprocess.run(f"docker kill {container_name}", shell=True, capture_output=True)
                break

            # Check if container is still running
            inspect = subprocess.run(
                f"docker inspect -f '{{{{.State.Running}}}}' {container_name}",
                shell=True, capture_output=True, text=True
            )
            container_running = inspect.stdout.strip() == 'true'

            # Read available output (non-blocking) - log EVERY line from the container
            try:
                ready, _, _ = select.select([log_process.stdout], [], [], 1.0)
                if ready:
                    data = log_process.stdout.read()
                    if data:
                        for line in data.strip().split('\n'):
                            line = line.strip()
                            if not line:
                                continue
                            # Determine log level based on content
                            if 'error' in line.lower() or 'AADSTS' in line or 'fail' in line.lower() or 'exception' in line.lower():
                                log(f"[CONTAINER] {line}", "error")
                            elif 'warning' in line.lower() or 'warn' in line.lower():
                                log(f"[CONTAINER] {line}", "warning")
                            else:
                                # Log everything including raw JSON - nothing is skipped
                                log(f"[CONTAINER] {line}", "info")
                            last_log_time = time.time()

                            # Recoverable-error / recovery tracking. A
                            # recoverable error sets the flag; the next
                            # forward-progress line clears it and announces
                            # the recovery so the operator sees a clean
                            # "ERROR -> resolved" pair instead of just ERROR.
                            for pat in RECOVERABLE_ERROR_PATTERNS:
                                if pat in line:
                                    last_recoverable_err = pat
                                    break
                            if last_recoverable_err is not None:
                                for pat in RECOVERY_PATTERNS:
                                    if pat in line:
                                        log(
                                            f"  ↳ resolved: recovered from "
                                            f"\"{last_recoverable_err}\"",
                                            "success",
                                        )
                                        last_recoverable_err = None
                                        break

                            # Detect fatal errors and kill immediately
                            if not fatal_error_seen:
                                for pattern in FATAL_ERROR_PATTERNS:
                                    if pattern in line:
                                        fatal_error_seen = True
                                        fatal_error_message = line  # Save the exact error line
                                        log(
                                            f"[CONTAINER] Fatal error detected ({pattern}) — killing container "
                                            f"immediately to skip the rest of the timeout",
                                            "error",
                                        )
                                        subprocess.run(
                                            f"docker kill {container_name}",
                                            shell=True, capture_output=True,
                                        )
                                        break
            except (IOError, OSError):
                pass

            # If we killed on a fatal error, exit the wait loop
            if fatal_error_seen:
                break

            if not container_running:
                # Read any remaining output - log every line
                time.sleep(0.5)
                try:
                    remaining = log_process.stdout.read()
                    if remaining:
                        for line in remaining.strip().split('\n'):
                            line = line.strip()
                            if not line:
                                continue
                            if 'error' in line.lower() or 'fail' in line.lower() or 'exception' in line.lower():
                                log(f"[CONTAINER] {line}", "error")
                            elif 'warning' in line.lower():
                                log(f"[CONTAINER] {line}", "warning")
                            else:
                                log(f"[CONTAINER] {line}", "info")
                except (IOError, OSError):
                    pass
                break

            # Log a heartbeat if no output for 30s
            if time.time() - last_log_time > 30:
                log(f"  Waiting for Azure response... ({int(elapsed)}s elapsed)", "info")
                last_log_time = time.time()

        log_process.kill()

        # Get exit code
        if not timed_out:
            inspect_exit = subprocess.run(
                f"docker inspect -f '{{{{.State.ExitCode}}}}' {container_name}",
                shell=True, capture_output=True, text=True
            )
            exit_code = int(inspect_exit.stdout.strip()) if inspect_exit.stdout.strip().isdigit() else -1
        else:
            exit_code = -1

    except Exception as e:
        log(f"Failed to run DFIR-O365RC: {e}", "error")
        _cleanup_container(container_name)
        shutil.rmtree(output_dir, ignore_errors=True)
        return {'success': False, 'records': [], 'error': str(e)}

    # Always cleanup container (in case --rm didn't work due to kill)
    _cleanup_container(container_name)

    if fatal_error_seen and fatal_error_message:
        error = f"DFIR-O365RC fatal error — {fatal_error_message}"
        log(error, "error")
        shutil.rmtree(output_dir, ignore_errors=True)
        return {'success': False, 'records': [], 'error': error}

    if timed_out:
        error = "DFIR-O365RC timed out. Possible causes: (1) Exchange Online inactive/blocked on this tenant (2) Certificate not uploaded to App Registration (3) Missing Exchange.ManageAsApp permission or View-only audit logs role"
        log(error, "warning")
        shutil.rmtree(output_dir, ignore_errors=True)
        return {'success': False, 'records': [], 'error': error}

    if exit_code != 0:
        log(f"DFIR-O365RC exited with code {exit_code}", "warning")
        shutil.rmtree(output_dir, ignore_errors=True)
        return {'success': False, 'records': [], 'error': f'DFIR-O365RC failed (exit code {exit_code}). Check logs above for details.'}

    # Parse JSON output files
    records = []
    json_files = glob.glob(f"{output_dir}/**/*.json", recursive=True)
    log(f"Found {len(json_files)} output files", "info")

    for json_file in json_files:
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                if isinstance(data, list):
                    records.extend(data)
                elif isinstance(data, dict):
                    # Some outputs are single objects
                    records.append(data)
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            log(f"Warning: Could not parse {os.path.basename(json_file)}: {e}", "warning")

    # Cleanup temp directory
    shutil.rmtree(output_dir, ignore_errors=True)

    log(f"Collected {len(records)} raw Unified Audit Log records", "success")

    # Client-side filter by target users (matches UAL UserId/UserKey fields)
    if target_users:
        target_set = {u.lower() for u in target_users}

        def _to_strs(v):
            """Normalize a UAL field that may be a string, list, or dict to a list of strings."""
            if v is None:
                return []
            if isinstance(v, str):
                return [v.lower()]
            if isinstance(v, list):
                out = []
                for item in v:
                    if isinstance(item, str):
                        out.append(item.lower())
                    elif isinstance(item, dict):
                        # UAL Actor field is often [{Type:0, ID:"user@x.com"}]
                        for val in item.values():
                            if isinstance(val, str):
                                out.append(val.lower())
                return out
            if isinstance(v, dict):
                return [str(val).lower() for val in v.values() if isinstance(val, str)]
            return []

        def _matches_user(r):
            for field in ('UserId', 'UserKey', 'Actor', 'ObjectId'):
                for val in _to_strs(r.get(field)):
                    if val in target_set:
                        return True
            return False

        before = len(records)
        records = [r for r in records if _matches_user(r)]
        log(f"User filter: {before} -> {len(records)} records (kept events for {', '.join(target_users)})", "info")

    # Filter noise and add severity scoring (security-relevant events only)
    filter_result = filter_and_score_ual_records(records, min_severity='low')
    stats = filter_result['stats']
    log(f"After filtering: {stats['filtered_count']} security-relevant events "
        f"(removed {stats['noise_filtered']} noise, "
        f"{stats['unknown_operations']} unknown ops)", "info")

    if stats['by_severity']:
        sev_summary = ", ".join(f"{k}={v}" for k, v in stats['by_severity'].items() if v > 0)
        log(f"  Severity distribution: {sev_summary}", "info")
    if stats['by_category']:
        cat_summary = ", ".join(f"{k}={v}" for k, v in sorted(stats['by_category'].items(), key=lambda x: -x[1])[:5])
        log(f"  Top categories: {cat_summary}", "info")

    return {'success': True, 'records': filter_result['filtered'], 'error': None, 'stats': stats}


def _run_dfir_command(
    ps_cmd: str,
    timestamp: int,
    timeout_seconds: int = 300,
    logger=None
) -> Dict:
    """Run a DFIR-O365RC PowerShell command in a Docker container.

    Generic helper for running any DFIR-O365RC command. Returns dict with
    'success', 'records' (list of parsed JSON), 'error', and 'output_dir'.
    """
    log = logger or (lambda msg, level="info": print(f"[DFIR-O365RC] [{level}] {msg}"))

    output_dir = f"/app/data/tmp/dfir-o365rc-{timestamp}"
    os.makedirs(output_dir, exist_ok=True)

    host_output_dir = f"{HOST_PATH}/data/tmp/dfir-o365rc-{timestamp}"
    host_data_dir = f"{HOST_PATH}/data"
    container_name = f"dfir_o365rc_{timestamp}"

    try:
        start_result = subprocess.run(
            f'docker run -d --name {container_name} '
            f'-v {host_output_dir}:/mnt/host/output '
            f'-v {host_data_dir}:/mnt/cert:ro '
            f'{_docker_image()} '
            f'pwsh -NonInteractive -Command "{ps_cmd}"',
            shell=True, capture_output=True, text=True, timeout=30
        )

        if start_result.returncode != 0:
            error = start_result.stderr[:300]
            _cleanup_container(container_name)
            shutil.rmtree(output_dir, ignore_errors=True)
            return {'success': False, 'records': [], 'error': f'Container start failed: {error}'}

        # Wait for container to finish (with timeout AND fatal-error early-exit).
        # Same fatal patterns as collect_unified_audit_log — auth failures and
        # permission errors will never recover, so we kill immediately instead
        # of waiting for the full timeout.
        FATAL_ERROR_PATTERNS = (
            'AADSTS', 'unauthorized_client', 'invalid_client', 'ErrorAccessDenied',
            'access_denied', 'MsalServiceException', 'MsalClientException',
            'is not a valid application identifier', 'Cannot validate argument',
            'MissingGraphAuthenticationType', 'AuthenticationFailedException',
            'No connection could be made', 'The remote certificate is invalid',
            'Forbidden', 'application is not authorized',
        )
        start_time = time.time()
        timed_out = False
        fatal_error_seen = False

        while True:
            elapsed = time.time() - start_time
            if elapsed > timeout_seconds:
                timed_out = True
                subprocess.run(f"docker kill {container_name}", shell=True, capture_output=True)
                break

            # Peek at container logs to detect fatal errors early
            try:
                peek = subprocess.run(
                    f"docker logs --tail 50 {container_name}",
                    shell=True, capture_output=True, text=True, timeout=5,
                )
                peek_text = (peek.stdout or '') + (peek.stderr or '')
                for pattern in FATAL_ERROR_PATTERNS:
                    if pattern in peek_text:
                        fatal_error_seen = True
                        log(
                            f"Fatal error detected in DFIR output ({pattern}) — "
                            f"killing container immediately",
                            "error",
                        )
                        subprocess.run(
                            f"docker kill {container_name}",
                            shell=True, capture_output=True,
                        )
                        break
            except Exception:
                pass
            if fatal_error_seen:
                break

            inspect = subprocess.run(
                f"docker inspect -f '{{{{.State.Running}}}}' {container_name}",
                shell=True, capture_output=True, text=True
            )
            if inspect.stdout.strip() != 'true':
                break
            time.sleep(2)

        # Get exit code
        if not timed_out:
            inspect_exit = subprocess.run(
                f"docker inspect -f '{{{{.State.ExitCode}}}}' {container_name}",
                shell=True, capture_output=True, text=True
            )
            exit_code = int(inspect_exit.stdout.strip()) if inspect_exit.stdout.strip().isdigit() else -1
        else:
            exit_code = -1

        # Get container logs for diagnostics
        logs_result = subprocess.run(
            f"docker logs {container_name}",
            shell=True, capture_output=True, text=True
        )
        container_logs = (logs_result.stdout or '') + (logs_result.stderr or '')

    except Exception as e:
        _cleanup_container(container_name)
        shutil.rmtree(output_dir, ignore_errors=True)
        return {'success': False, 'records': [], 'error': str(e)}

    _cleanup_container(container_name)

    if timed_out:
        shutil.rmtree(output_dir, ignore_errors=True)
        return {'success': False, 'records': [], 'error': f'Command timed out after {timeout_seconds}s'}

    if exit_code != 0:
        # Extract meaningful error from logs
        error_lines = [l for l in container_logs.split('\n') if 'error' in l.lower() or 'exception' in l.lower()]
        error_msg = error_lines[0][:300] if error_lines else f'Exit code {exit_code}'
        shutil.rmtree(output_dir, ignore_errors=True)
        return {'success': False, 'records': [], 'error': error_msg}

    # Parse JSON output files
    records = []
    json_files = glob.glob(f"{output_dir}/**/*.json", recursive=True)

    for json_file in json_files:
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                if isinstance(data, list):
                    records.extend(data)
                elif isinstance(data, dict):
                    records.append(data)
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass

    shutil.rmtree(output_dir, ignore_errors=True)
    return {'success': True, 'records': records, 'error': None, 'files_count': len(json_files)}


def collect_azure_activity_logs(
    tenant: str,
    app_id: str,
    start_date: str,
    end_date: str,
    logger=None
) -> Dict:
    """Collect Azure Resource Manager activity logs via DFIR-O365RC.

    This works WITHOUT Exchange Online - only requires the certificate
    and Azure RM permissions on the App Registration.
    """
    log = logger or (lambda msg, level="info": print(f"[DFIR-O365RC] [{level}] {msg}"))

    status = is_available()
    if not status['available']:
        return {'success': False, 'records': [], 'error': status['message']}

    timestamp = int(time.time())
    ps_start = _format_date_for_powershell(start_date)
    ps_end = _format_date_for_powershell(end_date)

    ps_cmd = (
        f"cd /mnt/host/output; "
        f"Get-AzRMActivityLogs "
        f"-startDate '{ps_start}' "
        f"-endDate '{ps_end}' "
        f"-appId '{app_id}' "
        f"-tenant '{tenant}' "
        f"-certificatePath '/mnt/cert/azure_cert.pfx'"
    )

    log("Collecting Azure RM Activity Logs via DFIR-O365RC...", "info")
    result = _run_dfir_command(ps_cmd, timestamp, timeout_seconds=300, logger=log)

    if result['success']:
        log(f"Collected {len(result['records'])} Azure RM Activity Log records", "success")
    else:
        log(f"Azure RM Activity Logs failed: {result['error']}", "warning")

    return result


# =============================================================================
# UAL Event Filtering & Severity Scoring
# =============================================================================

# Operations that are noise (audit searches, page views, etc.)
UAL_NOISE_OPERATIONS = {
    'AuditSearchCreated', 'AuditSearchCompleted', 'AuditSearchStarted',
    'PageViewed', 'ListViewed', 'FilePreviewed', 'FolderModified',
    'FileSyncDownloadedFull', 'FileSyncUploadedFull',
    'SearchQueryPerformed', 'ListItemViewed',
}

# Operations with security severity scoring
# Format: { 'Operation': ('severity', 'category', 'description') }
UAL_SECURITY_OPERATIONS = {
    # === CRITICAL: Privileged actions ===
    'Add member to role.': ('high', 'privilege_escalation', 'User added to admin role'),
    'Remove member from role.': ('medium', 'privilege_change', 'User removed from admin role'),
    'Add eligible member to role.': ('high', 'privilege_escalation', 'PIM eligible role assignment'),
    'Add user.': ('medium', 'account_management', 'New user created'),
    'Delete user.': ('high', 'account_management', 'User deleted'),
    'Reset user password.': ('medium', 'credential_access', 'User password reset'),
    'Change user password.': ('medium', 'credential_access', 'Password changed'),
    'Set force change user password.': ('medium', 'credential_access', 'Forced password change'),

    # === CRITICAL: MFA / Auth changes ===
    'Disable Strong Authentication.': ('critical', 'defense_evasion', 'MFA disabled for user'),
    'Disable account.': ('high', 'account_management', 'Account disabled'),
    'Enable account.': ('medium', 'account_management', 'Account enabled'),
    'Update StsRefreshTokenValidFrom Timestamp.': ('high', 'persistence', 'Token validity reset'),

    # === HIGH: App / Permission changes ===
    'Add application.': ('high', 'persistence', 'New application registered'),
    'Add service principal.': ('high', 'persistence', 'New service principal'),
    'Add service principal credentials.': ('critical', 'persistence', 'Service principal secret added'),
    'Update application – Certificates and secrets management ': ('high', 'persistence', 'App credentials updated'),
    'Add app role assignment to service principal.': ('high', 'privilege_escalation', 'App permission granted'),
    'Add app role assignment grant to user.': ('medium', 'privilege_escalation', 'User granted app role'),
    'Consent to application.': ('high', 'initial_access', 'OAuth consent granted'),
    'Add OAuth2PermissionGrant.': ('high', 'persistence', 'OAuth permission grant added'),
    'Add delegated permission grant.': ('high', 'persistence', 'Delegated permission added'),
    'Remove delegated permission grant.': ('medium', 'defense_evasion', 'Delegated permission removed'),

    # === HIGH: Federation / Domain changes ===
    'Set federation settings on domain.': ('critical', 'persistence', 'Federation settings modified (golden SAML risk)'),
    'Set domain authentication.': ('high', 'persistence', 'Domain auth changed'),
    'Add domain to company.': ('high', 'persistence', 'New domain added'),
    'Remove domain from company.': ('high', 'defense_evasion', 'Domain removed'),

    # === HIGH: Mailbox / Exchange ===
    'Set-Mailbox': ('medium', 'collection', 'Mailbox settings modified'),
    'Add-MailboxPermission': ('high', 'collection', 'Mailbox permission added'),
    'Set-InboxRule': ('high', 'collection', 'Inbox rule created (forwarding risk)'),
    'New-InboxRule': ('high', 'collection', 'New inbox rule (forwarding risk)'),
    'Set-TransportRule': ('high', 'collection', 'Transport rule changed'),
    'New-TransportRule': ('high', 'collection', 'New transport rule'),
    'MailItemsAccessed': ('low', 'collection', 'Mail items accessed'),

    # === MEDIUM: File / Sharing ===
    'FileDownloaded': ('low', 'collection', 'File downloaded'),
    'FileSyncDownloadedFull': ('low', 'collection', 'File synced'),
    'SharingSet': ('medium', 'lateral_movement', 'Sharing permission set'),
    'AnonymousLinkCreated': ('high', 'exfiltration', 'Anonymous link created'),
    'AnonymousLinkUsed': ('medium', 'lateral_movement', 'Anonymous link used'),
    'CompanyLinkCreated': ('low', 'collection', 'Company link created'),
    'AddedToSecureLink': ('medium', 'lateral_movement', 'Added to secure link'),

    # === LOGIN ===
    'UserLoggedIn': ('informational', 'authentication', 'User login'),
    'UserLoginFailed': ('low', 'authentication', 'Login failed'),
    'UserStrongAuthClientAuthNRequired': ('informational', 'authentication', 'MFA required'),
}


def filter_and_score_ual_records(records: List[Dict], min_severity: str = 'low') -> Dict:
    """Filter UAL records to remove noise and add severity scoring.

    Args:
        records: Raw UAL records from DFIR-O365RC
        min_severity: Minimum severity to include ('informational', 'low', 'medium', 'high', 'critical')

    Returns dict with 'filtered' (security-relevant records) and 'stats' (counts).
    """
    severity_order = {'informational': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
    min_level = severity_order.get(min_severity, 1)

    filtered = []
    stats = {
        'total': len(records),
        'noise_filtered': 0,
        'unknown_operations': 0,
        'by_severity': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'informational': 0},
        'by_category': {},
    }

    for record in records:
        operation = record.get('Operation', '')

        # Skip noise
        if operation in UAL_NOISE_OPERATIONS:
            stats['noise_filtered'] += 1
            continue

        # Lookup security info
        sec_info = UAL_SECURITY_OPERATIONS.get(operation)
        if not sec_info:
            stats['unknown_operations'] += 1
            # Include unknown operations as 'low' severity (better visibility)
            severity, category, description = 'low', 'unknown', f'Unknown operation: {operation}'
        else:
            severity, category, description = sec_info

        # Apply severity filter
        if severity_order.get(severity, 0) < min_level:
            continue

        # Enrich record with security metadata
        record['_severity'] = severity
        record['_category'] = category
        record['_description'] = description
        filtered.append(record)

        stats['by_severity'][severity] = stats['by_severity'].get(severity, 0) + 1
        stats['by_category'][category] = stats['by_category'].get(category, 0) + 1

    stats['filtered_count'] = len(filtered)
    return {'filtered': filtered, 'stats': stats}


def _format_date_for_powershell(date_str: str) -> str:
    """Convert ISO date to PowerShell date format (MM/DD/YYYY HH:mm:ss)."""
    if not date_str:
        return date_str

    # Already in PowerShell format
    if '/' in date_str:
        return date_str

    # ISO format: 2026-04-05T00:00:00Z → 04/05/2026 00:00:00
    try:
        from datetime import datetime
        if 'T' in date_str:
            dt = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
        else:
            dt = datetime.fromisoformat(date_str)
        return dt.strftime('%m/%d/%Y %H:%M:%S')
    except (ValueError, TypeError):
        return date_str
