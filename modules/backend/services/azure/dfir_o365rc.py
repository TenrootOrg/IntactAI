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
from typing import Dict, List, Optional

from services.upgrade.base import run_command

CERT_PATH = "/app/data/azure_cert.pfx"
CERT_PUBLIC_PATH = "/app/data/azure_cert_public.pem"
DOCKER_IMAGE = "anssi/dfir-o365rc:latest"


def is_available() -> Dict[str, any]:
    """Check if DFIR-O365RC is available and configured."""
    result = {
        'available': False,
        'has_image': False,
        'has_certificate': False,
        'message': ''
    }

    # Check Docker image
    check = run_command(f"docker image inspect {DOCKER_IMAGE}", logger=None)
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


def collect_unified_audit_log(
    tenant: str,
    app_id: str,
    start_date: str,
    end_date: str,
    target_users: Optional[List[str]] = None,
    logger=None
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

    Returns:
        Dict with 'success', 'records' list, and 'error' if failed
    """
    log = logger or (lambda msg, level="info": print(f"[DFIR-O365RC] [{level}] {msg}"))

    # Validate prerequisites
    status = is_available()
    if not status['available']:
        return {'success': False, 'records': [], 'error': status['message']}

    # Create temp output directory on host (mounted into container)
    output_dir = f"/data/tmp/dfir-o365rc-{int(time.time())}"
    os.makedirs(output_dir, exist_ok=True)

    # Format dates for PowerShell (MM/DD/YYYY HH:mm:ss)
    ps_start = _format_date_for_powershell(start_date)
    ps_end = _format_date_for_powershell(end_date)

    # Build PowerShell command
    if target_users:
        user_ids_str = '","'.join(target_users)
        ps_cmd = (
            f'Search-O365 '
            f'-startDate "{ps_start}" '
            f'-endDate "{ps_end}" '
            f'-appId "{app_id}" '
            f'-tenant "{tenant}" '
            f'-certificatePath "/mnt/cert/azure_cert.pfx" '
            f'-userIds "{user_ids_str}"'
        )
        log(f"Collecting UAL for users: {', '.join(target_users)}", "info")
    else:
        ps_cmd = (
            f'Get-O365Light '
            f'-startDate "{ps_start}" '
            f'-endDate "{ps_end}" '
            f'-appId "{app_id}" '
            f'-tenant "{tenant}" '
            f'-certificatePath "/mnt/cert/azure_cert.pfx"'
        )
        log("Collecting UAL (all users, light mode)", "info")

    # Run DFIR-O365RC in Docker container
    # The cert is at /app/data/ inside backend container, but the Docker run
    # command executes on the host via docker socket, so we need the HOST path.
    # /app/data maps to {WORKDIR}/data on host (from docker-compose volume mount)
    from services.upgrade.base import HOST_PATH
    host_data_dir = f"{HOST_PATH}/data"

    docker_cmd = (
        f'docker run --rm '
        f'-v {output_dir}:/mnt/host/output '
        f'-v {host_data_dir}:/mnt/cert:ro '
        f'{DOCKER_IMAGE} '
        f'pwsh -NonInteractive -Command "{ps_cmd}"'
    )

    log("Starting DFIR-O365RC container...", "info")
    result = run_command(docker_cmd, timeout=600, logger=None)

    if not result.get('success'):
        error = result.get('stderr', result.get('error', 'Unknown error'))
        # Check for common auth errors
        if 'AADSTS' in str(error):
            error = f"Azure authentication failed. Ensure the public certificate is uploaded to your App Registration. Error: {error[:200]}"
        elif 'certificate' in str(error).lower():
            error = f"Certificate error. Check that the PFX certificate is valid and the public key is uploaded to Azure. Error: {error[:200]}"

        log(f"DFIR-O365RC failed: {error[:300]}", "error")
        shutil.rmtree(output_dir, ignore_errors=True)
        return {'success': False, 'records': [], 'error': error[:500]}

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

    log(f"Collected {len(records)} Unified Audit Log records", "success")
    return {'success': True, 'records': records, 'error': None}


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
