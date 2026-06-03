"""
Prowler Runner — AWS posture scan via Docker subprocess.

Mirrors the pattern used by `services.azure.dfir_o365rc`: this module
launches a sibling container on the host's Docker daemon, captures its
OCSF-formatted output, parses it into the IntactAI record shape, and
cleans up after itself.

Called from `services.aws.collectors._stub_collect` when source is
`prowler_posture` and Prowler is available. Falls back to the fixture
loader when the image isn't present.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from services.upgrade.base import HOST_PATH


def _docker_image() -> str:
    """Prowler image ref, version-pinned via config.yaml -> backend .env.
    Read fresh so an upgrade applies without a backend restart."""
    try:
        from config import get_prowler_image
        return get_prowler_image()
    except Exception:
        return f"toniblyx/prowler:{os.environ.get('PROWLER_VERSION', '5.28.1')}"

# Service families we ever ask Prowler for, in the order they appear on
# the CLI. Anything not in this list is ignored to keep arg quoting
# simple.
ALLOWED_SERVICES = (
    "iam", "cloudtrail", "guardduty", "s3", "accessanalyzer",
    "ec2", "lambda", "rds", "kms", "secretsmanager",
)

ALLOWED_SEVERITIES = ("critical", "high", "medium", "low", "informational")


def is_available() -> Dict[str, Any]:
    """Check Prowler docker image is pulled and runnable.

    Returns dict shape used by `is_available()` across providers — same
    keys (`available`, `has_image`, `message`) as the Azure equivalent so
    the status endpoint can render uniformly.
    """
    result: Dict[str, Any] = {
        "available": False,
        "has_image": False,
        "message": "",
    }
    try:
        check = subprocess.run(
            f"docker image inspect {_docker_image()}",
            shell=True, capture_output=True, timeout=10,
        )
        result["has_image"] = check.returncode == 0
    except Exception as e:
        result["message"] = f"Docker not reachable: {e}"
        return result

    if not result["has_image"]:
        result["message"] = (
            f"Prowler docker image missing. Run: docker pull {_docker_image()}"
        )
        return result

    result["available"] = True
    result["message"] = "Ready"
    return result


def cleanup_orphan_containers() -> int:
    """Remove any leftover Prowler containers from prior runs."""
    try:
        result = subprocess.run(
            "docker ps -a --filter name=intact_prowler_ -q",
            shell=True, capture_output=True, text=True, timeout=10,
        )
        if result.stdout.strip():
            cids = result.stdout.strip().split("\n")
            for cid in cids:
                subprocess.run(f"docker rm -f {cid}", shell=True, capture_output=True, timeout=10)
            return len(cids)
    except Exception:
        pass
    return 0


def _cleanup_container(name: str) -> None:
    try:
        subprocess.run(f"docker rm -f {name}", shell=True, capture_output=True, timeout=10)
    except Exception:
        pass


def _build_command(
    container_name: str,
    host_output_dir: str,
    aws_config: Dict[str, Any],
    *,
    regions: Optional[List[str]],
    services: Optional[List[str]],
    severities: Optional[List[str]],
    resource_arn: Optional[str],
    fail_only: bool,
) -> str:
    """Compose the docker-run command. Returns a single shell string."""
    env_args = [
        f'-e AWS_ACCESS_KEY_ID={aws_config["access_key_id"]}',
        f'-e AWS_SECRET_ACCESS_KEY={aws_config["secret_access_key"]}',
        f'-e AWS_DEFAULT_REGION={aws_config.get("region", "us-east-1")}',
    ]
    if aws_config.get("session_token"):
        env_args.append(f'-e AWS_SESSION_TOKEN={aws_config["session_token"]}')

    prowler_args = ["aws", "-M", "json-ocsf", "-o", "/out"]

    if services:
        safe = [s for s in services if s in ALLOWED_SERVICES]
        if safe:
            prowler_args.extend(["--service"] + safe)
    if severities:
        safe = [s for s in severities if s in ALLOWED_SEVERITIES]
        if safe:
            prowler_args.extend(["--severity"] + safe)
    if regions:
        # Whitelist-style sanity check on region format.
        safe = [r for r in regions if r and all(c.isalnum() or c == "-" for c in r)]
        if safe:
            prowler_args.extend(["--region"] + safe)
    if resource_arn and resource_arn.startswith("arn:aws:"):
        prowler_args.extend(["--resource-arn", resource_arn])
    if fail_only:
        prowler_args.append("--status")
        prowler_args.append("FAIL")

    return (
        f"docker run -d --name {container_name} "
        f"{' '.join(env_args)} "
        f"-v {host_output_dir}:/out "
        f"{_docker_image()} {' '.join(prowler_args)}"
    )


def _wait_for_container(
    container_name: str,
    timeout_seconds: int,
    log: Callable[[str, str], None],
    is_cancelled_func: Optional[Callable[[], bool]],
) -> Dict[str, Any]:
    """Poll until the container exits or the timeout/cancel fires.

    Same shape as Azure's wait loop: early-exit on fatal-error patterns so
    auth failures don't burn the full timeout.
    """
    FATAL_PATTERNS = (
        "InvalidClientTokenId",
        "SignatureDoesNotMatch",
        "AuthFailure",
        "AccessDenied: User",   # AccessDenied alone is too common (per-check)
        "ExpiredToken",
        "UnrecognizedClientException",
    )

    start = time.time()
    while True:
        if is_cancelled_func and is_cancelled_func():
            log("[prowler] cancelled — killing container", "warning")
            subprocess.run(f"docker kill {container_name}", shell=True, capture_output=True)
            return {"success": False, "error": "cancelled", "exit_code": -1}

        if time.time() - start > timeout_seconds:
            log(f"[prowler] timed out after {timeout_seconds}s — killing container", "error")
            subprocess.run(f"docker kill {container_name}", shell=True, capture_output=True)
            return {"success": False, "error": "timeout", "exit_code": -1}

        try:
            inspect = subprocess.run(
                f"docker inspect --format '{{{{.State.Status}}}} {{{{.State.ExitCode}}}}' {container_name}",
                shell=True, capture_output=True, text=True, timeout=5,
            )
            state_line = inspect.stdout.strip()
            if state_line.startswith("exited"):
                exit_code = int(state_line.split()[-1])
                # Prowler convention: exit 0 = clean, exit 3 = findings present.
                # Both are SUCCESSFUL scans from our point of view; only true
                # crashes (non-zero non-3) should be flagged as failures.
                ok = exit_code in (0, 3)
                return {"success": ok, "exit_code": exit_code, "error": None if ok else f"non-zero exit {exit_code}"}
        except Exception:
            pass

        # Peek for fatal patterns so we don't burn timeout on auth failures.
        try:
            peek = subprocess.run(
                f"docker logs --tail 30 {container_name}",
                shell=True, capture_output=True, text=True, timeout=5,
            )
            blob = (peek.stdout or "") + (peek.stderr or "")
            for p in FATAL_PATTERNS:
                if p in blob:
                    log(f"[prowler] fatal error detected ({p}) — killing", "error")
                    subprocess.run(f"docker kill {container_name}", shell=True, capture_output=True)
                    return {"success": False, "error": f"fatal: {p}", "exit_code": -1}
        except Exception:
            pass

        time.sleep(2)


def _parse_ocsf_file(ocsf_path: Path, log: Callable[[str, str], None]) -> List[Dict]:
    """Parse a Prowler OCSF JSON file into our internal record shape.

    Each output record carries `_source='prowler_posture'`,
    `EventSource='AWS.Prowler'`, and the high-signal fields the LLM and
    SIGMA matcher want. The full original OCSF entry is preserved under
    `_raw_ocsf` for tools that want it.
    """
    try:
        with open(ocsf_path, "r", encoding="utf-8") as f:
            ocsf = json.load(f)
    except Exception as e:
        log(f"[prowler] could not parse OCSF file {ocsf_path}: {e}", "error")
        return []

    if not isinstance(ocsf, list):
        log(f"[prowler] OCSF file is not a list (got {type(ocsf).__name__})", "warning")
        return []

    records: List[Dict] = []
    for finding in ocsf:
        if not isinstance(finding, dict):
            continue
        fi = finding.get("finding_info", {}) or {}
        resources = finding.get("resources", []) or []
        first_resource = resources[0] if resources else {}
        sev = (finding.get("severity") or "Informational").strip()
        title = fi.get("title", "") or ""
        # Emit both the PascalCase keys (LLM-friendly, used by reports/UI)
        # AND the lowercase/snake_case keys that pipeline.py's
        # STATE_SOURCE_MAP wrapper looks up. Belt-and-suspenders.
        records.append({
            "_source": "prowler_posture",
            "EventSource": "AWS.Prowler",
            # canonical fields
            "Severity": sev,
            "StatusCode": finding.get("status_code", ""),
            "CheckId": fi.get("uid", ""),
            "CheckTitle": title,
            "Detail": finding.get("status_detail", ""),
            "ResourceName": first_resource.get("name", ""),
            "ResourceType": first_resource.get("type", ""),
            "ResourceUid": first_resource.get("uid", ""),
            "Service": (finding.get("metadata") or {}).get("product", {}).get("feature", {}).get("name", ""),
            # aliases for the pipeline's state-snapshot wrapper
            "severity": sev.lower(),
            "_severity": sev.lower(),
            "check_title": title,
            "Title": title,
            "_raw_ocsf": finding,
        })
    return records


def run_prowler_scan(
    aws_config: Dict[str, Any],
    *,
    regions: Optional[List[str]] = None,
    services: Optional[List[str]] = None,
    severities: Optional[List[str]] = None,
    resource_arn: Optional[str] = None,
    fail_only: bool = True,
    timeout_seconds: int = 1800,
    log_func: Optional[Callable[[str, str], None]] = None,
    is_cancelled_func: Optional[Callable[[], bool]] = None,
) -> List[Dict]:
    """Run Prowler in a sibling container, parse OCSF output, return records.

    Args mirror the CLI flags the eval doc recommended:
      - `services=['iam', 'cloudtrail', 'guardduty', 's3', 'accessanalyzer']`
        keeps the scan to high-signal services for DFIR.
      - `severities=['critical', 'high']` drops low-severity noise at the
        scan level (Prowler's native filter).
      - `resource_arn='arn:aws:iam::...:user/X'` for user-mode scans.
      - `regions=['us-east-1']` cuts walltime 3-5x on focused accounts.

    Returns an empty list on any failure (image missing, auth error,
    timeout); callers can fall back to a fixture in that case.
    """
    log = log_func or (lambda msg, level="info": None)

    avail = is_available()
    if not avail["available"]:
        log(f"[prowler] not available: {avail['message']}", "warning")
        return []

    timestamp = int(time.time())
    container_name = f"intact_prowler_{timestamp}"
    container_output_dir = f"/app/data/tmp/prowler-{timestamp}"
    host_output_dir = f"{HOST_PATH}/data/tmp/prowler-{timestamp}"

    os.makedirs(container_output_dir, exist_ok=True)
    os.chmod(container_output_dir, 0o777)  # prowler container writes as a non-root uid

    try:
        cmd = _build_command(
            container_name=container_name,
            host_output_dir=host_output_dir,
            aws_config=aws_config,
            regions=regions,
            services=services,
            severities=severities,
            resource_arn=resource_arn,
            fail_only=fail_only,
        )
        log(f"[prowler] starting container {container_name}", "info")
        start = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=30,
        )
        if start.returncode != 0:
            log(f"[prowler] container start failed: {start.stderr[:300]}", "error")
            shutil.rmtree(container_output_dir, ignore_errors=True)
            return []

        wait_result = _wait_for_container(
            container_name, timeout_seconds, log, is_cancelled_func,
        )
        if not wait_result["success"]:
            log(f"[prowler] run failed: {wait_result.get('error')}", "error")
            _cleanup_container(container_name)
            shutil.rmtree(container_output_dir, ignore_errors=True)
            return []

        # Prowler writes prowler-output-<account>-<ts>.ocsf.json.
        ocsf_files = list(Path(container_output_dir).glob("*.ocsf.json"))
        if not ocsf_files:
            log(f"[prowler] no OCSF output file produced in {container_output_dir}", "error")
            _cleanup_container(container_name)
            shutil.rmtree(container_output_dir, ignore_errors=True)
            return []

        records = _parse_ocsf_file(ocsf_files[0], log)
        log(f"[prowler] parsed {len(records)} findings from {ocsf_files[0].name}", "info")
        return records
    finally:
        _cleanup_container(container_name)
        # Keep the OCSF file around for analyst download? For now wipe;
        # the parsed records are what downstream needs.
        shutil.rmtree(container_output_dir, ignore_errors=True)
