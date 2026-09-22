"""
GuardDuty Runner — live boto3 findings collection.

GuardDuty findings are AWS-native threat detections (recon, IAM
anomalies, credential exfil, crypto-mining, etc.). High-signal: any
non-archived finding warrants investigation. We iterate regions
because detectors are per-region.

Returns IntactAI records mirroring the `fake_guardduty_findings.json`
shape so downstream SIGMA / state-snapshot / LLM phases work
unchanged.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional

from . import boto_client
from .boto_client import FATAL_KINDS, AwsFatal, classify


def _safe_client(service: str, aws_config: Dict[str, Any], region: str):
    """Bounded client (see boto_client) — the library defaults are 60s x 5."""
    return boto_client.client(service, aws_config, region)


def is_available(aws_config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    result: Dict[str, Any] = {"available": False, "message": ""}
    try:
        import boto3  # noqa: F401
    except ImportError as e:
        result["message"] = f"boto3 not installed: {e}"
        return result
    if not aws_config or not aws_config.get("access_key_id"):
        result["message"] = "boto3 available but no AWS creds in config"
        return result
    result["available"] = True
    result["message"] = "Ready"
    return result


def _severity_label(num: float) -> str:
    """GuardDuty severity is 0-10. Bucket into IntactAI labels."""
    try:
        n = float(num)
    except Exception:
        return "low"
    if n >= 7.0:
        return "high"
    if n >= 4.0:
        return "medium"
    return "low"


def _normalize_finding(raw: Dict[str, Any]) -> Dict[str, Any]:
    sev_num = raw.get("Severity", 0.0)
    sev_label = _severity_label(sev_num)
    resource = raw.get("Resource", {}) or {}
    service = raw.get("Service", {}) or {}
    return {
        "_source": "guardduty_findings",
        "EventSource": "AWS.GuardDuty",
        "FindingId": raw.get("Id"),
        "FindingType": raw.get("Type"),
        "Severity": sev_label,
        "SeverityScore": sev_num,
        "Title": raw.get("Title"),
        "Description": raw.get("Description"),
        "CreatedAt": raw.get("CreatedAt"),
        "UpdatedAt": raw.get("UpdatedAt"),
        "_timestamp": raw.get("UpdatedAt") or raw.get("CreatedAt"),
        "Region": raw.get("Region"),
        "AccountId": raw.get("AccountId"),
        "ResourceType": resource.get("ResourceType"),
        "Resource": resource,
        "Service": service,
        # aliases for state-snapshot wrapper (same as iam_runner)
        "severity": sev_label,
        "_severity": sev_label,
        "check_title": raw.get("Title"),
        "Title_": raw.get("Title"),
        "_raw_finding": raw,
    }


def collect_guardduty(
    aws_config: Dict[str, Any],
    *,
    regions: Optional[List[str]] = None,
    log_func: Optional[Callable[[str, str], None]] = None,
    is_cancelled_func: Optional[Callable[[], bool]] = None,
) -> List[Dict[str, Any]]:
    """For each region, list detectors → list active findings → get
    full finding records. Returns empty if GuardDuty is disabled in
    the account or all regions return no detectors."""
    log = log_func or (lambda msg, lvl="info": None)

    avail = is_available(aws_config)
    if not avail["available"]:
        log(f"[guardduty] not available: {avail['message']}", "warning")
        return []

    regions_to_scan = regions or [aws_config.get("region", "us-east-1")]
    out: List[Dict] = []
    total_detectors = 0
    # A region we could not read is NOT a region with no findings. Tracked so
    # the caller can tell "GuardDuty is clean" from "GuardDuty went unread".
    unread: List[str] = []
    for region in regions_to_scan:
        if is_cancelled_func and is_cancelled_func():
            break
        try:
            gd = _safe_client("guardduty", aws_config, region)
            det_ids = gd.list_detectors().get("DetectorIds") or []
        except Exception as e:
            kind, msg = classify(e)
            unread.append(region)
            log(f"[guardduty] region={region} unreadable — {msg}", "warning")
            if kind in FATAL_KINDS:
                # Same credentials and the same endpoint family everywhere:
                # the remaining regions cannot answer either. Keep what the
                # regions before this one produced.
                log(f"[guardduty] aborting after {len(out)} finding(s) — {msg}", "error")
                break
            continue
        total_detectors += len(det_ids)
        for det in det_ids:
            try:
                paginator = gd.get_paginator("list_findings")
                finding_ids: List[str] = []
                for page in paginator.paginate(
                    DetectorId=det,
                    FindingCriteria={"Criterion": {"service.archived": {"Eq": ["false"]}}},
                ):
                    finding_ids.extend(page.get("FindingIds") or [])
                if not finding_ids:
                    continue
                # get_findings caps at 50 IDs per call
                for i in range(0, len(finding_ids), 50):
                    chunk = finding_ids[i:i+50]
                    full = gd.get_findings(DetectorId=det, FindingIds=chunk).get("Findings") or []
                    for f in full:
                        out.append(_normalize_finding(f))
            except Exception as e:
                kind, msg = classify(e)
                unread.append(f"{region}/{det}")
                log(f"[guardduty] region={region} detector={det} failed — {msg}", "warning")
                if kind in FATAL_KINDS:
                    raise AwsFatal(kind, msg, partial=out)
                continue
    if unread:
        log(f"[guardduty] {len(unread)} of {len(regions_to_scan)} region(s)/detector(s) "
            f"could not be read ({', '.join(unread[:10])}) — a zero-finding result "
            f"here does NOT mean the account is clean", "error")
    log(f"[guardduty] {len(out)} active findings across {total_detectors} detector(s) in {len(regions_to_scan)} region(s)", "info")
    return out
