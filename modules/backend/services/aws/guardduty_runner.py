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


def _safe_client(service: str, aws_config: Dict[str, Any], region: str):
    import boto3
    kwargs = {
        "aws_access_key_id": aws_config["access_key_id"],
        "aws_secret_access_key": aws_config["secret_access_key"],
        "region_name": region,
    }
    if aws_config.get("session_token"):
        kwargs["aws_session_token"] = aws_config["session_token"]
    return boto3.client(service, **kwargs)


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
    for region in regions_to_scan:
        if is_cancelled_func and is_cancelled_func():
            break
        try:
            gd = _safe_client("guardduty", aws_config, region)
        except Exception as e:
            log(f"[guardduty] region={region} client failed: {e}", "warning")
            continue
        try:
            det_ids = gd.list_detectors().get("DetectorIds") or []
        except Exception as e:
            log(f"[guardduty] list_detectors({region}) failed: {e}", "warning")
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
                log(f"[guardduty] region={region} detector={det} failed: {e}", "warning")
                continue
    log(f"[guardduty] {len(out)} active findings across {total_detectors} detector(s) in {len(regions_to_scan)} region(s)", "info")
    return out
