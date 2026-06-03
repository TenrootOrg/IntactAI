"""
Access Analyzer Runner — live boto3 findings collection.

AWS IAM Access Analyzer surfaces resources accessible from outside
the account or organization boundary (public S3 buckets, cross-account
IAM trust, public SNS topics, etc.). Per-region. Lists analyzers
then iterates their active findings.
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


def _normalize_finding(raw: Dict[str, Any], analyzer_arn: str, region: str) -> Dict[str, Any]:
    status = raw.get("status") or "ACTIVE"
    # Access Analyzer findings don't carry numeric severity — public
    # access on any resource is HIGH by default; anything ARCHIVED
    # downgrades to INFORMATIONAL so it doesn't dominate the report.
    sev = "high" if status == "ACTIVE" else "informational"
    return {
        "_source": "accessanalyzer_findings",
        "EventSource": "AWS.AccessAnalyzer",
        "FindingId": raw.get("id"),
        "AnalyzerArn": analyzer_arn,
        "ResourceType": raw.get("resourceType"),
        "Resource": raw.get("resource"),
        "IsPublic": bool(raw.get("isPublic")),
        "Principal": raw.get("principal"),
        "Action": raw.get("action"),
        "Condition": raw.get("condition"),
        "Status": status,
        "CreatedAt": raw.get("createdAt"),
        "UpdatedAt": raw.get("updatedAt"),
        "AnalyzedAt": raw.get("analyzedAt"),
        "_timestamp": raw.get("updatedAt") or raw.get("createdAt"),
        "Region": region,
        "Severity": sev.capitalize(),
        # aliases for the state-snapshot wrapper
        "severity": sev,
        "_severity": sev,
        "check_title": f"Access Analyzer: {raw.get('resourceType')} {raw.get('resource')}",
        "_raw_finding": raw,
    }


def collect_accessanalyzer(
    aws_config: Dict[str, Any],
    *,
    regions: Optional[List[str]] = None,
    log_func: Optional[Callable[[str, str], None]] = None,
    is_cancelled_func: Optional[Callable[[], bool]] = None,
) -> List[Dict[str, Any]]:
    log = log_func or (lambda msg, lvl="info": None)

    avail = is_available(aws_config)
    if not avail["available"]:
        log(f"[accessanalyzer] not available: {avail['message']}", "warning")
        return []

    regions_to_scan = regions or [aws_config.get("region", "us-east-1")]
    out: List[Dict] = []
    total_analyzers = 0
    for region in regions_to_scan:
        if is_cancelled_func and is_cancelled_func():
            break
        try:
            aa = _safe_client("accessanalyzer", aws_config, region)
        except Exception as e:
            log(f"[accessanalyzer] region={region} client failed: {e}", "warning")
            continue
        try:
            analyzers = aa.list_analyzers().get("analyzers") or []
        except Exception as e:
            log(f"[accessanalyzer] list_analyzers({region}) failed: {e}", "warning")
            continue
        total_analyzers += len(analyzers)
        for a in analyzers:
            arn = a.get("arn")
            if not arn:
                continue
            try:
                paginator = aa.get_paginator("list_findings")
                for page in paginator.paginate(analyzerArn=arn):
                    for f in page.get("findings") or []:
                        out.append(_normalize_finding(f, arn, region))
            except Exception as e:
                log(f"[accessanalyzer] region={region} analyzer={arn} failed: {e}", "warning")
                continue
    log(f"[accessanalyzer] {len(out)} findings across {total_analyzers} analyzer(s) in {len(regions_to_scan)} region(s)", "info")
    return out
