"""
CloudTrail Runner — live boto3 LookupEvents collection.

Replaces the fixture-based `cloudtrail_console` / `cloudtrail_iam` /
`cloudtrail_full` sources. The IntactAI-shape records this module
emits feed straight into the SIGMA matcher + LLM analyzer alongside
the IAM collector.

Notes:
  - `LookupEvents` is rate-limited to 2 req/s per region. We page
    carefully and cap regions / events per region so a full sweep on a
    large account doesn't blow the request budget.
  - The `light` mode focuses on the high-signal event names a DFIR
    analyst actually cares about (console logins, IAM changes,
    AssumeRole). `full` paginates everything up to a hard cap.
  - Identity-scoped runs pass a Username/AccessKeyId attribute and
    get back just that principal's events in seconds.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional

# High-signal CloudTrail event names for `light` mode.
#
# Ordering matters: events earlier in the tuple are queried first and,
# if we hit the per-region cap, later events are dropped. So put the
# textbook compromise indicators FIRST (CreateUser, AttachUserPolicy,
# StopLogging, etc.) and the high-volume-noise items LAST.
#
# NOTE: AssumeRole / AssumeRoleWithWebIdentity / AssumeRoleWithSAML
# are deliberately EXCLUDED from `light`. CrowdStrike CSPM and other
# cross-account scanners fire AssumeRole hundreds of times per hour on
# a perfectly idle account — those events would always saturate the
# 500-events-per-region cap before any real compromise signal had a
# chance to be collected. The `full` mode still picks them up when
# the analyst is specifically hunting lateral movement.
LIGHT_EVENT_NAMES_CONSOLE = ("ConsoleLogin",)
LIGHT_EVENT_NAMES_IAM = (
    # Tier-1 high-signal IAM lifecycle (compromise / persistence indicators)
    "CreateUser", "DeleteUser",
    "CreateAccessKey", "DeleteAccessKey", "UpdateAccessKey",
    "AttachUserPolicy", "DetachUserPolicy",
    "PutUserPolicy", "DeleteUserPolicy",
    "AttachRolePolicy", "DetachRolePolicy",
    "PutRolePolicy", "DeleteRolePolicy",
    "CreateRole", "DeleteRole", "UpdateAssumeRolePolicy",
    "CreateLoginProfile", "UpdateLoginProfile", "DeleteLoginProfile",
    "StopLogging", "DeleteTrail", "UpdateTrail",
    # Tier-2 (lower signal but still useful)
    "UpdateUser",
)

# Hard caps so a busy account can't burn the whole rate budget.
DEFAULT_MAX_EVENTS_PER_REGION = 500
DEFAULT_LOOKBACK_HOURS = 24


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
    result: Dict[str, Any] = {"available": False, "has_boto3": False, "message": ""}
    try:
        import boto3  # noqa: F401
        result["has_boto3"] = True
    except ImportError as e:
        result["message"] = f"boto3 not installed: {e}"
        return result
    if not aws_config or not aws_config.get("access_key_id"):
        result["message"] = "boto3 available but no AWS creds in config"
        return result
    result["available"] = True
    result["message"] = "Ready"
    return result


def _resolve_time_window(time_filter: Optional[Dict[str, Any]]) -> tuple:
    """Convert pipeline time_filter into (start_dt, end_dt) tuple.

    Field names must match the schema the frontend/pipeline actually sends
    (`mode` / `relative_range` / `start_datetime` / `end_datetime` — see
    `services/agentic/utils/_helpers.py`'s `filter_results_by_time` and
    `services/scheduler/jobs.py`), NOT `type` / `value` / `start` / `end`,
    which this used to read — those keys are never present, so every call
    silently fell through to the DEFAULT_LOOKBACK_HOURS default regardless
    of what the operator configured.
    """
    now = datetime.now(timezone.utc)
    if not time_filter or not isinstance(time_filter, dict) or not time_filter.get("enabled", True):
        return now - timedelta(hours=DEFAULT_LOOKBACK_HOURS), now
    mode = time_filter.get("mode", "relative")
    if mode == "between":
        start_raw = time_filter.get("start_datetime") or ""
        end_raw = time_filter.get("end_datetime") or ""
        try:
            start_dt = datetime.fromisoformat(start_raw.replace("Z", "+00:00"))
            if start_dt.tzinfo is None:
                start_dt = start_dt.replace(tzinfo=timezone.utc)
        except Exception:
            start_dt = now - timedelta(hours=DEFAULT_LOOKBACK_HOURS)
        try:
            end_dt = datetime.fromisoformat(end_raw.replace("Z", "+00:00")) if end_raw else now
            if end_dt.tzinfo is None:
                end_dt = end_dt.replace(tzinfo=timezone.utc)
        except Exception:
            end_dt = now
        return start_dt, end_dt
    # 'relative' or anything else falls through to relative_range parsing
    val = (time_filter.get("relative_range") or "24h").lower()
    try:
        if val.endswith("h"):
            hours = int(val[:-1])
            return now - timedelta(hours=hours), now
        if val.endswith("d"):
            days = int(val[:-1])
            return now - timedelta(days=days), now
    except Exception:
        pass
    return now - timedelta(hours=DEFAULT_LOOKBACK_HOURS), now


def _normalize_event(raw: Dict[str, Any]) -> Dict[str, Any]:
    """CloudTrail event → IntactAI record shape.

    Strategy: emit the **native nested CloudTrail JSON** (`eventName`
    lowercase, `userIdentity.userName`, `requestParameters.*`, etc.)
    AS-IS so SIGMA rules and the LLM see exactly the shape they
    expect — the same shape the bundled fixtures use. The fixtures
    were modelled on the native CT envelope precisely so real events
    flowing through here drop in without remapping.

    We also add a handful of IntactAI helper fields prefixed with `_`
    so they don't collide with native CT keys: `_source`,
    `EventSource` (sigma_prefix bucket), `_timestamp`.
    """
    import json
    full: Dict[str, Any] = {}
    try:
        full = json.loads(raw.get("CloudTrailEvent") or "{}") or {}
    except Exception:
        full = {}
    # Backstop fields from the LookupEvents envelope if the embedded
    # CloudTrailEvent didn't include them (rare but possible).
    if not full.get("eventName"):
        full["eventName"] = raw.get("EventName")
    if not full.get("eventTime") and raw.get("EventTime"):
        full["eventTime"] = raw["EventTime"].isoformat()
    if not full.get("eventSource"):
        full["eventSource"] = raw.get("EventSource")
    if not full.get("awsRegion"):
        full["awsRegion"] = raw.get("AwsRegion")
    # Resources from the envelope, if not already inside the event
    if not full.get("resources") and raw.get("Resources"):
        full["resources"] = [
            {"resourceType": r.get("ResourceType"), "resourceName": r.get("ResourceName")}
            for r in raw.get("Resources") or []
        ]
    # IntactAI helper annotations on top of the native CT shape
    full["_source"] = "cloudtrail"
    full["EventSource"] = "AWS.CloudTrail"
    full["_timestamp"] = full.get("eventTime")
    return full


def _lookup_one_page(client, *, lookup_attributes, start_dt, end_dt, next_token):
    kwargs = {
        "StartTime": start_dt,
        "EndTime": end_dt,
        "MaxResults": 50,  # AWS hard cap is 50/page
    }
    if lookup_attributes:
        kwargs["LookupAttributes"] = lookup_attributes
    if next_token:
        kwargs["NextToken"] = next_token
    return client.lookup_events(**kwargs)


def _collect_for_region(
    *,
    client,
    region: str,
    start_dt,
    end_dt,
    event_names: Optional[List[str]],
    username_filter: Optional[str],
    max_events: int,
    log,
    is_cancelled_func: Optional[Callable[[], bool]],
) -> List[Dict[str, Any]]:
    """LookupEvents loop for one region."""
    out: List[Dict] = []

    # Build LookupAttributes — LookupEvents only accepts ONE attribute
    # at a time. We make multiple passes and dedupe by EventId.
    #
    # For identity-scoped runs we need BOTH directions:
    #   - "Events by the user" (Username=X) — catches the user acting
    #   - "Events about the user" (ResourceName=arn:...:user/X) —
    #     catches CreateUser / CreateAccessKey / AttachUserPolicy that
    #     SET UP this user even when the actor is someone else. Without
    #     this second pass, investigating a freshly-compromised user
    #     surfaces zero events because the victim itself never acted.
    if username_filter:
        attr_passes = [[{"AttributeKey": "Username", "AttributeValue": username_filter}]]
        # If we know the full ARN (or can reconstruct it), also pass
        # ResourceName so events ON the user surface. We store the
        # username in the closure but the caller may also pass a full
        # ARN via `username_filter` — handle both.
        if username_filter.startswith("arn:aws:"):
            attr_passes.append([{"AttributeKey": "ResourceName", "AttributeValue": username_filter}])
        else:
            # Best-effort: the AWS account-id isn't always known here,
            # but LookupEvents accepts a bare username for ResourceName
            # too on most services. Add a pass with just the name.
            attr_passes.append([{"AttributeKey": "ResourceName", "AttributeValue": username_filter}])
    elif event_names:
        attr_passes = [[{"AttributeKey": "EventName", "AttributeValue": en}] for en in event_names]
    else:
        attr_passes = [None]   # full sweep — no filter

    for attrs in attr_passes:
        if is_cancelled_func and is_cancelled_func():
            log(f"[cloudtrail] cancelled in region={region}", "warning")
            return out
        next_token = None
        page = 0
        while True:
            try:
                resp = _lookup_one_page(
                    client,
                    lookup_attributes=attrs,
                    start_dt=start_dt,
                    end_dt=end_dt,
                    next_token=next_token,
                )
            except Exception as e:
                log(f"[cloudtrail] region={region} lookup failed: {e}", "warning")
                break
            for raw in resp.get("Events", []) or []:
                out.append(_normalize_event(raw))
                if len(out) >= max_events:
                    log(f"[cloudtrail] region={region} hit cap {max_events}", "warning")
                    return out
            next_token = resp.get("NextToken")
            page += 1
            if not next_token:
                break
            # Safety cap on absurdly chatty accounts — derived from max_events
            # (50/page is AWS's hard per-page cap) rather than a fixed 20, so
            # a full-mode scan with a raised max_events_per_region isn't
            # silently truncated at 1000 events before it ever reaches its
            # own (higher) cap.
            max_pages = (max_events // 50) + 2
            if page > max_pages:
                log(f"[cloudtrail] region={region} hit page cap {max_pages}", "warning")
                break
    return out


def collect_cloudtrail(
    aws_config: Dict[str, Any],
    *,
    mode: str = "light",                              # 'light' | 'full' | 'iam_only' | 'console_only'
    regions: Optional[List[str]] = None,
    time_filter: Optional[Dict[str, Any]] = None,
    target_principal_arns: Optional[List[str]] = None,
    max_events_per_region: int = DEFAULT_MAX_EVENTS_PER_REGION,
    log_func: Optional[Callable[[str, str], None]] = None,
    is_cancelled_func: Optional[Callable[[], bool]] = None,
) -> List[Dict[str, Any]]:
    """Pull CloudTrail events live via LookupEvents.

    Return shape is a flat list of IntactAI records (same as fixtures).
    The pipeline's normalize/SIGMA/state-snapshot/LLM stages don't need
    to know it's real data — fields match the fixtures.
    """
    log = log_func or (lambda msg, lvl="info": None)

    avail = is_available(aws_config)
    if not avail["available"]:
        log(f"[cloudtrail] not available: {avail['message']}", "warning")
        return []

    if mode == "iam_only":
        event_names = list(LIGHT_EVENT_NAMES_IAM)
    elif mode == "console_only":
        event_names = list(LIGHT_EVENT_NAMES_CONSOLE)
    elif mode == "full":
        event_names = None  # no filter — paginate everything
    else:  # light (default)
        event_names = list(LIGHT_EVENT_NAMES_CONSOLE) + list(LIGHT_EVENT_NAMES_IAM)

    # Identity-scoped: extract usernames from target ARNs.
    username_filter = None
    if target_principal_arns:
        users = [a.rsplit("/", 1)[-1] for a in target_principal_arns if ":user/" in a]
        if len(users) == 1:
            username_filter = users[0]
            log(f"[cloudtrail] identity-scoped run: username={username_filter}", "info")

    start_dt, end_dt = _resolve_time_window(time_filter)
    log(f"[cloudtrail] mode={mode} window={start_dt.isoformat()} → {end_dt.isoformat()}", "info")

    regions_to_scan = regions or [aws_config.get("region", "us-east-1")]
    all_events: List[Dict] = []
    for region in regions_to_scan:
        if is_cancelled_func and is_cancelled_func():
            break
        try:
            client = _safe_client("cloudtrail", aws_config, region)
        except Exception as e:
            log(f"[cloudtrail] region={region} client failed: {e}", "warning")
            continue
        region_events = _collect_for_region(
            client=client,
            region=region,
            start_dt=start_dt,
            end_dt=end_dt,
            event_names=event_names,
            username_filter=username_filter,
            max_events=max_events_per_region,
            log=log,
            is_cancelled_func=is_cancelled_func,
        )
        log(f"[cloudtrail] region={region}: {len(region_events)} events", "info")
        all_events.extend(region_events)

    # Dedupe by EventId (same event can appear in multiple per-name passes)
    dedup: Dict[str, Dict] = {}
    for e in all_events:
        eid = e.get("EventId")
        if eid and eid not in dedup:
            dedup[eid] = e
        elif not eid:
            dedup[f"_pos_{len(dedup)}"] = e
    out = list(dedup.values())
    log(f"[cloudtrail] total deduped events: {len(out)}", "info")
    return out
