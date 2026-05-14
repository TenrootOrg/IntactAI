"""
IAM Runner — boto3-based equivalent of CloudFox's principals/access-keys.

CloudFox's distinguishing value is the dense, tabular "who's an admin, what
keys do they have" view. The binary is 325 MB and incompatible with the
alpine images used as sibling-container hosts, so this module replicates
the same data via boto3 directly — cleaner deps, identical detection.

Replicates these CloudFox columns from the eval doc:
  - principals.csv: Account, Type, Name, Arn, AttachedPolicies, IsAdminRole?
  - access-keys.csv: Account, User Name, Access Key ID, Status, CreateDate
  - permissions.csv (filtered): per-user Effect=Allow Action=* Resource=*

Each principal becomes one record. The state-snapshot wrapper in
pipeline.py promotes severity=high/critical records into findings.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional


def _safe_client(service: str, aws_config: Dict[str, Any]):
    """Build a boto3 client from the IntactAI aws_config shape."""
    import boto3
    kwargs = {
        "aws_access_key_id": aws_config["access_key_id"],
        "aws_secret_access_key": aws_config["secret_access_key"],
        "region_name": aws_config.get("region", "us-east-1"),
    }
    if aws_config.get("session_token"):
        kwargs["aws_session_token"] = aws_config["session_token"]
    return boto3.client(service, **kwargs)


def is_available(aws_config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Probe boto3 + creds. Doesn't make any AWS calls without creds."""
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


def _policy_is_effective_admin(iam, policy_arn: str) -> bool:
    """A policy is 'effective admin' if any Allow statement grants
    Action='*' on Resource='*'. Mirrors how CloudFox's IsAdminRole?
    detection looks beyond the AdministratorAccess ARN."""
    try:
        pol = iam.get_policy(PolicyArn=policy_arn)["Policy"]
        ver = iam.get_policy_version(
            PolicyArn=policy_arn,
            VersionId=pol["DefaultVersionId"],
        )["PolicyVersion"]
        doc = ver.get("Document") or {}
        # Document can be a JSON string in some paths.
        if isinstance(doc, str):
            doc = json.loads(doc)
        for stmt in doc.get("Statement", []) or []:
            if not isinstance(stmt, dict) or stmt.get("Effect") != "Allow":
                continue
            actions = stmt.get("Action", [])
            resources = stmt.get("Resource", [])
            if isinstance(actions, str):
                actions = [actions]
            if isinstance(resources, str):
                resources = [resources]
            if "*" in actions and "*" in resources:
                return True
        return False
    except Exception:
        return False


def _inline_policies_are_effective_admin(iam, user_name: str) -> bool:
    """Same check, applied to a user's inline policies."""
    try:
        names = iam.list_user_policies(UserName=user_name).get("PolicyNames", [])
        for name in names:
            doc = iam.get_user_policy(UserName=user_name, PolicyName=name)
            policy_doc = doc.get("PolicyDocument") or {}
            if isinstance(policy_doc, str):
                policy_doc = json.loads(policy_doc)
            for stmt in policy_doc.get("Statement", []) or []:
                if not isinstance(stmt, dict) or stmt.get("Effect") != "Allow":
                    continue
                actions = stmt.get("Action", [])
                resources = stmt.get("Resource", [])
                if isinstance(actions, str):
                    actions = [actions]
                if isinstance(resources, str):
                    resources = [resources]
                if "*" in actions and "*" in resources:
                    return True
        return False
    except Exception:
        return False


def _is_admin_principal(iam, user_name: str, attached: List[Dict]) -> bool:
    """A user is 'admin' if they have AdministratorAccess attached OR any
    custom managed policy grants *:*  OR any inline policy grants *:* ."""
    admin_arns = {
        "arn:aws:iam::aws:policy/AdministratorAccess",
        "arn:aws:iam::aws:policy/IAMFullAccess",
    }
    for p in attached:
        arn = p.get("PolicyArn", "")
        if arn in admin_arns:
            return True
        # Customer-managed policy — inspect its document
        if "::aws:policy/" not in arn:
            if _policy_is_effective_admin(iam, arn):
                return True
    return _inline_policies_are_effective_admin(iam, user_name)


def _severity_for_principal(
    is_admin: bool,
    active_keys: int,
    has_mfa: bool,
    *,
    user_is_fresh: bool = False,
    any_key_is_fresh: bool = False,
) -> str:
    """Derive a severity for the state-snapshot wrapper.

    Baseline:
       admin + ≥1 active key + no MFA → critical
       admin + active key + MFA       → high
       admin only                     → high
       non-admin + multiple keys      → medium
       else                           → low

    Age-based promotion (DFIR signal): a recently-created admin user OR
    a recently-issued key on an admin user is the textbook compromise
    indicator. Force `critical` in those cases regardless of MFA, so
    the analyst sees fresh-admin compromise even when MFA appears set.
    """
    if is_admin and (user_is_fresh or any_key_is_fresh):
        return "critical"
    if is_admin and active_keys >= 1 and not has_mfa:
        return "critical"
    if is_admin:
        return "high"
    if active_keys >= 2:
        return "medium"
    return "low"


def _age_days(dt) -> Optional[float]:
    """Return age in days, or None if dt is missing/unparseable."""
    if not dt:
        return None
    try:
        if isinstance(dt, str):
            dt = datetime.fromisoformat(dt.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        return (now - dt).total_seconds() / 86400.0
    except Exception:
        return None


def collect_iam_principals(
    aws_config: Dict[str, Any],
    *,
    max_principal_age_days: Optional[float] = None,
    max_access_key_age_days: Optional[float] = None,
    target_principal_arns: Optional[List[str]] = None,
    log_func: Optional[Callable[[str, str], None]] = None,
    is_cancelled_func: Optional[Callable[[], bool]] = None,
) -> List[Dict[str, Any]]:
    """Enumerate every IAM user, their attached managed policies, their
    access keys, and an 'is_admin' computation. Returns one record per
    user in IntactAI shape (carries both PascalCase and lowercase keys so
    the state-snapshot wrapper in pipeline.py picks them up).

    Date-based DFIR filters (optional):
      - max_principal_age_days: users created within this window are
        flagged `fresh` and (if admin) bumped to `critical`.
      - max_access_key_age_days: keys created within this window are
        flagged `fresh` and (if owner is admin) bump the principal to
        `critical`.

    Returns [] on any boto3/import error or if creds are missing —
    callers fall back to fixtures.
    """
    log = log_func or (lambda msg, lvl="info": None)

    avail = is_available(aws_config)
    if not avail["available"]:
        log(f"[iam] not available: {avail['message']}", "warning")
        return []

    try:
        iam = _safe_client("iam", aws_config)
    except Exception as e:
        log(f"[iam] failed to create boto3 client: {e}", "error")
        return []

    # Identity-scoped path: when caller passes specific IAM user ARNs we
    # GetUser() each one directly. ~30s/user against arbitrarily large
    # accounts. Falls back to full enumeration if no targets given.
    target_user_names: List[str] = []
    if target_principal_arns:
        for arn in target_principal_arns:
            if not isinstance(arn, str):
                continue
            # accept user/role ARNs — for roles, we'd want a separate
            # path, but for now scope to users only since that's what
            # iam_principals enumerates anyway.
            if ":user/" in arn:
                target_user_names.append(arn.rsplit("/", 1)[-1])

    records: List[Dict[str, Any]] = []
    try:
        if target_user_names:
            log(f"[iam] identity-scoped run: fetching {len(target_user_names)} targeted user(s)", "info")
            all_users = []
            for un in target_user_names:
                try:
                    u = iam.get_user(UserName=un).get("User")
                    if u:
                        all_users.append(u)
                except Exception as e:
                    log(f"[iam] get_user({un}) failed: {e}", "warning")
        else:
            paginator = iam.get_paginator("list_users")
            all_users = []
            for page in paginator.paginate():
                if is_cancelled_func and is_cancelled_func():
                    log("[iam] cancelled during list_users", "warning")
                    return []
                all_users.extend(page.get("Users", []))
            log(f"[iam] enumerated {len(all_users)} users — inspecting policies + keys", "info")
    except Exception as e:
        log(f"[iam] list_users failed: {e}", "error")
        return []

    for u in all_users:
        if is_cancelled_func and is_cancelled_func():
            log("[iam] cancelled mid-enumeration", "warning")
            break
        name = u["UserName"]
        arn = u["Arn"]
        user_id = u["UserId"]

        try:
            attached = iam.list_attached_user_policies(UserName=name).get("AttachedPolicies", [])
        except Exception as e:
            log(f"[iam] list_attached_user_policies({name}) failed: {e}", "warning")
            attached = []

        try:
            keys = iam.list_access_keys(UserName=name).get("AccessKeyMetadata", [])
        except Exception as e:
            log(f"[iam] list_access_keys({name}) failed: {e}", "warning")
            keys = []

        try:
            mfa_devices = iam.list_mfa_devices(UserName=name).get("MFADevices", [])
            has_mfa = len(mfa_devices) > 0
        except Exception:
            has_mfa = False

        active_keys = [k for k in keys if k.get("Status") == "Active"]
        is_admin = _is_admin_principal(iam, name, attached)

        # ---- Age-based DFIR filters ----------------------------------
        user_age = _age_days(u.get("CreateDate"))
        user_is_fresh = (
            max_principal_age_days is not None
            and user_age is not None
            and user_age <= float(max_principal_age_days)
        )
        # Per-key ages
        key_ages: List[Dict[str, Any]] = []
        any_active_key_is_fresh = False
        for k in keys:
            age = _age_days(k.get("CreateDate"))
            fresh = (
                k.get("Status") == "Active"
                and max_access_key_age_days is not None
                and age is not None
                and age <= float(max_access_key_age_days)
            )
            if fresh:
                any_active_key_is_fresh = True
            key_ages.append({
                "AccessKeyId": k["AccessKeyId"],
                "Status": k["Status"],
                "CreateDate": k["CreateDate"].isoformat() if k.get("CreateDate") else None,
                "AgeDays": round(age, 1) if age is not None else None,
                "Fresh": fresh,
            })

        severity = _severity_for_principal(
            is_admin, len(active_keys), has_mfa,
            user_is_fresh=user_is_fresh,
            any_key_is_fresh=any_active_key_is_fresh,
        )

        # Title annotates fresh-admin patterns explicitly so the LLM/UI
        # surface the textbook compromise indicator without re-deriving.
        if is_admin and user_is_fresh:
            title = f"FRESH ADMIN user {name} (created {round(user_age,1)}d ago) with {len(active_keys)} active key(s)"
        elif is_admin and any_active_key_is_fresh:
            fresh_keys = [k['AccessKeyId'] for k in key_ages if k['Fresh']]
            title = f"Admin user {name} with FRESH access key(s) {fresh_keys} — possible persistence"
        elif is_admin:
            title = f"User {name} has admin privileges + {len(active_keys)} active key(s)"
        else:
            title = f"User {name}: {len(active_keys)} active key(s), MFA={'on' if has_mfa else 'off'}"

        attached_names = [p.get("PolicyName", "") for p in attached]
        records.append({
            "_source": "iam_principals",
            "EventSource": "AWS.IAM",
            # canonical (PascalCase, LLM/UI friendly)
            "Severity": severity.capitalize(),
            "StatusCode": "FAIL" if is_admin and (not has_mfa or user_is_fresh or any_active_key_is_fresh) else "INFO",
            "CheckId": "iam_principal_state",
            "CheckTitle": title,
            "Detail": (
                f"IAM user {name} ({arn}) — admin={is_admin}, "
                f"active_keys={len(active_keys)}, mfa={'on' if has_mfa else 'off'}, "
                f"user_age_days={round(user_age,1) if user_age is not None else '?'}, "
                f"user_is_fresh={user_is_fresh}, any_key_is_fresh={any_active_key_is_fresh}, "
                f"attached_policies={attached_names or 'none'}"
            ),
            "ResourceName": name,
            "ResourceType": "AWS::IAM::User",
            "ResourceUid": arn,
            "Service": "iam",
            "UserId": user_id,
            "IsAdmin": is_admin,
            "UserAgeDays": round(user_age, 1) if user_age is not None else None,
            "UserIsFresh": user_is_fresh,
            "AnyKeyIsFresh": any_active_key_is_fresh,
            "HasMFA": has_mfa,
            "AttachedPolicies": attached_names,
            # Per-key shape now carries age/fresh metadata for downstream
            # consumers (LLM analyzer, reports).
            "AccessKeys": key_ages,
            # aliases for state-snapshot wrapper
            "severity": severity,
            "_severity": severity,
            "check_title": title,
            "Title": title,
        })

    admin_count = sum(1 for r in records if r.get("IsAdmin"))
    log(
        f"[iam] {len(records)} principals enumerated; {admin_count} admin",
        "info",
    )
    return records
