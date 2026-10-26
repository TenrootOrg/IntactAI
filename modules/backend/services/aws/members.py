"""Scanning other AWS accounts through a role in each (read-only).

Settings (cloud config, aws block):
  member_accounts: ["111122223333", ...]  or  "all"  (every ACTIVE account of the
                   organization -- needs organizations:ListAccounts on the main credentials)
  member_role:     the role name to assume in each, e.g. a read-only audit role
                   (default OrganizationAccountAccessRole, the role AWS Organizations creates)

Each account gets the same collection as the main one; its records are tagged with the
account id so the case shows one cloud account per account. A role that cannot be
assumed is reported for that account and the others go on.
"""
from __future__ import annotations

import re
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple

from . import boto_client
from .boto_client import classify

DEFAULT_ROLE = "OrganizationAccountAccessRole"
MAX_ACCOUNTS = 50
_ACCT = re.compile(r"^\d{12}$")
_ROLE = re.compile(r"^[\w+=,.@/-]{1,128}$")


def clean(value) -> Tuple[Any, Optional[str]]:
    """Settings input -> ("all" | [ids], error)."""
    if value in (None, "", []):
        return [], None
    if isinstance(value, str) and value.strip().lower() == "all":
        return "all", None
    items = re.split(r"[\s,;]+", value.strip()) if isinstance(value, str) else list(value)
    ids, bad = [], []
    for x in items:
        x = str(x).strip()
        if not x:
            continue
        (ids if _ACCT.match(x) else bad).append(x)
    if bad:
        return None, f"not a 12-digit account id: {', '.join(bad[:5])}"
    return list(dict.fromkeys(ids))[:MAX_ACCOUNTS], None


def member_accounts(aws_config: Dict[str, Any], log: Optional[Callable] = None) -> List[str]:
    log = log or (lambda m, l="info": None)
    want, err = clean(aws_config.get("member_accounts"))
    if err:
        log(f"[AWS] member accounts ignored — {err}", "warning")
        return []
    if want != "all":
        return want or []
    try:
        org = boto_client.client("organizations", aws_config, "us-east-1")
        out = []
        for page in org.get_paginator("list_accounts").paginate():
            out += [a["Id"] for a in page.get("Accounts", []) if a.get("Status") == "ACTIVE"]
        if len(out) > MAX_ACCOUNTS:
            log(f"[AWS] the organization has {len(out)} accounts; scanning the first {MAX_ACCOUNTS}", "warning")
        return out[:MAX_ACCOUNTS]
    except Exception as e:                                   # noqa: BLE001
        log(f"[AWS] member accounts: the organization's accounts could not be listed — {classify(e)[1]}", "warning")
        return []


def member_configs(aws_config: Dict[str, Any], accounts: List[str], *,
                   preflight_account: Optional[str] = None) -> Iterator[Tuple[str, Optional[dict], Optional[str]]]:
    """(account, temporary aws_config or None, error or None) per account other than the main one."""
    role = str(aws_config.get("member_role") or DEFAULT_ROLE).strip()
    if not _ROLE.match(role):
        for a in accounts:
            yield a, None, f"invalid role name {role!r}"
        return
    for acct in accounts:
        if acct == preflight_account:
            continue                                         # the main credentials' own account
        try:
            sts = boto_client.client("sts", aws_config)
            arn = f"arn:aws:iam::{acct}:role/{role}"
            creds = sts.assume_role(RoleArn=arn, RoleSessionName="intact-scan", DurationSeconds=3600)["Credentials"]
            cfg = {k: v for k, v in aws_config.items() if k not in ("member_accounts", "member_role")}
            cfg.update(access_key_id=creds["AccessKeyId"], secret_access_key=creds["SecretAccessKey"],
                       session_token=creds["SessionToken"])
            yield acct, cfg, None
        except Exception as e:                               # noqa: BLE001
            yield acct, None, f"could not assume {role} — {classify(e)[1]}"


def merge(into: Dict[str, List[Dict]], data: Dict[str, List[Dict]], account: str) -> None:
    """Add one account's records, each tagged with the account it came from."""
    for src, rows in (data or {}).items():
        for r in rows or []:
            if isinstance(r, dict):
                r.setdefault("AccountId", account)
                r.setdefault("recipientAccountId", account)
        into.setdefault(src, []).extend(rows or [])
