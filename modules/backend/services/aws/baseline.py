"""What is NORMAL for this account, so the first time something new happens can be seen.

Fixed rules cannot say "this person never worked from this network" or "this account
never used that region". This keeps, per account, when each thing was FIRST seen:

  * per person (IAM user, SSO, federated): the networks they act from (/16, /48 for IPv6
    -- there is no GeoIP database offline, so a new network stands in for a new country);
  * per identity (people and roles): the sensitive changes it makes (IAM, STS, KMS,
    Organizations, CloudTrail, GuardDuty, ...);
  * per account: the regions where anything is changed.

A thing is NEW at an event when nothing earlier -- in the stored baseline or earlier in
this scan -- had it, and the identity (or account) already has MIN_HISTORY of history:
someone brand new has no normal yet. Items keep their FIRST-SEEN time, so re-scanning the
same days finds the same new things (learning an attacker's network from the first scan
must not hide it from the second).

Stored in BASE_DIR/<account>.json (no customer data beyond identity ARNs, /16 networks,
API and region names). Read or write failures are logged; detection still runs on the
scan's own history.
"""
from __future__ import annotations

import ipaddress
import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

BASE_DIR = os.environ.get("INTACT_AWS_BASELINE_DIR", "/app/data/aws_baseline")
MIN_HISTORY_S = 7 * 86400
MAX_PER_IDENTITY = 2000
MAX_IDENTITIES = 5000
SENSITIVE_SOURCES = {
    "iam.amazonaws.com", "sts.amazonaws.com", "kms.amazonaws.com", "organizations.amazonaws.com",
    "cloudtrail.amazonaws.com", "guardduty.amazonaws.com", "securityhub.amazonaws.com", "config.amazonaws.com",
    "secretsmanager.amazonaws.com", "sso.amazonaws.com", "account.amazonaws.com", "access-analyzer.amazonaws.com",
}


# Global services log in us-east-1 whatever region is in use: not a region signal.
GLOBAL_SOURCES = {"iam.amazonaws.com", "organizations.amazonaws.com", "route53.amazonaws.com",
                  "cloudfront.amazonaws.com", "account.amazonaws.com", "signin.amazonaws.com",
                  "sts.amazonaws.com", "support.amazonaws.com", "health.amazonaws.com", "billingconsole.amazonaws.com"}


def _epoch(ts) -> Optional[float]:
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00")).replace(tzinfo=timezone.utc).timestamp()
    except (TypeError, ValueError):
        return None


_INTERNAL = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7")]


def _net(ip) -> Optional[str]:
    try:
        a = ipaddress.ip_address(str(ip))
    except ValueError:
        return None                                   # "s3.amazonaws.com", "AWS Internal" ...
    if a.is_loopback or a.is_link_local or any(a in n for n in _INTERNAL if n.version == a.version):
        return None                                   # inside a VPC: not a network a person "comes from"
    return str(ipaddress.ip_network(f"{a}/{16 if a.version == 4 else 48}", strict=False))


def _who(r) -> tuple:
    """(identity key, is a person)."""
    ui = r.get("userIdentity") if isinstance(r.get("userIdentity"), dict) else {}
    t, arn = str(ui.get("type") or ""), str(ui.get("arn") or "")
    if t == "IAMUser":
        return arn or f"user/{ui.get('userName')}", True
    if t == "Root":
        return arn or "root", True
    if t == "FederatedUser" or ":assumed-role/AWSReservedSSO_" in arn:
        return arn, True
    if t == "AssumedRole":                              # a role: key on the ROLE, not the session
        issuer = ((ui.get("sessionContext") or {}).get("sessionIssuer") or {}) if isinstance(ui.get("sessionContext"), dict) else {}
        return str(issuer.get("arn") or arn.rsplit("/", 1)[0]), False
    return "", False


def _label(who: str) -> str:
    return "root" if who.endswith(":root") or who == "root" else who.rsplit("/", 1)[-1]


def _path(account) -> str:
    return os.path.join(BASE_DIR, f"{''.join(c for c in str(account) if c.isalnum())}.json")


def load(account, log=None) -> Dict[str, Any]:
    try:
        with open(_path(account)) as fh:
            d = json.load(fh)
        return d if isinstance(d, dict) else {}
    except FileNotFoundError:
        return {}
    except Exception as e:                            # noqa: BLE001
        (log or (lambda m, l="info": None))(f"[AWS] baseline unreadable, starting fresh: {e}", "warning")
        return {}


def save(account, d, log=None) -> None:
    try:
        os.makedirs(BASE_DIR, exist_ok=True)
        tmp = _path(account) + ".tmp"
        with open(tmp, "w") as fh:
            json.dump(d, fh)
        os.replace(tmp, _path(account))
    except Exception as e:                            # noqa: BLE001
        (log or (lambda m, l="info": None))(f"[AWS] baseline not saved: {e}", "warning")


def _seen(table: Dict[str, float], key: str, t: float) -> bool:
    """Known before t; records the earliest sighting either way."""
    first = table.get(key)
    if first is None or t < first:
        table[key] = t
    return first is not None and first < t


def detect(recs: List[Dict[str, Any]], *, persist: bool = True, log=None) -> List[Dict[str, Any]]:
    """Findings (detections._finding shape) for the first new network / change / region."""
    from .detections import _finding
    rows = sorted(((t, r) for r in recs if isinstance(r, dict)
                   for t in [_epoch(r.get("eventTime"))] if t is not None), key=lambda x: x[0])
    by_acct: Dict[str, list] = {}
    for t, r in rows:
        a = str(r.get("recipientAccountId") or "")
        if a:
            by_acct.setdefault(a, []).append((t, r))
    out = []
    for account, acct_rows in by_acct.items():          # one baseline per account
        out += _detect_account(account, acct_rows, persist, log, _finding)
    return out


def _detect_account(account, rows, persist, log, _finding) -> List[Dict[str, Any]]:
    base = load(account, log) if persist else {}
    ids = base.setdefault("identities", {})
    regions = base.setdefault("regions", {})
    acct_first = base.get("first")
    out, flagged = [], set()

    for t, r in rows:
        who, person = _who(r)
        if not who:
            continue
        me = ids.setdefault(who, {"first": t, "nets": {}, "apis": {}})
        if t < me["first"]:
            me["first"] = t
        acct_first = t if acct_first is None or t < acct_first else acct_first
        mature = t - me["first"] >= MIN_HISTORY_S
        write = str(r.get("readOnly")).lower() != "true" and not r.get("errorCode")
        console = "console" in str(r.get("userAgent") or "").lower() or str(r.get("eventName")) == "ConsoleLogin"

        net = _net(r.get("sourceIPAddress")) if person else None
        if net and not _seen(me["nets"], net, t) and mature and (who, "net", net) not in flagged \
                and len(me["nets"]) > 1:              # a person with ONE known network so far: no "normal" yet
            flagged.add((who, "net", net))
            sensitive = write and str(r.get("eventSource")) in SENSITIVE_SOURCES
            out.append(_finding(
                "AWS Person Active From A New Network", "medium" if sensitive else "low",
                f"{_label(who)} {'made a sensitive change' if sensitive else 'acted'} from {r.get('sourceIPAddress')} "
                f"(network {net}), never seen for them in {int((t - me['first']) // 86400)} days of history"
                + (" (console)" if console else "") + f": {r.get('eventName')}",
                r, mitre=("T1078.004",)))

        if write and str(r.get("eventSource")) in SENSITIVE_SOURCES:
            api = f"{r.get('eventSource', '').split('.')[0]}:{r.get('eventName')}"
            if not _seen(me["apis"], api, t) and mature and (who, "api", api) not in flagged:
                flagged.add((who, "api", api))
                out.append(_finding(
                    "AWS Identity Made A Sensitive Change It Never Made Before", "low",
                    f"{_label(who)} called {api} for the first time in {int((t - me['first']) // 86400)} days of history",
                    r, mitre=("T1098",)))

        reg = str(r.get("awsRegion") or "")
        if write and reg and str(r.get("eventSource")) not in GLOBAL_SOURCES:
            if not _seen(regions, reg, t) and acct_first is not None and t - acct_first >= MIN_HISTORY_S \
                    and len(regions) > 1 and ("region", reg) not in flagged:
                flagged.add(("region", reg))
                out.append(_finding(
                    # a person in the console opening a region is usually planned work;
                    # mining and paid-AI abuse arrive by API
                    "AWS Account Used In A New Region", "low" if console else "medium",
                    f"first change ever seen in {reg} ({r.get('eventName')} by {_label(who)}); "
                    f"the account had only used {', '.join(sorted(k for k in regions if k != reg))[:200]}",
                    r, mitre=("T1535",)))

    if persist:
        base["first"] = acct_first
        base["updated"] = datetime.now(timezone.utc).isoformat()
        if len(ids) > MAX_IDENTITIES:                 # keep the most recently active identities
            keep = sorted(ids, key=lambda k: max(list(ids[k]["nets"].values()) + list(ids[k]["apis"].values()) + [ids[k]["first"]]))
            for k in keep[:len(ids) - MAX_IDENTITIES]:
                ids.pop(k, None)
        for me in ids.values():
            for tab in ("nets", "apis"):
                if len(me[tab]) > MAX_PER_IDENTITY:
                    me[tab] = dict(sorted(me[tab].items(), key=lambda kv: kv[1])[-MAX_PER_IDENTITY:])
        save(account, base, log)
    return out
