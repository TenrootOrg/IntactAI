"""Cloud mapper (AWS / Azure) — SIGMA findings + log records -> entities.

The payoff is CROSS-DOMAIN correlation: a cloud user principal or a malicious
source-IP that ALSO appears on an endpoint becomes one node. So:
  * source IPs are global ``ioc:ip`` (= same node as an endpoint NetScan IP)
  * user principals are keyed ``account:domain:{domain}\\{user}`` — the SAME
    shape the agentic mapper uses, so ``rami@omcdom.com`` (cloud UPN) collapses
    with ``OMCDOM\\rami`` (endpoint domain account).

Input: a list of SIGMA findings ({matched_record, rule_title, _severity,
mitre_attack, _timestamp}) or raw cloud records. AWS account / Azure tenant id
is the cloud asset anchor.
"""

from __future__ import annotations

from .. import keys
from ..schema import Entity, Relationship, EvidenceRef
from ..severity import from_string, rank
from . import fieldspec as F

MODULE = "cloud"


def _user(rec: dict):
    if not isinstance(rec, dict):
        return None
    ui = rec.get("userIdentity")
    if isinstance(ui, dict):
        u = ui.get("userName") or ui.get("arn") or ui.get("principalId")
        if u:
            return u
    # IAM-posture STATE findings (AccessAnalyzer / IAM principals) name their
    # subject in ResourceName (AWS::IAM::User/Role). Surface it so the principal
    # becomes an account entity — it then correlates AND is masked like any other
    # user (otherwise the username only lives in the event label -> leaks to LLM).
    rt = str(rec.get("ResourceType") or "")
    if rec.get("ResourceName") and ("IAM" in rt or str(rec.get("Service") or "").lower() == "iam"):
        return rec.get("ResourceName")
    return F.get(rec, "userPrincipalName", "user", "caller", "Caller", "Actor",
                 "InitiatedBy", "SubjectUserName", default=None)


def _ip(rec: dict):
    if not isinstance(rec, dict):
        return None
    return F.get(rec, "sourceIPAddress", "ipAddress", "callerIpAddress", "IPAddress",
                 "ip", "RemoteAddr", default=None)


def _mitre_ids(mitre) -> list[str]:
    """Normalise a SIGMA rule's mitre_attack to a flat list of hashable strings.

    SIGMA emits it as a list of dicts — ``[{'type':'technique','id':'T1098'},
    {'type':'tactic','name':'Persistence'}]`` — but downstream findings put mitre
    in a ``set()`` (render._phase), so dicts must collapse to their id/name string
    (a technique id like 'T1098' when present, else the tactic name)."""
    if not mitre:
        return []
    if isinstance(mitre, str):
        return [mitre]
    if isinstance(mitre, dict):
        mitre = [mitre]
    out = []
    for m in mitre:
        if isinstance(m, str):
            out.append(m)
        elif isinstance(m, dict):
            v = m.get("id") or m.get("technique") or m.get("name") or m.get("tactic")
            if v:
                out.append(str(v))
        elif m is not None:
            out.append(str(m))
    return out


def _account_key(user) -> str | None:
    """Key a cloud principal the SAME way the agentic mapper keys a domain
    account, so cloud UPNs bridge to endpoint domain accounts."""
    if not user:
        return None
    s = str(user).strip().lower()
    if s in ("-", "n/a", "root", "system"):
        return f"account:cloud:{s}" if s else None
    if "@" in s:                              # UPN: rami@omcdom.com
        u, dom = s.split("@", 1)
        d = dom.split(".")[0]                 # omcdom.com -> omcdom
        return f"account:domain:{d}\\{u}"
    if "\\" in s:                             # DOMAIN\user
        d, u = s.split("\\", 1)
        return f"account:domain:{d.split('.')[0]}\\{u}"
    return f"account:cloud:{s}"               # bare principal (no domain to bridge)


def map_cloud(findings, *, run_id: str, provider: str = "cloud", account=None) -> tuple[list, list]:
    ents: list[Entity] = []
    rels: list[Relationship] = []
    casset = f"asset:cloud_account:{provider}:{account or 'unknown'}"
    ents.append(Entity(id=casset, type="asset", label=f"{provider}:{account or '?'}",
                       attrs={"kind": "cloud_account", "provider": provider, "_assets": [casset]},
                       sources=[MODULE], evidence=[EvidenceRef(MODULE, run_id, "asset")]))

    for i, f in enumerate(findings or []):
        if not isinstance(f, dict):
            continue
        rec = f.get("matched_record") if isinstance(f.get("matched_record"), dict) else f
        ts = keys.norm_ts(F.get(f, "_timestamp", "_finding_time", default=None)
                          or F.get(rec, "eventTime", "timeGenerated", "createdDateTime",
                                   "activityDateTime", "time", default=None))
        rule = (F.get(f, "rule_title", "rule", "title", "_rule", default=None)
                or F.get(rec, "eventName", "operationName", "displayName", default="cloud event"))
        severity = from_string(F.get(f, "_severity", "severity", "Severity", "riskLevel",
                                     default="medium"))
        mitre = _mitre_ids(f.get("mitre_attack") or f.get("mitre"))
        loc = f"{provider}/finding={i}"
        eid = keys.event_id(casset, ts, f"{provider}:{rule}")
        ents.append(Entity(id=eid, type="event", label=f"{provider}: {rule}",
                           attrs={"_assets": [casset], "provider": provider, "rule": rule,
                                  "mitre": list(mitre), "cloud_finding": rank(severity) >= rank("medium")},
                           sources=[MODULE], evidence=[EvidenceRef(MODULE, run_id, loc)],
                           severity=severity, anomaly=_RW.get(severity, 0),
                           first_seen=ts, last_seen=ts))

        aeid = _account_key(_user(rec))
        if aeid:
            u = aeid.split("\\")[-1].split(":")[-1]
            ents.append(Entity(id=aeid, type="account", label=u, attrs={"_assets": [casset]},
                               sources=[MODULE], evidence=[EvidenceRef(MODULE, run_id, loc)],
                               first_seen=ts))
            rels.append(Relationship(aeid, eid, "executed", sources=[MODULE], ts=ts))
            rels.append(Relationship(aeid, casset, "authenticated", sources=[MODULE], ts=ts))

        ip = _ip(rec)
        kind = keys.classify_indicator(ip) if ip else None
        if kind:
            iid = keys.ioc_id(kind, ip)
            ents.append(Entity(id=iid, type="ioc", label=str(ip),
                               attrs={"_assets": [casset], "ioc_kind": kind},
                               sources=[MODULE], evidence=[EvidenceRef(MODULE, run_id, loc)],
                               anomaly=1, first_seen=ts))
            rels.append(Relationship(eid, iid, "event_about", sources=[MODULE], ts=ts))

    return ents, rels


_RW = {"critical": 100, "high": 40, "medium": 10, "low": 2, "informational": 0}
