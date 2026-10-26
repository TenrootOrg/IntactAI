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
from ..schema import Entity, Relationship, EvidenceRef, map_skip
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


def _aws_root(rec, account=None):
    """(key, label) when the AWS ROOT user did this, else None.

    Root used to be keyed off its ARN and labelled "root" -- a word the Identities
    page drops as generic (it means Linux/system root elsewhere), so the busiest
    actor of a real case had no identity card (AWS TEST, 2026-10-26: 9 of 10
    findings). It gets its own key per AWS account and a name nothing filters."""
    ui = rec.get("userIdentity") if isinstance(rec, dict) else None
    if not isinstance(ui, dict):
        return None
    arn = str(ui.get("arn") or "")
    if str(ui.get("type") or "") != "Root" and not arn.endswith(":root"):
        return None
    acct = str(ui.get("accountId") or (arn.split(":")[4] if arn.count(":") >= 5 else "") or account or "").strip()
    # The label carries no account number: the masking step keeps "aws-root" readable
    # (llm_sim._assign_account) -- a model told "SAM1 deleted two users" cannot know it
    # was THE root user. ponytail: two AWS accounts' roots share the label; the keys
    # stay apart, and the Identities page can split a merged card.
    return f"account:cloud:aws-root:{acct or 'unknown'}", "aws-root"


def _map_each(findings, *, run_id: str, provider: str = "cloud", account=None) -> tuple[list, list]:
    """One event per finding -- the original mapping. Azure uses it; AWS falls back to it."""
    ents: list[Entity] = []
    rels: list[Relationship] = []
    casset = f"asset:cloud_account:{provider}:{account or 'unknown'}"
    ents.append(Entity(id=casset, type="asset", label=f"{provider}:{account or '?'}",
                       attrs={"kind": "cloud_account", "provider": provider, "_assets": [casset]},
                       sources=[MODULE], evidence=[EvidenceRef(MODULE, run_id, "asset")]))

    for i, f in enumerate(findings or []):
        try:
            if not isinstance(f, dict):
                continue
            rec = f.get("matched_record") if isinstance(f.get("matched_record"), dict) else f
            ts = keys.norm_ts(F.get(f, "_timestamp", "_finding_time", default=None)
                              or F.get(rec, "eventTime", "timeGenerated", "createdDateTime",
                                       "activityDateTime", "time", default=None))
            if f.get("_state_snapshot"):
                # Account SETUP ("admin + active key + no MFA"), not an event: it has no
                # time of its own. Stamped with the scan's time it fell outside a case
                # window that ended before the scan and the case lost its only critical
                # finding (AWS TEST, 2026-10-26). Untimed rows are always in a window,
                # and repeated scans of the same setup collapse into one.
                ts = None
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

            root = _aws_root(rec, account) if provider == "aws" else None
            aeid = root[0] if root else _account_key(_user(rec))
            if aeid:
                u = root[1] if root else aeid.split("\\")[-1].split(":")[-1]
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
        except Exception as _x:                       # noqa: BLE001 -- one bad item, not the run
            map_skip(f"{provider} findings", _x)
            continue

    return ents, rels


def map_cloud(findings, *, run_id: str, provider: str = "cloud", account=None,
              context=None) -> tuple[list, list]:
    """Findings -> entities. Azure: one event per finding, as always. AWS: grouped by
    session, with the principal acted ON and the actor's surrounding events (see
    _map_aws). If the AWS path fails as a whole the original mapping runs instead,
    so a bug here can only ever cost the extras, never the findings."""
    if provider != "aws":
        return _map_each(findings, run_id=run_id, provider=provider, account=account)
    try:
        return _map_aws(findings, run_id=run_id, account=account, context=context)
    except Exception as _x:                               # noqa: BLE001 -- the whole AWS extra pass
        map_skip("aws grouping (fell back to one row per finding)", _x)
        return _map_each(findings, run_id=run_id, provider=provider, account=account)


# ---- AWS ------------------------------------------------------------------------------
MAX_GROUP_IPS = 5
SESSION_GAP_S = 30 * 60        # the same rule by the same principal, gaps <= 30 min: one row
CONTEXT_S = 15 * 60            # the actor's other events this close to a row are its context
CONTEXT_MAX = 20
AFTER_S = 24 * 3600            # what a principal acted on did in the following day
_TARGET_PARAMS = (("userName", ""), ("roleName", "role/"))   # IAM principals an action is ABOUT


def _not_an_indicator(v) -> bool:
    """CloudTrail puts the CALLING SERVICE in sourceIPAddress when AWS acts for you
    (iam.amazonaws.com, "AWS Internal"). Those became 'domain' IOCs on every case."""
    s = str(v or "").strip().lower()
    return not s or s == "aws internal" or s.endswith(".amazonaws.com") or s == "amazonaws.com"


def _aws_actor(rec, account):
    """(key, label) of who did it. Root, SSO / federated people and assumed roles get
    keys that mean something; everything else is keyed exactly as before."""
    root = _aws_root(rec, account)
    if root:
        return root
    ui = rec.get("userIdentity") if isinstance(rec, dict) else None
    if isinstance(ui, dict):
        arn = str(ui.get("arn") or "")
        for marker in (":assumed-role/", ":federated-user/"):
            if marker not in arn:
                continue
            parts = [p for p in arn.split(marker, 1)[1].split("/") if p]
            role = parts[0] if parts else ""
            who = parts[-1] if marker == ":federated-user/" else (parts[1] if len(parts) > 1 else "")
            # A person signing in through SSO / a federated IdP: their e-mail is the
            # session name -> corp\rami, the SAME key Velociraptor gives the AD account.
            if "@" in who:
                k = _account_key(who)
                return k, k.split("\\")[-1].split(":")[-1]
            if who and (marker == ":federated-user/" or role.startswith("AWSReservedSSO_")):
                return f"account:cloud:{who.lower()}", who
            if role:                                   # a workload's role session: the role acts
                return f"account:cloud:role/{role.lower()}", f"role/{role}"
    k = _account_key(_user(rec))
    return (k, k.split("\\")[-1].split(":")[-1]) if k else (None, None)


def _aws_targets(rec, actor_key):
    rp = rec.get("requestParameters") if isinstance(rec, dict) else None
    out = []
    if isinstance(rp, dict):
        for field, prefix in _TARGET_PARAMS:
            v = rp.get(field)
            if isinstance(v, str) and v.strip():
                k = f"account:cloud:{prefix}{v.strip().lower()}"
                if k != actor_key and k not in [t[0] for t in out]:
                    out.append((k, f"{prefix}{v.strip()}"))
    return out


def _secs(ts):
    dt = keys.to_utc_dt(ts) if ts else None
    return dt.timestamp() if dt else None


_RESOURCE_PARAMS = ("instanceName", "instanceNames", "instanceSnapshotName", "staticIpName", "keyPairName",
                    "bucketName", "functionName", "dbInstanceIdentifier", "clusterName", "groupName", "trailName")
_ANYONE = ("0.0.0.0/0", "::/0")


def _safe(fn, rec, empty):
    """A detail that cannot be read costs the detail, never the row."""
    try:
        return fn(rec)
    except Exception:                                      # noqa: BLE001
        return empty


def _resources(rec) -> list:
    """Names of what the call touched (instance, snapshot, bucket, key pair ...). They name
    the customer's servers like hostnames do: the mask hides them (attrs cloud_resources)."""
    rp = rec.get("requestParameters") if isinstance(rec, dict) else None
    out = []
    if isinstance(rp, dict):
        for k in _RESOURCE_PARAMS:
            v = rp.get(k)
            for x in (v if isinstance(v, list) else [v]):
                if isinstance(x, str) and x.strip() and x.strip() not in out:
                    out.append(x.strip())
    return out[:4]


def _details(rec) -> str:
    """What a reader needs to judge the change: ports and who may reach them, what a
    policy allows. 'the supplied data does not identify ... ports' was the report's
    complaint while CloudTrail had them (2026-10-26)."""
    rp = rec.get("requestParameters") if isinstance(rec, dict) else None
    if not isinstance(rp, dict):
        return ""
    bits = []
    perms = rp.get("portInfos")
    ipp = (rp.get("ipPermissions") or {}).get("items") if isinstance(rp.get("ipPermissions"), dict) else None
    rules = []
    for p in (perms if isinstance(perms, list) else []):
        if isinstance(p, dict):
            rules.append((p.get("fromPort"), p.get("toPort"), list(p.get("cidrs") or []) + list(p.get("ipv6Cidrs") or [])))
    for p in (ipp if isinstance(ipp, list) else []):
        if isinstance(p, dict):
            rng = [r.get("cidrIp") for r in ((p.get("ipRanges") or {}).get("items") or []) if isinstance(r, dict)]
            rng += [r.get("cidrIpv6") for r in ((p.get("ipv6Ranges") or {}).get("items") or []) if isinstance(r, dict)]
            rules.append((p.get("fromPort"), p.get("toPort"), [x for x in rng if x]))
    if rules:
        ports = sorted({str(a) if a == b or b is None else f"{a}-{b}" for a, b, _c in rules if a is not None})
        cidrs = {c for _a, _b, cs in rules for c in cs}
        who = ("OPEN TO THE WHOLE INTERNET" if cidrs & set(_ANYONE)
               else f"open to {len(cidrs)} address range(s)" if cidrs else "")
        bits.append(f"port(s) {', '.join(ports[:6])}" + (f" {who}" if who else ""))
    doc = rp.get("policyDocument")
    if isinstance(doc, str) and doc.strip().startswith("{"):
        try:
            import json as _json
            st = _json.loads(doc).get("Statement") or []
            st = st if isinstance(st, list) else [st]
            allow = [a for s in st if isinstance(s, dict) and s.get("Effect") == "Allow"
                     for a in (s.get("Action") if isinstance(s.get("Action"), list) else [s.get("Action")]) if a]
            if allow:
                bits.append("allows " + ", ".join(map(str, allow[:3])) + ("…" if len(allow) > 3 else ""))
        except Exception:                                  # noqa: BLE001 -- a summary, never a failure
            pass
    if rp.get("policyArn"):
        bits.append("policy " + str(rp["policyArn"]).rsplit("/", 1)[-1])
    return "; ".join(bits)


def _event_line(rec, actor_key):
    """'18:11:30 CreateUser → web-deployer' / '20:37:56 PutInstancePublicPorts [web-01; port(s) 22
    OPEN TO THE WHOLE INTERNET]' for a member, context or follow-up event."""
    t = keys.norm_ts(rec.get("eventTime")) or ""
    tgt = ", ".join(lbl for _k, lbl in _aws_targets(rec, actor_key))
    extra = "; ".join(x for x in (", ".join(_safe(_resources, rec, [])), _safe(_details, rec, "")) if x)
    return (f"{t[11:19] or '?'} {rec.get('eventName') or '?'}" + (f" → {tgt}" if tgt else "")
            + (f" [{extra}]" if extra else ""))


def _how(recs) -> str:
    """'from 203.0.113.10 · console · MFA · us-east-1' -- what a reader needs to judge it."""
    ips, via, regions, mfa = [], [], [], set()
    for r in recs:
        if not isinstance(r, dict):
            continue
        ip = r.get("sourceIPAddress")
        if ip and ip not in ips:
            ips.append(str(ip))
        ua = str(r.get("userAgent") or "")
        v = ("console" if (str(r.get("sessionCredentialFromConsole")) == "true" or "Mozilla" in ua
                           or ua.startswith(("console.", "signin.", "AWS Internal")))
             else "AWS CLI" if "aws-cli" in ua else "SDK/script" if ("boto" in ua.lower() or "aws-sdk" in ua)
             else (ua.split("/")[0][:30] or None))
        if v and v not in via:
            via.append(v)
        if r.get("awsRegion") and r["awsRegion"] not in regions:
            regions.append(str(r["awsRegion"]))
        ui = r.get("userIdentity") if isinstance(r.get("userIdentity"), dict) else {}
        att = ((ui.get("sessionContext") or {}).get("attributes") or {}) if isinstance(ui.get("sessionContext"), dict) else {}
        aed = r.get("additionalEventData") if isinstance(r.get("additionalEventData"), dict) else {}
        m = str(att.get("mfaAuthenticated") or aed.get("MFAUsed") or "").lower()
        if m in ("true", "yes"):
            mfa.add("MFA")
        elif m in ("false", "no"):
            mfa.add("no MFA")
    bits = ([f"from {', '.join(ips[:3])}"] if ips else []) + via[:2] + sorted(mfa) + regions[:3]
    return " · ".join(bits)


def _state_since(f, rec):
    """When an account-setup finding ("admin + active key + no MFA") became true: its newest
    active key's creation (the key IS the exposure), else the user's creation (scan time -
    UserAgeDays). Undated, it sat at the bottom of the timeline as if it had no time
    (2026-10-26) -- the IAM record has the dates."""
    import json as _json
    r = rec
    if isinstance(f.get("matched_record"), str):
        try:
            r = _json.loads(f["matched_record"])
        except Exception:                                  # noqa: BLE001
            r = {}
    if not isinstance(r, dict):
        return None
    if r.get("Since"):                               # exposure: the resource's creation
        return keys.norm_ts(r["Since"])
    keys_ = [k.get("CreateDate") for k in (r.get("AccessKeys") or [])
             if isinstance(k, dict) and str(k.get("Status", "Active")).lower() == "active" and k.get("CreateDate")]
    if keys_:
        return keys.norm_ts(max(str(k) for k in keys_))
    scan = keys.to_utc_dt(F.get(f, "_finding_time", default=None))
    try:
        age = float(r.get("UserAgeDays"))
    except (TypeError, ValueError):
        return None
    if scan is None:
        return None
    from datetime import timedelta
    return keys.norm_ts((scan - timedelta(days=age)).isoformat())


def _map_aws(findings, *, run_id, account=None, context=None):
    provider = "aws"
    ents: list[Entity] = []
    rels: list[Relationship] = []
    casset = f"asset:cloud_account:{provider}:{account or 'unknown'}"
    ents.append(Entity(id=casset, type="asset", label=f"{provider}:{account or '?'}",
                       attrs={"kind": "cloud_account", "provider": provider, "_assets": [casset]},
                       sources=[MODULE], evidence=[EvidenceRef(MODULE, run_id, "asset")]))

    # 1. read every finding once; a bad one is skipped alone
    items = []
    for i, f in enumerate(findings or []):
        try:
            if not isinstance(f, dict):
                continue
            rec = f.get("matched_record") if isinstance(f.get("matched_record"), dict) else f
            state = bool(f.get("_state_snapshot"))
            ts = keys.norm_ts(
                F.get(f, "_timestamp", "_finding_time", default=None)
                or F.get(rec, "eventTime", "timeGenerated", "createdDateTime", "activityDateTime", "time",
                         default=None))
            last = ts
            if state and not f.get("mitre_attack") and not f.get("mitre"):
                # runs saved before setup findings carried a technique ("[Unclassified]")
                src = str(f.get("_source") or "")
                body = str(f.get("matched_record") or "")
                f = dict(f, mitre_attack=[{"type": "technique", "id": (
                    ("T1530" if "AWS::S3" in body else "T1133") if "Exposure" in src or "exposure" in body
                    else "T1098" if "AccessAnalyzer" in src else "T1078.004")}])
            if state:
                # account setup: true SINCE it was set up, UNTIL the scan that saw it -- dated,
                # and inside any case window that overlaps that span
                last = keys.norm_ts(F.get(f, "_finding_time", default=None))
                # no creation date (a security group): "seen like this at the scan"
                ts = _state_since(f, rec) or last
            rule = (F.get(f, "rule_title", "rule", "title", "_rule", default=None)
                    or F.get(rec, "eventName", "operationName", "displayName", default="cloud event"))
            # A multi-account scan (services/aws/members.py) tags each record with its
            # account: another account is another cloud asset. The scan's own account
            # keeps the run's asset, so single-account ids never move.
            racct = str(rec.get("AccountId") or rec.get("recipientAccountId") or "").strip()
            acct = racct if (racct and account and racct != str(account)) else account
            actor = _aws_actor(rec, acct)
            ui = rec.get("userIdentity") if isinstance(rec.get("userIdentity"), dict) else {}
            items.append({
                "acct": acct,
                "i": i, "rec": rec, "ts": ts, "last": last, "sec": _secs(ts), "rule": rule, "state": state,
                "severity": from_string(F.get(f, "_severity", "severity", "Severity", "riskLevel",
                                              default="medium")),
                "mitre": _mitre_ids(f.get("mitre_attack") or f.get("mitre")),
                "actor": actor, "targets": _aws_targets(rec, actor[0]),
                # a console session rotates its temporary key: 14:51 / 15:07 / 15:17 of
                # one sign-in became three rows. The source IP holds a session together.
                "session": str(_ip(rec) or ""), "ip": _ip(rec),
                "event_id": str(rec.get("eventID") or ""),
            })
        except Exception as _x:                            # noqa: BLE001 -- one bad item, not the run
            map_skip("aws findings", _x)

    # 2. one row per session: same rule, same principal, same source IP, gaps <= 30 min.
    #    Untimed (account setup) rows are never grouped.
    groups, open_ = [], {}
    for it in sorted(items, key=lambda x: (x["sec"] is None, x["sec"] or 0, x["i"])):
        if it["sec"] is None or it["state"]:
            groups.append([it])                      # undated, or account setup: its own row
            continue
        # A ROLE (a machine) has no sitting: an integration polling from a new address
        # each call made 331 one-event rows and 347 IP nodes in one case (2026-10-26).
        # Its repeats of one rule are one row (hits, first..last); a person keeps sessions.
        role = str(it["actor"][1] or "").startswith("role/")
        k = (it["rule"], it["actor"][0], "" if role else it["session"], it["acct"])
        g = open_.get(k)
        if g and (role or it["sec"] - g[-1]["sec"] <= SESSION_GAP_S):
            g.append(it)
        else:
            open_[k] = [it]
            groups.append(open_[k])

    # 3. the actor's own events around each row (raw CloudTrail the scan kept)
    by_actor: dict = {}
    for rec in (context or [])[:200000]:
        try:
            if isinstance(rec, dict) and rec.get("eventTime"):
                a = _aws_actor(rec, account)[0]
                s = _secs(rec.get("eventTime"))
                if a and s is not None:
                    by_actor.setdefault(a, []).append((s, rec))
        except Exception as _x:                            # noqa: BLE001 -- one bad record
            map_skip("aws context", _x)

    assets = {account: casset}
    for grp in groups:
        try:
            a = grp[0].get("acct")
            if a not in assets:
                assets[a] = f"asset:cloud_account:{provider}:{a or 'unknown'}"
                ents.append(Entity(id=assets[a], type="asset", label=f"{provider}:{a or '?'}",
                                   attrs={"kind": "cloud_account", "provider": provider, "_assets": [assets[a]]},
                                   sources=[MODULE], evidence=[EvidenceRef(MODULE, run_id, "asset")]))
            ents_g, rels_g = _aws_group(grp, assets[a], run_id, by_actor)
            ents += ents_g
            rels += rels_g
        except Exception as _x:                            # noqa: BLE001 -- one bad row, not the run
            map_skip("aws findings", _x)
    return ents, rels


def _aws_group(grp, casset, run_id, by_actor):
    provider = "aws"
    head = grp[0]
    rule, ts = head["rule"], head["ts"]
    last = max((it.get("last") or it["ts"] or "") for it in grp) or grp[-1]["ts"]
    sev = max((it["severity"] for it in grp), key=rank)
    mitre = sorted({m for it in grp for m in it["mitre"]})
    eid = keys.event_id(casset, ts, f"{provider}:{rule}")      # a lone row keeps its old id
    members = [keys.event_id(casset, it["ts"], f"{provider}:{rule}") for it in grp]
    attrs = {"_assets": [casset], "provider": provider, "rule": rule, "mitre": mitre,
             "cloud_finding": rank(sev) >= rank("medium")}
    if head["state"] and ts:
        attrs["state_span"] = True       # true from first_seen until last_seen (the scan)
    actor_key, actor_label = head["actor"]
    who = actor_label or "an unknown principal"
    how = _how([it["rec"] for it in grp])
    lines, ctx_recs = [], []
    if len(grp) > 1:
        attrs["hits"] = len(grp)
        attrs["member_eids"] = [m for m in dict.fromkeys(members) if m != eid]
        span = (ts[11:19], last[11:19]) if ts[:10] == last[:10] else (ts[:16].replace("T", " "), last[:16].replace("T", " "))
        lines.append(f"{len(grp)} events by {who} between {span[0]} and {span[1]} UTC"
                     + (f" ({how})" if how else "") + ": "
                     + "; ".join(_event_line(it["rec"], actor_key) for it in grp[:12])
                     + ("…" if len(grp) > 12 else "") + ".")
    elif not head["state"] and isinstance(head["rec"], dict) and head["rec"].get("eventName"):
        # a lone event says what happened too: a report reading only "AWS Root
        # Credentials" wrote "no underlying event, principal or action" (2026-10-26)
        lines.append(f"{who}: {_event_line(head['rec'], actor_key)}" + (f" ({how})" if how else "") + ".")
    if head["sec"] is not None and not head["state"] and actor_key in by_actor:
        own = {it["event_id"] for it in grp if it["event_id"]}
        lo, hi = head["sec"] - CONTEXT_S, grp[-1]["sec"] + CONTEXT_S
        # key= : two events in the same second must not fall through to comparing the
        # records (dict < dict raised and the whole row was skipped, 2026-10-26)
        near = sorted(((s, r) for s, r in by_actor[actor_key]
                       if lo <= s <= hi and str(r.get("eventID") or "") not in own), key=lambda x: x[0])
        if near:
            ctx = [_event_line(r, actor_key) for _s, r in near[:CONTEXT_MAX]]
            ctx_recs.extend(r for _s, r in near[:CONTEXT_MAX])
            attrs["context"] = ctx
            lines.append(f"Around it, {who} also did: " + "; ".join(ctx)
                         + (f" (+{len(near) - CONTEXT_MAX} more)" if len(near) > CONTEXT_MAX else ""))
    # What a principal did AFTER something was done to it (a key or a user created for
    # it): the new user's own changes are the story, and no rule fires on most of them
    # (a created user then building Lightsail servers and opening ports, 2026-10-26).
    targets = list(dict.fromkeys(t for it in grp for t in it["targets"]))
    if grp[-1]["sec"] is not None and not head["state"]:
        for tk, tl in targets:
            later = sorted(((s, r) for s, r in by_actor.get(tk, ())
                            if grp[-1]["sec"] < s <= grp[-1]["sec"] + AFTER_S), key=lambda x: x[0])
            if later:
                aft = [_event_line(r, tk) for _s, r in later[:CONTEXT_MAX]]
                attrs.setdefault("after", {})[tl] = aft
                lines.append(f"Afterwards, {tl} did: " + "; ".join(aft)
                             + (f" (+{len(later) - CONTEXT_MAX} more)" if len(later) > CONTEXT_MAX else ""))
                ctx_recs.extend(r for _s, r in later[:CONTEXT_MAX])
    res = list(dict.fromkeys(n for r in [it["rec"] for it in grp] + ctx_recs for n in _safe(_resources, r, [])))
    if head["state"]:                                # an exposed instance / bucket / group by name
        st = head["rec"]
        if isinstance(st, dict) and isinstance(st.get("matched_record"), str):
            st = st["matched_record"]                # the run file keeps the record as JSON text
        if isinstance(st, str):
            try:
                import json as _json
                st = _json.loads(st)
            except Exception:                        # noqa: BLE001
                st = {}
        if isinstance(st, dict) and st.get("ResourceName") and "IAM" not in str(st.get("ResourceType") or ""):
            res.append(str(st["ResourceName"]))
    if res:
        attrs["cloud_resources"] = res[:30]
    if lines:
        attrs["summary_extra"] = " ".join(lines)
    ents = [Entity(id=eid, type="event", label=f"{provider}: {rule}", attrs=attrs,
                   sources=[MODULE],
                   evidence=[EvidenceRef(MODULE, run_id, f"{provider}/finding={it['i']}") for it in grp],
                   severity=sev, anomaly=_RW.get(sev, 0), first_seen=ts, last_seen=last)]
    rels = []
    if actor_key:
        ents.append(Entity(id=actor_key, type="account", label=actor_label, attrs={"_assets": [casset]},
                           sources=[MODULE], evidence=[EvidenceRef(MODULE, run_id, f"{provider}/finding={head['i']}")],
                           first_seen=ts))
        rels.append(Relationship(actor_key, eid, "executed", sources=[MODULE], ts=ts))
        rels.append(Relationship(actor_key, casset, "authenticated", sources=[MODULE], ts=ts))
    # who it was done TO -- their card shows it too (same link Velociraptor uses for
    # "added X to Administrators")
    for tk, tl in targets:
        ents.append(Entity(id=tk, type="account", label=tl, attrs={"_assets": [casset]},
                           sources=[MODULE], evidence=[EvidenceRef(MODULE, run_id, f"{provider}/finding={head['i']}")],
                           first_seen=ts))
        rels.append(Relationship(tk, eid, "event_about", sources=[MODULE], ts=ts))
    ips = list(dict.fromkeys(it["ip"] for it in grp if it["ip"]))
    if len(ips) > MAX_GROUP_IPS:                     # a polling role's addresses: examples, not hundreds of nodes
        attrs["ips_total"] = len(ips)
        attrs["summary_extra"] = (attrs.get("summary_extra", "") + f" From {len(ips)} different addresses "
                                  f"(first {MAX_GROUP_IPS} linked).").strip()
    for ip in ips[:MAX_GROUP_IPS]:
        kind = None if _not_an_indicator(ip) else keys.classify_indicator(ip)
        if kind:
            iid = keys.ioc_id(kind, ip)
            ents.append(Entity(id=iid, type="ioc", label=str(ip), attrs={"_assets": [casset], "ioc_kind": kind},
                               sources=[MODULE], evidence=[EvidenceRef(MODULE, run_id, f"{provider}/finding={head['i']}")],
                               anomaly=1, first_seen=ts))
            rels.append(Relationship(eid, iid, "event_about", sources=[MODULE], ts=ts))
    return ents, rels


_RW = {"critical": 100, "high": 40, "medium": 10, "low": 2, "informational": 0}
