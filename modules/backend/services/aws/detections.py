"""AWS scan detection, on the same Sigma engine as the rest of Intact.

It used to be a separate, simplified matcher (services/azure/sigma_runner) that only knew
"selection and not filter" -- a second filter was ignored, "1 of x and not y" never
parsed -- and ran SigmaHQ's 57 AWS rules alone. On 53 real attack recordings it detected
24 (2026-10-26). Now, per scan:

  1. every CloudTrail event, enriched (cloudtrail_enrich: port open to the internet, policy
     granting "*", role trusting another account ...), against SigmaHQ's AWS rules, our
     Splunk-derived AWS rules and our own AWS pack (config/sigma-aws), in the main engine;
  2. the count rules (a burst of denied calls, a discovery sweep, mass log or secret reads,
     mass deletion ...) over the same events;
  3. GuardDuty's own findings, with GuardDuty's severity -- they were collected and then
     dropped: no rule matches a GuardDuty finding;
  4. sequences no single event shows: a user created and then put to work, an access key
     created and then used from somewhere else;
  5. what is new for this account: a person on a new network, an identity's first-ever
     sensitive change, the first change in a region (baseline.py, kept per account).

Findings keep the shape the pipeline, the run file and the fusion mapper already read.
Any part that fails is logged and skipped; the others still report.
"""
from __future__ import annotations

import time
import traceback
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

LEVELS = ["informational", "low", "medium", "high", "critical"]
NEW_USER_WINDOW_S = 7 * 86400          # a created user acting within a week of creation
# SigmaHQ hunting queries that match EVERY call of their kind -- not detections. "AWS STS
# AssumeRole Misuse" is any call made through an assumed role: 2,339 rows from one
# security integration's polling in a single scan (2026-10-26), none of them an event.
HUNTING_ONLY = {"905d389b-b853-46d0-9d3d-dea0d3a3cd49"}


def _rank(level) -> int:
    return LEVELS.index(level) if level in LEVELS else 2


def _epoch(ts):
    if not ts:
        return None
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00").replace(" ", "T")) \
            .replace(tzinfo=timezone.utc).timestamp()
    except Exception:                                      # noqa: BLE001
        return None


def _mitre(ids):
    return [{"type": "technique", "id": m} for m in ids or []]


def _finding(title, level, desc, rec, *, rule_id="", mitre=(), extra=None) -> Dict[str, Any]:
    f = {
        "rule_title": title, "rule_id": rule_id, "rule_description": desc, "severity": level,
        "status": "experimental", "mitre_attack": _mitre(mitre),
        "tags": [f"attack.{m.lower()}" for m in mitre], "logsource": {"product": "aws", "service": "cloudtrail"},
        "_timestamp": rec.get("_timestamp") or rec.get("eventTime"), "_source": rec.get("_source"),
        "matched_record": {k: v for k, v in rec.items() if not str(k).startswith("_original")},
        "_finding_time": datetime.utcnow().isoformat(),
    }
    if extra:
        f.update(extra)
    return f


def _key(title) -> str:
    return "SIGMA." + str(title).replace(" ", "_")


def detect(collected_data: Dict[str, List[Dict]], min_level: str = "low", log=None) -> Tuple[Dict, Dict]:
    """(findings {key: [finding]}, status) -- the run_sigma_rules contract."""
    log = log or (lambda m, l="info": None)
    floor = _rank(min_level)
    findings: Dict[str, List[Dict]] = {}
    tally: Dict[str, int] = {}
    by_sev = {lv: 0 for lv in LEVELS}
    rules_n = 0

    def add(key, f):
        if _rank(f["severity"]) < floor:
            return
        findings.setdefault(key, []).append(f)
        tally[f["rule_title"]] = tally.get(f["rule_title"], 0) + 1
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1

    ct = [r for src, rows in (collected_data or {}).items() if "CloudTrail" in str(src)
          for r in (rows or []) if isinstance(r, dict)]

    # 1 + 2: the main engine
    try:
        from services.fusion import sigma_eval as s
        from services.fusion.external_logs import sigma_event
        loaded = s.load()
        rules = [r for r in loaded["rules"] if r.get("product") == "aws" and r.get("id") not in HUNTING_ONLY]
        corrs = [c for c in loaded.get("correlations") or []
                 if all(b.get("product") == "aws" for b in c.get("bases") or [])]
        rules_n = len(rules) + len(corrs)
        cache, items, t0 = {}, [], time.time()
        for rec in ct:
            ev = sigma_event(rec)
            items.append((_epoch(rec.get("eventTime") or rec.get("_timestamp")), ev))
            for h in s.evaluate(ev, rules, cache):
                add(_key(h["title"]), _finding(h["title"], h["level"], h.get("description") or h["title"], ev,
                                               rule_id=h["id"], mitre=h.get("mitre")))
        for hit in s.correlate(items, corrs):
            c = hit["rule"]
            first = items[hit["members"][0]][1] if hit["members"] else {}
            who = ", ".join(f"{k}={v}" for k, v in hit["group"].items() if v)
            desc = (f"{hit['count']} matching events within {c['timespan'] // 60} min"
                    + (f" by {who}" if who else "") + " -- " + (c.get("title") or ""))
            add(_key(c["title"]), _finding(c["title"], c["level"], desc, first, rule_id=c["id"], mitre=c.get("mitre"),
                                           extra={"count": hit["count"], "first": hit["first"], "last": hit["last"]}))
        log(f"[AWS] Sigma: {len(rules)} AWS rules + {len(corrs)} count rules over {len(ct):,} CloudTrail "
            f"events in {time.time() - t0:.1f}s", "info")
    except Exception as e:                                 # noqa: BLE001 -- the other parts still report
        traceback.print_exc()
        log(f"[AWS] Sigma detection failed: {type(e).__name__}: {e}", "error")

    # 3: GuardDuty's own verdicts
    try:
        for src, rows in (collected_data or {}).items():
            if "GuardDuty" not in str(src):
                continue
            for r in rows or []:
                if not isinstance(r, dict) or not r.get("FindingType"):
                    continue
                score = r.get("SeverityScore")
                try:
                    score = float(score)
                except (TypeError, ValueError):
                    score = None
                level = ("critical" if score is not None and score >= 9 else
                         str(r.get("Severity") or "medium").lower())
                add("GUARDDUTY." + str(r["FindingType"]).replace(" ", "_"),
                    _finding(f"GuardDuty: {r.get('Title') or r['FindingType']}", level if level in LEVELS else "medium",
                             str(r.get("Description") or r["FindingType"])[:600], r))
    except Exception as e:                                 # noqa: BLE001
        log(f"[AWS] GuardDuty findings could not be read: {e}", "warning")

    # 4: sequences
    try:
        for f in behaviours(ct):
            add(_key(f["rule_title"]), f)
    except Exception as e:                                 # noqa: BLE001
        log(f"[AWS] sequence detection failed: {e}", "warning")

    # 5: what is new for this account (first new network, change, region) -- see baseline.py
    try:
        from . import baseline
        for f in baseline.detect(ct, log=log):
            add(_key(f["rule_title"]), f)
    except Exception as e:                                 # noqa: BLE001
        log(f"[AWS] baseline check failed: {e}", "warning")

    # 6: network + Kubernetes logs (netlogs_runner): behaviour checks, and the SigmaHQ
    #    Kubernetes audit rules over EKS audit events
    net = [r for src, rows in (collected_data or {}).items() if "Network" in str(src)
           for r in (rows or []) if isinstance(r, dict)]
    if net:
        try:
            from . import netdetect
            for f in netdetect.detect(net):
                add(_key(f["rule_title"]), f)
        except Exception as e:                             # noqa: BLE001
            log(f"[AWS] network checks failed: {e}", "warning")
        try:
            from services.fusion import sigma_eval as s
            k8s = [r for r in s.load()["rules"] if r.get("product") == "kubernetes"]
            cache, n = {}, 0
            for rec in net:
                if rec.get("EventSource") != "AWS.EKSAudit":
                    continue
                n += 1
                for h in s.evaluate(rec, k8s, cache):
                    add(_key(h["title"]), _finding(h["title"], h["level"], h.get("description") or h["title"], rec,
                                                   rule_id=h["id"], mitre=h.get("mitre")))
            if n:
                log(f"[AWS] Kubernetes: {len(k8s)} audit rules over {n:,} EKS audit events", "info")
        except Exception as e:                             # noqa: BLE001
            log(f"[AWS] Kubernetes audit rules failed: {e}", "warning")

    status = {"rules_count": rules_n, "total_findings": sum(len(v) for v in findings.values()),
              "matches_by_severity": by_sev, "rule_tally": tally,
              "execution_end": datetime.utcnow().isoformat()}
    return findings, status


def behaviours(recs: List[Dict]) -> List[Dict]:
    """What only a sequence shows. Written for real cases: a scanner account created a
    user, gave it a policy and a key, and the new user then built servers and opened
    ports (2026-10-26) -- each step alone looked routine."""
    out = []
    rows = sorted((r for r in recs if isinstance(r, dict) and r.get("eventTime")),
                  key=lambda r: str(r.get("eventTime")))

    def actor(r):
        ui = r.get("userIdentity") if isinstance(r.get("userIdentity"), dict) else {}
        return str(ui.get("userName") or "")

    def ok(r):
        return not r.get("errorCode")

    created = {}                                     # user -> (epoch, CreateUser event)
    for r in rows:
        rp = r.get("requestParameters") if isinstance(r.get("requestParameters"), dict) else {}
        if r.get("eventName") == "CreateUser" and ok(r) and rp.get("userName"):
            created.setdefault(str(rp["userName"]).lower(), (_epoch(r.get("eventTime")), r))
    seen = set()
    for r in rows:
        u = actor(r).lower()
        if not u or u not in created or u in seen or not ok(r) or str(r.get("readOnly")).lower() == "true":
            continue
        t0, cr = created[u]
        t = _epoch(r.get("eventTime"))
        if t0 is None or t is None or not (t0 < t <= t0 + NEW_USER_WINDOW_S):
            continue
        seen.add(u)
        later = [x for x in rows if actor(x).lower() == u and ok(x) and str(x.get("readOnly")).lower() != "true"
                 and (_epoch(x.get("eventTime")) or 0) >= t]
        names = ", ".join(dict.fromkeys(str(x.get("eventName")) for x in later))[:300]
        creator = actor(cr) or str((cr.get("userIdentity") or {}).get("type") or "?")
        out.append(_finding(
            "AWS Newly Created User Started Making Changes", "medium",
            f"User {u} was created by {creator} at {str(cr.get('eventTime'))[:19]} and made {len(later)} "
            f"change(s) from {str(r.get('eventTime'))[:19]}: {names}", r, mitre=("T1136.003",)))

    keys = {}                                        # access key id -> (creator ip, CreateAccessKey event)
    for r in rows:
        if r.get("eventName") == "CreateAccessKey" and ok(r):
            re_ = r.get("responseElements") if isinstance(r.get("responseElements"), dict) else {}
            ak = re_.get("accessKey") if isinstance(re_.get("accessKey"), dict) else {}
            if ak.get("accessKeyId"):
                keys[str(ak["accessKeyId"])] = (str(r.get("sourceIPAddress") or ""), r)
    flagged = set()
    for r in rows:
        ui = r.get("userIdentity") if isinstance(r.get("userIdentity"), dict) else {}
        k = str(ui.get("accessKeyId") or "")
        if k in keys and k not in flagged:
            ip0, cr = keys[k]
            ip = str(r.get("sourceIPAddress") or "")
            if ip and ip0 and ip != ip0 and not ip.endswith(".amazonaws.com") and ip != "AWS Internal":
                flagged.add(k)
                out.append(_finding(
                    "AWS New Access Key Used From Another Address", "medium",
                    f"Access key {k[:8]}… was created from {ip0} at {str(cr.get('eventTime'))[:19]} and first used "
                    f"from {ip} ({r.get('eventName')}) at {str(r.get('eventTime'))[:19]}", r, mitre=("T1098.001", "T1078.004")))
    return out
