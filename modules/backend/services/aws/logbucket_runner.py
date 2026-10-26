"""Logs AWS keeps in S3 that the lookup API never returns (read-only).

CloudTrail's LookupEvents returns management events only. S3 object reads, writes and
deletes, Lambda invokes and other DATA events exist only in the trail's own bucket -- and
only when a trail is set to record them. Without them a mass download, a mass deletion or
a ransomware re-encryption of a bucket cannot be seen by a live scan (2026-10-26).

collect_trail_data_events():
  1. finds the trails that record data events (event selectors);
  2. reads that trail's log files for the scan window, newest day first;
  3. keeps the data events only (the management events came through LookupEvents already).

Bounded: MAX_FILES files, MAX_EVENTS events, MAX_SECONDS, and the log says how far back it
got. A trail or bucket that cannot be read is logged and skipped; nothing here is fatal
except bad credentials.
"""
from __future__ import annotations

import gzip
import json
import time
from datetime import timedelta
from typing import Any, Callable, Dict, List, Optional

from . import boto_client
from .boto_client import FATAL_KINDS, AwsFatal, classify

MAX_FILES = 3000
MAX_EVENTS = 100_000
MAX_SECONDS = 240
# ponytail: newest-first with hard caps; a busy bucket's older days are reported as not
# read, not sampled. Raise the caps (or add per-bucket sampling) if real accounts hit them.


def _records_data_events(sel: Dict[str, Any]) -> bool:
    for s in sel.get("EventSelectors") or []:
        if s.get("DataResources"):
            return True
    for s in sel.get("AdvancedEventSelectors") or []:
        for f in s.get("FieldSelectors") or []:
            if f.get("Field") == "eventCategory" and "Data" in (f.get("Equals") or []):
                return True
    return False


def _days(start_dt, end_dt):
    d = end_dt.date()
    while d >= start_dt.date():
        yield d
        d -= timedelta(days=1)


def data_trails(aws_config, region, log) -> List[Dict[str, Any]]:
    """Trails (deduped by bucket+prefix) that record data events."""
    ct = boto_client.client("cloudtrail", aws_config, region)
    out, seen = [], set()
    for t in ct.describe_trails(includeShadowTrails=True).get("trailList") or []:
        bucket = t.get("S3BucketName")
        if not bucket:
            continue
        key = (bucket, t.get("S3KeyPrefix") or "")
        if key in seen:
            continue
        try:
            home = t.get("HomeRegion") or region
            sel = boto_client.client("cloudtrail", aws_config, home).get_event_selectors(TrailName=t["TrailARN"])
        except Exception as e:                                  # noqa: BLE001
            kind, msg = classify(e)
            if kind in FATAL_KINDS:
                raise
            log(f"[data events] trail {t.get('Name')}: selectors unreadable — {msg}", "warning")
            continue
        if _records_data_events(sel):
            seen.add(key)
            out.append({"name": t.get("Name"), "bucket": bucket, "prefix": key[1],
                        "multi_region": bool(t.get("IsMultiRegionTrail")), "org": bool(t.get("IsOrganizationTrail")),
                        "home": t.get("HomeRegion") or region})
    return out


def _log_prefixes(s3, bucket, prefix, account):
    """AWSLogs/<account>/CloudTrail/ -- or, for an organization trail, AWSLogs/<org-id>/<account>/CloudTrail/."""
    base = (prefix.rstrip("/") + "/" if prefix else "") + "AWSLogs/"
    own = f"{base}{account}/CloudTrail/"
    if s3.list_objects_v2(Bucket=bucket, Prefix=own, MaxKeys=1).get("KeyCount"):
        return [own]
    out = []
    for cp in s3.list_objects_v2(Bucket=bucket, Prefix=base, Delimiter="/").get("CommonPrefixes") or []:
        p = f"{cp['Prefix']}{account}/CloudTrail/"
        if s3.list_objects_v2(Bucket=bucket, Prefix=p, MaxKeys=1).get("KeyCount"):
            out.append(p)
    return out


def collect_trail_data_events(aws_config: Dict[str, Any], *, regions: Optional[List[str]] = None,
                              time_filter: Optional[Dict[str, Any]] = None,
                              log_func: Optional[Callable[[str, str], None]] = None,
                              is_cancelled_func: Optional[Callable[[], bool]] = None) -> List[Dict[str, Any]]:
    from .cloudtrail_runner import _resolve_time_window
    log = log_func or (lambda m, l="info": None)
    regions = regions or boto_client.default_regions(aws_config)
    start_dt, end_dt = _resolve_time_window(time_filter)
    out: List[Dict[str, Any]] = []
    try:
        account = boto_client.client("sts", aws_config, regions[0]).get_caller_identity()["Account"]
        trails = data_trails(aws_config, regions[0], log)
    except Exception as e:                                      # noqa: BLE001
        kind, msg = classify(e)
        if kind in FATAL_KINDS:
            raise AwsFatal(kind, f"data events: {msg}", partial=out)
        log(f"[data events] trails could not be read — {msg}", "warning")
        return out
    if not trails:
        log("[data events] no trail records data events (S3 object reads/writes/deletes, Lambda invokes) — "
            "mass download, mass deletion and S3 ransomware cannot be checked on this account", "info")
        return out

    t0, files, cut = time.time(), 0, None
    for tr in trails:
        try:
            loc = boto_client.client("s3", aws_config, regions[0]).get_bucket_location(Bucket=tr["bucket"])
            s3 = boto_client.client("s3", aws_config, loc.get("LocationConstraint") or "us-east-1")
            bases = _log_prefixes(s3, tr["bucket"], tr["prefix"], account)
        except Exception as e:                                  # noqa: BLE001
            kind, msg = classify(e)
            if kind in FATAL_KINDS:
                raise AwsFatal(kind, f"data events: {msg}", partial=out)
            log(f"[data events] trail {tr['name']}: bucket {tr['bucket']} not readable — {msg}", "warning")
            continue
        read_regions = regions if tr["multi_region"] else [tr["home"]]
        for day in _days(start_dt, end_dt):
            for base in bases:
                for region in read_regions:
                    if is_cancelled_func and is_cancelled_func():
                        return out
                    pfx = f"{base}{region}/{day:%Y/%m/%d}/"
                    try:
                        pages = s3.get_paginator("list_objects_v2").paginate(Bucket=tr["bucket"], Prefix=pfx)
                        keys = sorted((o["Key"] for p in pages for o in p.get("Contents") or []), reverse=True)
                    except Exception as e:                      # noqa: BLE001
                        log(f"[data events] {pfx}: list failed — {classify(e)[1]}", "warning")
                        continue
                    for k in keys:
                        if files >= MAX_FILES or len(out) >= MAX_EVENTS or time.time() - t0 > MAX_SECONDS:
                            cut = day
                            break
                        try:
                            body = s3.get_object(Bucket=tr["bucket"], Key=k)["Body"].read()
                            recs = json.loads(gzip.decompress(body) if k.endswith(".gz") else body).get("Records") or []
                        except Exception as e:                  # noqa: BLE001
                            kind, msg = classify(e)
                            if kind in FATAL_KINDS:
                                raise AwsFatal(kind, f"data events: {msg}", partial=out)
                            log(f"[data events] {k}: unreadable — {msg}", "warning")
                            files += 1
                            continue
                        files += 1
                        for r in recs:
                            if not isinstance(r, dict):
                                continue
                            if r.get("eventCategory") != "Data" and r.get("managementEvent") is not False:
                                continue
                            ts = str(r.get("eventTime") or "")
                            if ts and not (start_dt.isoformat()[:19] <= ts.replace("Z", "")[:19] <= end_dt.isoformat()[:19]):
                                continue
                            r["_source"] = "cloudtrail_data"
                            r["EventSource"] = "AWS.CloudTrail"
                            r["_timestamp"] = r.get("eventTime")
                            out.append(r)
                    if cut:
                        break
                if cut:
                    break
            if cut:
                break
    if cut:
        log(f"[data events] stopped at {cut} ({files} files, {len(out):,} events, {time.time() - t0:.0f}s) — "
            f"older data events in the window were not read", "warning")
    log(f"[data events] {len(out):,} data events from {files} log file(s) of {len(trails)} trail(s)", "info")
    return out
