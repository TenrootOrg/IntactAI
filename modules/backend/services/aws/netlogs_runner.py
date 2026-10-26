"""Network and Kubernetes logs, read from where the account sends them (read-only).

CloudTrail says who changed what; it never sees traffic, DNS lookups or what happens
inside a Kubernetes cluster. These logs do, when the account has them switched on:

  * VPC flow logs (CloudWatch Logs or S3)        -> AWS.FlowLogs, collapsed into
    conversations: (source, destination, port, protocol, accept/reject) with totals --
    a busy VPC writes millions of lines, a scan needs the conversations;
  * Route 53 resolver query logs (CloudWatch Logs or S3) -> AWS.DNSLogs;
  * EKS control-plane audit logs (CloudWatch Logs) -> AWS.EKSAudit, matched by the
    SigmaHQ Kubernetes audit rules.

Each destination is found from the service's own settings. Bounded per source
(MAX_LINES lines read, MAX_SECONDS); a destination that cannot be read is logged and
skipped. Nothing found = said once, not an error.
"""
from __future__ import annotations

import gzip
import json
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterator, List, Optional

from . import boto_client
from .boto_client import FATAL_KINDS, AwsFatal, classify

MAX_LINES = 200_000          # per destination
MAX_SECONDS = 120            # per destination
MAX_EKS_EVENTS = 50_000
DEFAULT_FLOW_FIELDS = ["version", "account-id", "interface-id", "srcaddr", "dstaddr", "srcport", "dstport",
                       "protocol", "packets", "bytes", "start", "end", "action", "log-status"]
# ponytail: CloudWatch filter_log_events walks oldest-first, so a capped source keeps
# the OLDEST part of the window; read newest-first per stream if real accounts hit MAX_LINES.


def _iso(epoch) -> Optional[str]:
    try:
        return datetime.fromtimestamp(int(epoch), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (TypeError, ValueError, OSError):
        return None


def _cw_lines(aws_config, region, group, start_dt, end_dt, prefix=None) -> Iterator[str]:
    logs = boto_client.client("logs", aws_config, region)
    kw = {"logGroupName": group, "startTime": int(start_dt.timestamp() * 1000), "endTime": int(end_dt.timestamp() * 1000)}
    if prefix:
        kw["logStreamNamePrefix"] = prefix
    for page in logs.get_paginator("filter_log_events").paginate(**kw):
        for e in page.get("events", []):
            yield e.get("message") or ""


def _s3_lines(aws_config, bucket_arn, kind, account, start_dt, end_dt) -> Iterator[str]:
    """Lines of the S3 log files for the window: <prefix>/AWSLogs/<acct>/<kind>/<region|vpc>/YYYY/MM/DD/."""
    from datetime import timedelta
    path = bucket_arn.split(":::", 1)[-1]
    bucket, _, prefix = path.partition("/")
    loc = boto_client.client("s3", aws_config).get_bucket_location(Bucket=bucket).get("LocationConstraint") or "us-east-1"
    s3 = boto_client.client("s3", aws_config, loc)
    base = (prefix.rstrip("/") + "/" if prefix else "") + f"AWSLogs/{account}/{kind}/"
    subs = [p["Prefix"] for p in s3.list_objects_v2(Bucket=bucket, Prefix=base, Delimiter="/").get("CommonPrefixes") or []]
    d = end_dt.date()
    while d >= start_dt.date():                                # newest day first
        for sub in subs:
            for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=f"{sub}{d:%Y/%m/%d}/"):
                for o in page.get("Contents") or []:
                    body = s3.get_object(Bucket=bucket, Key=o["Key"])["Body"].read()
                    text = (gzip.decompress(body) if o["Key"].endswith(".gz") else body).decode("utf-8", "replace")
                    yield from text.splitlines()
        d -= timedelta(days=1)


def _flows(lines, fields, region) -> List[Dict[str, Any]]:
    conv: Dict[tuple, Dict[str, Any]] = {}
    for line in lines:
        parts = line.split()
        if not parts or parts[0] == "version" or parts[0].startswith("${"):
            if parts and parts[0] == "version":
                fields = parts                                 # an S3 file's header line
            continue
        r = dict(zip(fields, parts))
        if r.get("log-status") in ("NODATA", "SKIPDATA") or r.get("srcaddr") in (None, "-"):
            continue
        k = (r.get("srcaddr"), r.get("dstaddr"), r.get("dstport"), r.get("protocol"), r.get("action"))
        c = conv.get(k)
        b = int(r["bytes"]) if str(r.get("bytes", "")).isdigit() else 0
        st = int(r["start"]) if str(r.get("start", "")).isdigit() else None
        if not c:
            conv[k] = c = {"srcaddr": k[0], "dstaddr": k[1], "dstport": k[2], "protocol": k[3], "action": k[4],
                           "bytes": 0, "flows": 0, "first": st, "last": st, "interface_id": r.get("interface-id"),
                           "instance_id": r.get("instance-id"), "awsRegion": region}
        c["bytes"] += b
        c["flows"] += 1
        if st:
            c["first"] = min(c["first"] or st, st)
            c["last"] = max(c["last"] or st, st)
    out = []
    for c in conv.values():
        c["eventTime"] = _iso(c["first"])
        c["lastTime"] = _iso(c["last"])
        c["_timestamp"] = c["eventTime"]
        c["EventSource"] = "AWS.FlowLogs"
        c["_source"] = "flowlogs"
        out.append(c)
    return out


def _bounded(lines: Iterator[str], log, what) -> Iterator[str]:
    t0, n = time.time(), 0
    for line in lines:
        n += 1
        if n > MAX_LINES or time.time() - t0 > MAX_SECONDS:
            log(f"[network logs] {what}: stopped after {n - 1:,} lines ({time.time() - t0:.0f}s) — the rest of the window was not read", "warning")
            return
        yield line


def collect_network_logs(aws_config: Dict[str, Any], *, regions: Optional[List[str]] = None,
                         time_filter: Optional[Dict[str, Any]] = None,
                         log_func: Optional[Callable[[str, str], None]] = None,
                         is_cancelled_func: Optional[Callable[[], bool]] = None) -> List[Dict[str, Any]]:
    from .cloudtrail_runner import _resolve_time_window
    log = log_func or (lambda m, l="info": None)
    regions = regions or boto_client.default_regions(aws_config)
    start_dt, end_dt = _resolve_time_window(time_filter)
    out: List[Dict[str, Any]] = []
    found = 0

    def guarded(what, fn):
        try:
            fn()
        except AwsFatal:
            raise
        except Exception as e:                                 # noqa: BLE001
            kind, msg = classify(e)
            if kind in FATAL_KINDS:
                raise AwsFatal(kind, f"network logs: {msg}", partial=out)
            log(f"[network logs] {what} could not be read — {msg}", "warning")

    account = None
    try:
        account = boto_client.client("sts", aws_config, regions[0]).get_caller_identity()["Account"]
    except Exception:                                          # noqa: BLE001 -- only S3 paths need it
        pass

    for region in regions:
        if is_cancelled_func and is_cancelled_func():
            break

        def flow():
            nonlocal found
            ec2 = boto_client.client("ec2", aws_config, region)
            done = set()
            for fl in ec2.describe_flow_logs().get("FlowLogs", []):
                dest = (fl.get("LogDestinationType"), fl.get("LogGroupName") or fl.get("LogDestination"))
                if dest in done or not dest[1]:
                    continue
                done.add(dest)
                found += 1
                fields = [f.strip("${}") for f in (fl.get("LogFormat") or "").split()] or DEFAULT_FLOW_FIELDS
                if dest[0] == "s3" and account:
                    lines = _s3_lines(aws_config, dest[1], "vpcflowlogs", account, start_dt, end_dt)
                elif dest[0] in (None, "cloud-watch-logs"):
                    lines = _cw_lines(aws_config, region, dest[1], start_dt, end_dt)
                else:
                    log(f"[network logs] flow log {fl.get('FlowLogId')} goes to {dest[0]} — not readable here", "info")
                    continue
                conv = _flows(_bounded(lines, log, f"flow logs {dest[1]}"), fields, region)
                log(f"[network logs] {region}: flow logs {dest[1]} → {len(conv):,} conversations", "info")
                out.extend(conv)

        def dns():
            nonlocal found
            r53 = boto_client.client("route53resolver", aws_config, region)
            for cfg in r53.list_resolver_query_log_configs().get("ResolverQueryLogConfigs", []):
                arn = cfg.get("DestinationArn") or ""
                found += 1
                if ":logs:" in arn:
                    lines = _cw_lines(aws_config, region, arn.split(":log-group:")[-1].split(":")[0], start_dt, end_dt)
                elif ":s3:" in arn and account:
                    lines = _s3_lines(aws_config, arn, "vpcdnsquerylogs", account, start_dt, end_dt)
                else:
                    log(f"[network logs] DNS query log {cfg.get('Name')} goes to {arn.split(':')[2] if arn.count(':') > 2 else '?'} — not readable here", "info")
                    continue
                n = 0
                for line in _bounded(lines, log, f"DNS query log {cfg.get('Name')}"):
                    try:
                        q = json.loads(line)
                    except ValueError:
                        continue
                    q.update(eventTime=q.get("query_timestamp"), _timestamp=q.get("query_timestamp"),
                             EventSource="AWS.DNSLogs", _source="dnslogs", awsRegion=region)
                    out.append(q)
                    n += 1
                log(f"[network logs] {region}: DNS query log {cfg.get('Name')} → {n:,} lookups", "info")

        def eks():
            nonlocal found
            c = boto_client.client("eks", aws_config, region)
            for name in c.list_clusters().get("clusters", []):
                cl = c.describe_cluster(name=name).get("cluster") or {}
                on = any("audit" in (x.get("types") or []) and x.get("enabled")
                         for x in (cl.get("logging") or {}).get("clusterLogging", []))
                if not on:
                    log(f"[network logs] {region}: EKS cluster {name} has audit logging off — nothing to read", "info")
                    continue
                found += 1
                n = 0
                for line in _bounded(_cw_lines(aws_config, region, f"/aws/eks/{name}/cluster", start_dt, end_dt,
                                               prefix="kube-apiserver-audit"), log, f"EKS audit {name}"):
                    try:
                        a = json.loads(line)
                    except ValueError:
                        continue
                    a.update(eventTime=a.get("requestReceivedTimestamp") or a.get("stageTimestamp"),
                             EventSource="AWS.EKSAudit", _source="eksaudit", cluster=name, awsRegion=region)
                    a["_timestamp"] = a["eventTime"]
                    out.append(a)
                    n += 1
                    if n >= MAX_EKS_EVENTS:
                        log(f"[network logs] EKS audit {name}: capped at {MAX_EKS_EVENTS:,} events", "warning")
                        break
                log(f"[network logs] {region}: EKS audit {name} → {n:,} events", "info")

        guarded(f"flow logs in {region}", flow)
        guarded(f"DNS query logs in {region}", dns)
        guarded(f"EKS audit logs in {region}", eks)

    if not found:
        log("[network logs] no VPC flow logs, DNS query logs or EKS audit logs are switched on in the scanned regions", "info")
    return out
