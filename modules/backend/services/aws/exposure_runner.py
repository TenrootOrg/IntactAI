"""What is reachable from the internet RIGHT NOW (read-only), across services.

CloudTrail shows a port being opened only if that happened inside its 90 days and inside
the scan window; an SSH port opened two years ago is invisible to it. This reads the
current state instead, per region:

  * EC2 security groups attached to something, letting 0.0.0.0/0 or ::/0 in;
  * Lightsail instances' public ports;
  * RDS instances marked publicly accessible;
  * S3 buckets whose policy makes them public (once, account-wide);
  * public AMIs, public EBS and RDS snapshots (anyone can copy the disk);
  * Lambda function URLs with no authentication, ECR repositories and OpenSearch domains
    whose policy lets anyone in, EKS API endpoints open to 0.0.0.0/0, and internet-facing
    load balancers (the listener ports decide the level, like a security group).

One record per exposed resource, shaped like the IAM posture records (Severity, CheckTitle,
ResourceName ...), so the pipeline wraps them as account-setup findings. Severity: an
administrative port (SSH, RDP, databases ...) or every port -> high; 80/443 -> low (a
public website is normal, still worth listing); anything else -> medium. A service that
cannot be read is logged and skipped -- the others still report.
"""
from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional

from . import boto_client
from .boto_client import FATAL_KINDS, AwsFatal, classify
from .cloudtrail_enrich import ADMIN_PORTS

WEB_PORTS = {80, 443}
_ANYONE = {"0.0.0.0/0", "::/0"}
MAX_BUCKETS = 300
MAX_PER_SERVICE = 300          # per-resource calls (snapshot attributes, function URLs, repo policies)


def _open_to_anyone(policy) -> bool:
    """An Allow statement for principal "*" with no Condition (a condition such as an
    organization or VPC id is what keeps a "*" policy private)."""
    import json
    try:
        doc = json.loads(policy) if isinstance(policy, str) else (policy or {})
    except ValueError:
        return False
    st = doc.get("Statement") if isinstance(doc, dict) else None
    for x in st if isinstance(st, list) else [st] if isinstance(st, dict) else []:
        if not isinstance(x, dict) or str(x.get("Effect")).lower() != "allow" or x.get("Condition"):
            continue
        p = x.get("Principal")
        if p == "*" or (isinstance(p, dict) and "*" in ([p.get("AWS")] if isinstance(p.get("AWS"), str) else p.get("AWS") or [])):
            return True
    return False


def is_available(aws_config: Dict[str, Any]) -> Dict[str, Any]:
    from .iam_runner import is_available as _avail      # the same boto3 + credentials probe
    return _avail(aws_config)


def _level(rules) -> str:
    """rules: [(from, to)] open to anyone."""
    lv = "low"
    for fp, tp in rules:
        fp = 0 if fp in (None, -1) else int(fp)
        tp = 65535 if tp in (None, -1) else int(tp)
        if tp - fp >= 1000 or any(fp <= p <= tp for p in ADMIN_PORTS):
            return "high"
        if not (fp == tp and fp in WEB_PORTS):
            lv = "medium"
    return lv


def _ports_text(rules):
    out = []
    for fp, tp in rules:
        if fp in (None, -1) or (fp == 0 and tp in (65535, -1)):
            out.append("all ports")
        else:
            out.append(str(fp) if fp == tp else f"{fp}-{tp}")
    return ", ".join(dict.fromkeys(out))


def _record(kind, name, region, level, title, detail, since=None, **extra):
    r = {"_source": "exposure", "EventSource": "AWS.Exposure", "CheckId": f"exposure_{kind}",
         "Severity": level.capitalize(), "severity": level, "_severity": level, "StatusCode": "FAIL",
         "CheckTitle": title, "Title": title, "check_title": title, "Detail": detail,
         "ResourceName": name, "ResourceType": kind, "Region": region, "Since": since}
    r.update(extra)
    return r


def _iso(v):
    try:
        return v.isoformat() if hasattr(v, "isoformat") else (str(v) if v else None)
    except Exception:                                      # noqa: BLE001
        return None


def collect_exposure(aws_config: Dict[str, Any], *, regions: Optional[List[str]] = None,
                     log_func: Optional[Callable[[str, str], None]] = None,
                     is_cancelled_func: Optional[Callable[[], bool]] = None) -> List[Dict[str, Any]]:
    log = log_func or (lambda m, l="info": None)
    out: List[Dict[str, Any]] = []
    regions = regions or boto_client.default_regions(aws_config)

    def guarded(what, region, fn):
        try:
            fn()
        except Exception as e:                             # noqa: BLE001
            kind, msg = classify(e)
            if kind in FATAL_KINDS:
                raise AwsFatal(kind, f"{what} region={region}: {msg}", partial=out)
            log(f"[exposure] {what} in {region} could not be read — {msg}", "warning")

    for region in regions:
        if is_cancelled_func and is_cancelled_func():
            break

        def ec2():
            c = boto_client.client("ec2", aws_config, region)
            used = set()
            for page in c.get_paginator("describe_network_interfaces").paginate():
                for ni in page.get("NetworkInterfaces", []):
                    used.update(g.get("GroupId") for g in ni.get("Groups", []) if g.get("GroupId"))
            for page in c.get_paginator("describe_security_groups").paginate():
                for sg in page.get("SecurityGroups", []):
                    rules = []
                    for p in sg.get("IpPermissions", []):
                        cidrs = {r.get("CidrIp") for r in p.get("IpRanges", [])} | {r.get("CidrIpv6") for r in p.get("Ipv6Ranges", [])}
                        if cidrs & _ANYONE:
                            fp, tp = p.get("FromPort"), p.get("ToPort")
                            if str(p.get("IpProtocol")) == "-1":
                                fp, tp = 0, 65535
                            rules.append((fp, tp))
                    if not rules:
                        continue
                    attached = sg.get("GroupId") in used
                    lv = _level(rules) if attached else "low"
                    name = f"{sg.get('GroupName') or sg.get('GroupId')} ({sg.get('GroupId')})"
                    out.append(_record(
                        "AWS::EC2::SecurityGroup", name, region, lv,
                        f"Security group {name} lets the internet reach {_ports_text(rules)}"
                        + ("" if attached else " (not attached to anything)"),
                        f"{region}: inbound from 0.0.0.0/0 or ::/0 on {_ports_text(rules)}; attached={attached}",
                        OpenPorts=_ports_text(rules)))

        def lightsail():
            c = boto_client.client("lightsail", aws_config, region)
            tok = None
            while True:
                resp = c.get_instances(**({"pageToken": tok} if tok else {}))
                for inst in resp.get("instances", []):
                    rules = [(p.get("fromPort"), p.get("toPort")) for p in (inst.get("networking") or {}).get("ports", [])
                             if set(p.get("cidrs") or []) & _ANYONE or set(p.get("ipv6Cidrs") or []) & _ANYONE]
                    if rules:
                        name = inst.get("name") or "?"
                        out.append(_record(
                            "AWS::Lightsail::Instance", name, region, _level(rules),
                            f"Lightsail instance {name} lets the internet reach {_ports_text(rules)}",
                            f"{region}: public ports {_ports_text(rules)}", since=_iso(inst.get("createdAt")),
                            OpenPorts=_ports_text(rules)))
                tok = resp.get("nextPageToken")
                if not tok:
                    break

        def rds():
            c = boto_client.client("rds", aws_config, region)
            for page in c.get_paginator("describe_db_instances").paginate():
                for db in page.get("DBInstances", []):
                    if db.get("PubliclyAccessible"):
                        name = db.get("DBInstanceIdentifier") or "?"
                        out.append(_record(
                            "AWS::RDS::DBInstance", name, region, "high",
                            f"Database {name} is publicly accessible",
                            f"{region}: {db.get('Engine')} on port {(db.get('Endpoint') or {}).get('Port')}",
                            since=_iso(db.get("InstanceCreateTime"))))

        def images_and_snapshots():
            c = boto_client.client("ec2", aws_config, region)
            for img in c.describe_images(Owners=["self"]).get("Images", []):
                if img.get("Public"):
                    name = f"{img.get('Name') or img.get('ImageId')} ({img.get('ImageId')})"
                    out.append(_record("AWS::EC2::Image", name, region, "high", f"Machine image {name} is public",
                                       f"{region}: any AWS account can launch this image and read its disk",
                                       since=img.get("CreationDate")))
            for page in c.get_paginator("describe_snapshots").paginate(OwnerIds=["self"], RestorableByUserIds=["all"]):
                for sn in page.get("Snapshots", []):
                    name = sn.get("SnapshotId")
                    out.append(_record("AWS::EC2::Snapshot", name, region, "high", f"Disk snapshot {name} is public",
                                       f"{region}: any AWS account can copy this {sn.get('VolumeSize')} GiB disk",
                                       since=_iso(sn.get("StartTime"))))
            r = boto_client.client("rds", aws_config, region)
            n = 0
            for page in r.get_paginator("describe_db_snapshots").paginate(SnapshotType="manual"):
                for sn in page.get("DBSnapshots", []):
                    n += 1
                    if n > MAX_PER_SERVICE:
                        return
                    attrs = r.describe_db_snapshot_attributes(DBSnapshotIdentifier=sn["DBSnapshotIdentifier"])
                    for a in (attrs.get("DBSnapshotAttributesResult") or {}).get("DBSnapshotAttributes", []):
                        if a.get("AttributeName") == "restore" and "all" in (a.get("AttributeValues") or []):
                            name = sn["DBSnapshotIdentifier"]
                            out.append(_record("AWS::RDS::DBSnapshot", name, region, "high", f"Database snapshot {name} is public",
                                               f"{region}: any AWS account can restore this {sn.get('Engine')} database",
                                               since=_iso(sn.get("SnapshotCreateTime"))))

        def lambda_urls():
            c = boto_client.client("lambda", aws_config, region)
            n = 0
            for page in c.get_paginator("list_functions").paginate():
                for fn in page.get("Functions", []):
                    n += 1
                    if n > MAX_PER_SERVICE:
                        return
                    for u in c.list_function_url_configs(FunctionName=fn["FunctionName"]).get("FunctionUrlConfigs", []):
                        if u.get("AuthType") == "NONE":
                            name = fn["FunctionName"]
                            out.append(_record("AWS::Lambda::Url", name, region, "medium",
                                               f"Function {name} has a public URL with no authentication",
                                               f"{region}: anyone can call {u.get('FunctionUrl')}", since=u.get("CreationTime")))

        def ecr():
            c = boto_client.client("ecr", aws_config, region)
            n = 0
            for page in c.get_paginator("describe_repositories").paginate():
                for repo in page.get("repositories", []):
                    n += 1
                    if n > MAX_PER_SERVICE:
                        return
                    try:
                        pol = c.get_repository_policy(repositoryName=repo["repositoryName"]).get("policyText")
                    except Exception as e:                 # noqa: BLE001 -- no policy = private
                        if "RepositoryPolicyNotFound" in str(e):
                            continue
                        raise
                    if _open_to_anyone(pol):
                        name = repo["repositoryName"]
                        out.append(_record("AWS::ECR::Repository", name, region, "high",
                                           f"Container repository {name} is open to anyone",
                                           f"{region}: the repository policy allows any principal",
                                           since=_iso(repo.get("createdAt"))))

        def opensearch():
            c = boto_client.client("opensearch", aws_config, region)
            names = [d["DomainName"] for d in c.list_domain_names().get("DomainNames", [])]
            for i in range(0, len(names), 5):
                for d in c.describe_domains(DomainNames=names[i:i + 5]).get("DomainStatusList", []):
                    if not (d.get("VPCOptions") or {}).get("VPCId") and _open_to_anyone(d.get("AccessPolicies")):
                        out.append(_record("AWS::OpenSearch::Domain", d["DomainName"], region, "high",
                                           f"Search domain {d['DomainName']} is reachable by anyone",
                                           f"{region}: public endpoint {d.get('Endpoint')} with an open access policy"))

        def eks():
            c = boto_client.client("eks", aws_config, region)
            for name in c.list_clusters().get("clusters", []):
                v = (c.describe_cluster(name=name).get("cluster") or {})
                vpc = v.get("resourcesVpcConfig") or {}
                if vpc.get("endpointPublicAccess") and set(vpc.get("publicAccessCidrs") or ["0.0.0.0/0"]) & _ANYONE:
                    out.append(_record("AWS::EKS::Cluster", name, region, "medium",
                                       f"Kubernetes cluster {name}'s API is open to the internet",
                                       f"{region}: public endpoint allowed from 0.0.0.0/0", since=_iso(v.get("createdAt"))))

        def load_balancers():
            c = boto_client.client("elbv2", aws_config, region)
            for page in c.get_paginator("describe_load_balancers").paginate():
                for lb_ in page.get("LoadBalancers", []):
                    if lb_.get("Scheme") != "internet-facing":
                        continue
                    ports = [(x.get("Port"), x.get("Port")) for x in
                             c.describe_listeners(LoadBalancerArn=lb_["LoadBalancerArn"]).get("Listeners", [])]
                    if ports:
                        name = lb_.get("LoadBalancerName")
                        out.append(_record("AWS::ElasticLoadBalancingV2::LoadBalancer", name, region, _level(ports),
                                           f"Load balancer {name} is internet-facing on {_ports_text(ports)}",
                                           f"{region}: {lb_.get('DNSName')}", since=_iso(lb_.get("CreatedTime")),
                                           OpenPorts=_ports_text(ports)))

        for what, fn in (("EC2 security groups", ec2), ("Lightsail", lightsail), ("RDS", rds),
                         ("public images and snapshots", images_and_snapshots), ("Lambda URLs", lambda_urls),
                         ("ECR", ecr), ("OpenSearch", opensearch), ("EKS", eks), ("load balancers", load_balancers)):
            guarded(what, region, fn)

    def s3():
        c = boto_client.client("s3", aws_config, regions[0] if regions else None)
        for b in (c.list_buckets().get("Buckets") or [])[:MAX_BUCKETS]:
            name = b.get("Name")
            try:
                loc = c.get_bucket_location(Bucket=name).get("LocationConstraint") or "us-east-1"
                bc = boto_client.client("s3", aws_config, loc)
                public = bc.get_bucket_policy_status(Bucket=name).get("PolicyStatus", {}).get("IsPublic")
            except Exception as e:                         # noqa: BLE001 -- no policy = not public by policy
                if "NoSuchBucketPolicy" in str(e) or "NoSuchBucket" in str(e):
                    continue
                kind, msg = classify(e)
                if kind in FATAL_KINDS:
                    raise
                continue
            if public:
                out.append(_record("AWS::S3::Bucket", name, loc, "high", f"S3 bucket {name} is public (bucket policy)",
                                   f"{loc}: the bucket policy grants public access", since=_iso(b.get("CreationDate"))))

    guarded("S3", "global", s3)
    hi = sum(1 for r in out if r["severity"] == "high")
    log(f"[exposure] {len(out)} internet-facing resource(s) ({hi} high) across {len(regions)} region(s)", "info")
    return out
