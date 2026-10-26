"""VPC flow, DNS query and EKS audit logs: found from the services' own settings, flows
collapsed into conversations, and each behaviour check fires on its shape and not on a
quiet network."""
import json
import os
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (_HERE, os.path.join(os.path.dirname(_HERE), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
_optional_deps.stub("markupsafe", "werkzeug", "werkzeug.utils")

from services.aws import boto_client, netdetect, netlogs_runner as nl  # noqa: E402

WINDOW = {"enabled": True, "mode": "between", "start_datetime": "2026-10-20T00:00:00Z", "end_datetime": "2026-10-26T00:00:00Z"}
T = 1792000000                                          # 2026-10-15-ish epoch; flow start


def flow(src, dst, port, action="ACCEPT", nbytes=500):
    return f"2 111122223333 eni-1 {src} {dst} 50000 {port} 6 10 {nbytes} {T} {T + 60} {action} OK"


class Fake:
    def __init__(self, groups):
        self.groups, self.calls = groups, []

    def get_caller_identity(self):
        return {"Account": "111122223333"}

    def describe_flow_logs(self):
        return {"FlowLogs": [{"FlowLogId": "fl-1", "LogDestinationType": "cloud-watch-logs", "LogGroupName": "flows"}]}

    def list_resolver_query_log_configs(self):
        return {"ResolverQueryLogConfigs": [{"Name": "q", "DestinationArn": "arn:aws:logs:us-east-1:111122223333:log-group:dns"}]}

    def list_clusters(self):
        return {"clusters": ["prod", "quiet"]}

    def describe_cluster(self, name):
        return {"cluster": {"logging": {"clusterLogging": [{"types": ["audit"], "enabled": name == "prod"}]}}}

    def get_paginator(self, name):
        groups, calls = self.groups, self.calls

        class P:
            def paginate(self, logGroupName, **kw):
                calls.append(kw.get("startTime"))
                # every line belongs to the newest day of the window (one chunk only)
                newest = len([c for c in calls if c is not None]) == 1 or kw.get("startTime") == max(c for c in calls if c)
                return [{"events": [{"message": m} for m in groups.get(logGroupName, [])]}] if newest else [{"events": []}]
        return P()


def run(groups):
    logs = []
    orig = boto_client.client
    boto_client.client = lambda *a, **k: Fake(groups)
    try:
        return nl.collect_network_logs({"access_key_id": "x"}, regions=["us-east-1"], time_filter=WINDOW,
                                       log_func=lambda m, l="info": logs.append(m)), logs
    finally:
        boto_client.client = orig


def titles(records):
    return sorted({f["rule_title"] for f in netdetect.detect(records)})


class NetworkLogs(unittest.TestCase):
    def test_flows_become_conversations(self):
        recs, _ = run({"flows": [flow("10.0.0.5", "203.0.113.9", 443)] * 3})
        conv = [r for r in recs if r["EventSource"] == "AWS.FlowLogs"]
        self.assertEqual(len(conv), 1)
        self.assertEqual((conv[0]["flows"], conv[0]["bytes"]), (3, 1500))
        self.assertTrue(conv[0]["eventTime"].startswith("2026-"))

    def test_eks_audit_only_where_it_is_switched_on(self):
        audit = json.dumps({"verb": "create", "objectRef": {"resource": "pods", "subresource": "exec"},
                            "requestReceivedTimestamp": "2026-10-21T10:00:00Z", "user": {"username": "x"}})
        recs, logs = run({"/aws/eks/prod/cluster": [audit]})
        eks = [r for r in recs if r["EventSource"] == "AWS.EKSAudit"]
        self.assertEqual([r["cluster"] for r in eks], ["prod"])
        self.assertTrue(any("quiet has audit logging off" in m for m in logs))

    def test_a_quiet_network_is_quiet(self):
        lines = [flow("10.0.0.5", "203.0.113.9", 443), flow("198.51.100.4", "10.0.0.5", 22)]
        dns = [json.dumps({"query_name": "www.example.com.", "srcaddr": "10.0.0.5", "rcode": "NOERROR",
                           "query_timestamp": "2026-10-21T10:00:00Z"})]
        recs, _ = run({"flows": lines, "dns": dns})
        self.assertEqual(titles(recs), [])

    def test_every_flow_check_fires(self):
        lines = [flow(f"198.51.{i // 250}.{i % 250}", "10.0.0.5", 22) for i in range(25)]     # 25 internet hosts on SSH
        lines += [flow("10.0.0.7", "203.0.113.50", 3333)]                                    # mining port
        lines += [flow("10.0.0.8", f"10.0.1.{i % 200}", 1000 + i, "REJECT") for i in range(120)]   # scanning
        lines += [flow("10.0.0.9", "203.0.113.60", 443, nbytes=6 * 1024 ** 3)]               # 6 GiB out
        recs, _ = run({"flows": lines})
        self.assertEqual(titles(recs), ["AWS Admin Port Reached By Many Internet Hosts", "AWS Host Probed Many Ports Or Hosts",
                                        "AWS Instance Connected To A Mining Port", "AWS Large Transfer Out Of The Network"])

    def test_every_dns_check_fires(self):
        q = lambda name, rcode="NOERROR": json.dumps({"query_name": name, "srcaddr": "10.0.0.5", "rcode": rcode,  # noqa: E731
                                                      "query_timestamp": "2026-10-21T10:00:00Z"})
        dns = [q(f"{'a' * 40}{i}.tunnel-example.net.") for i in range(60)]
        dns += [q(f"x{i}qz.example.org.", "NXDOMAIN") for i in range(210)]
        dns += [q("pool.xmr.example.com.")]
        recs, _ = run({"dns": dns})
        self.assertEqual(titles(recs), ["AWS DNS Tunnelling Pattern", "AWS Host Failed To Resolve Many Domains",
                                        "AWS Host Looked Up A Mining-Related Name"])

    def test_a_broken_service_costs_only_itself(self):
        class Broken(Fake):
            def describe_flow_logs(self):
                raise RuntimeError("flow logs exploded")
        logs = []
        orig = boto_client.client
        boto_client.client = lambda *a, **k: Broken({"dns": [json.dumps({"query_name": "a.example.com", "query_timestamp": "x"})]})
        try:
            recs = nl.collect_network_logs({"access_key_id": "x"}, regions=["us-east-1"], time_filter=WINDOW,
                                           log_func=lambda m, l="info": logs.append(m))
        finally:
            boto_client.client = orig
        self.assertEqual([r["EventSource"] for r in recs], ["AWS.DNSLogs"])
        self.assertTrue(any("flow logs in us-east-1 could not be read" in m for m in logs))

    def test_the_kubernetes_rules_run_on_eks_audit_events(self):
        from services.aws.detections import detect
        from services.fusion import sigma_eval as s
        want = "Potential Remote Command Execution In Pod Container"
        if not [r for r in s.load()["rules"] if r.get("product") == "kubernetes" and r.get("title") == want]:
            # CI's SigmaHQ copy differs from the backend image's (2026-10-26: it has
            # Kubernetes rules, not this one)
            self.skipTest(f"SigmaHQ rule {want!r} is not on this machine (it is in the backend image)")
        ev = {"EventSource": "AWS.EKSAudit", "auditID": "a1", "verb": "create", "objectRef": {"resource": "pods", "subresource": "exec"},
              "eventTime": "2026-10-21T10:00:00Z", "user": {"username": "x"}}
        f, _ = detect({"AWS.Network": [ev]}, min_level="low")
        self.assertIn(want, {x["rule_title"] for v in f.values() for x in v})



class CloudWatchIsReadNewestDayFirst(unittest.TestCase):
    def test_it(self):
        fake = Fake({"g": ["a", "b"]})
        orig = boto_client.client
        boto_client.client = lambda *a, **k: fake
        try:
            from datetime import datetime, timezone
            got = list(nl._cw_lines({}, "r", "g", datetime(2026, 10, 20, tzinfo=timezone.utc), datetime(2026, 10, 23, tzinfo=timezone.utc)))
        finally:
            boto_client.client = orig
        self.assertEqual(len(fake.calls), 3, "one call per day")
        self.assertEqual(fake.calls, sorted(fake.calls, reverse=True), "newest day first")
        self.assertEqual(got, ["a", "b"])

if __name__ == "__main__":
    unittest.main()
