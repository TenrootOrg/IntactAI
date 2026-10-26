"""What the internet can reach right now: one record per exposed resource, one broken
service costs only itself, and a "*" policy with a condition is not public."""
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

from services.aws import boto_client, exposure_runner as ex  # noqa: E402

OPEN = json.dumps({"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "*"}]})
ORG_ONLY = json.dumps({"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "*",
                                      "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-1"}}}]})


class Pager:
    def __init__(self, fn):
        self.fn = fn

    def paginate(self, **kw):
        return [self.fn(**kw)]


class Fake:
    def __init__(self, service, broken=()):
        self.service, self.broken = service, broken

    def __getattr__(self, name):
        raise AttributeError(name)

    def get_paginator(self, name):
        return Pager(getattr(self, name))

    def _check(self):
        if self.service in self.broken:
            raise RuntimeError(f"{self.service} exploded")

    # ec2
    def describe_network_interfaces(self, **kw):
        return {"NetworkInterfaces": [{"Groups": [{"GroupId": "sg-1"}]}]}

    def describe_security_groups(self, **kw):
        self._check()
        return {"SecurityGroups": [{"GroupId": "sg-1", "GroupName": "web", "IpPermissions": [
            {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}]}

    def describe_images(self, **kw):
        return {"Images": [{"ImageId": "ami-1", "Name": "golden", "Public": True}, {"ImageId": "ami-2", "Public": False}]}

    def describe_snapshots(self, **kw):
        assert kw.get("RestorableByUserIds") == ["all"]
        return {"Snapshots": [{"SnapshotId": "snap-1", "VolumeSize": 8}]}

    # lightsail
    def get_instances(self, **kw):
        return {"instances": []}

    # rds
    def describe_db_instances(self, **kw):
        return {"DBInstances": []}

    def describe_db_snapshots(self, **kw):
        return {"DBSnapshots": [{"DBSnapshotIdentifier": "db-snap", "Engine": "postgres"}, {"DBSnapshotIdentifier": "priv"}]}

    def describe_db_snapshot_attributes(self, DBSnapshotIdentifier):
        vals = ["all"] if DBSnapshotIdentifier == "db-snap" else ["999988887777"]
        return {"DBSnapshotAttributesResult": {"DBSnapshotAttributes": [{"AttributeName": "restore", "AttributeValues": vals}]}}

    # lambda
    def list_functions(self, **kw):
        self._check()
        return {"Functions": [{"FunctionName": "open-fn"}, {"FunctionName": "iam-fn"}]}

    def list_function_url_configs(self, FunctionName):
        auth = "NONE" if FunctionName == "open-fn" else "AWS_IAM"
        return {"FunctionUrlConfigs": [{"AuthType": auth, "FunctionUrl": "https://x.lambda-url"}]}

    # ecr
    def describe_repositories(self, **kw):
        return {"repositories": [{"repositoryName": "pub"}, {"repositoryName": "org"}, {"repositoryName": "none"}]}

    def get_repository_policy(self, repositoryName):
        if repositoryName == "none":
            raise RuntimeError("RepositoryPolicyNotFoundException")
        return {"policyText": OPEN if repositoryName == "pub" else ORG_ONLY}

    # opensearch
    def list_domain_names(self):
        return {"DomainNames": [{"DomainName": "logs"}, {"DomainName": "vpc"}]}

    def describe_domains(self, DomainNames):
        return {"DomainStatusList": [{"DomainName": "logs", "AccessPolicies": OPEN},
                                     {"DomainName": "vpc", "AccessPolicies": OPEN, "VPCOptions": {"VPCId": "vpc-1"}}]}

    # eks
    def list_clusters(self):
        return {"clusters": ["prod"]}

    def describe_cluster(self, name):
        return {"cluster": {"resourcesVpcConfig": {"endpointPublicAccess": True, "publicAccessCidrs": ["0.0.0.0/0"]}}}

    # elbv2
    def describe_load_balancers(self, **kw):
        return {"LoadBalancers": [{"LoadBalancerArn": "a", "LoadBalancerName": "site", "Scheme": "internet-facing"},
                                  {"LoadBalancerArn": "b", "LoadBalancerName": "inner", "Scheme": "internal"}]}

    def describe_listeners(self, LoadBalancerArn):
        return {"Listeners": [{"Port": 443}]}

    # s3
    def list_buckets(self):
        return {"Buckets": []}


def run(broken=()):
    logs = []
    orig = boto_client.client
    boto_client.client = lambda service, *a, **k: Fake(service, broken)
    try:
        out = ex.collect_exposure({"access_key_id": "x"}, regions=["us-east-1"], log_func=lambda m, l="info": logs.append(m))
    finally:
        boto_client.client = orig
    return {(r["ResourceType"].split("::")[-1], r["ResourceName"]): r["severity"] for r in out}, logs


class ExposureCheck(unittest.TestCase):
    def test_every_kind_of_exposure_is_one_record(self):
        got, _ = run()
        self.assertEqual(got, {
            ("SecurityGroup", "web (sg-1)"): "high",
            ("Image", "golden (ami-1)"): "high",
            ("Snapshot", "snap-1"): "high",
            ("DBSnapshot", "db-snap"): "high",
            ("Url", "open-fn"): "medium",
            ("Repository", "pub"): "high",
            ("Domain", "logs"): "high",
            ("Cluster", "prod"): "medium",
            ("LoadBalancer", "site"): "low",
        })

    def test_a_broken_service_costs_only_itself(self):
        got, logs = run(broken=("lambda",))
        self.assertNotIn(("Url", "open-fn"), got)
        self.assertIn(("Repository", "pub"), got)
        self.assertTrue(any("Lambda URLs" in m and "could not be read" in m for m in logs))

    def test_a_star_policy_with_a_condition_is_not_public(self):
        self.assertTrue(ex._open_to_anyone(OPEN))
        self.assertFalse(ex._open_to_anyone(ORG_ONLY))
        self.assertTrue(ex._open_to_anyone({"Statement": {"Effect": "Allow", "Principal": {"AWS": ["*"]}}}))
        self.assertFalse(ex._open_to_anyone("not json"))

    def test_data_exposure_is_filed_as_data_not_a_way_in(self):
        from services.aws.pipeline import _state_technique
        self.assertEqual(_state_technique("AWS.Exposure", {"ResourceType": "AWS::EC2::Snapshot"}), "T1530")
        self.assertEqual(_state_technique("AWS.Exposure", {"ResourceType": "AWS::EC2::SecurityGroup"}), "T1133")


if __name__ == "__main__":
    unittest.main()
