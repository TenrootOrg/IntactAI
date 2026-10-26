"""Every Intact AWS rule fires on the event it describes and stays quiet on its near miss.

The rules (config/sigma-aws) are generic: no account, vendor or resource name. Each case
below is a CloudTrail event shaped like the real recordings the rules were built on
(Splunk attack_data, Stratus Red Team -- 49 of 53 scenarios detected, was 24), and a
near miss a normal account produces (a failed call, a private CIDR, a role instead of a
person, the console). The count and sequence rules run through the scan's own detect().
"""
import copy
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

from services.fusion import sigma_eval as s  # noqa: E402
from services.fusion.external_logs import sigma_event  # noqa: E402

ACCT, OTHER = "111122223333", "999988887777"


def ev(name, src="iam", who="IAMUser", rp=None, **kw):
    e = {"eventVersion": "1.08", "eventSource": f"{src}.amazonaws.com", "eventName": name, "awsRegion": "us-east-1",
         "eventTime": kw.pop("t", "2026-10-25T10:00:00Z"), "recipientAccountId": ACCT, "sourceIPAddress": "203.0.113.10",
         "userAgent": "aws-cli/2.15.0 Python/3.11", "requestParameters": rp or {},
         "userIdentity": {"type": who, "userName": "alice" if who == "IAMUser" else None, "accountId": ACCT,
                          "arn": f"arn:aws:iam::{ACCT}:user/alice" if who == "IAMUser" else f"arn:aws:sts::{ACCT}:assumed-role/app/x"}}
    e.update(kw)
    return e


INSTANCE = {"type": "AssumedRole", "accountId": ACCT, "arn": f"arn:aws:sts::{ACCT}:assumed-role/web-role/i-0abc123def4567890"}
SSO = {"type": "AssumedRole", "accountId": ACCT, "arn": f"arn:aws:sts::{ACCT}:assumed-role/AWSReservedSSO_Admin_0a1b/jane",
       "sessionContext": {"sessionIssuer": {"type": "Role", "userName": "AWSReservedSSO_Admin_0a1b"}}}


def doc(actions, effect="Allow"):
    import json
    return json.dumps({"Statement": [{"Effect": effect, "Action": actions, "Resource": "*"}]})


def trust(principal):
    import json
    return json.dumps({"Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": {"AWS": principal}}]})


def ports(cidr, fp=22, tp=22):
    return {"instanceName": "web", "portInfos": [{"fromPort": fp, "toPort": tp, "cidrs": [cidr]}]}


CASES = [  # (rule, firing event, near miss)
    ("AWS Admin Port Opened To The Internet", ev("PutInstancePublicPorts", "lightsail", rp=ports("0.0.0.0/0")),
     ev("PutInstancePublicPorts", "lightsail", rp=ports("198.51.100.0/24"))),
    ("AWS Admin Port Opened To The Internet",
     ev("AuthorizeSecurityGroupIngress", "ec2", rp={"ipPermissions": {"items": [{"ipProtocol": "tcp", "fromPort": 3389, "toPort": 3389,
                                                                               "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]}}]}}),
     ev("AuthorizeSecurityGroupIngress", "ec2", errorCode="Client.UnauthorizedOperation",
        rp={"ipPermissions": {"items": [{"ipProtocol": "tcp", "fromPort": 3389, "toPort": 3389, "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]}}]}})),
    ("AWS Port Opened To The Internet", ev("PutInstancePublicPorts", "lightsail", rp=ports("0.0.0.0/0", 443, 443)),
     ev("PutInstancePublicPorts", "lightsail", rp=ports("0.0.0.0/0", 22, 22))),     # that one is the admin-port rule
    ("AWS IAM Policy Grants Full Admin Rights", ev("PutUserPolicy", rp={"userName": "bob", "policyDocument": doc("*")}),
     ev("PutUserPolicy", rp={"userName": "bob", "policyDocument": doc("s3:GetObject")})),
    ("AWS IAM Policy Grants Full Admin Rights", ev("AttachRolePolicy", rp={"policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}),
     ev("AttachRolePolicy", rp={"policyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"})),
    ("AWS IAM Policy Grants Every Action Of A Service", ev("PutUserPolicy", rp={"userName": "bob", "policyDocument": doc("lightsail:*")}),
     ev("PutUserPolicy", rp={"userName": "bob", "policyDocument": doc(["lightsail:GetInstances"])})),
    ("AWS IAM Policy Version Set As Default", ev("CreatePolicyVersion", rp={"policyArn": "p", "setAsDefault": True}),
     ev("CreatePolicyVersion", rp={"policyArn": "p", "setAsDefault": False})),
    ("AWS IAM Role Trusts Another Account Or Anyone", ev("CreateRole", rp={"roleName": "r", "assumeRolePolicyDocument": trust(f"arn:aws:iam::{OTHER}:root")}),
     ev("CreateRole", rp={"roleName": "r", "assumeRolePolicyDocument": trust(f"arn:aws:iam::{ACCT}:root")})),
    ("AWS IAM Login Profile Created For Another User", ev("CreateLoginProfile", rp={"userName": "bob"}),
     ev("CreateLoginProfile", rp={"userName": "alice"})),
    ("AWS IAM Access Key Created For The Root User", ev("CreateAccessKey", who="Root"),
     ev("CreateAccessKey", who="Root", rp={"userName": "bob"})),
    ("AWS IAM MFA Removed", ev("DeactivateMFADevice", rp={"userName": "bob"}), ev("EnableMFADevice", rp={"userName": "bob"})),
    ("AWS Image Or Snapshot Shared Publicly", ev("ModifySnapshotAttribute", "ec2", rp={"createVolumePermission": {"add": {"items": [{"group": "all"}]}}}),
     ev("ModifySnapshotAttribute", "ec2", rp={"createVolumePermission": {"add": {"items": [{"userId": ACCT}]}}})),
    ("AWS Image Or Snapshot Shared With Another Account", ev("ModifyImageAttribute", "ec2", rp={"launchPermission": {"add": {"items": [{"userId": OTHER}]}}}),
     ev("ModifyImageAttribute", "ec2", rp={"launchPermission": {"add": {"items": [{"userId": ACCT}]}}})),
    ("AWS S3 Bucket Or Object Made Public", ev("PutBucketAcl", "s3", rp={"bucketName": "b", "accessControlList": {"x-amz-grant-read": "uri=http://acs.amazonaws.com/groups/global/AllUsers"}}),
     ev("PutBucketAcl", "s3", rp={"bucketName": "b", "accessControlList": {"x-amz-grant-read": "id=abc"}})),
    ("AWS S3 Lifecycle Deletes Data Within A Week", ev("PutBucketLifecycle", "s3", rp={"bucketName": "b", "LifecycleConfiguration": {"Rule": {"Status": "Enabled", "Expiration": {"Days": 1}}}}),
     ev("PutBucketLifecycle", "s3", rp={"bucketName": "b", "LifecycleConfiguration": {"Rule": {"Status": "Enabled", "Expiration": {"Days": 365}}}})),
    ("AWS S3 Objects Re-encrypted In Place With KMS", ev("CopyObject", "s3", rp={"bucketName": "b", "x-amz-copy-source": "b/file", "x-amz-server-side-encryption": "aws:kms"}),
     ev("CopyObject", "s3", rp={"bucketName": "b", "x-amz-copy-source": "other/file", "x-amz-server-side-encryption": "aws:kms"})),
    ("AWS KMS Key Scheduled For Deletion Or Disabled", ev("ScheduleKeyDeletion", "kms"), ev("DescribeKey", "kms")),
    ("AWS EC2 Windows Password Retrieved", ev("GetPasswordData", "ec2"), ev("GetConsoleOutput", "ec2")),
    ("AWS Secrets Manager Batch Retrieval", ev("BatchGetSecretValue", "secretsmanager"), ev("ListSecrets", "secretsmanager")),
    ("AWS EC2 Instance Connect SSH Key Pushed", ev("SendSSHPublicKey", "ec2-instance-connect"), ev("DescribeInstances", "ec2")),
    ("AWS Lambda Code Changed By A Person", ev("UpdateFunctionCode20150331v2", "lambda"), ev("UpdateFunctionCode20150331v2", "lambda", who="AssumedRole")),
    ("AWS ECR Image Pushed By A Person", ev("PutImage", "ecr"), ev("PutImage", "ecr", who="AssumedRole")),
    ("AWS Security Or Logging Service Disabled", ev("DeleteDetector", "guardduty"), ev("DeleteDetector", "foo")),
    ("AWS Lightsail Instance Credentials Retrieved By A Person", ev("GetInstanceAccessDetails", "lightsail"),
     ev("GetInstanceAccessDetails", "lightsail", who="AssumedRole")),
    ("AWS Lightsail Instance Credentials Retrieved By A Role", ev("GetInstanceAccessDetails", "lightsail", who="AssumedRole"),
     ev("GetInstanceAccessDetails", "lightsail")),
    ("AWS Offensive Tool Used", ev("ListUsers", userAgent="stratus-red-team_abc"), ev("ListUsers")),
    ("AWS Cloud Audit Tool Used", ev("ListUsers", userAgent="Scout Suite/5.0"), ev("ListUsers")),
    ("AWS Organizations Account Left", ev("LeaveOrganization", "organizations"), ev("DescribeOrganization", "organizations")),
    ("AWS IAM Federation Provider Created Or Changed", ev("CreateSAMLProvider"), ev("ListSAMLProviders")),
    ("AWS IAM User Added To An Admin Group", ev("AddUserToGroup", rp={"groupName": "Admins", "userName": "bob"}),
     ev("AddUserToGroup", rp={"groupName": "Developers", "userName": "bob"})),
    ("AWS IAM Password Policy Weakened Or Removed", ev("DeleteAccountPasswordPolicy"), ev("GetAccountPasswordPolicy")),
    ("AWS STS Federation Token Issued To A User", ev("GetFederationToken", "sts"), ev("GetFederationToken", "sts", who="AssumedRole")),
    ("AWS Resource Policy Open To Anyone", ev("AddPermission20150331v2", "lambda", rp={"principal": "*"}),
     ev("AddPermission20150331v2", "lambda", rp={"principal": "s3.amazonaws.com"})),
    ("AWS Resource Policy Grants Another Account", ev("PutKeyPolicy", "kms", rp={"policy": trust(f"arn:aws:iam::{OTHER}:root")}),
     ev("PutKeyPolicy", "kms", rp={"policy": trust(f"arn:aws:iam::{ACCT}:root")})),
    ("AWS Lambda Function URL Without Authentication", ev("CreateFunctionUrlConfig", "lambda", rp={"authType": "NONE"}),
     ev("CreateFunctionUrlConfig", "lambda", rp={"authType": "AWS_IAM"})),
    ("AWS RDS Database Made Publicly Accessible", ev("ModifyDBInstance", "rds", rp={"publiclyAccessible": True}),
     ev("ModifyDBInstance", "rds", rp={"publiclyAccessible": False})),
    ("AWS VPC Traffic Mirroring Created", ev("CreateTrafficMirrorSession", "ec2"), ev("DescribeTrafficMirrorSessions", "ec2")),
    ("AWS EKS Cluster API Made Public", ev("UpdateClusterConfig", "eks", rp={"resourcesVpcConfig": {"endpointPublicAccess": True, "publicAccessCidrs": ["0.0.0.0/0"]}}),
     ev("UpdateClusterConfig", "eks", rp={"resourcesVpcConfig": {"endpointPublicAccess": True, "publicAccessCidrs": ["198.51.100.0/24"]}})),
    ("AWS ECS Task Runs A Privileged Container", ev("RegisterTaskDefinition", "ecs", rp={"containerDefinitions": [{"name": "a", "privileged": True}]}),
     ev("RegisterTaskDefinition", "ecs", rp={"containerDefinitions": [{"name": "a", "privileged": False}]})),
    ("AWS CloudFormation Stack From An Outside Template", ev("CreateStack", "cloudformation", rp={"templateURL": "https://example.net/t.yaml"}),
     ev("CreateStack", "cloudformation", rp={"templateURL": "https://my-bucket.s3.amazonaws.com/t.yaml"})),
    ("AWS DynamoDB Table Exported Or Backups Disabled", ev("ExportTableToPointInTime", "dynamodb"), ev("DescribeTable", "dynamodb")),
    ("AWS Route 53 Hosted Zone Deleted", ev("DeleteHostedZone", "route53"), ev("ListHostedZones", "route53")),
    ("AWS EC2 Serial Console Access Enabled", ev("EnableSerialConsoleAccess", "ec2"), ev("GetSerialConsoleAccessStatus", "ec2")),
    ("AWS Backup Or Recovery Point Deleted", ev("DeleteRecoveryPoint", "backup"), ev("ListRecoveryPointsByBackupVault", "backup")),
    # round 5 (2026-10-26): gaps found against SigmaHQ, Splunk, Elastic (ideas only), Stratus Red Team
    ("AWS CloudTrail Stops Recording Management Events",
     ev("PutEventSelectors", "cloudtrail", rp={"eventSelectors": [{"includeManagementEvents": False, "readWriteType": "All"}]}),
     ev("PutEventSelectors", "cloudtrail", rp={"eventSelectors": [{"includeManagementEvents": True, "readWriteType": "All"}]})),
    ("AWS Security Monitoring Weakened", ev("DeleteResolverQueryLogConfig", "route53resolver"), ev("ListResolverQueryLogConfigs", "route53resolver")),
    ("AWS Security Monitoring Weakened", ev("UpdateClusterConfig", "eks", rp={"logging": {"clusterLogging": [{"types": ["audit"], "enabled": False}]}}),
     ev("UpdateClusterConfig", "eks", rp={"logging": {"clusterLogging": [{"types": ["audit"], "enabled": True}]}})),
    ("AWS GuardDuty Told To Ignore Activity", ev("CreateIPSet", "guardduty"), ev("ListIPSets", "guardduty")),
    ("AWS GuardDuty Told To Ignore Activity", ev("CreateFilter", "guardduty", rp={"action": "ARCHIVE"}), ev("CreateFilter", "guardduty", rp={"action": "NOOP"})),
    ("AWS Leaked Access Key Quarantined", ev("AttachUserPolicy", who="AWSService", rp={"policyArn": "arn:aws:iam::aws:policy/AWSCompromisedKeyQuarantineV3"}),
     ev("AttachUserPolicy", rp={"policyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"})),
    ("AWS Root Session Taken From Another Account", ev("AssumeRoot", "sts"), ev("AssumeRole", "sts")),
    ("AWS Root Password Recovery", ev("PasswordRecoveryRequested", "signin", who="Root"), ev("ConsoleLogin", "signin", who="Root")),
    ("AWS Console Opened With A Workload's Credentials", ev("GetSigninToken", "signin", who="AssumedRole", userIdentity=INSTANCE),
     ev("GetSigninToken", "signin", who="AssumedRole")),
    ("AWS IAM Change Made With An Instance's Credentials", ev("CreateUser", who="AssumedRole", userIdentity=INSTANCE), ev("CreateUser", who="AssumedRole")),
    ("AWS Data Encrypted With Another Account's KMS Key",
     ev("PutBucketEncryption", "s3", rp={"bucketName": "b", "ServerSideEncryptionConfiguration": {"Rule": [{"ApplyServerSideEncryptionByDefault": {
         "SSEAlgorithm": "aws:kms", "KMSMasterKeyID": f"arn:aws:kms:us-east-1:{OTHER}:key/k"}}]}}),
     ev("PutBucketEncryption", "s3", rp={"bucketName": "b", "ServerSideEncryptionConfiguration": {"Rule": [{"ApplyServerSideEncryptionByDefault": {
         "SSEAlgorithm": "aws:kms", "KMSMasterKeyID": f"arn:aws:kms:us-east-1:{ACCT}:key/k"}}]}})),
    ("AWS Resources Shared Outside The Account", ev("CreateResourceShare", "ram", rp={"name": "s", "principals": [OTHER]}),
     ev("CreateResourceShare", "ram", rp={"name": "s", "principals": [ACCT]})),
    ("AWS Systems Manager Document Made Public", ev("ModifyDocumentPermission", "ssm", rp={"name": "d", "permissionType": "Share", "accountIdsToAdd": ["All"]}),
     ev("ModifyDocumentPermission", "ssm", rp={"name": "d", "permissionType": "Share", "accountIdsToRemove": ["All"]})),
    ("AWS IAM Roles Anywhere Trust Anchor Added", ev("CreateTrustAnchor", "rolesanywhere"), ev("ListTrustAnchors", "rolesanywhere")),
    ("AWS EKS Cluster Admin Access Granted",
     ev("AssociateAccessPolicy", "eks", rp={"policyArn": "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"}),
     ev("AssociateAccessPolicy", "eks", rp={"policyArn": "arn:aws:eks::aws:cluster-access-policy/AmazonEKSViewPolicy"})),
    ("AWS Database Protection Removed", ev("ModifyDBInstance", "rds", rp={"dBInstanceIdentifier": "d", "deletionProtection": False}),
     ev("ModifyDBInstance", "rds", rp={"dBInstanceIdentifier": "d", "deletionProtection": True})),
    ("AWS Database Protection Removed", ev("ModifyDBCluster", "rds", rp={"backupRetentionPeriod": 0}), ev("ModifyDBCluster", "rds", rp={"backupRetentionPeriod": 7})),
    ("AWS Backup Vault Lock Or Policy Removed", ev("DeleteBackupVaultLockConfiguration", "backup"), ev("GetBackupVaultAccessPolicy", "backup")),
    ("AWS Database Or Disk Exported", ev("StartExportTask", "rds"), ev("DescribeExportTasks", "rds")),
    ("AWS Database Or Disk Exported", ev("CopyDBSnapshot", "rds", rp={"sourceRegion": "eu-west-1"}), ev("CopyDBSnapshot", "rds", rp={"sourceRegion": "us-east-1"})),
    ("AWS Bedrock Model Access Enabled", ev("PutFoundationModelEntitlement", "bedrock"), ev("ListFoundationModels", "bedrock")),
    ("AWS Bedrock Model Access Enabled", ev("CreateServiceSpecificCredential", rp={"userName": "u", "serviceName": "bedrock.amazonaws.com"}),
     ev("ListServiceSpecificCredentials", rp={"userName": "u"})),
    ("AWS Email Sending Enabled Or Expanded", ev("UpdateAccountSendingEnabled", "ses", rp={"enabled": True}), ev("GetSendQuota", "ses")),
    ("AWS GPU Or Very Large Instance Launched", ev("RunInstances", "ec2", rp={"instanceType": "g5.12xlarge"}), ev("RunInstances", "ec2", rp={"instanceType": "t3.micro"})),
    ("AWS Service Quota Increase Requested", ev("RequestServiceQuotaIncrease", "servicequotas"), ev("ListServiceQuotas", "servicequotas")),
    ("AWS SageMaker Startup Script Created Or Changed", ev("CreateNotebookInstanceLifecycleConfig", "sagemaker"),
     ev("CreateNotebookInstanceLifecycleConfig", "sagemaker", who="AssumedRole")),
    ("AWS Instance Role Swapped", ev("ReplaceIamInstanceProfileAssociation", "ec2"),
     ev("ReplaceIamInstanceProfileAssociation", "ec2", userAgent="console.ec2.amazonaws.com")),
    ("AWS Permissions Boundary Removed", ev("DeleteRolePermissionsBoundary"), ev("PutRolePermissionsBoundary")),
    ("AWS Organization Guard Rail Removed", ev("DetachPolicy", "organizations"), ev("AttachPolicy", "organizations")),
    ("AWS Account-Wide Public Access Guard Removed", ev("DisableSnapshotBlockPublicAccess", "ec2"), ev("EnableSnapshotBlockPublicAccess", "ec2")),
    ("AWS Account-Wide Public Access Guard Removed", ev("DeletePublicAccessBlock", "s3", rp={"accountId": ACCT}),
     ev("DeletePublicAccessBlock", "s3", rp={"bucketName": "b"})),
    ("AWS IAM Identity Center Admin Access Assigned",
     ev("AttachManagedPolicyToPermissionSet", "sso", rp={"managedPolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}),
     ev("AttachManagedPolicyToPermissionSet", "sso", rp={"managedPolicyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"})),
    ("AWS Alternative Credentials Added To A User", ev("UpdateAccessKey", rp={"accessKeyId": "AKIA", "status": "Active"}),
     ev("UpdateAccessKey", rp={"accessKeyId": "AKIA", "status": "Inactive"})),
    ("AWS Account Contact Details Changed", ev("PutAlternateContact", "account"), ev("GetAlternateContact", "account")),
    ("AWS CodeBuild Project Made Public", ev("UpdateProjectVisibility", "codebuild", rp={"projectVisibility": "PUBLIC_READ"}),
     ev("UpdateProjectVisibility", "codebuild", rp={"projectVisibility": "PRIVATE"})),
    ("AWS Data Stream Redirected", ev("UpdateDestination", "firehose"), ev("DescribeDeliveryStream", "firehose")),
    ("AWS IAM Policy Written Without A Recorded Document", ev("PutUserPolicy", rp={"omitted": True, "originalSize": 150000}),
     ev("PutUserPolicy", rp={"userName": "u", "policyDocument": doc("s3:GetObject")})),
    ("AWS IAM Policy Opens A Privilege Escalation Path", ev("PutRolePolicy", rp={"roleName": "r", "policyDocument": doc(["iam:PassRole", "ec2:RunInstances"])}),
     ev("PutRolePolicy", rp={"roleName": "r", "policyDocument": doc(["iam:PassRole", "s3:GetObject"])})),
    ("AWS IAM Policy Opens A Privilege Escalation Path", ev("CreatePolicyVersion", rp={"policyArn": "p", "policyDocument": doc("iam:CreatePolicyVersion")}),
     ev("CreatePolicyVersion", rp={"policyArn": "p", "policyDocument": doc("iam:GetPolicyVersion")})),
    ("AWS ECR Image Scanning Turned Off", ev("PutImageScanningConfiguration", "ecr", rp={"imageScanningConfiguration": {"scanOnPush": False}}),
     ev("PutImageScanningConfiguration", "ecr", rp={"imageScanningConfiguration": {"scanOnPush": True}})),
    ("AWS GuardDuty Told To Ignore Activity", ev("DeletePublishingDestination", "guardduty"), ev("ListPublishingDestinations", "guardduty")),
    ("AWS Region Enabled Or Disabled", ev("EnableRegion", "account", rp={"regionName": "me-central-1"}), ev("ListRegions", "account")),
    ("AWS API Gateway Keys Read", ev("GetApiKeys", "apigateway", rp={"includeValue": True}), ev("GetApiKeys", "apigateway", rp={"includeValue": False})),
    ("AWS MFA Device Registered For Another User", ev("EnableMFADevice", rp={"userName": "bob", "serialNumber": "arn:mfa"}),
     ev("EnableMFADevice", rp={"userName": "alice", "serialNumber": "arn:mfa"})),
    # helper-field fixes: each service keeps its policy in its own field; SSO people are people
    ("AWS Resource Policy Grants Another Account", ev("SetQueueAttributes", "sqs", rp={"attributes": {"Policy": trust(f"arn:aws:iam::{OTHER}:root")}}),
     ev("SetQueueAttributes", "sqs", rp={"attributes": {"Policy": trust(f"arn:aws:iam::{ACCT}:root")}})),
    ("AWS Resource Policy Grants Another Account",
     ev("SetTopicAttributes", "sns", rp={"attributeName": "Policy", "attributeValue": trust(f"arn:aws:iam::{OTHER}:root")}),
     ev("SetTopicAttributes", "sns", rp={"attributeName": "DisplayName", "attributeValue": trust(f"arn:aws:iam::{OTHER}:root")})),
    ("AWS Resource Policy Grants Another Account", ev("PutBucketPolicy", "s3", rp={"bucketName": "b", "bucketPolicy": trust(f"arn:aws:iam::{OTHER}:root")}),
     ev("PutBucketPolicy", "s3", rp={"bucketName": "b", "bucketPolicy": json.dumps({"Statement": [{"Effect": "Allow", "Action": "s3:PutObject",
                                                                                         "Principal": {"AWS": f"arn:aws:iam::{OTHER}:root"}}]})})),
    ("AWS Resource Policy Grants Another Account", ev("AddPermission20150331v2", "lambda", rp={"principal": OTHER}),
     ev("AddPermission20150331v2", "lambda", rp={"principal": "s3.amazonaws.com"})),
    ("AWS IAM Policy Grants Every Action Of A Service", ev("AttachUserPolicy", rp={"policyArn": "arn:aws:iam::aws:policy/AmazonS3FullAccess"}),
     ev("AttachUserPolicy", rp={"policyArn": "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"})),
    ("AWS Lambda Code Changed By A Person", ev("UpdateFunctionCode20150331v2", "lambda", who="AssumedRole", userIdentity=SSO),
     ev("UpdateFunctionCode20150331v2", "lambda", who="AssumedRole")),
]


class EveryRuleFiresAndStaysQuiet(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        loaded = s.load(dirs=(s.AWS_BUNDLED,))
        cls.rules = {r["title"]: r for r in loaded["rules"]}

    def _hits(self, e):
        return {h["title"] for h in s.evaluate(sigma_event(copy.deepcopy(e)), list(self.rules.values()), {})}

    def test_every_case(self):
        for title, hit, miss in CASES:
            with self.subTest(rule=title):
                self.assertIn(title, self.rules, "rule did not load")
                self.assertIn(title, self._hits(hit))
                self.assertNotIn(title, self._hits(miss))

    def test_every_per_event_rule_has_a_case(self):
        covered = {t for t, _h, _m in CASES}
        untested = {t for t, r in self.rules.items() if r["level"] != "informational"} - covered \
            - {"AWS IAM User Created", "AWS Key Pair Created Or Imported", "AWS SSM Session Started By A Person",
               "AWS EC2 Instance Launched With A Startup Script By A Person"}          # low context rows
        self.assertFalse(untested, untested)

    def test_no_rule_names_a_vendor_account_or_resource(self):
        text = open(os.path.join(s.AWS_BUNDLED, "intact_aws_cloudtrail.yml")).read()
        for word in ("crowdstrike", "intactai"):                     # a vendor or product name
            self.assertNotIn(word, text.lower())
        import re
        self.assertFalse(re.findall(r"(?<!\d)\d{12}(?!\d)", text), "an AWS account number")
        self.assertFalse(set(re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text)) - {"0.0.0.0"}, "an IP address")


class EveryRuleHasATimelinePhase(unittest.TestCase):
    """A cloud technique the timeline does not know reads "[Unclassified]" (2026-10-26:
    T1530, T1526, T1580 ... -- 12 rules)."""

    def test_it(self):
        import glob
        import re
        import types
        import yaml
        from services.fusion import render
        files = [os.path.join(s.AWS_BUNDLED, "intact_aws_cloudtrail.yml")] + glob.glob(
            os.path.join(os.path.dirname(s.AWS_BUNDLED), "sigma-escu", "*.yml"))
        bad = []
        for fn in files:
            with open(fn) as fh:
                for d in yaml.safe_load_all(fh):
                    if not d or d.get("level") == "informational" or (d.get("logsource") or {}).get("product", "aws") != "aws":
                        continue
                    ids = [t.split(".", 1)[1].upper() for t in d.get("tags") or [] if re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", t)]
                    if ids and render._phase(types.SimpleNamespace(title=d["title"], mitre=ids)) == "Unclassified":
                        bad.append((d["title"], ids))
        self.assertFalse(bad, bad)


class CountAndSequenceRules(unittest.TestCase):
    def _detect(self, recs):
        from services.aws.detections import detect
        f, _ = detect({"AWS.CloudTrail": recs}, min_level="low")
        return {x["rule_title"] for v in f.values() for x in v}

    def _times(self, n, step=10):
        return [f"2026-10-25T10:{(i * step) // 60:02d}:{(i * step) % 60:02d}Z" for i in range(n)]

    def test_denied_burst_by_a_person_not_by_the_console(self):
        cli = [ev("ListUsers", t=t, errorCode="AccessDenied") for t in self._times(25)]
        self.assertIn("AWS Burst Of Denied Calls", self._detect(cli))
        con = [ev("ListUsers", t=t, errorCode="AccessDenied", userAgent="Mozilla/5.0") for t in self._times(25)]
        self.assertNotIn("AWS Burst Of Denied Calls", self._detect(con))

    def test_discovery_sweep_needs_many_different_apis(self):
        sweep = [ev(f"List{chr(65 + i)}Things", t=t) for i, t in enumerate(self._times(26))]
        self.assertIn("AWS Discovery Sweep By A User Or Key", self._detect(sweep))
        same = [ev("ListUsers", t=t) for t in self._times(60)]
        self.assertNotIn("AWS Discovery Sweep By A User Or Key", self._detect(same))

    def test_password_spray_and_many_addresses(self):
        spray = []
        for i, t in enumerate(self._times(5)):
            e = ev("ConsoleLogin", "signin", t=t, responseElements={"ConsoleLogin": "Failure"})
            e["userIdentity"]["userName"] = f"user{i}"
            spray.append(e)
        self.assertIn("AWS Console Password Spray", self._detect(spray))
        self.assertNotIn("AWS Console Password Spray", self._detect(spray[:4]))
        hop = [ev("ConsoleLogin", "signin", t=t, responseElements={"ConsoleLogin": "Success"}, sourceIPAddress=f"198.51.100.{i}")
               for i, t in enumerate(self._times(3, 600))]
        self.assertIn("AWS User Signed In From Many Addresses", self._detect(hop))
        same = [dict(h, sourceIPAddress="198.51.100.1") for h in hop]
        self.assertNotIn("AWS User Signed In From Many Addresses", self._detect(same))

    def test_keys_for_many_users(self):
        recs = [ev("CreateAccessKey", t=t, rp={"userName": f"u{i}"}) for i, t in enumerate(self._times(5))]
        self.assertIn("AWS Access Keys Created For Many Users", self._detect(recs))
        self.assertNotIn("AWS Access Keys Created For Many Users", self._detect(recs[:4]))

    def test_new_user_put_to_work(self):
        recs = [ev("CreateUser", rp={"userName": "newbie"}, t="2026-10-25T10:00:00Z")]
        later = ev("RunInstances", "ec2", t="2026-10-25T12:00:00Z", readOnly=False)
        later["userIdentity"]["userName"] = "newbie"
        self.assertIn("AWS Newly Created User Started Making Changes", self._detect(recs + [later]))
        self.assertNotIn("AWS Newly Created User Started Making Changes", self._detect(recs))

    def test_new_key_used_elsewhere(self):
        mk = ev("CreateAccessKey", rp={"userName": "bob"}, responseElements={"accessKey": {"accessKeyId": "AKIATESTKEY0000001"}})
        use = ev("ListBuckets", "s3", t="2026-10-25T11:00:00Z", sourceIPAddress="198.51.100.9")
        use["userIdentity"]["accessKeyId"] = "AKIATESTKEY0000001"
        self.assertIn("AWS New Access Key Used From Another Address", self._detect([mk, use]))
        use2 = copy.deepcopy(use); use2["sourceIPAddress"] = "203.0.113.10"
        self.assertNotIn("AWS New Access Key Used From Another Address", self._detect([mk, use2]))

    def test_round5_count_rules(self):
        t = self._times
        ssec = [ev("CopyObject", "s3", t=x, rp={"bucketName": "b", "key": f"k{i}", "x-amz-server-side-encryption-customer-algorithm": "AES256"})
                for i, x in enumerate(t(20))]
        self.assertIn("AWS S3 Data Encrypted With Customer-Supplied Keys", self._detect(ssec))
        self.assertNotIn("AWS S3 Data Encrypted With Customer-Supplied Keys", self._detect(ssec[:19]))
        brute = [ev("ConsoleLogin", "signin", t=x, responseElements={"ConsoleLogin": "Failure"}) for x in t(5)]
        self.assertIn("AWS Console Brute Force On One User", self._detect(brute))
        self.assertNotIn("AWS Console Brute Force On One User", self._detect(brute[:4]))
        regions = [ev("RunInstances", "ec2", t=x, awsRegion=r) for x, r in zip(t(3), ("us-east-1", "eu-west-1", "ap-south-1"))]
        self.assertIn("AWS Instances Launched In Many Regions", self._detect(regions))
        self.assertNotIn("AWS Instances Launched In Many Regions", self._detect([dict(r, awsRegion="us-east-1") for r in regions]))
        bed = [ev("InvokeModel", "bedrock", t=x, awsRegion=r) for x, r in zip(t(3), ("us-east-1", "us-west-2", "eu-central-1"))]
        self.assertIn("AWS Bedrock Probed In Many Regions", self._detect(bed))
        self.assertNotIn("AWS Bedrock Probed In Many Regions", self._detect(bed[:2]))
        ses = [ev(n, "ses", t=x) for n, x in zip(("GetSendQuota", "ListIdentities", "GetAccountSendingEnabled"), t(3))]
        self.assertIn("AWS Email Service Enumerated", self._detect(ses))
        self.assertNotIn("AWS Email Service Enumerated", self._detect([dict(e, userAgent="console.amazonaws.com") for e in ses]))
        ud = [ev("DescribeInstanceAttribute", "ec2", t=x, rp={"attribute": "userData", "instanceId": f"i-{i:017x}"}) for i, x in enumerate(t(5))]
        self.assertIn("AWS Startup Scripts Read From Many Instances", self._detect(ud))
        self.assertNotIn("AWS Startup Scripts Read From Many Instances", self._detect(ud[:4]))
        iam = [ev(n, t=x, userIdentity=dict(INSTANCE)) for n, x in zip(("ListUsers", "ListRoles", "ListPolicies", "GetAccountAuthorizationDetails",
                                                                         "ListAttachedRolePolicies"), t(5))]
        self.assertIn("AWS IAM Enumerated With An Instance's Credentials", self._detect(iam))
        self.assertNotIn("AWS IAM Enumerated With An Instance's Credentials", self._detect(iam[:4]))
        hop = [ev("DescribeInstances", "ec2", t=x, sourceIPAddress=ip, userIdentity=dict(INSTANCE))
               for x, ip in zip(t(3), ("198.51.100.1", "198.51.100.2", "203.0.113.7"))]
        self.assertIn("AWS Instance Credentials Used From Many Addresses", self._detect(hop))
        self.assertNotIn("AWS Instance Credentials Used From Many Addresses",
                         self._detect(hop[:2] + [dict(hop[2], sourceIPAddress="ec2.amazonaws.com")]))

    def test_guardduty_findings_are_detections(self):
        from services.aws.detections import detect
        f, _ = detect({"AWS.GuardDuty": [{"FindingType": "UnauthorizedAccess:IAMUser/MaliciousIPCaller", "Title": "API from a known bad IP",
                                          "Severity": "high", "SeverityScore": 8.0, "_timestamp": "2026-10-25T10:00:00Z"}]}, min_level="low")
        rows = [x for v in f.values() for x in v]
        self.assertEqual([(x["rule_title"], x["severity"]) for x in rows], [("GuardDuty: API from a known bad IP", "high")])

    def test_a_broken_record_costs_only_itself(self):
        recs = [None, "x", {}, {"eventName": "PutInstancePublicPorts"}, ev("GetPasswordData", "ec2")]
        self.assertIn("AWS EC2 Windows Password Retrieved", self._detect(recs))


if __name__ == "__main__":
    unittest.main()
