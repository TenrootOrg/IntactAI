"""CloudTrail -> plain facts a Sigma rule can match ("intact.*" fields).

SigmaHQ's AWS rules match event names; the risk is usually in the request: WHICH port,
open to WHOM, a policy granting "*", a role trusting ANOTHER account, a snapshot shared
with "all". Those live in nested JSON (portInfos, ipPermissions.items, a policy document
that is a JSON string) no Sigma field path can reach. enrich() reads them once and adds:

  intact.open_to_internet / admin_port_open / open_ports   (EC2 SG, Lightsail, network ACL)
  intact.policy_admin / policy_wildcard / policy_actions    (inline, managed, versions)
  intact.trust_anyone / trust_external                       (role trust policy)
  intact.shared_public / shared_external                     (AMI, EBS/RDS snapshot)
  intact.bucket_public                                       (ACL, policy, public-access block)
  intact.short_expiry                                        (lifecycle deleting within 7 days)
  intact.reencrypt_in_place                                  (S3 copied onto itself with SSE-KMS)
  intact.acts_on_other_user / denied / tool
  intact.person / instance_role / lambda_role / cloudshell    (whose credentials: SSO users are people)
  intact.policy_privesc                                      (a published IAM escalation path)
  intact.resource_policy_*  per service: SQS/SNS/Secrets/ECR/OpenSearch/Glacier/EFS/Backup/Logs/S3/Lambda
  intact.mgmt_logging_off / k8s_logging_off / kms_foreign_key / copied_cross_region
  intact.instance_type / large_instance                      (GPU, accelerator, 24xlarge+)

Values are the strings "true" (absent otherwise) so every Sigma engine compares them
alike. Built 2026-10-26: 24 of 53 real attack recordings were detected without it.
Every reader is defensive: an odd request costs that fact, never the event.
"""
from __future__ import annotations

import json
import re
from urllib.parse import unquote

ADMIN_PORTS = {22, 23, 135, 139, 445, 1433, 2375, 2376, 3306, 3389, 5432, 5900, 5985, 5986, 6379,
               9200, 11211, 27017}
_ANYONE = {"0.0.0.0/0", "::/0"}
_DENIED = {"accessdenied", "accessdeniedexception", "unauthorizedoperation", "client.unauthorizedoperation",
           "unauthorizedaccess", "unauthorized"}
# Offensive frameworks first (named in the finding), then cloud audit tools.
TOOLS = re.compile(r"(pacu|stratus[- ]red[- ]team|cloudgoat|weirdaal|aws_pwn|nimbostratus|endgame|"
                   r"scoutsuite|scout suite|prowler|cloudsploit|pmapper|principalmapper|cloudmapper|cloudfox|"
                   r"enumerate-iam|cloudbrute|s3scanner|kali|parrot ?os)", re.I)
ADMIN_MANAGED = ("/AdministratorAccess", "/IAMFullAccess", "/AWSOrganizationsFullAccess")
WIDE_MANAGED = ("/PowerUserAccess",)        # + every AWS-managed "...FullAccess" policy (below)
# Grants that let the holder make itself more powerful (the published IAM escalation paths):
# alone, or together with iam:PassRole (hand a stronger role to something it can create).
PRIVESC_ALONE = {"iam:createpolicyversion", "iam:setdefaultpolicyversion", "iam:attachuserpolicy", "iam:attachrolepolicy",
                 "iam:attachgrouppolicy", "iam:putuserpolicy", "iam:putrolepolicy", "iam:putgrouppolicy",
                 "iam:updateassumerolepolicy", "iam:addusertogroup", "iam:createloginprofile", "iam:updateloginprofile",
                 "iam:createaccesskey"}
PRIVESC_WITH_PASSROLE = {"ec2:runinstances", "lambda:createfunction", "glue:createdevendpoint", "glue:createjob",
                         "cloudformation:createstack", "datapipeline:createpipeline", "sagemaker:createnotebookinstance",
                         "ecs:runtask", "ecs:registertaskdefinition", "codebuild:createproject", "ssm:sendcommand"}
_INSTANCE_SESSION = re.compile(r":assumed-role/[^/]+/i-[0-9a-f]{8,17}$")
_BIG_INSTANCE = re.compile(r"^(p[2-6]|g[3-6]|inf\d|trn\d|dl\d|x2|u-)|metal|(24|32|48)xlarge", re.I)


def _json(v):
    """A policy document: a dict, a JSON string, or a URL-encoded JSON string."""
    if isinstance(v, dict):
        return v
    if isinstance(v, str) and v.strip():
        s = v.strip()
        if s.startswith("%7B") or s.startswith("%7b"):
            s = unquote(s)
        try:
            d = json.loads(s)
            return d if isinstance(d, dict) else None
        except Exception:                                  # noqa: BLE001
            return None
    return None


def _list(v):
    return v if isinstance(v, list) else ([] if v is None else [v])


def _own_account(rec):
    ui = rec.get("userIdentity") if isinstance(rec.get("userIdentity"), dict) else {}
    return str(rec.get("recipientAccountId") or ui.get("accountId") or "")


def _ports(rp):
    """[(from, to, [cidrs])] from an EC2 security-group change, Lightsail ports, a NACL entry."""
    out = []
    for p in _list(rp.get("portInfos")) + _list(rp.get("portInfo")):
        if isinstance(p, dict):
            out.append((p.get("fromPort"), p.get("toPort"),
                        [str(c) for c in _list(p.get("cidrs")) + _list(p.get("ipv6Cidrs"))]))
    perms = rp.get("ipPermissions")
    items = perms.get("items") if isinstance(perms, dict) else perms
    for p in _list(items):
        if not isinstance(p, dict):
            continue
        rng = []
        for key, sub in (("ipRanges", "cidrIp"), ("ipv6Ranges", "cidrIpv6")):
            r = p.get(key)
            for x in _list(r.get("items") if isinstance(r, dict) else r):
                if isinstance(x, dict) and x.get(sub):
                    rng.append(str(x[sub]))
        fp, tp = p.get("fromPort"), p.get("toPort")
        if str(p.get("ipProtocol")) == "-1":
            fp, tp = 0, 65535
        out.append((fp, tp, rng))
    if rp.get("cidrBlock") or rp.get("ipv6CidrBlock"):               # network ACL entry
        if str(rp.get("ruleAction", "allow")).lower() == "allow" and not rp.get("egress"):
            pr = rp.get("portRange") if isinstance(rp.get("portRange"), dict) else {}
            fp, tp = pr.get("from"), pr.get("to")
            if str(rp.get("protocol")) == "-1" or fp is None:
                fp, tp = 0, 65535
            out.append((fp, tp, [str(rp.get("cidrBlock") or rp.get("ipv6CidrBlock"))]))
    return out


def _int(v, default=None):
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def _statements(doc):
    st = (doc or {}).get("Statement")
    return [s for s in _list(st) if isinstance(s, dict)]


def _allowed_actions(doc):
    return [str(a) for s in _statements(doc) if str(s.get("Effect")).lower() == "allow"
            for a in _list(s.get("Action")) if a]


def _principals(doc):
    out = []
    for s in _statements(doc):
        if str(s.get("Effect")).lower() != "allow":
            continue
        p = s.get("Principal")
        if p == "*":
            out.append("*")
        elif isinstance(p, dict):
            for v in _list(p.get("AWS")):
                out.append(str(v))
    return out


def _account_of(principal):
    m = re.search(r"(?:arn:aws[\w-]*:iam::)?(\d{12})", principal)
    return m.group(1) if m else ""


def enrich(rec):
    """rec with rec["intact"] = {fact: "true" | value}; rec unchanged if nothing applies."""
    if not isinstance(rec, dict) or not rec.get("eventName"):
        return rec
    facts = {}
    try:
        _facts(rec, facts)
    except Exception:                                      # noqa: BLE001 -- a fact, never the event
        pass
    if facts:
        rec["intact"] = facts
    return rec


def _facts(rec, f):
    name = str(rec.get("eventName") or "")
    rp = rec.get("requestParameters") if isinstance(rec.get("requestParameters"), dict) else {}
    ui = rec.get("userIdentity") if isinstance(rec.get("userIdentity"), dict) else {}
    own = _own_account(rec)

    # -- exposure ------------------------------------------------------------------
    rules = _ports(rp)
    if rules:
        ports, anyone, admin = set(), False, False
        for fp, tp, cidrs in rules:
            fp, tp = _int(fp, 0), _int(tp, _int(fp, 0))
            if tp is None or tp < fp:
                tp = fp
            if set(cidrs) & _ANYONE:
                anyone = True
                if tp - fp >= 1000 or any(fp <= p <= tp for p in ADMIN_PORTS):
                    admin = True
            ports.add(str(fp) if fp == tp else f"{fp}-{tp}")
        f["open_ports"] = ",".join(sorted(ports))[:120]
        if anyone:
            f["open_to_internet"] = "true"
        if admin:
            f["admin_port_open"] = "true"

    # -- policies --------------------------------------------------------------------
    doc = _json(rp.get("policyDocument") or rp.get("inlinePolicy"))
    if doc:
        acts = _allowed_actions(doc)
        if acts:
            f["policy_actions"] = ",".join(acts[:8])[:200]
        if any(a in ("*", "iam:*", "*:*") for a in acts):
            f["policy_admin"] = "true"
        elif any(a.endswith(":*") for a in acts):
            f["policy_wildcard"] = "true"
        low = {a.lower() for a in acts}
        if not f.get("policy_admin") and (low & PRIVESC_ALONE or ("iam:passrole" in low and low & PRIVESC_WITH_PASSROLE)):
            f["policy_privesc"] = "true"
    arns = [str(rp.get("policyArn") or ""), str(rp.get("managedPolicyArn") or "")] + [str(a.get("arn") if isinstance(a, dict) else a)
                                               for a in _list(rp.get("policyArns"))]
    if name == "GetFederationToken":
        fdoc = _json(rp.get("policy"))
        if fdoc and any(a in ("*", "iam:*", "*:*") for a in _allowed_actions(fdoc)):
            f["policy_admin"] = "true"
    for arn in arns:
        if arn.endswith(ADMIN_MANAGED):
            f["policy_admin"] = "true"
        elif arn.endswith(WIDE_MANAGED) or (":aws:policy/" in arn and arn.endswith("FullAccess")):
            f["policy_wildcard"] = "true"

    # -- trust --------------------------------------------------------------------------
    trust = _json(rp.get("assumeRolePolicyDocument")) or (doc if name == "UpdateAssumeRolePolicy" else None)
    if trust:
        for p in _principals(trust):
            if p == "*":
                f["trust_anyone"] = "true"
            elif own and _account_of(p) and _account_of(p) != own:
                f["trust_external"] = "true"

    # -- resource policies: each service keeps the document in its own field -----------
    raw = []
    attrs = rp.get("attributes") if isinstance(rp.get("attributes"), dict) else {}
    if name in ("PutKeyPolicy", "CreateKey", "PutFileSystemPolicy", "PutBackupVaultAccessPolicy"):
        raw.append(rp.get("policy"))
    if name == "PutResourcePolicy":                       # Secrets Manager / CloudWatch Logs / others
        raw += [rp.get("resourcePolicy"), rp.get("policyDocument"), rp.get("policy")]
    if name in ("SetQueueAttributes", "CreateQueue", "CreateTopic"):
        raw.append(attrs.get("Policy"))
    if name == "SetTopicAttributes" and str(rp.get("attributeName", "")).lower() == "policy":
        raw.append(rp.get("attributeValue"))
    if name in ("SetRepositoryPolicy", "PutRegistryPolicy"):
        raw.append(rp.get("policyText"))
    if name in ("CreateElasticsearchDomain", "UpdateElasticsearchDomainConfig", "CreateDomain", "UpdateDomainConfig"):
        raw.append(rp.get("accessPolicies"))
    if name == "SetVaultAccessPolicy":
        v = rp.get("policy")
        raw.append(v.get("policy") if isinstance(v, dict) else v)
    if name == "PutBucketPolicy":
        raw.append(rp.get("bucketPolicy"))
    for pol in raw:
        for s in _statements(_json(pol)):
            if str(s.get("Effect")).lower() != "allow":
                continue
            acts = [str(a).lower() for a in _list(s.get("Action"))]
            if name == "PutBucketPolicy" and acts and all(a in ("s3:putobject", "s3:getbucketacl") for a in acts):
                continue                       # log delivery into a bucket, not access to it
            for p in _principals({"Statement": [s]}):
                if p == "*" and name != "PutBucketPolicy":          # S3: bucket_public, below
                    f["resource_policy_anyone"] = "true"
                elif p != "*" and own and _account_of(p) and _account_of(p) != own:
                    f["resource_policy_external"] = "true"
    if name.startswith(("AddPermission", "AddLayerVersionPermission")) or name == "PutPermission":
        pr = str(rp.get("principal") or "").strip()
        if pr == "*" and not rp.get("organizationId"):
            f["resource_policy_anyone"] = "true"
        elif pr and _account_of(pr) and own and _account_of(pr) != own:
            f["resource_policy_external"] = "true"

    # -- containers / Kubernetes (values inside lists no Sigma path reaches) -------------
    if name == "RegisterTaskDefinition":
        for c in _list(rp.get("containerDefinitions")):
            if isinstance(c, dict) and str(c.get("privileged")).lower() == "true":
                f["privileged_container"] = "true"
    vpc = rp.get("resourcesVpcConfig") if isinstance(rp.get("resourcesVpcConfig"), dict) else None
    if vpc and str(vpc.get("endpointPublicAccess")).lower() == "true":
        cidrs = [str(c) for c in _list(vpc.get("publicAccessCidrs"))]
        if not cidrs or set(cidrs) & _ANYONE:
            f["k8s_api_public"] = "true"

    # -- logging switched off at the source -------------------------------------------
    if name == "PutEventSelectors":
        sels = [s for s in _list(rp.get("eventSelectors")) if isinstance(s, dict)]
        if any(str(s.get("includeManagementEvents")).lower() == "false" or
               str(s.get("readWriteType", "")).lower() == "readonly" for s in sels):
            f["mgmt_logging_off"] = "true"
        adv = [s for s in _list(rp.get("advancedEventSelectors")) if isinstance(s, dict)]
        if adv and not any(str(fs.get("field")) == "eventCategory" and "Management" in _list(fs.get("equals"))
                           for s in adv for fs in _list(s.get("fieldSelectors")) if isinstance(fs, dict)):
            f["mgmt_logging_off"] = "true"
    logging = rp.get("logging") if isinstance(rp.get("logging"), dict) else {}
    for c in _list(logging.get("clusterLogging")):
        if isinstance(c, dict) and str(c.get("enabled")).lower() == "false":
            f["k8s_logging_off"] = "true"

    # -- data handed to someone else ---------------------------------------------------
    key_ids = [rp.get("x-amz-server-side-encryption-aws-kms-key-id"), rp.get("kmsKeyId")]
    sse = rp.get("ServerSideEncryptionConfiguration") if isinstance(rp.get("ServerSideEncryptionConfiguration"), dict) else {}
    for rule_ in _list(sse.get("Rule")):
        d = rule_.get("ApplyServerSideEncryptionByDefault") if isinstance(rule_, dict) else None
        if isinstance(d, dict):
            key_ids.append(d.get("KMSMasterKeyID"))
    for k in key_ids:
        m = re.match(r"arn:aws[\w-]*:kms:[^:]*:(\d{12}):", str(k or ""))
        if m and own and m.group(1) != own:
            f["kms_foreign_key"] = "true"
    if name in ("CopyDBSnapshot", "CopyDBClusterSnapshot", "CopySnapshot", "CopyImage"):
        src_region = rp.get("sourceRegion") or rp.get("SourceRegion")
        if src_region and rec.get("awsRegion") and str(src_region) != str(rec.get("awsRegion")):
            f["copied_cross_region"] = "true"
    if str(rec.get("eventSource", "")).startswith("ram.") and name in ("CreateResourceShare", "AssociateResourceShare",
                                                                       "UpdateResourceShare"):
        for p in _list(rp.get("principals")):
            if re.fullmatch(r"\d{12}", str(p)) and str(p) != own:
                f["shared_external"] = "true"
        if str(rp.get("allowExternalPrincipals")).lower() == "true":
            f["shared_external"] = "true"
        re_ = rec.get("responseElements") if isinstance(rec.get("responseElements"), dict) else {}
        if any(isinstance(a, dict) and str(a.get("external")).lower() == "true"
               for a in _list(re_.get("resourceShareAssociations"))):
            f["shared_external"] = "true"
    if name == "ModifyDocumentPermission" and str(rp.get("permissionType", "")).lower() == "share":
        for a in _list(rp.get("accountIdsToAdd")):
            if str(a).lower() == "all":
                f["shared_public"] = "true"
            elif str(a) != own:
                f["shared_external"] = "true"

    # -- compute ----------------------------------------------------------------------------
    it = rp.get("instanceType")
    it = it.get("value") if isinstance(it, dict) else it
    if isinstance(it, str) and it:
        f["instance_type"] = it
        if _BIG_INSTANCE.search(it):
            f["large_instance"] = "true"

    # -- whose credentials: a person, or a workload's ---------------------------------------
    issuer = (((ui.get("sessionContext") or {}).get("sessionIssuer") or {}) if isinstance(ui.get("sessionContext"), dict) else {})
    arn_ = str(ui.get("arn") or "")
    ua_ = str(rec.get("userAgent") or "")
    if _INSTANCE_SESSION.search(arn_):
        f["instance_role"] = "true"                 # an EC2 instance's role credentials
    if "exec-env/AWS_Lambda_" in ua_ or str(ui.get("invokedBy") or "") == "lambda.amazonaws.com":
        f["lambda_role"] = "true"
    if "CloudShell" in ua_:
        f["cloudshell"] = "true"

    # -- console or script ---------------------------------------------------------------
    ua = str(rec.get("userAgent") or "")
    if str(rec.get("sessionCredentialFromConsole")).lower() == "true" or "Mozilla/" in ua \
            or ua.startswith(("console.", "signin.", "[S3Console")):
        f["console"] = "true"
    # A PERSON: a user, root, a federated user, or someone signed in through SSO (an assumed
    # role whose issuer is AWSReservedSSO_*) -- the "by a person" rules missed SSO people.
    if str(ui.get("type")) in ("IAMUser", "Root", "FederatedUser") or f.get("console") or \
            str((issuer or {}).get("userName") or "").startswith("AWSReservedSSO_") or \
            ":assumed-role/AWSReservedSSO_" in str(ui.get("arn") or ""):
        if not f.get("instance_role") and not f.get("lambda_role"):
            f["person"] = "true"

    # -- sharing -----------------------------------------------------------------------
    for key in ("launchPermission", "createVolumePermission"):
        perm = rp.get(key)
        add = perm.get("add") if isinstance(perm, dict) else None
        items = add.get("items") if isinstance(add, dict) else add
        for it in _list(items):
            if isinstance(it, dict):
                if str(it.get("group", "")).lower() == "all":
                    f["shared_public"] = "true"
                elif it.get("userId") and str(it["userId"]) != own:
                    f["shared_external"] = "true"
    if name in ("ModifyDBSnapshotAttribute", "ModifyDBClusterSnapshotAttribute") and \
            str(rp.get("attributeName", "")).lower() == "restore":
        for v in _list(rp.get("valuesToAdd")):
            if str(v).lower() == "all":
                f["shared_public"] = "true"
            elif str(v) != own:
                f["shared_external"] = "true"

    # -- S3 ----------------------------------------------------------------------------
    if name in ("PutBucketAcl", "PutObjectAcl"):
        blob = json.dumps(rp).lower()
        if "allusers" in blob or "authenticatedusers" in blob or '"public-read' in blob:
            f["bucket_public"] = "true"
    if name == "PutBucketPolicy":
        pol = _json(rp.get("bucketPolicy")) or (rp.get("bucketPolicy") if isinstance(rp.get("bucketPolicy"), dict) else None)
        for s in _statements(pol):
            p = s.get("Principal")
            if str(s.get("Effect")).lower() == "allow" and not s.get("Condition") and \
                    (p == "*" or (isinstance(p, dict) and "*" in _list(p.get("AWS")))):
                f["bucket_public"] = "true"
    if name in ("DeleteBucketPublicAccessBlock", "DeletePublicAccessBlock"):
        f["bucket_public"] = "true"
    if name in ("PutBucketPublicAccessBlock", "PutPublicAccessBlock"):
        cfg = rp.get("PublicAccessBlockConfiguration") or rp.get("publicAccessBlock") or {}
        if isinstance(cfg, dict) and any(str(v).lower() == "false" for k, v in cfg.items() if k != "xmlns"):
            f["bucket_public"] = "true"
    if name == "PutBucketLifecycle" or name == "PutBucketLifecycleConfiguration":
        lc = rp.get("LifecycleConfiguration") if isinstance(rp.get("LifecycleConfiguration"), dict) else {}
        for r in _list(lc.get("Rule")):
            if isinstance(r, dict) and str(r.get("Status", "Enabled")).lower() == "enabled":
                exp = r.get("Expiration") if isinstance(r.get("Expiration"), dict) else {}
                d = _int(exp.get("Days"))
                if d is not None and d <= 7:
                    f["short_expiry"] = "true"
    if name in ("CopyObject",) and str(rp.get("x-amz-server-side-encryption", "")).lower() == "aws:kms":
        src = str(rp.get("x-amz-copy-source") or "")
        if rp.get("bucketName") and src.lstrip("/").startswith(f"{rp['bucketName']}/"):
            f["reencrypt_in_place"] = "true"

    # -- who / how -------------------------------------------------------------------------
    target = rp.get("userName")
    actor = ui.get("userName") or ""
    if isinstance(target, str) and target and str(ui.get("type")) in ("IAMUser", "AssumedRole", "Root", "FederatedUser") \
            and target.lower() != str(actor).lower():
        f["acts_on_other_user"] = "true"
    if str(rec.get("errorCode") or "").lower() in _DENIED or "not authorized" in str(rec.get("errorMessage") or "").lower():
        f["denied"] = "true"
    m = TOOLS.search(str(rec.get("userAgent") or ""))
    if m:
        f["tool"] = m.group(1).lower()
