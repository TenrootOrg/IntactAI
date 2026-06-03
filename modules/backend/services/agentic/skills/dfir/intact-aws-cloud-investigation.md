---
name: intact-aws-cloud-investigation
description: Atomic DFIR guidance for AWS-account investigations. Covers CloudTrail
  event semantics, IAM principal shapes (user / role / federated), GuardDuty
  finding-type taxonomy, AssumeRole chain reading, state-vs-event discipline
  (Prowler / AccessAnalyzer findings are current state, not time-bound events),
  and the AWS-relevant subset of the MITRE ATT&CK Cloud Matrix.
domain: cybersecurity
subdomain: cloud-incident-response
tags:
- aws
- cloudtrail
- iam
- guardduty
- access-analyzer
- prowler
- assumerole
- saml
- federation
- cloud-ir
- identity-forensics
mitre_attack:
- T1078.004    # Valid Accounts: Cloud Accounts
- T1098        # Account Manipulation
- T1098.001    # Additional Cloud Credentials (CreateAccessKey for-another-user)
- T1098.003    # Additional Cloud Roles (AttachUserPolicy AdministratorAccess)
- T1136.003    # Create Account: Cloud Account (CreateUser)
- T1199        # Trusted Relationship (cross-account / federated abuse)
- T1530        # Data from Cloud Storage Object (public-bucket exfil)
- T1562.008    # Impair Defenses: Disable Cloud Logs (StopLogging / DeleteTrail)
- T1580        # Cloud Infrastructure Discovery
- T1496        # Resource Hijacking (crypto-mining EC2)
- T1110        # Brute Force (failed console logins)
---

# AWS account investigation — atomic DFIR guide

Use this guide whenever the LLM is reasoning about AWS-native artefacts
collected by Intact: CloudTrail events, GuardDuty findings, AccessAnalyzer
findings, Prowler posture results. The goal is to keep the analysis grounded
in AWS primitives (principals, roles, regions, event names) and to call out
the state-vs-event boundary so the model does not confabulate event timestamps
for what are actually current-state observations.

## Data shapes in this pipeline

The collector returns records grouped by **`EventSource`** (the SIGMA-prefix
field):

| EventSource             | Shape it carries                                                      |
|-------------------------|-----------------------------------------------------------------------|
| `AWS.CloudTrail`        | Per-API-call audit events: `eventName`, `eventSource`, `userIdentity`, `sourceIPAddress`, `requestParameters`, `responseElements`, `eventTime`. **These are time-anchored.** |
| `AWS.GuardDuty`         | Detection findings: `Type` (taxonomy), `Severity` (0-10), `Service.Action.*` (what was observed), `Resource.*` (what was targeted), `CreatedAt` / `UpdatedAt`. Time-anchored. |
| `AWS.AccessAnalyzer`    | Resource-policy findings: `resource`, `resourceType`, `principal`, `action`, `isPublic`, `status`. **Current state** — `analyzedAt` is when AA last looked, NOT when the resource went public. |
| `AWS.Prowler`           | Posture check results: `check_id`, `check_title`, `severity`, `status_code` (`PASS` / `FAIL`), `resource_arn`. **Current state** — represents "this is true right now". Do not narrate it as an event. |

## CloudTrail event semantics — the must-know subset

CloudTrail records are not all the same shape. Look at `eventSource` first to
decide what the event represents:

| `eventSource`             | What it tells you                                                       |
|---------------------------|-------------------------------------------------------------------------|
| `signin.amazonaws.com`    | Console login attempt. `eventName: ConsoleLogin`, `responseElements.ConsoleLogin: Success|Failure`, `additionalEventData.MFAUsed: YES|NO`. |
| `iam.amazonaws.com`       | IAM mutations. High-signal `eventName` values: `CreateAccessKey`, `AttachUserPolicy`, `PutUserPolicy`, `AttachRolePolicy`, `CreateUser`, `CreateLoginProfile`, `UpdateLoginProfile`, `CreateSAMLProvider`, `DeleteSAMLProvider`. |
| `sts.amazonaws.com`       | Role assumption. `eventName: AssumeRole | AssumeRoleWithSAML | AssumeRoleWithWebIdentity`. `responseElements.assumedRoleUser.arn` tells you who they became. Chain matters. |
| `cloudtrail.amazonaws.com`| Trail mutations. `StopLogging`, `DeleteTrail`, `UpdateTrail` (especially `is-multi-region-trail: false`). **Defense evasion.** |
| `s3.amazonaws.com`        | S3 control-plane events: `PutBucketPolicy` (look for `Principal: *`), `PutBucketAcl`, `DeleteBucketPolicy`, `PutBucketPublicAccessBlock`. Data-plane (`GetObject`, `PutObject`) appears only if the trail is configured for S3 data events. |
| `ec2.amazonaws.com`       | `RunInstances` (watch instance-type for crypto-mining shapes like `p3.*xlarge` or `g5.*xlarge` off-hours), `CreateImage`, `ModifyImageAttribute` (sharing AMIs publicly). |
| `kms.amazonaws.com`       | `ScheduleKeyDeletion`, `PutKeyPolicy` (widening grants), `Decrypt` from unusual principals. |

`userIdentity.type` distinguishes the actor: `Root`, `IAMUser`,
`AssumedRole` (look at `userIdentity.sessionContext.sessionIssuer.arn` for the
role that was assumed), `FederatedUser`, `SAMLUser`, `WebIdentityUser`.

## IAM principal patterns to recognise

- **CreateAccessKey for-another-user** — `userIdentity.arn` doesn't equal
  `responseElements.accessKey.userName`. Classic backdoor-key pattern
  (Pacu's `iam__backdoor_users_keys` module). HIGH-confidence flag.
- **AttachUserPolicy of `AdministratorAccess` / `IAMFullAccess`** — direct
  privilege escalation, especially when the target user was created in
  the same window.
- **iam:PassRole + ec2:RunInstances / lambda:CreateFunction** — passing a
  high-privilege role to a compute resource to inherit its permissions.
- **Role-trust modification** — `UpdateAssumeRolePolicy` widening a role's
  trust policy to allow an external account. Look at `requestParameters.policyDocument`.

## AssumeRole chain reading

When you see an `AssumeRole` event, the actor *becomes* the role for the
duration of that session. Subsequent events from that session carry
`userIdentity.type: AssumedRole` with `sessionContext.sessionIssuer.arn`
pointing back at the role.

To trace a chain:

1. Start at the most-privileged action (e.g. `AttachUserPolicy`).
2. If `userIdentity.type == AssumedRole`, follow `sessionContext.sessionIssuer.arn`
   back to the role.
3. Find the `AssumeRole` event whose `responseElements.assumedRoleUser.arn`
   matches that. Its `userIdentity` is who started the chain.
4. Repeat until you hit `IAMUser` or `Root`. That's the originating identity.

## GuardDuty finding-type taxonomy

`Type` is a dotted hierarchy: `<ThreatPurpose>:<ResourceTypeAffected>/<ThreatFamilyName>.<DetectionMechanism>!<Artifact>`.

The first segment is the most useful for triage:

| ThreatPurpose                    | Severity (typical) | Meaning                                        |
|----------------------------------|--------------------|------------------------------------------------|
| `UnauthorizedAccess`             | HIGH–CRITICAL      | Confirmed unauthorized API call / login        |
| `CryptoCurrency`                 | HIGH               | EC2 / EKS contacting a mining pool             |
| `Backdoor`                       | HIGH               | C2-shape DNS or network traffic                |
| `Trojan`                         | HIGH               | Malware-shape traffic                          |
| `Recon`                          | LOW–MEDIUM         | Port-scan, enumeration                         |
| `Discovery`                      | MEDIUM             | API enumeration (e.g. `ListBuckets` spike)     |
| `Persistence`                    | HIGH               | New IAM user / access key creation             |
| `Stealth`                        | HIGH               | Disabling logging / GuardDuty itself           |
| `PenTest:IAMUser`                | LOW (informational)| Pacu / ScoutSuite signature — often a fp on a test account, often very real on a prod account |
| `Policy`                         | LOW–MEDIUM         | Compliance check (root account used, etc.)    |
| `Impact`                         | CRITICAL           | Data destruction / ransom-style activity       |

## State vs event — discipline

When the data is a state snapshot (Prowler `status_code: FAIL`, AccessAnalyzer
`status: ACTIVE`), **do not** say "X happened at time Y". Say "as of the scan,
X is in state Y". The `analyzedAt` field is when the analyzer last looked,
not when the resource became non-compliant.

This is especially important for AccessAnalyzer findings: `isPublic: true`
means the resource is publicly accessible right now — not that it was made
public at the timestamp on the finding.

## False-positive patterns to call out

- Vendor service-linked roles often touch lots of resources benignly.
  `userIdentity.type: AWSService` is automated — look at `invokedBy`.
- AWS-managed automation (Config, GuardDuty itself, Trusted Advisor) makes
  high-volume read calls. Filter to mutating events when triaging.
- `errorCode: AccessDenied` on a single principal across many actions is
  more interesting than the same principal making many successful calls —
  the failures often reveal what they were trying to do.

## What to recommend after a finding

Concrete IR moves the LLM should suggest in its analysis (when applicable):

1. **Rotate / disable** suspect access keys: `aws iam update-access-key --status Inactive --access-key-id <id>`
2. **Detach** unauthorised policies: `aws iam detach-user-policy …`
3. **Revoke** active sessions for an IAM user: `aws iam delete-login-profile` + key rotation
4. **Quarantine** an instance: stop the instance, snapshot the EBS, isolate via SG
5. **Re-enable** trail and GuardDuty in all regions
6. **Check for SCP guardrails** that would have prevented the action and recommend adding them
7. **Pivot to other accounts** via Organizations if cross-account abuse is in scope
