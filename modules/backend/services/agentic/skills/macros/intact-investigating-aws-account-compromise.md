---
name: intact-investigating-aws-account-compromise
description: Macro playbook for investigating a suspected AWS-account compromise.
  Walks the five-stage attack arc (initial access → privilege escalation →
  persistence → defense evasion → blast radius), correlates CloudTrail events
  with GuardDuty findings and Prowler posture, and produces a chronological
  narrative with concrete containment actions per stage.
domain: cybersecurity
subdomain: incident-response
tags:
- aws
- account-compromise
- cloudtrail
- iam
- guardduty
- incident-response
- mitre-attack-cloud
- macro
- synthesis
mitre_attack:
- T1078.004    # Valid Accounts: Cloud Accounts
- T1098.001    # Account Manipulation: Additional Cloud Credentials
- T1098.003    # Account Manipulation: Additional Cloud Roles
- T1562.008    # Impair Defenses: Disable Cloud Logs
- T1530        # Data from Cloud Storage Object
- T1496        # Resource Hijacking
---

# Investigating an AWS account compromise

Macro playbook. Use this when the Intact pipeline has surfaced AWS findings
that suggest a real compromise (UnauthorizedAccess GuardDuty findings, multiple
SIGMA hits, or the operator-supplied scope says "treat this as IR"). The job
of this skill is to *narrate the chain*, not to repeat per-rule details — those
already live in the per-artifact analysis blocks.

Read the per-rule analyses first, then write the synthesis along the five
stages below. Every claim should be backed by a specific event reference
(rule name, eventName, principal ARN, timestamp).

## Stage 1 — Initial access

Which credential or session got the attacker in?

Look for:
- **`ConsoleLogin` success without MFA** (`additionalEventData.MFAUsed: NO`),
  especially from an unusual source IP / country.
- **Sudden activity from a long-dormant access key.** Compare `eventTime` to
  the key's `CreateDate`. Keys idle for months that suddenly burst into
  activity are the canonical IR red flag.
- **`AssumeRoleWithSAML` / `AssumeRoleWithWebIdentity` from an unusual
  source IP** — federated-identity abuse, often via a stolen IdP cookie.
- **GuardDuty `UnauthorizedAccess:IAMUser/*` findings** — these are
  Amazon's own confirmation that the call was abnormal.

Containment for this stage:
- Disable the access key (`update-access-key --status Inactive`).
- Force password reset + invalidate sessions on the IAM user.
- Block the source IP at SCP / WAF level if it's a single hostile IP.
- For federation: revoke the IdP session and rotate the IdP signing key.

## Stage 2 — Privilege escalation

How did they go from initial access → admin?

Look for:
- **`AttachUserPolicy` of `AdministratorAccess` / `IAMFullAccess`** to a
  user that didn't have it before. Most-direct-possible escalation.
- **`CreateAccessKey` for-another-user** (caller ARN ≠ target user). The
  classic "Pacu backdoor" move — keeps access even if the original
  credential is rotated.
- **`PutUserPolicy` / `PutRolePolicy` with `Effect: Allow`, `Action: "*"`,
  `Resource: "*"`** — the unconditional power move.
- **`UpdateAssumeRolePolicy` widening trust to an external account or `*`**.
- **`iam:PassRole` + a compute call** (`RunInstances`, `CreateFunction`) to
  inherit the role's privileges via the compute resource.

Containment for this stage:
- Detach the offending policy / delete the inline policy.
- Delete any keys created for other users during the incident window.
- Revert any role-trust modifications.
- Audit `iam:PassRole` on the suspect principal.

## Stage 3 — Persistence

What did they leave behind to come back later?

Look for:
- **`CreateUser`** (new IAM user that doesn't match your naming convention).
- **Additional `CreateAccessKey`** on existing privileged users.
- **`CreateLoginProfile`** on a previously console-less user.
- **`CreateSAMLProvider` / `UpdateSAMLProvider`** — federated-identity backdoor.
- **`CreateOpenIDConnectProvider`** — same idea, for OIDC.
- **`CreateRole` with a permissive trust policy** that the attacker can
  assume from outside.
- **EC2 user-data scripts or SSM associations** that re-establish access
  on boot.
- **`CreateAccountAlias` / `UpdateAccountPasswordPolicy`** weakening the
  account so future compromises stick.

Containment for this stage:
- Delete unauthorised users / roles / providers / login profiles.
- Audit ALL keys created during the incident window — even ones that look
  routine. Treat anything created in the window as suspect.
- Reset the account password policy back to your baseline.

## Stage 4 — Defense evasion

What did they do to cover their tracks or weaken detection?

Look for:
- **`StopLogging`** on the primary trail.
- **`DeleteTrail`** outright.
- **`UpdateTrail` with `IsMultiRegionTrail: false`** — they're still logging,
  just not in regions where they're working.
- **`PutEventSelectors` removing high-value event types**.
- **`DeleteSAMLProvider`** of a corporate IdP (breaks IR responder login).
- **`DeleteFlowLogs`** on VPCs.
- **GuardDuty `DisableOrganizationAdminAccount` / detector `Disable`**.
- **CloudWatch Alarms / Config Rules deleted**.

Containment for this stage:
- Re-enable trail logging, set `is-multi-region-trail` back to true.
- Re-create deleted CloudTrail / GuardDuty configurations from your IaC baseline.
- Audit ALL StopLogging / DeleteTrail / DisableSecurityHub events in the
  window across every region.

## Stage 5 — Blast radius

What can the compromised principal touch, and what did they actually touch?

Map the principal to its effective permissions (Prowler's IAM checks +
AccessAnalyzer's findings make this concrete), then look at what the
window's events actually exercised:

- **Data exfiltration**: `s3:GetObject` from new IPs, especially after
  `PutBucketPolicy` widened access. `DescribeDBSnapshots` / `CopyDBSnapshot`
  for RDS. `ExportSnapshot` to a cross-account destination.
- **Compute hijacking**: `RunInstances` with abnormally large instance
  types (`p3.*xlarge`, `g5.*xlarge`) off-hours = likely crypto-mining.
- **Cross-account pivot**: `AssumeRole` with `responseElements.assumedRoleUser`
  in another account — pivot vector.
- **KMS abuse**: `Decrypt` from unusual principals, `ScheduleKeyDeletion`
  to deny data.
- **Resource sharing**: `ModifyImageAttribute --launch-permission`,
  `PutBucketPolicy Principal: *`, `ModifySnapshotAttribute`.

Containment for this stage:
- Quarantine compromised resources (stop EC2, snapshot EBS, isolate via SG).
- Revoke any shared snapshots / images / buckets.
- Rotate KMS key grants.
- Notify downstream account owners if cross-account pivot was used.

## Output shape

When writing the synthesis, structure it as:

1. **Top-line attribution** — one sentence: which principal(s) were
   compromised, what initial-access vector, what time window.
2. **Stage-by-stage timeline** — for each of the five stages, the specific
   events with timestamps and the principal-of-record. Skip stages that
   show no evidence; do not invent them.
3. **MITRE ATT&CK Cloud mapping** — small table of the techniques each
   stage represents, with evidence references back to the per-rule blocks.
4. **Containment checklist** — concrete commands the IR analyst can run
   right now, grouped by urgency (immediate / within-24h / within-week).
5. **Forensic preservation** — what to snapshot / export before further
   remediation (CloudTrail Lake query, EBS snapshot, mailbox dump for
   anything that touched SES, etc.).
6. **Confidence + caveats** — what data is missing that would change the
   picture (VPC flow logs not collected, S3 data events disabled, etc.).
