---
name: intact-azure-cloud-investigation
description: Atomic DFIR guidance for Azure / Microsoft Entra ID cloud-identity
  investigations. Covers app-credential abuse, OAuth consent attacks, sign-in
  forensics, persistence patterns, conditional-access analysis, and federation-
  trust forensics. Distinguishes time-anchored audit events from current-state
  configuration snapshots so the LLM does not confabulate event times for
  state observations.
domain: cybersecurity
subdomain: cloud-incident-response
tags:
- azure
- entra-id
- aad
- oauth
- service-principal
- conditional-access
- federation
- cloud-ir
- identity-forensics
- token-replay
mitre_attack:
- T1078.004    # Valid Accounts: Cloud Accounts
- T1098.001    # Account Manipulation: Additional Cloud Credentials
- T1098.003    # Account Manipulation: Additional Cloud Roles
- T1098.005    # Account Manipulation: Device Registration
- T1136.003    # Create Account: Cloud Account
- T1528        # Steal Application Access Token
- T1556.006    # Modify Authentication Process: Multi-Factor Authentication
- T1606.002    # Forge Web Credentials: SAML Tokens
- T1110.003    # Brute Force: Password Spraying
version: '1.0'
author: intact
license: Apache-2.0
---

# Azure / Microsoft Entra ID DFIR Investigation

This skill guides triage of Azure cloud-identity events and configuration
snapshots collected by the Intact Azure pipeline. It is **the** atomic skill
for any artifact whose source is `Azure.*`, `SIGMA.Azure_*`, `SIGMA.Sign-ins*`,
`UAL.*`, or `INV.*` (CA policies, federation).

## Data shapes the analyzer will see

The Intact Azure pipeline collects from two layers:

| Source | API / tool | What it carries |
|---|---|---|
| `Azure.SignIn` | Microsoft Graph `auditLogs/signIns` | Interactive + non-interactive sign-ins; user, app, IP, device-compliance, MFA-satisfied, conditional-access status, risk-level (P1+) |
| `Azure.Audit` | Microsoft Graph `auditLogs/directoryAudits` | Identity admin events: `Add application`, `Update application – Certificates and secrets management`, `Add service principal`, `Add owner to ...`, role assignments, MFA method changes |
| `Azure.UnifiedAudit` | DFIR-O365RC via Purview Audit Log Query API | Office 365 + Entra in one stream; `Operation` + `Workload` fields; same events as `Azure.Audit` for AAD record types (8/9/15) plus Exchange/SharePoint/Teams |
| `Azure.CAPolicy` | Microsoft Graph `policies/conditionalAccessPolicies` | **State snapshot** of every CA policy — current `state`, `conditions`, `grantControls`, `lastModifiedDateTime`. Not events. |
| `Azure.Federation` | Microsoft Graph `domains/{id}/federationConfiguration` | **State snapshot** of federation trusts. Not events. |

Pre-detected finding buckets you may receive:

- `SIGMA.<rule_title>`: Sigma rule fired on collected records. Single-event matches.
- `UAL.persistence` / `UAL.lateral_movement` / `UAL.credential_access` / `UAL.authentication`: pre-tagged UAL events grouped by category (the operator's own scoring layer).
- `INV.ca_policies` / `INV.federation`: state-snapshot findings — current configuration the operator's wired to flag (e.g. MFA-disabled CA policy).

## Critical discipline: state vs. event

State-snapshot artifacts (`INV.ca_policies`, `INV.federation`, anything with
`_state_snapshot=True`) describe **current configuration**, not things that
happened during the timeline. They have a `lastModifiedDateTime` (when the
config last changed) and a finding time (when the scan observed them) — these
are not the same. **Never** narrate state observations as if they were
attacker actions during the scan window. A disabled MFA policy with a
`lastModifiedDateTime` 3 months ago is not "disabled by the attacker today";
it's a pre-existing weakness that the attacker may have exploited.

Time-anchored events (signins, audits, UAL events) DO have real timestamps;
narrate them in time order. Use the event timestamps to anchor the chain.

## High-signal app-credential / persistence patterns

The most consequential cloud-IR finding category. Look for these audit event
sequences from the same `initiatedBy.user.userPrincipalName` within minutes:

1. **`Add application`** → **`Add service principal`** for the same `appId`
   → **`Add password to application`** → **service-principal sign-in** to
   that `appId` with the new credential's `keyId`.
   Pattern: attacker-controlled OAuth app planted for long-lived access.

2. **`Update application – Certificates and secrets management`** on a
   *legitimate, high-trust* app the user already owns → service-principal
   sign-in to that app from a `keyId` not previously seen.
   Pattern: SolarWinds / Midnight Blizzard backdoor. The attacker piggybacks
   on a trusted SP rather than registering a new one. **Higher fidelity
   than #1** because the app already has its grants.

3. **`Add owner to application`** / **`Add owner to service principal`**
   adding a low-privilege user to an existing app's owners.
   Pattern: persistence via app-ownership rather than direct cred injection.

4. **`Consent to application`** for an app the user did not create, with
   `Mail.ReadWrite` / `Files.Read.All` / `User.ReadWrite.All` scopes.
   Pattern: OAuth consent phishing.

5. **`Add app role assignment to service principal`** granting a service
   principal a tenant-wide application permission.
   Pattern: privilege escalation via SP role assignment (often paired with
   #1 or #2).

When two or more of these fire from the same actor in a tight window, the
chain is the finding — call it out as a chain in the prose, not as
disconnected single events.

## Sign-in forensics

`Azure.SignIn` records carry these forensic fields:

- `userPrincipalName`, `userId` — actor
- `appDisplayName`, `appId`, `clientAppUsed` — what the user authenticated to
- `ipAddress`, `location.{countryOrRegion,city}` — origin
- `deviceDetail.{deviceId,isCompliant,operatingSystem,browser,trustType}` — device
- `conditionalAccessStatus` — `success` / `failure` / `notApplied`
- `status.{errorCode,failureReason,additionalDetails}` — pass/fail
- `authenticationDetails[]` — MFA factor used
- `riskLevelDuringSignIn` / `riskLevelAggregated` (P2 only) — Identity Protection's verdict

Common pivots:
- Same `userId` from a new `ipAddress` outside the user's normal subnet/country
- Same `userId` from multiple geographies in <1h (impossible-travel)
- `conditionalAccessStatus: notApplied` for a user that policies *should* cover (MFA bypass via missing condition)
- `deviceDetail.isCompliant: false` despite a CA policy requiring compliance (= policy gap or attacker on non-managed device)
- `clientAppUsed: "Other clients; Other"` or legacy auth protocols (often token replay or legacy auth bypass)

## Conditional access analysis

Each `Azure.CAPolicy` record has:
- `state`: `enabled` / `disabled` / `enabledForReportingButNotEnforced`
- `conditions.users`: who the policy targets (or excludes)
- `conditions.applications`: which apps the policy guards
- `grantControls`: what's required to pass (mfa, compliantDevice, blocked)
- `lastModifiedDateTime`: when config last changed

Findings worth surfacing:
- A policy named "MFA for all users" in `disabled` state
- A policy with empty `grantControls.builtInControls` (it allows anything)
- An `enabled` policy excluding a privileged user (admin exclusion = bypass)
- Recently-modified policies whose `lastModifiedDateTime` falls within the scan window — *this* is when state changes count as events; if the change is in the timeline, narrate it; if it isn't, narrate it as state.

## Federation trust forensics

`Azure.Federation` snapshots show federated domain trust — the keys other
identity providers can use to assert tokens for your tenant. Findings:
- A federated domain whose `signingCertificate` was rotated within the scan
  window (Solorigate-style domain-takeover for SAML token forgery)
- A `nextSigningCertificate` set without a corresponding rotation event in
  `directoryAudits` (preparation for future forge)

## False positives to suppress

Do not surface as findings:

- Vendor SaaS platform sign-ins (Microsoft Teams, Office 365 Exchange Online,
  Microsoft Graph, Microsoft Azure CLI, Azure Portal, Microsoft Office Web,
  Outlook, OneDrive). Their `appId`s are well-known Microsoft first-party.
- Service-principal sign-ins by Microsoft-owned tenant-wide service apps
  (Microsoft Graph itself, Identity Platform tooling, Defender ingestion)
- Internal `DESKTOP-*` / `LAPTOP-*` Windows hostnames, `AzureAD\*`,
  `NT AUTHORITY\*` — never IOCs
- "User Authenticated to App" events for a user genuinely opening Microsoft
  apps in their normal session
- CA policy `notApplied` results for sign-ins where the policy's conditions
  legitimately don't apply (e.g. policy targets only admins, user isn't one)

## Valid IOCs from Azure data

Things an analyst would actually pivot on or block:

- Specific **App IDs** of decoy / suspicious applications: `c48cb4d1-...`
- Specific **Service Principal IDs**: `76510525-...`
- Specific **OAuth credential `keyId`s** that shouldn't exist on a known-good app
- **External IPs** from sign-in records — only when not on a known corporate range and the activity around them is suspicious
- **User UPNs** for confirmed-compromised accounts (with severity high enough to act on)
- **Operation names** for tenant-wide hunting queries: `Update application – Certificates and secrets management`

Always tag IOCs with type, value, and one-line evidence pointer ("seen in event id X at timestamp Y").

## What good Azure-IR prose looks like

- Time-ordered narrative anchored on real timestamps
- Names actors by UPN, targets by app displayName + appId
- Calls out chains explicitly: "X at T+0, then Y at T+30s, then Z at T+2m, all by same actor and IP"
- Distinguishes FACT (observable in the records) from INFERENCE (your interpretation)
- For state findings: "The CA policy is currently disabled; last modified 3 months ago" — not "policy was disabled today"
- For chained app-credential events: "this matches the SolarWinds / Midnight Blizzard TTP of planting credentials on a legitimate trusted application" — only if the chain actually fits
- One Calibration Check at the end: what would invalidate this narrative
