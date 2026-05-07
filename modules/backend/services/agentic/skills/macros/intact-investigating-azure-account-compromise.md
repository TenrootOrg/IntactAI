---
name: intact-investigating-azure-account-compromise
description: Macro DFIR playbook for cross-artifact Azure / Entra ID
  account-compromise investigations. Used by the synthesis pass and the
  single-pass timeline mode when the merged artifact set is Azure-shaped.
  Anchors the narrative on identity events (sign-ins, audits, UAL) plus
  current-state observations (CA policies, federation), and produces a
  prioritised action list that distinguishes immediate containment from
  longer-term hardening.
domain: cybersecurity
subdomain: cloud-incident-response
tags:
- azure
- entra-id
- aad
- account-compromise
- cloud-ir
- macro
mitre_attack:
- T1078.004
- T1098.001
- T1528
- T1556.006
version: '1.0'
author: intact
license: Apache-2.0
---

# Investigating Azure / Entra ID Account Compromise — Macro Playbook

This macro is the cross-artifact playbook for Intact's Azure pipeline. The
synthesis pass (and the small-run timeline pass) uses it to narrate a chain
across multiple finding buckets — sign-ins + audits + UAL + state.

## Investigation arc

A typical Azure account-compromise investigation walks five steps. Use them
to structure the executive narrative:

1. **Initial-access vector identification.** What sign-in event(s) place the
   actor in the tenant? Look for: new IP / country / device, MFA bypass
   patterns (notApplied / satisfied-without-prompt / legacy-auth), risky-IP
   hits (P2 only), tokens reused with stale `keyId`. Anchor on
   `Azure.SignIn` records.

2. **Lateral motion within identity.** Did the actor escalate or pivot? Look
   for: role-assignment events, group-membership changes, app-ownership
   additions, app-role-assignment grants. Anchor on `Azure.Audit` events
   from the same `initiatedBy.user`.

3. **Persistence-mechanism establishment.** Did the actor plant something
   long-lived? Look for the high-signal sequences:
   - new app + new SP + new credential (decoy backdoor)
   - new credential added to *existing* trusted app (SolarWinds pattern)
   - federated domain certificate rotation (SAML token forgery prep)
   - user authentication-method modification (MFA persistence)
   Anchor on `UAL.persistence`, `SIGMA.Application_*`, `SIGMA.Service_Principal_*`.

4. **Defense-control state.** What configuration weakness made the chain
   possible? CA policies (MFA enforcement, compliant-device requirement),
   federation trust posture, app-creation tenant policy. Anchor on
   `INV.ca_policies`, `INV.federation`. **State observations only — do not
   narrate them as events that happened during the timeline.**

5. **Blast-radius assessment.** What does the compromised account or app
   reach? App-permission scope (Mail.ReadWrite tenant-wide vs delegated
   self-only is a 100x difference), role memberships (Global Admin vs
   end-user), other apps owned by the same user. (The Intact pipeline does
   not currently enrich with attack-graph data; reason from the audit-log
   evidence alone.)

## Confidence calibration

Tag confidence honestly:

- **HIGH**: 3+ chain steps observed (initial access + persistence + state
  weakness, all from the same actor) within a coherent time window.
- **MEDIUM**: 2 steps observed, plausible chain, but a benign explanation
  exists (legitimate admin work, planned change).
- **LOW**: a single suspicious event or only state observations; the
  scenario is suggestive but not corroborated.

Do not auto-escalate confidence based on severity-tag count. Three "high"
signals from the same SIGMA rule firing on different rows of the same event
(common with `Sign-ins from Non-Compliant Devices`) is *one* finding, not
three.

## Action ranking

When listing recommended actions, put them in this order:

1. **Immediate containment** (minutes): revoke active sessions for compromised
   accounts; revoke planted credentials; disable suspicious apps.
2. **Investigation expansion** (hours): cross-reference IPs against other
   tenant users; pull mailbox / file activity for the affected accounts;
   check Defender for Endpoint for related host-side activity.
3. **Persistence cleanup** (hours): inventory all apps owned by the affected
   user; review their permissions; remove ones not business-justified.
4. **Hardening** (days): re-enable / tighten CA policies that were absent
   or misconfigured; enforce phish-resistant MFA; audit federation trust.

## Common false-positive shapes to demote

- "Lots of sign-ins from one IP" alone — without further context (new device,
  MFA bypass, post-auth admin actions), high IP volume is just normal user
  activity.
- "User updated their auth methods" — could be self-service password reset
  or MFA registration during onboarding.
- "App registered with no permissions" — developer testing, not an attack.
- "CA policy in `enabledForReportingButNotEnforced`" — the policy is in
  audit mode, not disabled. This is a deliberate state for measuring impact
  before enforcement.

The macro's job is to keep the story focused on the events whose joint
occurrence was the actual signal.
