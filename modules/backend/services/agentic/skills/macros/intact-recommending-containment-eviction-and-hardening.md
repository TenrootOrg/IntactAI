---
name: intact-recommending-containment-eviction-and-hardening
description: Turning the case evidence into containment, eviction, recovery and hardening recommendations, scoped by what each piece of evidence exposes, with the actions that do not revoke what people think they do.
families: [any]
report_only: true
---

# Recommendations: containment, eviction, recovery, hardening

Use this card when writing the Recommendations section. Every recommendation must trace to a finding in this case; do not add generic advice the evidence does not call for. Never write commands or vendor product steps, and never invent hosts, accounts or IOCs: use the identifiers exactly as the case shows them.

## Pick the stage from the evidence
- Scope still growing (new hosts or accounts keep appearing): contain quietly, preserve evidence, expand the investigation. Acting early warns the attacker, who then switches to persistence nobody has found yet.
- Scope known: one coordinated eviction, removing every persistence item and rotating every exposed credential in the same window.
- Active encryption, destruction or exfiltration: contain immediately even if it warns the attacker, and say in the report that this trade-off was made.
- Preserve evidence before remediating (memory and volatile data before a reboot, logs before they roll over). Disable accounts rather than delete them, so the audit trail stays.
- Act from admin workstations and communication channels the attacker has not touched.

## What the evidence exposes, and what it requires
- LSASS access or dump on a host: every account that logged on to that host since its last boot is exposed (interactive, RDP, service, batch), plus the service accounts stored in its LSA secrets. Reset those accounts, not all users.
- DCSync, NTDS.dit or SYSTEM hive theft from a DC: every domain secret is exposed. Reset krbtgt twice, waiting at least the maximum ticket lifetime plus replication time between the resets (also the RODC krbtgt accounts), then all privileged, service and Tier 0 computer accounts and trust keys.
- A domain admin used interactively on a compromised host: assume DCSync was possible even without 4662 events, because directory-service auditing is usually off.
- AD CS abuse: issued certificates keep working after password resets. Revoke them; if the CA key may be exposed, the CA has to be rebuilt.
- ADFS or Entra Connect host compromise: rotate the token-signing certificate and the sync account.
- Entra session or token theft (AiTM, token replay): a password reset alone is not eviction. Revoke sessions and refresh tokens, remove MFA methods and devices the attacker registered, remove their consents, inbox and forwarding rules. Access tokens already issued can stay valid until they expire.
- Service principal or app compromise: disable it, rotate its credentials, review what it did over the previous weeks, tell the owners of the data it could reach, then restore it with fewer permissions or retire it.
- AWS key misuse: deactivating the key does not end the temporary sessions issued from it. Revoke the active sessions too, then remove the IAM users, keys, login profiles, roles, trust-policy changes and functions the attacker created.
- Linux root: rotate SSH host keys and every authorized_keys entry; do not trust binaries on the host; rebuild if eradication cannot be confirmed.

## What an action does not revoke
Password reset: refresh tokens, primary refresh tokens, app consents, mailbox rules, registered MFA methods. Key deactivation: sessions already issued. One krbtgt reset: tickets forged with the previous key. Account disable: services and scheduled tasks already running as SYSTEM. Deleting an item: the record of what it did.

## Eviction inventory (remove in the same window)
- Windows: services (7045/4697), scheduled tasks (4698), WMI subscriptions, Run keys, startup items, new accounts (4720), privileged group adds (4728/4732/4756), GPO, AdminSDHolder and SIDHistory changes, remote-access tools the attacker installed.
- Linux: cron, systemd units and timers, authorized_keys, ld.so.preload, PAM changes, profile scripts, new UID-0 or sudoers entries.
- Entra / M365: inbox and forwarding rules, mailbox delegation, OAuth consents, service principal credentials, federation and Conditional Access changes.
- AWS: IAM users, keys, roles and trust policies, functions, resources shared to other accounts.
One persistence item found does not mean all were found: check every class above that the evidence can reach.

## Recovery
- Restore in dependency order: identity (DCs, DNS), then certificate services, network, databases, applications, file servers.
- The clean restore point is set by the EARLIEST evidence of compromise, not the detection date. If the earliest evidence sits at the start of log retention, the compromise may be older: rebuild Tier 0 from known-good media and treat backups as suspect.
- Backups are suspect if the backup console was accessed or shadow copies were deleted.
- Re-check persistence before reconnecting; reconnect in phases while watching.

## Checking that containment worked
After the actions, the logs should show: failed logons from disabled accounts (4625, Kerberos 0x12 "revoked"), and repeats point to a leftover service, mapped drive or the attacker, so name the source host; Entra failures 50057 (disabled) or 50133/50173 (session or grant revoked) rather than successes on old sessions; CloudTrail AccessDenied for revoked principals; no new beacons; no privileged ticket requests from unexpected hosts. Recommend a watch period.

## Root cause to hardening (only where the evidence shows the cause)
- RDP exposed or brute-forced: remove internet exposure, MFA on remote access.
- VPN or IdP sign-in without MFA: require MFA; phishing-resistant MFA and compliant-device access against AiTM.
- LSASS theft: Credential Guard, LSA protection, Protected Users, tiered admin accounts.
- Local-admin hash reuse: unique local admin passwords (LAPS), restrict NTLM.
- Kerberoasting: gMSA or long random passwords, AES only.
- Consent phishing: restrict user consent to apps.
- Long-lived AWS keys: roles and SSO, IMDSv2, guardrails that block disabling CloudTrail.
- Visibility gaps hit in THIS case (cleared logs, auditing off, no Sysmon, missing DC logs, retention too short): name each one as a logging recommendation.

## How to write them
Group recommendations as Immediate containment, Coordinated eviction, Recovery, Hardening and Monitoring. Cite the finding behind each one. Label conditional items ("if X is confirmed"). Scope by evidence ("accounts that logged on to HOST since T"), not "all users".
