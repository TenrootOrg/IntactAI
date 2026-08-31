## Executive Summary

**Assessment — HIGH confidence:** A single, coordinated intrusion affected all three covered hosts—DC02, CA01, and DC01—from 2026-08-24T06:17:57Z through 2026-08-29T18:54:40Z. Multiple independent detections show directory reconnaissance, concealed PowerShell execution, persistence, credential access, Kerberos-ticket activity, cross-host credential use, remote access, and security-control suppression.

The activity is attributed operationally to the identity represented by `adatumlab\svc0`, although the identity data is internally incomplete. The cross-host finding proves that this account authenticated or executed on CA01 and DC01 at 2026-08-27T18:01:41Z; the entity data additionally associates it with DC02. The identity record itself lists only DC01, so account ownership and the precise DC02 activity require validation. **Assessment — MODERATE confidence:** `adatumlab\svc0` was compromised and used by the adversary rather than newly created, because its service-account naming and reuse across critical servers are consistent with stolen shared credentials, but creation history and legitimate-use baselines are absent.

**Assessment — MODERATE confidence:** The earliest observed foothold was DC02, where SharpHound/BloodHound collection began at 2026-08-24T06:17:57Z and encoded PowerShell followed at 2026-08-24T07:49:33Z. The evidence begins after execution was already underway, so it does not establish how DC02—or any earlier system outside the dataset—was initially compromised.

The apparent objective was control of Active Directory and its trust infrastructure. DC02 and DC01 are hostname-inferred domain controllers, while CA01 is hostname-inferred to be a certificate authority; their findings support treating all three as high-value infrastructure despite their nominal informational asset severities. Credential extraction on DC02, Kerberos-ticket activity and persistence on DC01, and persistence plus disabled protection and outbound RDP on CA01 gave the adversary multiple potential paths to retain or expand privileged access.

**Assessment — HIGH confidence:** The adversary established persistence on DC01 and CA01 and impaired Defender on both. **Assessment — MODERATE confidence:** Domain-wide compromise is plausible but not proven because the graph contains no evidence of Domain Admin membership changes, directory replication credential theft, forged tickets, certificate issuance, CA private-key access, or successful access to every domain system. Continued access remained possible at the end of the evidence period because DC01’s Defender protection was disabled at 2026-08-29T18:54:40Z and no removal events are provided.

## Critical Findings

**Shared `adatumlab\svc0` credentials linked CA01 and DC01**

Observation: `adatumlab\svc0` authenticated or executed on CA01 and DC01 at exactly 2026-08-27T18:01:41Z. No process, path, or hash is present in the graph for this event. **Assessment — HIGH confidence**, based on a validated cross-host correlation.

**Why it matters:** This is direct evidence that the incident crossed host boundaries using one credential context and reached both a likely domain controller and the likely certificate-authority host. It turns otherwise separate detections into one intrusion story. The evidence does not establish which host was the source, so direction of movement between CA01 and DC01 remains undetermined.

**Evidence:** Summary: “The account `adatumlab\svc0` authenticated/executed on CA01, DC01 at 2026-08-27T18:01:41Z — consistent with lateral movement using shared credentials.” MITRE: `T1021`, `T1078`. Timestamp: `2026-08-27T18:01:41Z`. This corroborates persistence and later activity on both hosts.

**Credential access through LSASS on DC02**

Observation: LSASS memory access was detected on DC02 at 2026-08-25T16:25:52Z. The responsible account, accessing process, path, and hash are not supplied. **Assessment — HIGH confidence** that the access occurred; **MODERATE confidence** that credentials were successfully recovered because no extraction result is recorded.

**Why it matters:** DC02 is likely a domain controller, subject to confirmation. Successful LSASS credential extraction there could expose highly privileged sessions and provide credentials for subsequent movement. Its timing before the cross-host use of `adatumlab\svc0` makes stolen credentials a coherent explanation, but the graph does not prove that this event yielded that account.

**Evidence:** Summary: “SIGMA rule 'LSASS Memory Access' matched on DC02 at 2026-08-25T16:25:52Z.” MITRE: `T1003.001`. Timestamp: `2026-08-25T16:25:52Z`. It follows SharpHound collection and encoded PowerShell on the same host, which independently corroborate hostile discovery and execution.

**Kerberos-ticket activity on DC01**

Observation: a Rubeus Kerberos ticket request was detected on DC01 at 2026-08-26T12:44:45Z. No account, command line, ticket target, process path, or hash is available. **Assessment — HIGH confidence** that Rubeus-associated ticket activity occurred; the effect of the requested ticket is **LOW confidence** because issuance and use are not shown.

**Why it matters:** On a likely domain controller, this could support service-account credential abuse and broader access. It preceded the confirmed use of `adatumlab\svc0` across DC01 and CA01 by roughly one day, providing a plausible—but unproven—credential path.

**Evidence:** Summary: “SIGMA rule 'Rubeus Kerberos Ticket Request' matched on DC01 at 2026-08-26T12:44:45Z.” MITRE: `T1558.003`. Timestamp: `2026-08-26T12:44:45Z`. The later cross-host account finding corroborates subsequent credential-based movement, but does not prove the requested ticket belonged to `svc0`.

**Persistence and weakened protection on CA01**

Observation: a suspicious service installation occurred on CA01 at 2026-08-24T13:45:05Z, followed by Defender real-time protection being disabled at 2026-08-25T00:14:05Z. No service name, binary path, account, process, or hash is supplied. **Assessment — MODERATE confidence**, reflecting both detections’ recorded confidence and the mutually reinforcing sequence.

**Why it matters:** CA01’s name suggests a certificate-authority role, and activity on the host supports treating it as a critical trust-system lead requiring immediate confirmation. Persistent code on a CA could expose certificate services or signing material. The graph does not show certificate enrollment, issuance, template manipulation, private-key access, or certificate theft, so CA key compromise is possible rather than demonstrated.

**Evidence:** Service summary: “SIGMA rule 'Suspicious Service Installation' matched on CA01 at 2026-08-24T13:45:05Z,” MITRE `T1543.003`. Defender summary: “SIGMA rule 'Windows Defender Real-time Protection Disabled' matched on CA01 at 2026-08-25T00:14:05Z,” MITRE `T1562.001`. These corroborate later `svc0` use and outbound RDP on CA01.

**Durable access and defense impairment on DC01**

Observation: DC01 recorded WMI event-consumer persistence at 2026-08-24T16:22:06Z, scheduled-task persistence at 2026-08-27T22:07:23Z and 2026-08-28T01:42:31Z, and Defender real-time protection disabled at 2026-08-29T18:54:40Z. No WMI object names, task names, accounts, executable paths, or hashes are provided. **Assessment — HIGH confidence**, based on several independent persistence and evasion detections.

**Why it matters:** Multiple persistence mechanisms on a likely domain controller mean that changing one account or deleting one task will not reliably remove access. The final recorded event is defense suppression, so the evidence permits continued, less-visible activity after collection ended.

**Evidence:** WMI summary: “SIGMA rule 'WMI Event Consumer Persistence' matched on DC01 at 2026-08-24T16:22:06Z,” MITRE `T1546.003`. Scheduled-task summaries matched at `2026-08-27T22:07:23Z` and `2026-08-28T01:42:31Z`, MITRE `T1053.005`. Defender summary matched at `2026-08-29T18:54:40Z`, MITRE `T1562.001`. The cross-host `svc0` finding and DC01 SharpHound detection independently corroborate adversary operation on this host.

## Attack Narrative

### Phase 1: Directory Discovery and Concealed Execution (2026-08-24T06:17:57Z–2026-08-24T07:49:33Z)

The first recorded activity was SharpHound/BloodHound collection on DC02 at 2026-08-24T06:17:57Z. Encoded PowerShell followed on DC02 at 2026-08-24T07:49:33Z. No account, command, script, process path, or hash accompanies either event.

**Observation — HIGH confidence:** Directory reconnaissance occurred on DC02. **Inference — MODERATE confidence:** DC02 was the earliest observed operational foothold and was used to map Active Directory before privilege expansion. This is not necessarily the true initial-access host because telemetry begins after tooling was already executing.

### Phase 2: Persistence Across Critical Infrastructure (2026-08-24T13:45:05Z–2026-08-25T00:14:05Z)

A suspicious service was installed on CA01 at 2026-08-24T13:45:05Z. WMI event-consumer persistence appeared on DC01 at 2026-08-24T16:22:06Z. Defender real-time protection was then disabled on CA01 at 2026-08-25T00:14:05Z.

**Observation — HIGH confidence:** Persistence existed on DC01; **MODERATE confidence:** suspicious service-based persistence existed on CA01. **Inference — MODERATE confidence:** The tight sequence across a likely CA and domain controller represents deliberate expansion into high-value identity infrastructure. The graph contains no direct common account or tool at this early stage, so the link rests on timing, later cross-host correlation, and the coherent progression of behavior.

### Phase 3: Credential and Ticket Acquisition (2026-08-25T16:25:52Z–2026-08-26T12:44:45Z)

LSASS memory was accessed on DC02 at 2026-08-25T16:25:52Z. Rubeus ticket activity followed on DC01 at 2026-08-26T12:44:45Z.

**Observation — HIGH confidence:** Both credential-access behaviors occurred. **Inference — MODERATE confidence:** The adversary sought reusable credentials and Kerberos access to support lateral movement. The evidence does not show what LSASS yielded, which account Rubeus used, or whether a requested ticket was successfully issued.

The Kerberos detection is confined to DC01. It is not shown reaching CA01. No certificate or ADCS operation appears anywhere in the graph. **Assessment — HIGH confidence:** CA01 was reached by the intrusion through persistence, `svc0` use, and outbound RDP—not through demonstrated certificate enrollment or Kerberos-ticket activity. This distinction is important: CA compromise is a serious possibility, but certificate abuse is not established.

### Phase 4: Confirmed Cross-Host Account Use and Reinforced Persistence (2026-08-27T18:01:41Z–2026-08-28T01:42:31Z)

At 2026-08-27T18:01:41Z, `adatumlab\svc0` authenticated or executed on both CA01 and DC01. Scheduled-task persistence was added on DC01 at 2026-08-27T22:07:23Z. SharpHound/BloodHound collection ran on DC01 at 2026-08-28T00:57:11Z, followed by another scheduled-task persistence detection at 2026-08-28T01:42:31Z.

**Observation — HIGH confidence:** The same account context linked CA01 and DC01. **Inference — HIGH confidence:** The adversary had moved beyond an isolated foothold and was maintaining access while refreshing its view of the directory from DC01. Whether movement ran from DC01 to CA01, CA01 to DC01, or through a third system cannot be determined from the simultaneous correlation timestamp.

### Phase 5: Remote Activity and Continued Defense Evasion (2026-08-28T07:59:37Z–2026-08-29T18:54:40Z)

CA01 generated non-standard outbound RDP detections at 2026-08-28T07:59:37Z and 2026-08-29T10:34:27Z. The destinations, ports, account, client process, and session outcomes are absent. DC01’s Defender real-time protection was disabled at 2026-08-29T18:54:40Z, the last event in the graph.

**Observation — MODERATE confidence:** CA01 initiated anomalous outbound RDP-related activity twice. **Inference — LOW confidence:** CA01 may have been used as a pivot to another system; without destination and logon records, neither direction beyond CA01 nor successful movement is proved. **Assessment — HIGH confidence:** Defense suppression on DC01 left a credible path for continued access at the end of the observed period.

**Attack Chain Summary:** The single most likely path is an observed foothold on DC02, directory discovery and concealed execution, credential harvesting from LSASS, expansion into DC01 and CA01, Kerberos credential activity on DC01, confirmed reuse of `adatumlab\svc0` across DC01 and CA01, and persistence plus security-control suppression on both critical systems. **Confidence — MODERATE:** Multiple independent artifacts support the overall progression, but the graph does not directly bind the early DC02 activity, recovered credentials, Rubeus request, and `svc0` use into a complete causal chain.

## Cross-Host Correlation

The sole `kind=='cross_host'` finding states that `adatumlab\svc0` authenticated or executed on CA01 and DC01 at 2026-08-27T18:01:41Z. **Assessment — HIGH confidence:** This proves shared credential activity across those two hosts and demonstrates spread beyond one system. It does not prove direction because the event supplies one timestamp and no source/destination session data.

The top-entity record associates `adatumlab\svc0` with DC01, DC02, and CA01, while the explicit cross-host finding names only DC01 and CA01 and the identity record lists only DC01. **Assessment — MODERATE confidence:** The account touched all three hosts at some point, based on the entity aggregation. **Assessment — LOW confidence:** The account directly connects DC02 to the later CA01/DC01 activity because no account-specific DC02 event or timestamp is provided. Authentication logs are required to elevate that link.

Repeated tooling connects the domain-controller candidates: SharpHound/BloodHound ran on DC02 at 2026-08-24T06:17:57Z and on DC01 at 2026-08-28T00:57:11Z. **Inference — MODERATE confidence:** The same operator or operational objective drove both collections. No executable path or hash is available to prove reuse of an identical binary.

The timing supports progression from DC02 toward DC01: LSASS access on DC02 at 2026-08-25T16:25:52Z preceded Rubeus activity on DC01 at 2026-08-26T12:44:45Z and confirmed `svc0` use across DC01 and CA01 at 2026-08-27T18:01:41Z. **Inference — MODERATE confidence:** Movement likely began after credential access on DC02. Direct DC02-to-DC01 network or authentication evidence is missing.

CA01 and DC01 also share defense-evasion behavior: Defender was disabled on CA01 at 2026-08-25T00:14:05Z and on DC01 at 2026-08-29T18:54:40Z. **Inference — MODERATE confidence:** This repeated operational pattern corroborates common control, although no shared process, command, account, or hash is present.

All covered hosts are accounted for:

- **DC01:** Likely a domain controller, subject to role confirmation. It sustained WMI and scheduled-task persistence, Rubeus and SharpHound activity, confirmed `svc0` use, and Defender suppression between 2026-08-24T16:22:06Z and 2026-08-29T18:54:40Z. **Assessment — HIGH confidence:** It is a central compromised system.
- **CA01:** Likely a certificate authority, subject to role confirmation. It sustained a suspicious service, Defender suppression, confirmed `svc0` use, and outbound RDP between 2026-08-24T13:45:05Z and 2026-08-29T10:34:27Z. **Assessment — HIGH confidence:** It was drawn into the intrusion; **LOW confidence:** its CA keys or certificate services were abused.
- **DC02:** Likely a domain controller, subject to role confirmation. It recorded SharpHound, encoded PowerShell, and LSASS access between 2026-08-24T06:17:57Z and 2026-08-25T16:25:52Z. **Assessment — HIGH confidence:** It was actively operated on, not peripheral, despite having no formal cross-host finding.

## Identities and Attribution

**Identity: `adatumlab\svc0`**

The identity cluster contains one account, `adatumlab\svc0`. The cross-host evidence shows that account acting on CA01 and DC01 at 2026-08-27T18:01:41Z. The top-entity record associates it with DC01, DC02, and CA01, but the identity record says `seen_on_hosts: ["DC01"]` and lists no `operates_hosts`.

**Observation — HIGH confidence:** `adatumlab\svc0` operated across CA01 and DC01. **Observation — MODERATE confidence:** It was also present on DC02, because only the aggregate entity data makes that association. The graph does not assign the SharpHound, PowerShell, LSASS, Rubeus, persistence, or Defender events to this account.

**Inference — MODERATE confidence:** This reads more like a compromised service account than legitimate owner activity. The account’s service-style name, anomalous score of 10, cross-host use, and coincidence with credential access and persistence support misuse. However, its flags list is empty, and the graph contains no approved job schedule, account owner, service dependencies, interactive-logon history, or change ticket. Legitimate automation cannot be excluded.

No other identity is present. **Assessment — LOW confidence:** One human adversary controlled the entire operation. The evidence supports one coordinated intrusion and one shared credential, but cannot determine the number or identity of human operators.

The deciding test is to compare `svc0` authentication type, source IP/workstation, logon ID, service-ticket requests, and process ancestry on DC02, DC01, and CA01 against the account’s documented service configuration and approved maintenance records for 2026-08-24 through 2026-08-29.

## Impact Assessment

**Active compromise of identity infrastructure — HIGH confidence:** All three covered systems show hostile or highly suspicious activity. If DC01 and DC02 are confirmed domain controllers and CA01 is confirmed as the enterprise CA, the incident encompasses both authentication and certificate-trust infrastructure.

**Credential exposure — MODERATE confidence:** LSASS access on DC02 and Rubeus activity on DC01 permit exposure or abuse of privileged credentials and tickets. Successful credential extraction and ticket issuance are not shown.

**Domain-wide control — MODERATE confidence as a plausible capability; LOW confidence as an accomplished fact:** Control of domain controllers, persistence, and shared-account movement could enable enterprise-wide access. The evidence does not show directory replication abuse, privileged-group modification, forged tickets, policy alteration, or access to all endpoints.

**Certificate-authority risk — MODERATE confidence:** CA01 was compromised sufficiently to host a suspicious service, have Defender disabled, use `svc0`, and initiate anomalous outbound RDP. This exposes the organisation to potential fraudulent certificate issuance or theft of signing material. **Certificate or CA-key abuse — LOW confidence:** The graph contains no certificate issuance, ADCS enrollment, template change, private-key access, backup, export, or HSM event. The Kerberos-ticket detection occurred only on DC01 and is not shown reaching CA01.

**Data exposure — LOW confidence:** The adversary could potentially access directory data, credentials, and any data reachable from these privileged servers. The graph shows directory collection but contains no file-access, archive, staging, exfiltration, or destination evidence proving business-data theft.

**Ongoing access — MODERATE confidence:** Persistence existed on DC01 and CA01, and the last recorded action was Defender suppression on DC01. The graph contains no eradication or clean shutdown evidence. It does not prove that the adversary remained connected after 2026-08-29T18:54:40Z.

If no action is taken, persistent access to identity infrastructure could be used to regain privileged sessions, move throughout the domain, alter authentication controls, or—if CA material was exposed—create longer-lived certificate-based access that survives ordinary password resets. **Confidence — MODERATE**, because the prerequisites are present but execution of these outcomes is not shown.

## Root Cause and Initial Access

**Assessment — LOW confidence:** DC02 was the first observed compromised host. Its SharpHound activity at 2026-08-24T06:17:57Z and encoded PowerShell at 2026-08-24T07:49:33Z establish active execution there before the first CA01 and DC01 events.

**Initial-access method — undetermined, HIGH confidence in that limitation.** The payload begins with post-compromise discovery and execution. It contains no phishing, browser, email, exploit, VPN, public-facing service, initial logon, software-deployment, or account-creation evidence. It therefore cannot distinguish stolen credentials, exploitation, malicious administration, or an earlier pivot from an uncovered host.

The following evidence is needed:

- DC02 Security, PowerShell, Sysmon/EDR, RDP, WinRM, SMB, WMI, and service-creation logs covering a meaningful period before 2026-08-24T06:17:57Z.
- Domain-controller authentication and Kerberos logs showing the source of the first session on DC02 and the source, destination, and logon type for `adatumlab\svc0`.
- VPN, identity-provider, firewall, and remote-access logs for the same preceding period.
- Account-management and service documentation showing when `svc0` was created, where it should run, and whether its observed host use was authorised.

## Containment and Recovery

**Immediate containment**

1. Isolate DC01, DC02, and CA01 from nonessential network paths while preserving management and evidence-collection access. Do not power them off before volatile acquisition unless active harm requires it. **Priority — HIGH confidence**, because all three show active compromise indicators.
2. Disable `adatumlab\svc0`, invalidate its active sessions and Kerberos tickets, and rotate its password from a known-clean administrative workstation. Identify and safely stop dependent services first where immediate disablement would create unacceptable operational impact. **Priority — HIGH confidence**, based on confirmed CA01/DC01 reuse.
3. Block CA01’s anomalous outbound RDP paths and determine the exact destinations for the sessions at 2026-08-28T07:59:37Z and 2026-08-29T10:34:27Z. **Priority — MODERATE confidence**, because successful connections and destinations are unknown.
4. Restore and verify Defender protection on DC01 and CA01 only after collecting volatile evidence and identifying the mechanism that disabled it. Apply temporary network and EDR controls in the interim. **Priority — HIGH confidence.**
5. Suspend privileged sessions and rotate credentials for accounts logged onto DC02 around 2026-08-25T16:25:52Z and DC01 around 2026-08-26T12:44:45Z. **Priority — MODERATE confidence**, because LSASS and ticket activity permit credential exposure even though recovered credentials are not enumerated.
6. Place CA01 into emergency CA containment if its certificate-authority role is confirmed: restrict enrollment and administrative access, preserve CA/HSM audit data, and prevent certificate publication changes pending validation. **Priority — MODERATE confidence**, reflecting confirmed host compromise but unproven CA-key abuse.

**Eradication**

1. Rebuild DC01 and CA01 from trusted media after evidence acquisition; do not rely solely on deleting the detected WMI objects, scheduled tasks, or service. **Assessment — HIGH confidence** for DC01 and **MODERATE confidence** for CA01, based on multiple persistence and evasion mechanisms.
2. Treat DC02 as requiring rebuild unless full forensic analysis can bound LSASS access, encoded PowerShell, and SharpHound execution to known, removable artifacts. **Assessment — HIGH confidence** that forensic validation is required; **MODERATE confidence** that reimage is necessary.
3. Remove and validate every WMI event subscription and scheduled task on DC01 and identify the suspicious service on CA01 by name, image path, signer, creation account, and hash before rebuilding. The payload supplies none of these artifact values.
4. Rotate all credentials exposed in interactive or service sessions on DC01, DC02, and CA01, including `adatumlab\svc0`, using a clean credential-reset sequence that prevents newly reset credentials from touching unrecovered systems. **Priority — MODERATE confidence.**
5. Purge applicable Kerberos tickets and perform targeted `krbtgt` rotation if investigation shows compromise of `krbtgt`, directory replication secrets, or ticket-forging capability. **Need — LOW confidence currently:** the present Rubeus detection alone does not prove those conditions.
6. If CA01 private-key access or unauthorized issuance is found, revoke unauthorized certificates, publish updated revocation information, replace exposed CA keys, and rebuild or re-establish the CA trust chain according to the organisation’s PKI design. **Need — LOW confidence currently but potentially critical:** CA host compromise is shown; key compromise is not.
7. Do not trust existing host-local persistence inventories or Defender status on DC01 and CA01 until independently verified from clean tooling. **Assessment — HIGH confidence.**

**Investigation priorities**

1. Determine whether CA01’s signing keys or certificate services were accessed. Acquire CA database and issuance logs, ADCS operational logs, template and ACL changes, private-key/HSM audit events, key export/backup events, and enrollment records from before 2026-08-24T13:45:05Z through after 2026-08-29T10:34:27Z. This decides whether host rebuild alone is sufficient or PKI-wide recovery is required.
2. Reconstruct `adatumlab\svc0` use on all three hosts. Obtain Security events, Kerberos records, source IPs, logon types, logon IDs, process creation, and service configuration surrounding 2026-08-27T18:01:41Z. This will resolve the DC01/CA01 direction and test the entity-only DC02 association.
3. Identify the LSASS-accessing process and outcome on DC02 at 2026-08-25T16:25:52Z. Memory, EDR telemetry, Sysmon process-access records, file hashes, and subsequent account logons will show whether credentials were extracted and reused.
4. Resolve the Rubeus request on DC01 at 2026-08-26T12:44:45Z. Collect the command line, executing identity, requested SPN, encryption type, ticket disposition, and follow-on logons to determine whether `svc0` or another privileged identity was targeted.
5. Identify and scope every persistence artifact: the CA01 service created at 2026-08-24T13:45:05Z; the DC01 WMI consumer at 2026-08-24T16:22:06Z; and DC01 tasks created at 2026-08-27T22:07:23Z and 2026-08-28T01:42:31Z. Names, paths, hashes, owners, triggers, and network connections will support enterprise-wide hunting.
6. Determine the destinations and outcomes of CA01 outbound RDP at 2026-08-28T07:59:37Z and 2026-08-29T10:34:27Z using firewall, Terminal Services, Security, and destination-host logs. This is the primary test for spread beyond the three covered systems.
7. Establish the true initial-access event by reviewing DC02 and central access telemetry before 2026-08-24T06:17:57Z. The first authenticated session, process ancestry for SharpHound and encoded PowerShell, and perimeter logs would distinguish account compromise from exploitation.
8. Hunt the full environment for the discovered behaviors and artifacts. The current graph covers only DC01, DC02, and CA01; broader authentication, EDR, scheduled-task, service, WMI, Rubeus, SharpHound, and Defender-tampering telemetry is needed to bound the incident.

## Limitations

- **Coverage limitation — HIGH confidence:** Only three hosts are represented. The graph cannot establish whether workstations, application servers, network devices, cloud services, or additional identity systems were involved.
- **Initial-access gap — HIGH confidence:** The first event is already post-compromise reconnaissance on DC02 at 2026-08-24T06:17:57Z. No preceding telemetry or stated collection start is provided.
- **Artifact-detail gap — HIGH confidence:** Timeline artifact arrays are empty. Process names beyond detection labels, command lines, executable paths, hashes, IP addresses, ports, task names, service names, WMI object names, ticket targets, and RDP destinations cannot be cited because they are absent.
- **Identity inconsistency — HIGH confidence:** The cross-host finding places `adatumlab\svc0` on CA01 and DC01, the top entity associates it with all three hosts, and the identity record lists only DC01. This prevents definitive attribution of DC02 events to that identity.
- **Role uncertainty — MODERATE confidence:** `DC01`, `DC02`, and `CA01` suggest domain-controller and certificate-authority roles, but `role_hint` is hostname-derived. The observed activity makes those roles credible leads, not confirmed configuration facts.
- **CA-impact gap — HIGH confidence:** CA01 was compromised, but no certificate, ADCS, CA database, key-access, HSM, issuance, enrollment, or revocation telemetry is included. Absence of such events in this payload is not evidence that certificate abuse did not occur.
- **Credential-impact gap — HIGH confidence:** LSASS and Rubeus detections show access attempts or activity, not which secrets were recovered, which tickets were issued, or whether they were successfully used.
- **Directionality gap — HIGH confidence:** The cross-host event proves `svc0` use on CA01 and DC01 but provides no source/destination relationship. The inferred DC02-to-DC01-to-CA01 progression is therefore graded MODERATE rather than HIGH.
- **Disposition and severity-floor gap — MODERATE confidence:** The payload provides no explicit benign, known-to-IT, or validated-real disposition fields and does not state the severity floor used to build the graph. Cleared lower-level activity may have been excluded, so this report cannot assess its corroborative value.
- **End-state gap — HIGH confidence:** No telemetry after 2026-08-29T18:54:40Z and no containment records are supplied. Continued access is plausible, but neither persistence nor eradication after that timestamp can be confirmed.
- **Data-loss gap — HIGH confidence:** No file-access, staging, archive, transfer, or exfiltration evidence is present. Data theft is not shown; it also cannot be ruled out from this graph.