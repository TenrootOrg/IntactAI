## Executive Summary

A coordinated intrusion affected domain controllers `DC02` and `DC01` and certificate authority `CA01` from `2026-08-24T06:17:57Z` through `2026-08-29T18:54:40Z`. The activity began with SharpHound/BloodHound discovery on `DC02`; subsequent credential access, Kerberos abuse, persistence, security-control impairment, and cross-host use of `adatumlab\svc0` indicate an effort to gain durable control of the Active Directory and certificate-services environment. The initial access vector is undetermined because the graph contains no preceding authentication, process ancestry, source address, or delivery telemetry. Overall assessment: **HIGH confidence**, driven by the convergence of credential-theft, Rubeus, persistence, lateral-movement, and Defender-tampering detections across all three critical servers.

## What happened

1. **OBSERVATION:** At `2026-08-24T06:17:57Z`, a high-confidence SharpHound/BloodHound collection detection fired on `DC02`. At `2026-08-24T07:49:33Z`, suspicious encoded PowerShell was detected on the same host with medium confidence. No executable name, command line, path, hash, account, or parent process is present in the graph.

   **INFERENCE — HIGH confidence:** The operator began by mapping Active Directory from `DC02`; encoded PowerShell approximately 92 minutes later likely supported execution or follow-on tooling. Confidence is driven by the specific SharpHound detection and close host/time correlation, but the precise PowerShell purpose cannot be established.

2. **OBSERVATION:** Suspicious service installation occurred on `CA01` at `2026-08-24T13:45:05Z` with medium confidence. WMI event-consumer persistence followed on `DC01` at `2026-08-24T16:22:06Z` with high confidence. Defender real-time protection was then disabled on `CA01` at `2026-08-25T00:14:05Z` with medium confidence.

   **INFERENCE — HIGH confidence:** By the end of August 24, the operator had reached both the certificate authority and a domain controller and established persistence. Disabling Defender on `CA01` corroborates that the service installation was hostile rather than routine administration. The exact service, WMI consumer, executing account, process, path, and hash are absent.

3. **OBSERVATION:** LSASS memory access was detected on `DC02` at `2026-08-25T16:25:52Z` with high confidence. A Rubeus Kerberos ticket request was detected on `DC01` at `2026-08-26T12:44:45Z`, also with high confidence.

   **INFERENCE — HIGH confidence:** The operator attempted to obtain reusable credentials or credential material from `DC02`, then abused Kerberos from `DC01`. The sequence is consistent with escalation toward domain-level access. The graph does not prove that LSASS access yielded `adatumlab\svc0` or that the Rubeus request succeeded, because it supplies neither credential linkage nor Kerberos result data.

4. **OBSERVATION:** At `2026-08-27T18:01:41Z`, `adatumlab\svc0` authenticated or executed across `CA01` and `DC01`; the cross-host finding rates this as high-confidence lateral movement using shared credentials. The entity data additionally associates the account with all three hosts, although the supplied identity record directly places it only on `DC01`.

   **INFERENCE — HIGH confidence:** Compromised or otherwise misused credentials for `adatumlab\svc0` were used to move between `CA01` and `DC01`. This is the strongest identity attribution available, but the evidence does not establish that the account performed the earlier `DC02` activity.

5. **OBSERVATION:** Scheduled-task persistence was detected on `DC01` at `2026-08-27T22:07:23Z` with high confidence and again at `2026-08-28T01:42:31Z` with medium confidence. Between those events, SharpHound/BloodHound collection ran on `DC01` at `2026-08-28T00:57:11Z` with high confidence.

   **INFERENCE — HIGH confidence:** After lateral movement with `adatumlab\svc0`, the operator reinforced persistence on `DC01` and refreshed domain reconnaissance. The ordering and common host corroborate continued interactive control, although task names, actions, principals, processes, paths, and hashes are missing.

6. **OBSERVATION:** `CA01` generated non-standard outbound RDP detections at `2026-08-28T07:59:37Z` and `2026-08-29T10:34:27Z`, both with medium confidence. Defender real-time protection was disabled on `DC01` at `2026-08-29T18:54:40Z` with high confidence.

   **INFERENCE — MODERATE confidence:** The operator likely used `CA01` as a lateral-movement pivot and subsequently reduced defenses on `DC01` to preserve or extend access. Confidence is limited because the RDP destinations, ports, sessions, and initiating account are not supplied.

The principal alternative is an authorized administrator conducting security assessment or maintenance. **LOW confidence** for that reading: Rubeus, LSASS access, multiple persistence mechanisms, shared-account movement, and Defender disablement form a strongly hostile pattern. The decisive test is to compare the exact commands, task/service/WMI definitions, logon source addresses, and change records with an approved activity window; those details are absent from the graph.

## Impact & Root Cause

**HIGH confidence:** Unauthorized access reached two domain controllers and the certificate authority, placing domain credentials, Kerberos trust, directory topology, and certificate-services privileges at risk. `adatumlab\svc0` should be treated as compromised. Persistence likely existed on `DC01` through WMI and scheduled tasks and on `CA01` through a service; whether it survives containment is **MODERATE confidence** because the graph does not show removal or validation of those artifacts.

**MODERATE confidence:** The adversary’s objective was durable control of the identity infrastructure, driven by discovery on both domain controllers, LSASS access, Rubeus activity, persistence, and activity on the certificate authority. There is no evidence in the graph of data exfiltration, certificate issuance, successful ticket forging, ransomware, or destructive action; whether any occurred is **undetermined**.

Root cause and initial entry are **LOW confidence/undetermined**. The earliest evidence is SharpHound on `DC02`, but the required precursor data—successful logons, source IPs, account attribution, process trees, command lines, email/web delivery, and vulnerability evidence—is missing.

## Do next

**Contain now**

1. Isolate `DC01`, `DC02`, and `CA01` from nonessential traffic while preserving domain and certificate-service evidence; **HIGH priority**, because all three show hostile activity.
2. Disable and rotate `adatumlab\svc0`, terminate its sessions, and identify dependent services before restoration; **HIGH confidence** the credential was misused across `CA01` and `DC01`.
3. On `DC01`, disable and preserve the WMI event consumer and both scheduled-task artifacts associated with `2026-08-24T16:22:06Z`, `2026-08-27T22:07:23Z`, and `2026-08-28T01:42:31Z`; **HIGH confidence** these represent persistence.
4. On `CA01`, disable and preserve the suspicious service installed at `2026-08-24T13:45:05Z`; **MODERATE confidence**, pending recovery of its name, binary, and configuration.
5. Re-enable Defender real-time protection and verify policy integrity on `CA01` and `DC01`; **HIGH priority**, supported by explicit disablement detections.

**Investigate next**

1. Recover process trees, command lines, accounts, paths, and hashes for every detection on `DC01`, `DC02`, and `CA01`; these fields are absent and are required to identify the payloads.
2. On `DC02`, correlate the SharpHound, encoded PowerShell, and LSASS events with logons and network connections from `2026-08-24T06:17:57Z` through `2026-08-25T16:25:52Z` to determine initial access and credential theft.
3. On `DC01`, inspect Kerberos logs around `2026-08-26T12:44:45Z` to determine the account, service principal, source, and outcome of the Rubeus request.
4. On `CA01`, identify the destinations and initiating identity for outbound RDP at `2026-08-28T07:59:37Z` and `2026-08-29T10:34:27Z`.
5. Audit `CA01` certificate templates, CA administration, issuance records, and private-key access for unauthorized changes or certificates; **MODERATE confidence** this infrastructure was an objective, but compromise impact is not yet demonstrated.