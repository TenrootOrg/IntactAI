## Executive Summary

The evidence shows a sustained, environment-wide intrusion affecting 94 of 100 covered hosts from 2025-08-31T15:15:16Z through 2026-08-30T02:21:39Z. The activity used multiple `adatumlab` service accounts to move between systems, extracted credentials, requested Kerberos tickets, mapped directory relationships, established persistence, disabled security controls, cleared logs, and operated Cobalt Strike on at least ten workstations. The affected estate includes both apparent domain controllers (`DC01` and `DC02`), the apparent software-distribution server `MECM01`, and the apparent certificate authority `CA01`. Host roles are inferred from names but supported in part by the directory, Kerberos, and remote-access activity seen on those systems.

The graph does not identify one human identity controlling all service accounts. It establishes that `adatumlab\svc0`, `adatumlab\svc1`, `adatumlab\svc4`, `adatumlab\svc5`, `adatumlab\svc7`, `adatumlab\svc9`, and `adatumlab\svc10` were each reused across multiple hosts. These may represent several compromised identities or one operator using several stolen credentials. Treating them collectively as one person would exceed the evidence.

Initial access is undetermined. The first recorded activity was a renamed `procdump/adfind`-type binary on `WKS043` at 2025-08-31T15:15:16Z, followed within days by service, WMI, and scheduled-task persistence on several other workstations. This establishes that the adversary was already executing tools by the beginning of the evidence window, not how access was obtained.

The likely objective was control of Active Directory and its authentication infrastructure. Credential dumping, Kerberos-ticket operations, BloodHound/SharpHound discovery, compromise of `DC01`, suspicious execution on `DC02`, and discovery on `CA01` support that conclusion. The evidence shows access to domain infrastructure and extensive credential exposure; it permits, but does not prove, domain-wide administrative control or issuance of fraudulent certificates.

**Overall confidence: HIGH** that this was a broad, persistent intrusion, because independent Cobalt Strike, Mimikatz/LSASS, Kerberos, persistence, defence-evasion, and cross-host authentication findings agree. **Confidence is MODERATE** on a single coordinated operator and the Active Directory-control objective because the graph does not map every tool execution to an account or provide source/destination session records.

## Critical Findings

**Domain infrastructure was reached through stolen or misused credentials**

Observation: `adatumlab\svc5` authenticated or executed across `WKS006`, `WKS013`, `DC01`, `WKS072`, `WKS019`, and `WKS068` at 2025-10-29T05:46:33Z. On `DC01`, non-standard outbound RDP occurred at 2025-10-27T11:59:18Z, a renamed `procdump/adfind`-type binary was detected at 2025-11-29T14:03:05Z, a Rubeus Kerberos-ticket request occurred at 2026-05-07T03:17:02Z, and further outbound RDP occurred at 2026-08-19T10:08:38Z. No exact process name, path, command line, or hash is present in the graph.

**Why it matters:** `DC01` is inferred to be a domain controller. Credential reuse reaching it, followed by discovery/evasion tooling and Kerberos activity, means directory credentials and potentially domain administration paths cannot be trusted. The repeated activity through August also argues against a short-lived, fully removed compromise.

**Evidence:** “The account `adatumlab\svc5` authenticated/executed on WKS006, WKS013, DC01, WKS072, WKS019, WKS068 at 2025-10-29T05:46:33Z — consistent with lateral movement using shared credentials.” MITRE: `T1021`, `T1078`; ts: `2025-10-29T05:46:33Z`. This is corroborated by the `DC01` findings for non-standard RDP (`T1021.001`), renamed binary (`T1036.003`), and Rubeus (`T1558.003`).

**Assessment: HIGH confidence** that `DC01` was involved in the intrusion; **MODERATE confidence** that domain-level authority was obtained, because privileges, ticket contents, and directory changes are absent.

**The apparent software-distribution server was used for credential and Kerberos operations**

Observation: `adatumlab\svc5` touched `MECM01`, `WKS009`, `WKS026`, `WKS078`, `WKS048`, and `WKS019` at 2025-10-07T00:49:40Z. `MECM01` then recorded encoded PowerShell at 2025-11-01T01:13:55Z, non-standard outbound RDP at 2026-01-10T22:49:12Z, LSASS access at 2026-03-04T07:34:28Z, and a Rubeus ticket request at 2026-06-28T13:07:12Z. No process path, command line, or hash was supplied.

**Why it matters:** If `MECM01` is the configuration-management/software-distribution server suggested by its name, its credentials and deployment authority may provide execution paths to large parts of the estate. Its compromise therefore carries greater organisational risk than a similarly noisy workstation.

**Evidence:** Cross-host summary: “The account `adatumlab\svc5` authenticated/executed on MECM01, WKS009, WKS026, WKS078, WKS048, WKS019 at 2025-10-07T00:49:40Z — consistent with lateral movement using shared credentials.” MITRE: `T1021`, `T1078`; ts: `2025-10-07T00:49:40Z`. Corroborating findings are encoded PowerShell (`T1059.001`), RDP (`T1021.001`), LSASS access (`T1003.001`), and Rubeus (`T1558.003`).

**Assessment: HIGH confidence** that `MECM01` requires compromise treatment; **MODERATE confidence** that its distribution capabilities were abused, because no deployment jobs, packages, or client-push records are included.

**The certificate-authority host was included in directory reconnaissance**

Observation: SharpHound/BloodHound collection was detected on `CA01` at 2026-04-02T04:22:27Z. The graph contains no certificate request, issuance, template modification, private-key access, process path, or hash on `CA01`.

**Why it matters:** `CA01` is inferred from its name to be a certificate authority. Directory reconnaissance executing there brings a trust-anchor host into scope, especially given Rubeus activity elsewhere. However, the available evidence does not show that certificate services or CA signing material were compromised.

**Evidence:** “SIGMA rule ‘SharpHound / BloodHound Collection’ matched on CA01 at 2026-04-02T04:22:27Z.” MITRE: `T1087.002`; ts: `2026-04-02T04:22:27Z`. This is contextually corroborated by Rubeus activity on `DC01`, `MECM01`, and numerous workstations, but no cross-host finding directly links those events to `CA01`.

**Assessment: MODERATE confidence** that adversary discovery occurred on `CA01`, because it is a single medium-confidence finding. **LOW confidence** that certificates or the CA private key were compromised; the necessary certificate-service evidence is absent.

**Cobalt Strike established interactive footholds on multiple workstations**

Observation: Cobalt Strike named pipes were detected on `WKS063` at 2025-10-09T18:54:38Z, `WKS092` at 2025-10-21T16:03:23Z, `WKS018` at 2025-11-16T17:26:02Z, `WKS005` at 2025-12-08T09:28:35Z, `WKS082` at 2025-12-12T17:23:12Z, `WKS064` at 2026-02-08T18:51:21Z, `WKS060` at 2026-04-11T05:22:56Z, `WKS097` at 2026-04-20T07:13:52Z, `WKS043` at 2026-05-30T18:13:56Z, and `WKS091` at 2026-06-28T15:20:38Z. The pipe names, parent processes, paths, and hashes are not present.

**Why it matters:** These detections show command-and-control capability at multiple points over nearly nine months. Several hosts also show credential theft, persistence, or shared-account movement, making isolated false positives unlikely.

**Evidence:** Each finding’s summary states that the SIGMA rule “Cobalt Strike Named Pipe” matched at the host and timestamp above; MITRE value: `C2-CobaltStrike`. `WKS097` is directly corroborated by Mimikatz at 2026-05-09T20:59:31Z; `WKS043` by Rubeus at 2026-05-09T00:37:03Z and Mimikatz at 2026-05-21T14:02:28Z; `WKS063` by Rubeus and later BloodHound activity.

**Assessment: HIGH confidence** that Cobalt Strike or closely matching tooling operated in the environment, based on ten independent host detections plus corroborating post-exploitation activity.

**Credential theft was repeated and operationally exploited**

Observation: Explicit Mimikatz execution occurred on `WKS017`, `WKS023`, `WKS081`, `WKS010`, `WKS049`, `WKS058`, `WKS056`, `WKS067`, `WKS097`, `WKS093`, `WKS043`, and `WKS032`. LSASS memory access occurred on `WKS070`, `WKS016`, `WKS046`, `WKS030`, `WKS095`, `WKS053`, `WKS065`, `MECM01`, `WKS031`, `WKS051`, `WKS068`, `WKS083`, `WKS059`, `WKS024`, `WKS026`, and `WKS008`. No dump paths, process details, or hashes are provided.

**Why it matters:** Credentials resident on these systems—including service, administrator, and potentially deployment credentials—must be considered exposed. Subsequent multi-host use of service accounts shows that credential access was not merely attempted; reusable credentials were exercised across the estate.

**Evidence:** The findings are grounded in `T1003.001`. They are corroborated by all 18 cross-host `T1021`/`T1078` findings and by Rubeus `T1558.003` activity.

**Assessment: HIGH confidence** that credential material was targeted and likely obtained; **MODERATE confidence** regarding exactly which secrets were recovered because memory-dump contents and account-to-process attribution are missing.

**Persistence and defence evasion indicate continued access**

Observation: WMI event-consumer persistence, scheduled tasks, or suspicious services appeared across numerous hosts, while Defender was disabled and security logs were cleared on others. The latest activity was encoded PowerShell on `WKS042` at 2026-08-30T02:21:39Z, two days after BloodHound collection on `WKS026` at 2026-08-28T19:09:02Z.

**Why it matters:** The persistence breadth and late activity mean the organisation cannot rely on credential resets alone. Hosts may re-establish access after accounts are changed, and cleared logs make full reconstruction harder.

**Evidence:** Persistence findings use `T1546.003`, `T1053.005`, and `T1543.003`; defence evasion uses `T1562.001` and `T1070.001`. These are corroborated by Cobalt Strike and credential-access detections rather than standing alone.

**Assessment: HIGH confidence** that multiple durable footholds existed. **MODERATE confidence** that access remained active at the end of collection, because recent execution and persistence support it but no live session or beacon telemetry is supplied.

## Attack Narrative

### Phase 1: Established Execution and Early Persistence (2025-08-31–2025-09-20)

The first evidence is a renamed `procdump/adfind`-type binary on `WKS043` at 2025-08-31T15:15:16Z. By 2025-09-03T19:38:38Z, a suspicious service was installed on `WKS058`; WMI persistence appeared on `WKS083` at 2025-09-05T04:46:05Z; and a scheduled task appeared on `WKS094` at 2025-09-05T04:52:29Z.

Credential and authentication targeting followed: LSASS access on `WKS070` at 2025-09-06T17:28:51Z, Rubeus on `WKS013` at 2025-09-08T20:29:19Z, Mimikatz on `WKS059` at 2025-09-14T20:05:22Z, Mimikatz on `WKS023` at 2025-09-18T22:07:23Z, and Rubeus on `WKS063` at 2025-09-20T04:30:15Z.

**Inference — MODERATE confidence:** The adversary entered before or at the start of the collection window and quickly established multiple footholds while harvesting authentication material. The graph does not show which of these hosts was the original entry point.

### Phase 2: Service-Account Expansion and Infrastructure Access (2025-09-21–2025-11-29)

At 2025-09-21T12:26:26Z, `adatumlab\svc4` appeared across `WKS094`, `WKS031`, and `WKS050`. `adatumlab\svc5` then reached `MECM01`, `WKS009`, `WKS026`, `WKS078`, `WKS048`, and `WKS019` at 2025-10-07T00:49:40Z. Cobalt Strike appeared on `WKS063` at 2025-10-09T18:54:38Z and `WKS092` at 2025-10-21T16:03:23Z.

`DC01` recorded non-standard outbound RDP at 2025-10-27T11:59:18Z. Two days later, `adatumlab\svc5` was used across `WKS006`, `WKS013`, `DC01`, `WKS072`, `WKS019`, and `WKS068` at 2025-10-29T05:46:33Z; it then appeared across `WKS062`, `WKS053`, and `WKS005` at 2025-10-30T05:04:04Z. On 2025-11-24T04:01:26Z, `adatumlab\svc7` linked `WKS023`, `WKS033`, `WKS036`, `DC01`, `WKS018`, and `WKS053`. A renamed `procdump/adfind`-type binary was detected on `DC01` at 2025-11-29T14:03:05Z.

**Inference — HIGH confidence:** Stolen or misused service credentials enabled broad lateral movement and reached both `MECM01` and `DC01`. Direction between members of each simultaneous cross-host cluster is not established, although `MECM01` involvement precedes the first `svc5` cluster containing `DC01`.

### Phase 3: Durable Control, Discovery, and Credential Cycling (2025-12-01–2026-03-22)

Cobalt Strike appeared on `WKS005` at 2025-12-08T09:28:35Z and `WKS082` at 2025-12-12T17:23:12Z. Rubeus, Mimikatz, LSASS access, Defender disabling, and log clearing continued across `WKS010`, `WKS016`, `WKS024`, `WKS026`, `WKS033`, `WKS040`, `WKS049`, `WKS053`, `WKS056`, `WKS058`, `WKS059`, `WKS060`, `WKS064`, `WKS065`, `WKS070`, `WKS071`, `WKS081`, and `WKS092`.

`adatumlab\svc7` moved across four hosts at 2026-01-04T15:45:57Z, two at 2026-01-20T16:43:09Z, five at 2026-01-21T20:29:28Z, and two at 2026-02-28T06:52:16Z. `adatumlab\svc4` linked `WKS055`, `WKS070`, and `WKS035` at 2026-01-24T14:24:13Z. `adatumlab\svc10` linked `WKS007` and `WKS093` at 2026-02-20T01:06:05Z. Cobalt Strike appeared on `WKS064` at 2026-02-08T18:51:21Z.

On 2026-03-04, LSASS access occurred on `MECM01` at 07:34:28Z, followed by a Rubeus request on `WKS089` at 07:54:22Z. `adatumlab\svc9` then linked `WKS040`, `WKS016`, `WKS088`, `WKS065`, `WKS079`, and `WKS083` at 2026-03-14T03:01:00Z.

**Inference — HIGH confidence:** The operator repeatedly harvested credentials, mapped directory relationships, and rotated among service accounts and persistence mechanisms. **LOW confidence** applies to a direct causal link between the `MECM01` LSASS access and later service-account use because account attribution is missing.

### Phase 4: Certificate-Authority Reconnaissance and Renewed Expansion (2026-04-02–2026-06-30)

SharpHound/BloodHound collection ran on `CA01` at 2026-04-02T04:22:27Z. The graph does not show certificate issuance or CA configuration changes. `adatumlab\svc1` linked `WKS065` and `WKS053` at 2026-04-10T06:28:51Z; Cobalt Strike appeared on `WKS060` at 2026-04-11T05:22:56Z and `WKS097` at 2026-04-20T07:13:52Z. Encoded PowerShell was detected on apparent domain controller `DC02` at 2026-04-14T17:16:50Z.

`adatumlab\svc5` linked six more workstations at 2026-04-19T13:25:40Z. `adatumlab\svc0` linked five hosts at 2026-05-04T19:30:45Z. Rubeus ran on `DC01` at 2026-05-07T03:17:02Z. `adatumlab\svc10` linked six hosts at 2026-05-14T01:04:12Z, and `adatumlab\svc5` linked another five at 2026-05-15T20:02:06Z. Cobalt Strike appeared on `WKS043` at 2026-05-30T18:13:56Z and `WKS091` at 2026-06-28T15:20:38Z; Rubeus ran on `MECM01` earlier that day at 2026-06-28T13:07:12Z.

**Inference — MODERATE confidence:** The adversary was exploring privileged directory and authentication paths, including the CA host, while maintaining interactive access. The evidence does not establish ADCS exploitation or a forged/issued certificate.

### Phase 5: Persistence Maintenance and Continued Discovery (2026-07-01–2026-08-30)

From July onward, services, scheduled tasks, and WMI persistence continued on `WKS013`, `WKS031`, `WKS032`, `WKS036`, `WKS046`, `WKS052`, `WKS081`, `WKS083`, `WKS084`, `WKS093`, and `WKS098`. Logs were cleared on `WKS056` and `WKS058`. Rubeus ran on `WKS057` at 2026-08-02T19:35:22Z and `WKS063` at 2026-08-03T16:24:31Z.

BloodHound collection on `WKS057` at 2026-08-16T05:21:38Z immediately preceded `adatumlab\svc1` use across `WKS073`, `WKS040`, `WKS043`, `WKS088`, `WKS044`, and `WKS076` at 2026-08-17T03:17:13Z. `DC01` again produced non-standard outbound RDP at 2026-08-19T10:08:38Z. Defender was disabled on `WKS089` at 2026-08-23T03:40:15Z, BloodHound ran on `WKS026` at 2026-08-28T19:09:02Z, and encoded PowerShell ran on `WKS042` at 2026-08-30T02:21:39Z.

**Inference — HIGH confidence:** The compromise persisted through the end of the evidence period. **MODERATE confidence** that a live operator still had access on 2026-08-30, because the activity is recent and adversary-like but live connection telemetry is unavailable.

**Attack Chain Summary:** The most likely path was an unidentified initial compromise before 2025-08-31, followed by local persistence and credential theft, reuse of service credentials across workstation clusters, access to `MECM01` and `DC01`, directory/Kerberos reconnaissance including `DC02` and `CA01`, and continuing Cobalt Strike-backed footholds and persistence through 2026-08-30. **Confidence: HIGH** for the progression from established execution through credential theft and lateral movement; **MODERATE** for the exact entry point, movement direction, and final privilege level.

## Cross-Host Correlation

Every cross-host finding supports credential-enabled spread:

- `adatumlab\svc4` linked `WKS094`, `WKS031`, and `WKS050` at 2025-09-21T12:26:26Z, then `WKS055`, `WKS070`, and `WKS035` at 2026-01-24T14:24:13Z. This proves the same credential operated in two distinct three-host clusters. Direction is not shown. **Confidence: HIGH.**

- `adatumlab\svc5` linked `MECM01`, `WKS009`, `WKS026`, `WKS078`, `WKS048`, and `WKS019` at 2025-10-07T00:49:40Z; `WKS006`, `WKS013`, `DC01`, `WKS072`, `WKS019`, and `WKS068` at 2025-10-29T05:46:33Z; `WKS062`, `WKS053`, and `WKS005` at 2025-10-30T05:04:04Z; `WKS046`, `WKS060`, `WKS015`, `WKS014`, `WKS062`, and `WKS059` at 2026-04-19T13:25:40Z; and `WKS029`, `WKS019`, `WKS010`, `WKS022`, and `WKS084` at 2026-05-15T20:02:06Z. Repeated members `WKS019` and `WKS062` bridge the clusters, proving reuse over more than seven months and connecting `MECM01` to `DC01`. The chronology supports spread from the October 7 cluster toward the October 29 cluster, but not a specific source host. **Confidence: HIGH.**

- `adatumlab\svc7` linked `WKS023`, `WKS033`, `WKS036`, `DC01`, `WKS018`, and `WKS053` at 2025-11-24T04:01:26Z; `WKS021`, `WKS078`, `WKS014`, and `WKS063` at 2026-01-04T15:45:57Z; `WKS021` and `WKS057` at 2026-01-20T16:43:09Z; `WKS007`, `WKS024`, `WKS008`, `WKS026`, and `WKS056` at 2026-01-21T20:29:28Z; and `WKS011` and `WKS034` at 2026-02-28T06:52:16Z. Repeated `WKS021` bridges the January 4 and January 20 clusters. The sequence demonstrates continuing expansion after the credential had reached `DC01`, but not that `DC01` was the source. **Confidence: HIGH.**

- `adatumlab\svc10` linked `WKS007` and `WKS093` at 2026-02-20T01:06:05Z, then `WKS087`, `WKS057`, `WKS036`, `WKS091`, `WKS049`, and `WKS085` at 2026-05-14T01:04:12Z. This proves reuse in two separated clusters; it does not identify the intermediate path. **Confidence: HIGH.**

- `adatumlab\svc9` linked `WKS040`, `WKS016`, `WKS088`, `WKS065`, `WKS079`, and `WKS083` at 2026-03-14T03:01:00Z. `WKS016`, `WKS065`, and `WKS083` already had credential-access or persistence evidence, corroborating malicious credential reuse. Direction is unresolved. **Confidence: HIGH.**

- `adatumlab\svc1` linked `WKS065` and `WKS053` at 2026-04-10T06:28:51Z, then `WKS073`, `WKS040`, `WKS043`, `WKS088`, `WKS044`, and `WKS076` at 2026-08-17T03:17:13Z. The second cluster followed BloodHound collection on `WKS057` by less than a day, but the graph does not connect `WKS057` to the `svc1` session. **Confidence: HIGH** for credential reuse; **LOW** for that proposed causal link.

- `adatumlab\svc0` linked `WKS099`, `WKS087`, `WKS071`, `WKS050`, and `WKS051` at 2026-05-04T19:30:45Z. LSASS access on `WKS051` at 2026-05-15T19:23:39Z and outbound RDP from `WKS099` at 2026-05-19T04:24:12Z corroborate exploitation within the cluster but do not establish direction. **Confidence: HIGH.**

Shared tooling further ties otherwise unlinked hosts together: Cobalt Strike named-pipe detections occurred on ten hosts; Mimikatz/LSASS activity spanned 28 distinct hosts; Rubeus and BloodHound repeatedly targeted authentication and directory relationships; WMI, services, and scheduled tasks provided recurring persistence; and Defender disabling/log clearing recurred throughout the same period. These patterns are consistent with one intrusion program, although no common hash, pipe value, command line, or external infrastructure IOC is supplied. **Assessment: HIGH confidence** that the cross-host account clusters are related malicious activity; **MODERATE confidence** that every single-host finding belongs to one operator rather than multiple operators or occasional administrative false positives.

## Identities and Attribution

The graph defines each account below as its own identity; it does not cluster them into one person:

- **`adatumlab\svc5`:** Identity baseline says it was seen on `WKS037`; cross-host evidence shows operation on `MECM01`, `DC01`, and 21 workstations across five clusters. This scale, the appearance on privileged infrastructure, and corroborating credential-access activity are inconsistent with a narrowly scoped service identity unless explicitly documented. **Assessment: HIGH confidence** the credential was compromised or seriously misused; legitimate automation can be tested through service ownership, approved logon endpoints, job history, and source-IP records.

- **`adatumlab\svc7`:** Baseline says seen on `WKS047`; it operated across `DC01` and 17 workstations in five clusters. Its repeated fan-out is more consistent with compromised credentials than a normal single-service pattern. **Assessment: HIGH confidence**, subject to validation against the service’s documented dependency map and scheduled operations.

- **`adatumlab\svc1`:** Baseline says seen on `WKS012`; it operated across eight cross-host-evidenced workstations in April and August. **Assessment: HIGH confidence** of misuse because the same credential appears in two unrelated host clusters; whether the legitimate owner initiated any activity is undetermined.

- **`adatumlab\svc10`:** Baseline says seen on `WKS089`; it operated across eight cross-host-evidenced workstations. Several later hosts also contained Mimikatz, Cobalt Strike, log-clearing, or Defender-disable evidence. **Assessment: HIGH confidence** of compromise or adversarial use.

- **`adatumlab\svc4`:** Baseline says seen on `WKS028`; it operated across six workstations in two clusters. **Assessment: HIGH confidence** of misuse; authorised administrative automation remains a testable alternative only if job and authentication-source records reproduce the exact timestamps and targets.

- **`adatumlab\svc9`:** Baseline says seen on `WKS059`; it operated across six workstations simultaneously at 2026-03-14T03:01:00Z. **Assessment: HIGH confidence** of misuse because several targets already contained post-exploitation evidence.

- **`adatumlab\svc0`:** Baseline says seen on `WKS019`; it operated across five workstations at 2026-05-04T19:30:45Z. **Assessment: HIGH confidence** of misuse, corroborated by later LSASS and RDP activity within that cluster.

- **`adatumlab\svc2`, `adatumlab\svc3`, `adatumlab\svc6`, `adatumlab\svc8`, and `adatumlab\svc11`:** These identities appear in entity/baseline data but have no cross-host finding in the supplied graph. The evidence therefore does not support attributing malicious actions to them. **Assessment: LOW confidence** of compromise; authentication logs and service ownership records are required.

No identity is shown to be adversary-created: account creation time, creator, directory attributes, and change history are absent. **Assessment: LOW confidence** on whether any account was created by the adversary. No named threat actor or campaign can be attributed. **Assessment: LOW confidence** because the payload contains no external infrastructure, malware hashes, or distinctive actor-specific artefacts.

## Impact Assessment

The evidence **shows** that the adversary reached 94 hosts, including apparent domain infrastructure; operated post-exploitation tooling; harvested or attempted to harvest credentials; requested Kerberos tickets; performed directory discovery; maintained persistence; and evaded or impaired logging and endpoint protection. **Confidence: HIGH.**

The evidence **shows** that `DC01` was included in two service-account movement clusters and later produced Rubeus, disguised-tool, and RDP detections. `DC02` produced encoded PowerShell. This makes domain credentials, privileged groups, Group Policy, directory objects, and trust relationships potentially exposed. **Confidence: HIGH** for exposure; **MODERATE** for actual modification or domain-wide control because directory-change and privilege-assignment logs are missing.

The evidence **shows** discovery activity on `CA01`, the apparent certificate-authority host. It does **not show** certificate issuance, template abuse, CA key access, or ADCS persistence. Certificate trust must nevertheless be investigated before containment is considered complete. **Confidence: MODERATE** for host compromise scope; **LOW** for certificate compromise.

If `MECM01` is the software-distribution system its name implies, its LSASS, Rubeus, PowerShell, RDP, and cross-host activity potentially exposed deployment credentials and the ability to push software broadly. The evidence does not show that this capability was exercised. **Confidence: MODERATE.**

No file-access, database, email, archive, staging, or exfiltration evidence is provided. Data theft is therefore undetermined—not disproved. **Confidence: HIGH** in that limitation.

Continued access at the end of collection is plausible because persistence and adversary-like execution continued through 2026-08-30T02:21:39Z. If nothing is done, stolen service credentials, WMI consumers, services, tasks, Kerberos artefacts, or Cobalt Strike implants could permit renewed access, credential recapture, domain takeover, software-distribution abuse, and potentially CA compromise. **Confidence: MODERATE** because current process/network state is absent.

All hosts are accounted for as follows:

- **Privileged/infrastructure hosts:** `DC01` had cross-host credential use, RDP, Rubeus, and disguised-tool activity and is a primary compromise concern; `DC02` had encoded PowerShell; `MECM01` had cross-host credential use, PowerShell, RDP, LSASS, and Rubeus activity; `CA01` had BloodHound/SharpHound collection. **Confidence: HIGH** that all require investigation; role attribution from names remains **MODERATE confidence**.

- **Cobalt Strike hosts:** `WKS005`, `WKS018`, `WKS043`, `WKS060`, `WKS063`, `WKS064`, `WKS082`, `WKS091`, `WKS092`, and `WKS097` had named-pipe detections and should be treated as confirmed or probable interactive footholds. **Confidence: HIGH overall**, with the individual finding confidence retained where medium.

- **Credential-theft or ticket-operation hosts:** `WKS008`, `WKS010`, `WKS013`, `WKS016`, `WKS017`, `WKS023`, `WKS024`, `WKS026`, `WKS029`, `WKS030`, `WKS031`, `WKS032`, `WKS033`, `WKS037`, `WKS038`, `WKS039`, `WKS046`, `WKS049`, `WKS051`, `WKS053`, `WKS054`, `WKS056`, `WKS057`, `WKS058`, `WKS059`, `WKS061`, `WKS063`, `WKS065`, `WKS067`, `WKS068`, `WKS070`, `WKS072`, `WKS076`, `WKS081`, `WKS083`, `WKS085`, `WKS089`, `WKS091`, `WKS093`, and `WKS095` recorded Mimikatz, LSASS, or Rubeus evidence; several also belong to other categories. **Confidence: HIGH** that credentials on these systems require exposure treatment.

- **Cross-host movement participants not already fully characterised above:** `WKS006`, `WKS007`, `WKS009`, `WKS011`, `WKS014`, `WKS015`, `WKS019`, `WKS021`, `WKS022`, `WKS034`, `WKS035`, `WKS036`, `WKS040`, `WKS044`, `WKS048`, `WKS050`, `WKS055`, `WKS057`, `WKS062`, `WKS071`, `WKS073`, `WKS078`, `WKS079`, `WKS084`, `WKS087`, `WKS088`, `WKS094`, and `WKS099` were directly tied into service-account clusters. **Confidence: HIGH** that they were touched by shared credentials; the initiating host is unknown.

- **Persistence, execution, discovery, defence-evasion, or remote-access-only hosts:** `WKS004`, `WKS020`, `WKS025`, `WKS027`, `WKS028`, `WKS042`, `WKS045`, `WKS052`, `WKS075`, `WKS077`, `WKS080`, `WKS086`, `WKS090`, `WKS096`, and `WKS098` have one or more suspicious findings but no cross-host link in this graph. They remain in scope because their techniques match the wider intrusion; direct attribution to the same operator is **MODERATE confidence**.

- **No finding data:** `WKS012`, `WKS041`, `WKS047`, `WKS066`, `WKS069`, and `WKS074` have zero findings and no activity interval. This is absence of recorded evidence, not proof they were unaffected. **Confidence: HIGH** in the coverage statement; **LOW** in any clean-host conclusion.

## Root Cause and Initial Access

Initial access is undetermined. The earliest graph event—renamed `procdump/adfind`-type execution on `WKS043` at 2025-08-31T15:15:16Z—already represents post-compromise tooling. No phishing artefact, browser/download history, email telemetry, VPN authentication, internet-facing exploit record, initial process tree, source IP, or account logon preceding it is supplied.

The rapid appearance of persistence and credential-access activity during early September permits several possibilities, including compromise of a workstation followed by credential theft, prior compromise of a service account, or activity predating retained telemetry. None can be selected responsibly.

**Assessment: LOW confidence** for any specific initial-access mechanism; **HIGH confidence** that initial access occurred no later than 2025-08-31T15:15:16Z and may predate the evidence window.

To establish root cause, the investigation needs `WKS043` EDR/process, file-creation, browser, email, and authentication telemetry preceding 2025-08-31T15:15:16Z; corresponding domain-controller logons; VPN/identity-provider records; and service-account password/change histories. The exact retention period before the first event is also required.

## Containment and Recovery

**Immediate containment**

1. Isolate `DC01`, `DC02`, `CA01`, and `MECM01` through an emergency identity-infrastructure procedure that preserves required business services while blocking nonessential remote administration. Capture volatile memory, active sessions, tickets, process trees, network connections, WMI state, services, and tasks before shutdown where operationally safe.
2. Disable or tightly deny interactive/network logon for `adatumlab\svc0`, `adatumlab\svc1`, `adatumlab\svc4`, `adatumlab\svc5`, `adatumlab\svc7`, `adatumlab\svc9`, and `adatumlab\svc10`; rotate their secrets from a known-clean administrative system and update only verified dependencies. Review `svc2`, `svc3`, `svc6`, `svc8`, and `svc11` before deciding whether rotation is also required.
3. Isolate the ten Cobalt Strike hosts: `WKS005`, `WKS018`, `WKS043`, `WKS060`, `WKS063`, `WKS064`, `WKS082`, `WKS091`, `WKS092`, and `WKS097`.
4. Isolate hosts with explicit Mimikatz or LSASS access, prioritising `MECM01`, `WKS016`, `WKS046`, `WKS053`, `WKS056`, `WKS058`, `WKS059`, `WKS065`, `WKS068`, and `WKS083`, then the remaining credential-access hosts listed in the Impact Assessment.
5. Block the observed lateral paths by restricting RDP, WMI, SMB/service control, PowerShell remoting, and service-account logon between workstation segments. Because source addresses are absent, apply controls by named account and host group rather than unverified IOCs.
6. Invalidate active Kerberos sessions and tickets after credential rotations, including those associated with Rubeus activity on `DC01`, `MECM01`, `WKS010`, `WKS013`, `WKS029`, `WKS033`, `WKS037`, `WKS038`, `WKS039`, `WKS043`, `WKS049`, `WKS054`, `WKS057`, `WKS061`, `WKS063`, `WKS072`, `WKS076`, `WKS085`, `WKS089`, and `WKS091`.
7. Restore and enforce Defender protection on `WKS018`, `WKS026`, `WKS028`, `WKS029`, `WKS033`, `WKS035`, `WKS049`, `WKS050`, `WKS058`, `WKS060`, `WKS064`, `WKS070`, `WKS071`, `WKS077`, `WKS089`, `WKS092`, and `WKS095`; do not treat re-enablement as remediation.
8. Preserve central logs immediately, especially for hosts with cleared security logs: `WKS006`, `WKS015`, `WKS016`, `WKS032`, `WKS033`, `WKS036`, `WKS040`, `WKS048`, `WKS054`, `WKS056`, `WKS058`, `WKS070`, `WKS071`, `WKS087`, and `WKS094`.

**Eradication**

1. Rebuild the Cobalt Strike hosts and systems with explicit Mimikatz execution from known-good media; do not rely solely on file deletion or antivirus scans.
2. Rebuild or conduct trust-reset recovery for `MECM01` after exporting and independently validating configuration, packages, deployment accounts, client-push credentials, and site-system relationships. Reissue all credentials stored or used there.
3. Treat `DC01` as untrusted pending full directory-compromise assessment. If unauthorised privileged changes, credential-material access, or persistent code is confirmed, execute a forest-recovery plan rather than an in-place cleanup. Validate `DC02` independently before using it as a recovery authority.
4. For `CA01`, inspect certificate-service logs, issued certificates, failed/pending requests, template and ACL changes, CA database changes, key-access auditing, backup activity, and installed binaries. If the CA signing key was accessed or certificate issuance was manipulated, revoke and replace the CA hierarchy and all dependent certificates; the present graph alone does not yet justify that conclusion.
5. Remove and validate all WMI event consumers, scheduled tasks, and suspicious services on the named persistence hosts. Reimage where provenance or payload cannot be established.
6. Rotate all credentials that logged onto credential-theft hosts, beginning with domain, service, backup, deployment, and privileged administrative accounts. Reset secrets in dependency order from known-clean systems so compromised hosts cannot capture replacements.
7. Review Kerberos service-account exposure and reset affected service secrets. If evidence establishes domain-controller credential-material compromise, perform the organisation’s controlled double reset of the Kerberos ticket-granting account as part of forest recovery.
8. Hunt for and remove Cobalt Strike pipe/process artefacts, renamed `procdump/adfind` variants, encoded PowerShell payloads, Mimikatz artefacts, dumps, staging files, and remote-service binaries. Exact hashes and paths must be derived during acquisition because none are supplied here.

**Investigation priorities**

1. Determine whether `DC01` privileges or directory objects changed: collect Security, Directory Service, PowerShell, RDP, Sysmon/EDR, and AD object-change records spanning 2025-10-27T11:59:18Z through 2026-08-19T10:08:38Z.
2. Determine whether `CA01` issued or enabled malicious certificates: examine CA operational/audit logs, the issuance database, template and ACL history, private-key access, certificate requests, and backups around and after 2026-04-02T04:22:27Z.
3. Establish the source and direction of every cross-host service-account session: retrieve domain-controller authentication events, network logons, source IPs, logon IDs, and remote-service/RDP/WMI records for all 18 exact cross-host timestamps.
4. Establish `MECM01` abuse: review deployment, package, application, script, collection, client-push, administrator, and site-control history from 2025-10-07T00:49:40Z through 2026-06-28T13:07:12Z.
5. Recover process, command-line, path, parent, signer, pipe-name, and hash evidence for all Cobalt Strike, Mimikatz, LSASS, Rubeus, encoded PowerShell, and renamed-binary detections.
6. Identify the initial-access path: obtain `WKS043` telemetry before 2025-08-31T15:15:16Z plus email, browser, proxy, DNS, VPN, identity-provider, and domain-authentication records for the same preceding period.
7. Test whether each service account’s activity was authorised: compare the exact hosts and timestamps against ownership records, scheduled jobs, service dependencies, change tickets, password changes, and approved administrative source hosts.
8. Determine whether data was staged or exfiltrated: examine endpoint file activity, archive creation, cloud and proxy logs, DNS, firewall/netflow, removable-media records, and outbound transfer telemetry across the full evidence interval.
9. Acquire the six no-finding hosts—`WKS012`, `WKS041`, `WKS047`, `WKS066`, `WKS069`, and `WKS074`—and confirm whether zero findings reflect clean telemetry, missing sensors, or retention gaps.

**Containment confidence: HIGH** that the named credentials and confirmed tooling hosts require immediate action. **Recovery scope confidence: MODERATE** because domain and CA compromise consequences depend on missing privilege, directory-change, certificate, and key-access evidence.

## Limitations

- All asset severities are recorded as `informational`, even where findings are critical or high. Host prioritisation therefore relies on role, technique, corroboration, and cross-host reach rather than the asset-severity field. **Confidence: HIGH.**
- The graph supplies 220 findings across 100 hosts over 363 days, but six hosts have no findings. It does not state whether sensors were continuously healthy, whether all relevant log sources were collected, or whether retention was complete. **Confidence: HIGH** that absence of findings cannot establish those hosts were clean.
- No raw events, process trees, command lines, named-pipe values, file paths, hashes, source/destination IP addresses, logon IDs, ticket details, or external IOCs are included. Exact tool variants and movement direction therefore cannot be reconstructed. **Confidence: HIGH.**
- The role hints for `DC01`, `DC02`, `CA01`, and `MECM01` are inferred from hostnames. Their actual installed roles and authority must be confirmed from configuration. **Confidence: MODERATE** in the inferred roles.
- The graph contains no finding disposition fields identifying benign or known-to-IT detections. Consequently, none could be explicitly excluded on that basis. Authorised administration remains a possible explanation for individual medium-confidence detections, although it does not plausibly explain the independently corroborated intrusion as a whole. **Confidence: HIGH** for the overall intrusion, variable for isolated findings.
- No account is mapped to individual process executions, and the identities model treats each service account separately. It is not possible to prove that one person operated all accounts or to distinguish several adversaries from one operator rotating credentials. **Confidence: HIGH.**
- No account-creation, password-change, group-membership, directory-object, Group Policy, or certificate issuance/change records are provided. Domain-wide control and certificate compromise remain plausible but unproven. **Confidence: HIGH.**
- No data-access or exfiltration telemetry is included. The assessment cannot determine what business data was viewed, staged, altered, or removed. **Confidence: HIGH.**
- The earliest recorded event is already post-exploitation activity. Initial access may predate 2025-08-31T15:15:16Z, and the evidence window may omit the root-cause event. **Confidence: HIGH.**
- If a severity floor excluded lower-severity findings, the payload does not state its threshold or which detections were omitted. Lower-level precursor, cleanup, and benign-context events may therefore be missing. **Confidence: MODERATE.**