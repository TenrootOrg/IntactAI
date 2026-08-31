## Assessment

Across 25 hosts and 90 findings over 58 days (2026-07-02–2026-08-30), the dominant pattern is repeated credential access, credential theft, discovery, persistence, and suspected Cobalt Strike activity reaching workstations, `MECM01`, `CA01`, `DC01`, and `DC02`. This supports **SEVERAL correlated intrusion scenarios, potentially one campaign**, but the graph lacks process, source-address, session, and IOC linkage needed to force a single narrative. Overall confidence: **HIGH** that material compromise requires containment; **LOW** that all activity shares one operator.

## Candidate Scenarios

**1. Shared service credentials enabled movement into tier-zero systems**

- **What** — `adatumlab\svc0`, `adatumlab\svc1`, and `adatumlab\svc2` may have been abused to traverse workstations and privileged infrastructure.
- **Where/When** — `adatumlab\svc0`: `MECM01`, `DC02`, `CA01` and multiple workstations, 2026-07-04–2026-07-19. `adatumlab\svc1`: `CA01`, `MECM01` and three workstations on 2026-08-02. `adatumlab\svc2`: workstation clusters plus `MECM01`, 2026-07-31–2026-08-05.
- **Evidence** — Cross-host executions by `adatumlab\svc0` on four hosts at `2026-07-04T19:04:44Z` [f_ch_1], six including `DC02` at `2026-07-09T10:16:29Z` [f_ch_0], and six including `CA01` and `DC02` at `2026-07-13T06:32:03Z` [f_ch_3]. `adatumlab\svc1` reached `CA01` and `MECM01` at `2026-08-02T12:16:58Z` [f_ch_6]; `adatumlab\svc2` reached `MECM01` at `2026-08-05T06:06:56Z` [f_ch_2].
- **Confidence** — **HIGH** for shared-credential propagation because seven cross-host findings explicitly correlate the accounts; **MODERATE** for malicious intent because approved service-account workflows and source systems are absent.
- **Zoom** — Pull authentication, remote-service, process, and network telemetry for `DC02`, `CA01`, `MECM01`, `WKS018`, and `WKS024` from `2026-07-04T18:00:00Z` through `2026-08-05T08:00:00Z`.

**2. Credential theft and C2 on a workstation cluster**

- **What** — `WKS023`, `WKS016`, `WKS018`, `WKS024`, `WKS015`, and `WKS010` may represent footholds used for Cobalt Strike, credential theft, and onward movement.
- **Where/When** — The strongest sequence spans `WKS023` on 2026-07-08–07-10, `WKS016` on 2026-07-28, and `WKS018`/`WKS024`/`WKS015`/`WKS010` from 2026-08-03–08-16.
- **Evidence** — High-confidence Cobalt Strike named-pipe detections on `WKS023` at `2026-07-10T11:50:41Z` [f_70], `WKS016` at `2026-07-28T14:16:39Z` [f_75], and `WKS024` at `2026-08-09T04:28:34Z` [f_44]. Medium-confidence detections occurred on `WKS018`, `WKS015`, and `WKS010` [f_25, f_59, f_10, f_9]. Mimikatz/LSASS findings on `WKS024`, `WKS015`, and `WKS010` reinforce compromise [f_40, f_23, f_88].
- **Confidence** — **HIGH** that `WKS023`, `WKS016`, and `WKS024` warrant compromise handling; **MODERATE** that all six hosts form one cluster because no shared pipe name, hash, process, or endpoint is supplied.
- **Zoom** — Acquire memory and detailed endpoint timelines from these six hosts, bounded to ±24 hours around each named-pipe detection; compare pipe values, process ancestry, hashes, C2 destinations, and logged-on identities.

**3. Domain and certificate-services targeting**

- **What** — Activity on `DC01`, `DC02`, and `CA01` may reflect escalation toward domain credentials and certificate infrastructure.
- **Where/When** — `DC01`, 2026-07-12–2026-08-20; `DC02`, 2026-07-09–2026-08-26; `CA01`, 2026-07-13–2026-08-26.
- **Evidence** — `DC01` recorded LSASS access at `2026-08-01T11:06:29Z` and a Rubeus ticket request at `2026-08-20T13:39:48Z` [f_74, f_63]. `DC02` had suspicious service installation, Defender disablement, and SharpHound collection [f_73, f_12, f_8]. `CA01` combined cross-host service-account access with suspicious service installation and outbound RDP [f_ch_3, f_ch_6, f_36, f_18].
- **Confidence** — **MODERATE-HIGH** due to multiple independent techniques on tier-zero hosts; attribution to the workstation/Cobalt Strike cluster remains **LOW** without session-level linkage.
- **Zoom** — Examine `DC01`, `DC02`, and `CA01` from `2026-07-09T09:00:00Z` through `2026-08-27T01:00:00Z`, prioritizing service creation, certificate issuance, privileged logons, Kerberos requests, LSASS accessors, and outbound RDP destinations.

## Suspicious Timeframes & Clusters

1. **2026-07-09–07-19 — `DC02`/`CA01` plus `WKS018`, `WKS023`, `WKS012`, `WKS024`, `WKS007`: HIGH.** Two six-host `adatumlab\svc0` events [f_ch_0, f_ch_3], followed by Cobalt Strike on `WKS023` [f_70], Rubeus on `WKS012` [f_17], and a service installation on `DC02` [f_73].
2. **2026-07-31–08-05 — `MECM01`, `WKS018`, `WKS024`, `WKS010`, `WKS014`, `WKS011`: HIGH.** `adatumlab\svc2` traversed both clusters [f_ch_4, f_ch_2], adjacent to LSASS access on `MECM01` [f_32] and Cobalt Strike on `WKS018` [f_25].
3. **2026-08-07–08-16 — `WKS015`, `WKS024`, `WKS010`: HIGH.** Repeated Cobalt Strike detections and Mimikatz activity [f_59, f_44, f_23, f_40, f_88, f_10, f_9].
4. **2026-08-20–08-30 — tier-zero and residual persistence cluster: MODERATE-HIGH.** Rubeus on `DC01`, SharpHound on `DC02`, outbound RDP from `CA01`, plus log clearing/persistence on `WKS005`, `WKS014`, `WKS016`, and `WKS012` [f_63, f_8, f_18, f_15, f_66, f_26, f_21].

## Priority actions

**Contain now**

- Isolate `WKS023`, `WKS016`, and `WKS024`; each has a **high-confidence** Cobalt Strike named-pipe finding [f_70, f_75, f_44].
- Isolate or tightly restrict `WKS015`, `WKS010`, and `WKS018` pending validation; each has Cobalt Strike evidence, with Mimikatz additionally present on `WKS015` and `WKS010` [f_10, f_9, f_25, f_23, f_88].
- Disable or rotate `adatumlab\svc0`, `adatumlab\svc1`, and `adatumlab\svc2` after mapping service dependencies; revoke sessions and tickets. Their cross-host use includes `DC02`, `CA01`, and `MECM01` [f_ch_0–f_ch_6].
- Restrict administration and outbound connectivity on `DC01`, `DC02`, and `CA01`; preserve evidence before remediation. LSASS/Rubeus, Defender disablement/SharpHound, and service/RDP activity respectively place tier-zero assets at risk [f_74, f_63, f_12, f_8, f_36, f_18].

**Investigate next**

- Start with the `adatumlab\svc2` cluster on `WKS024`, `WKS010`, `WKS014`, `WKS018`, `WKS011`, and `MECM01`, `2026-07-31T14:00:00Z`–`2026-08-05T08:00:00Z` [f_ch_4, f_ch_2].
- Pull memory first from any still-running `WKS024`, `WKS018`, `WKS010`, and `MECM01`, then full endpoint/authentication timelines.
- Decisive question: **Did the same source host, process, or network session use `adatumlab\svc2` across these systems and produce the Cobalt Strike/LSASS events?** If yes, the graph consolidates toward one campaign; if not, separate administrative misuse, credential compromise, and endpoint incidents must remain distinct.