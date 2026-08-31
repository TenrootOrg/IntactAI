## Assessment

Across 100 hosts and 220 findings over 363 days (2025-08-31 to 2026-08-30), the dominant pattern is credential access, cross-host service-account use, persistence, and defence evasion, with confirmed Cobalt Strike indicators on multiple workstations. This reads as **SEVERAL candidate compromise clusters**, potentially mixed with legitimate administration; the graph does not establish one continuous campaign across the full period. Overall confidence: **MODERATE** — individual detections are strong, but sparse temporal linkage and absent process/network context prevent campaign-level attribution.

## Candidate Scenarios

**1. Tier-zero credential compromise and administrative-plane access**

- **What** — Compromised service credentials may have reached `DC01` and `MECM01`, enabling domain-wide credential theft or software-distribution abuse.
- **Where/When** — `MECM01`, `DC01`, and associated workstations; 2025-10-07 to 2026-06-28.
- **Evidence** — `adatumlab\svc5` crossed `MECM01`, `WKS009`, `WKS026`, `WKS078`, `WKS048`, and `WKS019` at `2025-10-07T00:49:40Z`, then crossed `DC01` and five workstations at `2025-10-29T05:46:33Z`. `MECM01` later recorded encoded PowerShell (`2025-11-01T01:13:55Z`), LSASS access (`2026-03-04T07:34:28Z`), and Rubeus (`2026-06-28T13:07:12Z`). `DC01` recorded Rubeus (`2026-05-07T03:17:02Z`), alongside earlier renamed tooling and outbound RDP.
- **Confidence** — **MODERATE**: multiple high-confidence techniques affect privileged systems, but their wide separation in time does not prove a single sequence.
- **Zoom** — Pull `MECM01` and `DC01` telemetry for ±24 hours around `2025-10-07T00:49:40Z`, `2025-10-29T05:46:33Z`, `2026-03-04T07:34:28Z`, and `2026-05-07T03:17:02Z`; resolve `adatumlab\svc5` source logons, parent processes, ticket activity, and MECM deployments.

**2. Active Cobalt Strike footholds with credential theft**

- **What** — Multiple workstations may have hosted independent or recurring Cobalt Strike sessions followed by credential-access activity.
- **Where/When** — Highest-value pairs are `WKS097` (`2026-04-20`–`2026-05-09`) and `WKS043` (`2026-05-09`–`2026-05-30`); older indicators affect `WKS063`, `WKS092`, `WKS018`, `WKS005`, `WKS064`, `WKS060`, `WKS082`, and `WKS091`.
- **Evidence** — `WKS097` recorded a high-confidence Cobalt Strike named pipe at `2026-04-20T07:13:52Z` and Mimikatz at `2026-05-09T20:59:31Z`. `WKS043` recorded Rubeus at `2026-05-09T00:37:03Z`, Mimikatz at `2026-05-21T14:02:28Z`, and a Cobalt Strike named pipe at `2026-05-30T18:13:56Z`. The newest critical instance is `WKS091` at `2026-06-28T15:20:38Z`.
- **Confidence** — **HIGH** that these hosts warrant compromise validation; **LOW** that all instances belong to one campaign, because no shared hash, infrastructure, process, or identity is supplied.
- **Zoom** — Examine each host independently, initially `WKS097` from `2026-04-19` to `2026-05-10` and `WKS043` from `2026-05-08` to `2026-05-31`; recover named-pipe owners, process trees, memory, outbound destinations, and credentials exposed.

**3. Shared service-account lateral movement**

- **What** — `adatumlab\svc1`, `adatumlab\svc5`, `adatumlab\svc7`, and `adatumlab\svc10` may be reused for lateral movement across workstation clusters.
- **Where/When** — Discrete bursts from `2025-10-07` through `2026-08-17`; the latest is `adatumlab\svc1` across `WKS073`, `WKS040`, `WKS043`, `WKS088`, `WKS044`, and `WKS076`.
- **Evidence** — High-confidence cross-host findings include `adatumlab\svc7` across six hosts including `DC01` at `2025-11-24T04:01:26Z`; `adatumlab\svc10` across six hosts including `WKS091` and `WKS049` at `2026-05-14T01:04:12Z`; and `adatumlab\svc1` across six hosts at `2026-08-17T03:17:13Z`. Several endpoints also show credential theft or persistence, including `WKS043`, `WKS049`, `WKS053`, and `WKS091`.
- **Confidence** — **MODERATE**: simultaneous cross-host use is anomalous and explicitly mapped to T1021/T1078, but service-account purpose, approved management paths, and source systems are missing.
- **Zoom** — Start with `adatumlab\svc1` on the six hosts from `2026-08-17T02:17:13Z` to `2026-08-17T04:17:13Z`; determine the source host, logon types, remote service/task creation, and whether activity matches an approved job.

**4. Recent reconnaissance and defence-evasion cluster**

- **What** — Recent activity may represent renewed discovery and execution rather than residue from older compromises.
- **Where/When** — `WKS057`, `WKS083`, `WKS040`, `WKS043`, `WKS044`, `WKS076`, `DC01`, `WKS089`, `WKS035`, `WKS026`, and `WKS042`; 2026-08-02 to 2026-08-30.
- **Evidence** — Rubeus on `WKS057` (`2026-08-02T19:35:22Z`), SharpHound on `WKS057` (`2026-08-16T05:21:38Z`), WMI persistence on `WKS083` (`2026-08-16T14:58:50Z`), six-host `adatumlab\svc1` use (`2026-08-17T03:17:13Z`), outbound RDP on `DC01` (`2026-08-19T10:08:38Z`), Defender disabled on `WKS089` (`2026-08-23T03:40:15Z`), and SharpHound on `WKS026` (`2026-08-28T19:09:02Z`).
- **Confidence** — **LOW** as one cluster: recency raises operational concern, but the graph provides no common IOC or initiating host.
- **Zoom** — Correlate those hosts from `2026-08-16T00:00:00Z` through `2026-08-30T23:59:59Z`, pivoting first on `adatumlab\svc1`, remote-logon sources, and shared process or network indicators.

## Suspicious Timeframes & Clusters

1. **2025-10-07 to 2025-11-01 — `MECM01`/`DC01` and `adatumlab\svc5`: HIGH risk.** Cross-host access reaches both management and domain infrastructure, followed by encoded PowerShell on `MECM01`.
2. **2026-04-20 to 2026-05-31 — `WKS097`/`WKS043`: HIGH risk.** Cobalt Strike, Mimikatz, and Rubeus concentrate on two hosts in bounded windows.
3. **2026-06-28 — `MECM01`/`WKS091`/`WKS016`: HIGH risk.** Rubeus on `MECM01`, Cobalt Strike on `WKS091`, and LSASS access on `WKS016` occur within nine hours; correlation remains an inference.
4. **2026-08-16 to 2026-08-30 — recent multi-host cluster: MODERATE risk.** Discovery, persistence, service-account spread, tier-zero RDP, defence impairment, and encoded PowerShell indicate potentially continuing access.

## Priority actions

**Contain now**

- Isolate `WKS097`, `WKS043`, and `WKS091` pending validation; each has a Cobalt Strike named-pipe finding, with credential-theft detections on `WKS097` and `WKS043`.
- Disable or rotate `adatumlab\svc1` under emergency change control and terminate its active sessions; it touched six hosts at `2026-08-17T03:17:13Z`. If operationally indispensable, restrict it to documented source and destination systems first.
- Protect `DC01` and `MECM01`: block non-approved interactive/remote access and rotate credentials demonstrably exposed on them. Do not isolate these tier-zero systems without continuity planning; justification is Rubeus on both and cross-host `adatumlab\svc5` use.
- Isolate `WKS089` if Defender remains disabled; the finding occurred at `2026-08-23T03:40:15Z`, after earlier Rubeus and SharpHound detections on that host.

**Investigate next**

- Investigate the tier-zero scenario first: pull memory and full endpoint/network timelines from `MECM01` and `DC01`, then the `adatumlab\svc5` peers `WKS009`, `WKS026`, `WKS078`, `WKS048`, `WKS019`, `WKS006`, `WKS013`, `WKS072`, and `WKS068`.
- The decisive question is: **Were the `adatumlab\svc5` logons to `MECM01` and `DC01` generated by an approved management workflow, or by an anomalous source/process that also produced the PowerShell, LSASS, Rubeus, or remote-access activity?**