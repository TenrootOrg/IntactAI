## Assessment

Across 100 hosts from 2026-08-28T01:01:31Z to 2026-08-30T23:15:05Z, the dominant activity is credential access, post-exploitation tooling, persistence, and shared-service-account movement. The evidence supports several potentially related intrusion clusters—not yet one defensible campaign—with the highest business risk around MECM01, five Cobalt Strike detections, and `adatumlab\svc1`/`adatumlab\svc5` propagation. Overall confidence: **MODERATE**, driven by numerous high-confidence detections but limited process, network, and identity context linking the clusters.

## Candidate Scenarios

**1. Compromise of the software-distribution tier**

- **What** — MECM01 may have been used for credential theft and Kerberos abuse, creating a path to broad software-mediated access.
- **Where/When** — MECM01, 2026-08-28T12:14:24Z–2026-08-30T11:28:59Z.
- **Evidence** — Encoded PowerShell at 2026-08-28T12:14:24Z [f_49], high-confidence LSASS access at 2026-08-29T12:33:19Z [f_66], and Rubeus Kerberos ticket activity at 2026-08-30T11:28:59Z [f_55].
- **Confidence** — **MODERATE**: the three-stage pattern is concerning on a software-distribution server, but parent processes, commands, accounts, and ticket targets are absent.
- **Zoom** — MECM01, 2026-08-28T11:30:00Z–2026-08-30T12:00:00Z; determine whether the same process tree or identity connects PowerShell, LSASS access, and Rubeus.

**2. Active post-exploitation implants on multiple workstations**

- **What** — Cobalt Strike-like implants may have established execution on several endpoints, with credential dumping on WKS097.
- **Where/When** — WKS092, WKS064, WKS072, WKS060, and WKS097 between 2026-08-28T10:11:32Z and 2026-08-30T01:41:05Z.
- **Evidence** — Cobalt Strike named pipes on WKS092 [f_62], WKS064 [f_67], WKS072 [f_17], WKS060 [f_51], and WKS097 [f_36]. WKS097 subsequently recorded Mimikatz at 2026-08-30T01:41:05Z [f_32]; WKS064 also recorded a renamed `procdump/adfind` binary [f_35].
- **Confidence** — **MODERATE**: three named-pipe detections are high-confidence, but no shared hash, pipe name, account, or network IOC proves a common operator.
- **Zoom** — Pull memory and full endpoint/network timelines from all five hosts for ±6 hours around each named-pipe event; first test whether WKS097’s pipe process led to Mimikatz.

**3. Shared service-account compromise enabling lateral movement**

- **What** — `adatumlab\svc5` and `adatumlab\svc1` may have been used as reusable credentials for movement and persistence.
- **Where/When** — `adatumlab\svc5`: WKS062, WKS053, WKS005 at 2026-08-28T11:52:38Z. `adatumlab\svc1`: WKS065/WKS053 at 2026-08-29T19:50:42Z, then WKS073/WKS040/WKS043/WKS088/WKS044/WKS076 at 2026-08-30T21:15:55Z.
- **Evidence** — Cross-host authentication/execution by `adatumlab\svc5` [f_ch_1] precedes suspicious service installation on WKS005 [f_65] and later Defender disablement plus Mimikatz on WKS062 [f_27, f_15]. `adatumlab\svc1` crosses two hosts [f_ch_0] and later six hosts [f_ch_2]; WKS065 also shows outbound RDP and WMI persistence [f_68, f_18].
- **Confidence** — **MODERATE**: cross-host reuse is high-confidence and overlaps compromised-looking hosts, but source hosts, logon types, and service-account baselines are missing.
- **Zoom** — For `svc5`, WKS062/WKS053/WKS005 from 2026-08-28T10:30:00Z through 2026-08-29T23:59:59Z. For `svc1`, WKS053/WKS065 plus the six-host cluster from 2026-08-29T19:00:00Z through 2026-08-30T22:00:00Z.

## Suspicious Timeframes & Clusters

1. **MECM01, 2026-08-28T12:14:24Z–2026-08-30T11:28:59Z — HIGH risk.** PowerShell, LSASS access, and Rubeus activity converge on a high-leverage management server [f_49, f_66, f_55].
2. **WKS097/WKS060, 2026-08-29T20:01:59Z–2026-08-30T01:41:05Z — HIGH risk.** Two Cobalt Strike detections, followed by Mimikatz on WKS097 [f_51, f_36, f_32].
3. **WKS062/WKS053/WKS005, 2026-08-28T11:52:38Z–2026-08-29T23:24:47Z — HIGH risk.** `adatumlab\svc5` movement overlaps service persistence, Defender disablement, and Mimikatz [f_ch_1, f_65, f_27, f_15].
4. **WKS065 and six-host `svc1` cluster, 2026-08-29T19:50:42Z–2026-08-30T21:15:55Z — MODERATE risk.** Cross-host account reuse, outbound RDP, WMI persistence, then expansion to six endpoints [f_ch_0, f_68, f_18, f_ch_2].

## Priority actions

**Contain now**

- Isolate WKS097, WKS064, and WKS092 pending validation; each has a high-confidence Cobalt Strike named-pipe detection, with Mimikatz additionally present on WKS097 [f_36, f_67, f_62, f_32].
- Restrict MECM01 management paths and privileged logons; preserve memory before remediation because LSASS access and Rubeus were detected [f_66, f_55].
- Disable or immediately rotate `adatumlab\svc5` and `adatumlab\svc1`, then terminate their active sessions; both show high-confidence cross-host execution [f_ch_1, f_ch_0, f_ch_2].
- Increase monitoring and deny unnecessary access from affected hosts to DC01, DC02, and CA01. No finding currently demonstrates activity on those tier-zero systems.

**Investigate next**

- Start with MECM01 and pull memory, EDR process ancestry, PowerShell logs, Kerberos events, and outbound connections for 2026-08-28T11:30:00Z–2026-08-30T12:00:00Z.
- In parallel, acquire memory and detailed timelines from WKS097 and WKS062, where Cobalt Strike/Mimikatz and `svc5`/Mimikatz respectively overlap [f_36, f_32, f_ch_1, f_15].
- Decisive question: **Do MECM01, the Cobalt Strike hosts, and the `svc1`/`svc5` clusters share one initiating account, process artifact, or network destination?** Without that linkage, campaign scope and tier-zero exposure remain undetermined.