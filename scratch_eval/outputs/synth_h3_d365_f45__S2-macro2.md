## Assessment

Three tier-zero hosts—domain controllers `DC01` and `DC02`, and certificate authority `CA01`—have 45 findings across 351 days, from `2025-09-08T05:39:04Z` to `2026-08-26T01:27:05Z`. The dominant activity is credential access, persistence, defence evasion, and lateral use of `adatumlab\svc0`; the strongest concentration is `CA01`–`DC01` in March–April 2026. This supports several candidate episodes rather than one continuous campaign because the evidence lacks process, network, and session-level links across the full period. Overall confidence: **MODERATE**, driven by strong detections on critical systems but sparse underlying artifacts.

## Candidate Scenarios

1. **Tier-zero compromise spanning CA01 and DC01**

   - **What** — `CA01` may have hosted Cobalt Strike before `adatumlab\svc0` was used laterally to `DC01`, followed by persistence, credential access, discovery, and RDP activity.
   - **Where/When** — `CA01` and `DC01`, `2026-03-14T03:01:00Z`–`2026-04-19T12:22:35Z`.
   - **Evidence** — “Cobalt Strike Named Pipe on CA01” at `2026-03-14T03:01:00Z`; cross-host use of `adatumlab\svc0` on `CA01` and `DC01` at `2026-03-14T14:19:34Z` and `2026-03-20T03:10:26Z`; then scheduled-task persistence, LSASS access, SharpHound, outbound RDP, Defender disablement, and Mimikatz on `DC01` through `2026-04-19T12:22:35Z`.
   - **Confidence** — **MODERATE**. The timing and techniques form a credible chain, but no source/destination sessions, processes, hashes, or named-pipe value establish common execution.
   - **Zoom** — Pull `CA01` and `DC01` telemetry for `2026-03-13T00:00:00Z`–`2026-04-20T23:59:59Z`, prioritising `adatumlab\svc0` logons, process ancestry, service/task creation, named pipes, and RDP endpoints.

2. **Credential theft and Kerberos abuse on the domain controllers**

   - **What** — Credentials may have been harvested on both DCs and used for domain reconnaissance or ticket abuse.
   - **Where/When** — `DC01`, `2025-12-04T21:39:37Z`–`2026-04-19T12:22:35Z`; `DC02`, `2026-02-10T22:52:53Z`–`2026-06-26T00:53:28Z`.
   - **Evidence** — Mimikatz on `DC01` at `2025-12-04T21:39:37Z`, `2026-01-02T02:52:11Z`, and `2026-04-19T12:22:35Z`; Rubeus at `2026-01-09T23:27:41Z`; SharpHound at `2026-01-23T07:05:23Z` and `2026-03-29T15:25:18Z`; LSASS access on `DC02` at `2026-02-10T22:52:53Z` and `2026-06-26T00:53:28Z`, with Mimikatz at `2026-04-28T08:36:21Z`.
   - **Confidence** — **HIGH** that credential-access tooling or equivalent behavior occurred; **LOW** that all events share one operator, because they are separated by months and lack common artifacts.
   - **Zoom** — Examine `DC01` from `2025-12-04T00:00:00Z`–`2026-01-24T23:59:59Z` first, then `DC02` in ±48-hour windows around each LSASS/Mimikatz event. Establish the executing accounts and whether privileged tickets or credentials were subsequently used.

3. **Recurring persistence and defence evasion across tier-zero**

   - **What** — Long-lived unauthorized access—or repeated administrative/testing activity—may have established WMI, service, and scheduled-task persistence while suppressing controls and logs.
   - **Where/When** — All three hosts, `2025-09-22T03:27:51Z`–`2026-08-26T01:27:05Z`.
   - **Evidence** — WMI persistence on `DC02`, `DC01`, and `CA01`; suspicious services on all three; scheduled tasks on both DCs; Defender disabled on all three; security logs cleared on `CA01` and `DC01`. These are repeated technique classes, but no cross-host tooling or account connects them.
   - **Confidence** — **LOW** as one scenario; **MODERATE** that individual persistence/evasion events require validation. The long gaps and missing object names leave benign administration or security testing plausible.
   - **Zoom** — Validate the exact WMI consumers, services, tasks, initiating accounts, and change records on each host within ±24 hours of every cited detection; compare object names and binaries across hosts.

## Suspicious Timeframes & Clusters

1. **`CA01`–`DC01`, `2026-03-14T03:01:00Z`–`2026-04-19T12:22:35Z`** — Highest-risk cluster: Cobalt Strike signal, repeated cross-host `adatumlab\svc0` use, persistence, LSASS access, SharpHound, Defender disablement, outbound RDP, and Mimikatz.

2. **`DC01`–`CA01`, `2026-01-02T02:52:11Z`–`2026-01-23T07:05:23Z`** — Mimikatz and Rubeus on `DC01`, log clearing on `CA01`, then RDP and SharpHound on `DC01`.

3. **All tier-zero hosts, `2025-09-13T16:27:43Z`–`2025-10-30T05:04:04Z`** — `adatumlab\svc0` touched all three hosts, followed by encoded PowerShell, WMI/service persistence, Defender disablement, and log clearing. Correlation remains unproven.

4. **`CA01`–`DC01`–`DC02`, `2026-06-07T09:43:15Z`–`2026-08-26T01:27:05Z`** — Later execution and persistence signals show possible residual access, but no shared account or tooling link ties them together.

## Priority actions

**Contain now**

- Isolate `CA01` and `DC01` from nonessential management paths while preserving domain and certificate services; justified by Cobalt Strike on `CA01` at `2026-03-14T03:01:00Z` and Mimikatz on `DC01` at `2026-04-19T12:22:35Z`. **Confidence: MODERATE**, limited by the age of the events and absence of current-state telemetry.
- Disable or tightly restrict and rotate `adatumlab\svc0`, after validating service dependencies; it was used across `DC01`, `CA01`, and `DC02` at `2025-09-13T16:27:43Z`, and across `CA01`/`DC01` twice in March 2026. **Confidence: HIGH** that the credential has tier-zero reach; authorization of that use is undetermined.
- Protect `DC02` as potentially credential-exposed and remove unnecessary interactive access; Mimikatz was detected at `2026-04-28T08:36:21Z` and LSASS access at `2026-06-26T00:53:28Z`. **Confidence: HIGH** that urgent validation is warranted.

**Investigate next**

- Start with the March–April 2026 `CA01`–`DC01` scenario. Acquire volatile data if the systems remain live, plus EDR/process, authentication, task/service/WMI, RDP, CA audit, and network telemetry for `2026-03-13T00:00:00Z`–`2026-04-20T23:59:59Z`.
- The decisive question is: **Did the process or session responsible for the Cobalt Strike named-pipe detection on `CA01` use `adatumlab\svc0` to access `DC01`?** A matching logon ID, source address, process tree, binary, or service/task artifact would materially strengthen the single-episode hypothesis.
- Reconcile the identity data: the identity record lists `adatumlab\svc0` only on `DC01`, while cross-host findings place it on all three hosts. Until raw authentication evidence resolves this discrepancy, direction of movement and account ownership remain undetermined.