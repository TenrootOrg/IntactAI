## Assessment

Five hosts show activity over 53 minutes on 2026-08-01, dominated by credential theft, defense evasion, C2 tooling, and shared-account movement across `WKS-EVAL04` and `WKS-EVAL05`. This reads as several high-risk clusters that may belong to one campaign, but the graph directly links only the latter two hosts; campaign unity remains undetermined. Overall confidence: **MODERATE**, driven by high-confidence injected C2 on `WKS-EVAL01` and cross-host use of `adatumlab\svc_backup`, offset by mostly medium-confidence SIGMA detections.

## Candidate Scenarios

**1. Active Cobalt Strike access following credential theft**

- **What** — `WKS-EVAL01` may be actively compromised, with LSASS credential theft, log clearing, and an injected Cobalt Strike beacon.
- **Where/When** — `WKS-EVAL01`, `2026-08-01T09:12:00Z`–`2026-08-01T09:50:00`.
- **Evidence** — “Mimikatz LSASS Credential Dumping” at `09:12:00Z`; “Security Eventlog Cleared” at `09:20:00Z`; injected/RWX `explorer.exe (4820)` matching `CobaltStrike_Beacon` and beaconing externally at `09:50:00` (T1055, T1071).
- **Confidence** — **HIGH** that `WKS-EVAL01` is compromised, driven by the high-confidence memory/C2 finding corroborated by credential-theft and anti-forensic detections. Its relationship to other hosts is **LOW** confidence because no graph edge connects them.
- **Zoom** — `WKS-EVAL01`, `2026-08-01T08:45:00Z`–`2026-08-01T10:15:00Z`; acquire memory and reconstruct process, network, authentication, and event-log-clearing activity around PID `4820`.

**2. Compromised backup credential used for movement and tooling**

- **What** — `adatumlab\svc_backup` may have been used to move between `WKS-EVAL04` and `WKS-EVAL05`, followed by credential dumping and Cobalt Strike execution.
- **Where/When** — `WKS-EVAL04` and `WKS-EVAL05`, `2026-08-01T09:55:00Z`–`2026-08-01T10:05:00Z`.
- **Evidence** — High-confidence cross-host authentication/execution by `adatumlab\svc_backup` at `09:55:00Z` (T1021, T1078); Cobalt Strike named-pipe detection on `WKS-EVAL05` at `10:00:00Z`; renamed ProcDump execution on `WKS-EVAL04` at `10:05:00Z`.
- **Confidence** — **MODERATE**. The shared-account edge is direct and high confidence, and adjacent tooling is suspicious; the graph does not establish direction, originating host, or whether the account use was authorized. The identity record lists the account on `WKS-EVAL04` only, a coverage discrepancy requiring validation.
- **Zoom** — Both hosts, `2026-08-01T09:30:00Z`–`2026-08-01T10:30:00Z`; resolve logon source/destination, session type, process ancestry, named-pipe creator, and all `adatumlab\svc_backup` activity.

**3. Kerberos credential abuse with endpoint defenses suppressed**

- **What** — `WKS-EVAL02` may have been used for Kerberos ticket abuse after Windows Defender real-time protection was disabled.
- **Where/When** — `WKS-EVAL02`, `2026-08-01T09:30:00Z`–`2026-08-01T09:35:00Z`.
- **Evidence** — Rubeus Kerberos ticket-request detection at `09:30:00Z`, followed by Defender real-time protection being disabled at `09:35:00Z`.
- **Confidence** — **MODERATE** for malicious activity because two medium-confidence detections align closely; **LOW** for connection to the other clusters because no shared identity, process, or IOC is present.
- **Zoom** — `WKS-EVAL02` and relevant domain-controller authentication logs, `2026-08-01T09:00:00Z`–`2026-08-01T10:00:00Z`; determine which account requested which service tickets and whether it subsequently accessed another host.

## Priority actions

**Contain now**

- Isolate `WKS-EVAL01` while preserving memory; high-confidence injected `explorer.exe (4820)` was beaconing at `2026-08-01T09:50:00`.
- Disable or rotate `adatumlab\svc_backup` and terminate its sessions on `WKS-EVAL04` and `WKS-EVAL05`; high-confidence cross-host use occurred at `2026-08-01T09:55:00Z`.
- Isolate `WKS-EVAL05`; the Cobalt Strike named-pipe detection at `2026-08-01T10:00:00Z` indicates possible active post-exploitation tooling.
- Contain `WKS-EVAL02` pending validation and restore Defender protection; Rubeus activity and protection disablement occurred at `09:30:00Z` and `09:35:00Z`.

**Investigate next**

- Start with `WKS-EVAL01`: pull memory, network telemetry, process ancestry, and authentication history for `2026-08-01T08:45:00Z`–`10:15:00Z`.
- In parallel, reconstruct `adatumlab\svc_backup` sessions across `WKS-EVAL04` and `WKS-EVAL05` from `09:30:00Z`–`10:30:00Z`.
- The decisive question: did credentials or infrastructure originating from `WKS-EVAL01` authenticate to `WKS-EVAL02`, `WKS-EVAL04`, or `WKS-EVAL05`? That determines whether this is one campaign or several independent compromises.