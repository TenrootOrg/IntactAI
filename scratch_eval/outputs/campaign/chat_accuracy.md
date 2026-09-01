# Chat (Ask path) accuracy vs simulation

Chat answers from ONE distilled payload with no fetch-to-cite tool loop, so this is where fabrication is most likely. Neutral phrasing throughout.

**Chat accuracy: 33/33 — plants 24/24, negative controls 9/9 clean.**

| # | Question | Type | Correct | KW | Host | Answer (head) |
|---|---|---|:--:|:--:|:--:|---|
| 1 | Which host shows LSASS credential dumping, and | plant | ✅ | ✓ | ✓ | WKS-EVAL01 shows LSASS credential dumping at **2026-08-0 |
| 2 | Was a Kerberos ticket attack (Rubeus / Kerbero | plant | ✅ | ✓ | ✓ | Yes—Kerberos ticket abuse was observed on **WKS-EVAL02** |
| 3 | Which single account appears on more than one  | plant | ✅ | ✓ | ✓ | The single cross-host account is **`adatumlab\svc_backup |
| 4 | Was Windows Defender disabled or tampered with | plant | ✅ | ✓ | ✓ | Yes. The graph records **Windows Defender real-time prot |
| 5 | Is there ransomware or shadow-copy deletion ac | plant | ✅ | ✓ | ✓ | Yes—both are on **WKS-EVAL07**.  **Observations from the |
| 6 | Was data exfiltrated to cloud storage, and fro | plant | ✅ | ✓ | ✓ | Likely yes, from **WKS-EVAL04**.  - **Observation:** A h |
| 7 | What process injection was observed and on whi | plant | ✅ | ✓ | ✓ | Two process-injection observations are present:  - **WKS |
| 8 | Was NTDS.dit extracted from a domain controlle | plant | ✅ | ✓ | ✓ | Yes. The graph records **“NTDS.dit Extraction via Ntdsut |
| 9 | Is there evidence of cryptocurrency mining (XM | neg-ctrl | ✅ | ✓ | ✓ | No—this graph contains no evidence specifically indicati |
| 10 | Was there any macOS or Linux malware in this e | neg-ctrl | ✅ | ✓ | ✓ | No macOS or Linux malware is evidenced in this graph. Al |
| 11 | Did an attacker use a printer-spooler exploit  | neg-ctrl | ✅ | ✓ | ✓ | No evidence in this graph supports PrintNightmare or any |
| 12 | Which host shows LSASS credential dumping, and | plant | ✅ | ✓ | ✓ | WKS-EVAL01. A SIGMA detection identified **Mimikatz** du |
| 13 | Was a Kerberos ticket attack (Rubeus / Kerbero | plant | ✅ | ✓ | ✓ | Yes—on **WKS-EVAL02**.  **Observed:** A high-severity “R |
| 14 | Which single account appears on more than one  | plant | ✅ | ✓ | ✓ | The single cross-host account is **`adatumlab\svc_backup |
| 15 | Was Windows Defender disabled or tampered with | plant | ✅ | ✓ | ✓ | Yes—Windows Defender real-time protection was disabled o |
| 16 | Is there ransomware or shadow-copy deletion ac | plant | ✅ | ✓ | ✓ | Yes—both occurred on **WKS-EVAL07**.  - **Observed:** Ra |
| 17 | Was data exfiltrated to cloud storage, and fro | plant | ✅ | ✓ | ✓ | Yes—there is strong evidence of cloud exfiltration from |
| 18 | What process injection was observed and on whi | plant | ✅ | ✓ | ✓ | Two process-injection observations are present:  - **WKS |
| 19 | Was NTDS.dit extracted from a domain controlle | plant | ✅ | ✓ | ✓ | **Observation:** NTDS.dit extraction via `ntdsutil` was |
| 20 | Is there evidence of cryptocurrency mining (XM | neg-ctrl | ✅ | ✓ | ✓ | No—this graph contains no explicit evidence of XMRig, Mo |
| 21 | Was there any macOS or Linux malware in this e | neg-ctrl | ✅ | ✓ | ✓ | No evidence of macOS or Linux malware appears in this gr |
| 22 | Did an attacker use a printer-spooler exploit  | neg-ctrl | ✅ | ✓ | ✓ | No evidence in this graph supports PrintNightmare or any |
| 23 | Which host shows LSASS credential dumping, and | plant | ✅ | ✓ | ✓ | WKS-EVAL01 shows LSASS credential dumping at 2026-08-01 |
| 24 | Was a Kerberos ticket attack (Rubeus / Kerbero | plant | ✅ | ✓ | ✓ | Yes—Kerberos ticket abuse was detected on **WKS-EVAL02** |
| 25 | Which single account appears on more than one  | plant | ✅ | ✓ | ✓ | The single cross-host account is **`adatumlab\svc_backup |
| 26 | Was Windows Defender disabled or tampered with | plant | ✅ | ✓ | ✓ | Yes. Windows Defender real-time protection was disabled |
| 27 | Is there ransomware or shadow-copy deletion ac | plant | ✅ | ✓ | ✓ | Yes—both occurred on **WKS-EVAL07**:  - **Observed:** Ra |
| 28 | Was data exfiltrated to cloud storage, and fro | plant | ✅ | ✓ | ✓ | Likely yes, from **WKS-EVAL04**.  - **Observation:** A h |
| 29 | What process injection was observed and on whi | plant | ✅ | ✓ | ✓ | Two process-injection observations are present:  - **WKS |
| 30 | Was NTDS.dit extracted from a domain controlle | plant | ✅ | ✓ | ✓ | Yes. The graph records **“NTDS.dit Extraction via Ntdsut |
| 31 | Is there evidence of cryptocurrency mining (XM | neg-ctrl | ✅ | ✓ | ✓ | No—there is no direct evidence of cryptocurrency mining |
| 32 | Was there any macOS or Linux malware in this e | neg-ctrl | ✅ | ✓ | ✓ | No evidence of macOS or Linux malware appears in this gr |
| 33 | Did an attacker use a printer-spooler exploit  | neg-ctrl | ✅ | ✓ | ✓ | No evidence in this graph supports PrintNightmare or any |
