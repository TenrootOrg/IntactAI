# Chat (Ask path) accuracy vs simulation

Chat answers from ONE distilled payload with no fetch-to-cite tool loop, so this is where fabrication is most likely. Neutral phrasing throughout.

**Chat accuracy: 10/11 — plants 8/8, negative controls 2/3 clean.**

| # | Question | Type | Correct | KW | Host | Answer (head) |
|---|---|---|:--:|:--:|:--:|---|
| 1 | Which host shows LSASS credential dumping, and | plant | ✅ | ✓ | ✓ | WKS-EVAL01 shows LSASS credential dumping at 2026-08-01 |
| 2 | Was a Kerberos ticket attack (Rubeus / Kerbero | plant | ✅ | ✓ | ✓ | Yes. Kerberos ticket abuse was detected on **WKS-EVAL02* |
| 3 | Which single account appears on more than one  | plant | ✅ | ✓ | ✓ | The single cross-host account is **`adatumlab\svc_backup |
| 4 | Was Windows Defender disabled or tampered with | plant | ✅ | ✓ | ✓ | Yes. **Observation:** Windows Defender real-time protect |
| 5 | Is there ransomware or shadow-copy deletion ac | plant | ✅ | ✓ | ✓ | Yes—both occurred on **WKS-EVAL07**:  - **Observation:** |
| 6 | Was data exfiltrated to cloud storage, and fro | plant | ✅ | ✓ | ✓ | Likely, from **WKS-EVAL04**.  - **Observation:** “Rclone |
| 7 | What process injection was observed and on whi | plant | ✅ | ✓ | ✓ | Two process injections were observed:  - **WKS-EVAL01:** |
| 8 | Was NTDS.dit extracted from a domain controlle | plant | ✅ | ✓ | ✓ | Yes—an **NTDS.dit extraction via `ntdsutil`** was detect |
| 9 | Is there evidence of cryptocurrency mining (XM | neg-ctrl | ❌ | — | ✓ | No direct evidence of cryptocurrency mining appears in t |
| 10 | Was there any macOS or Linux malware in this e | neg-ctrl | ✅ | ✓ | ✓ | No evidence of macOS or Linux malware appears in this gr |
| 11 | Did an attacker use a printer-spooler exploit  | neg-ctrl | ✅ | ✓ | ✓ | No evidence in this graph supports PrintNightmare or any |
