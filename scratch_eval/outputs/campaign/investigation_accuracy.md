# AI investigation accuracy vs simulation

The agentic Investigate loop answered 10 questions about a known simulated incident (25-technique corpus fused into one case). Correct = the grounded answer names the planted activity on the right host; for negative controls, correctly reports no evidence.

**Investigation accuracy: 9/10 (90%)** — present 7/8, negative-control 2/2 (no fabrication).

| # | Question | Type | Correct | KW | Host | Tools | Answer (head) |
|---|---|---|:--:|:--:|:--:|---|---|
| 1 | What credential-dumping activity targeting LSASS occ | plant | ✅ | ✓ | ✓ | search>evidence | **Confidence: HIGH**  **Observation:** The raw evidence cont |
| 2 | Is there evidence of Kerberos abuse such as Kerberoa | plant | ✅ | ✓ | ✓ | list_findings>evidence>search>evidence | **Confidence: HIGH**  **OBSERVATION** - `WKS-EVAL02` produce |
| 3 | Which single account was used across more than one h | plant | ✅ | ✓ | ✓ | list_findings>evidence | **Account:** `adatumlab\svc_backup`  **Confidence:** HIGH  * |
| 4 | Was Windows Defender tampered with or disabled, and  | plant | ✅ | ✓ | ✓ | list_findings>evidence>search>pivot | **Confidence: HIGH**  **Observation:** Windows Defender real |
| 5 | Is there any evidence of ransomware or anti-recovery | plant | ✅ | ✓ | ✓ | list_findings>search>evidence>evidence | **Confidence: HIGH**  **OBSERVATION** - On `WKS-EVAL07`, Hay |
| 6 | Was any data exfiltration to cloud storage observed, | plant | ✅ | ✓ | ✓ | list_findings>search>search>evidence | **Confidence: HIGH**  **OBSERVATION:** The evidence contains |
| 7 | What process-injection activity was seen, and on whi | plant | ✅ | ✓ | ✓ | list_findings>evidence>search | **Confidence: HIGH**  **OBSERVATION** - On **WKS-EVAL01**, m |
| 8 | Was a renamed system utility (e.g. procdump) used fo | plant | ❌ | ✓ | — | list_findings>search>search>evidence>pivot | **Confidence: LOW**  **OBSERVATION** - A critical finding re |
| 9 | Is there any evidence of cryptocurrency mining (XMRi | neg-ctrl | ✅ | ✓ | ✓ | search>search>clusters>list_findings | **Confidence: MODERATE**  **OBSERVATION** - Searches for `XM |
| 10 | Was there any macOS or Linux malware activity in thi | neg-ctrl | ✅ | ✓ | ✓ | list_findings>search>search>search | **Conclusion:** No macOS or Linux malware activity was ident |
