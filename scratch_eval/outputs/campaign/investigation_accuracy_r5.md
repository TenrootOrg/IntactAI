# AI investigation accuracy vs simulation

The agentic Investigate loop answered 15 questions about a known simulated incident (25-technique corpus fused into one case). Correct = the grounded answer names the planted activity on the right host; for negative controls, correctly reports no evidence.

**Investigation accuracy: 15/15 (100%)** — present 12/12, negative-control 3/3 (no fabrication).

| # | Question | Type | Correct | KW | Host | Tools | Answer (head) |
|---|---|---|:--:|:--:|:--:|---|---|
| 1 | What credential-dumping activity targeting LSASS occ | plant | ✅ | ✓ | ✓ | list_findings>evidence>pivot | **Confidence: HIGH**  **Observation:** On **WKS-EVAL01** at |
| 2 | Is there evidence of Kerberos abuse such as Kerberoa | plant | ✅ | ✓ | ✓ | list_findings>search>evidence>search>evidence | **Confidence: MODERATE**  **OBSERVATION** - **WKS-EVAL02** g |
| 3 | Which single account was used across more than one h | plant | ✅ | ✓ | ✓ | list_findings>search>evidence | **Answer:** `adatumlab\svc_backup`  **OBSERVATION:** Windows |
| 4 | Was Windows Defender tampered with or disabled, and  | plant | ✅ | ✓ | ✓ | search>evidence>pivot>search | **Confidence: HIGH that real-time protection was disabled; L |
| 5 | Is there any evidence of ransomware or anti-recovery | plant | ✅ | ✓ | ✓ | list_findings>search>evidence>evidence | **Confidence: HIGH**  **OBSERVATION** - On `WKS-EVAL07`, a c |
| 6 | Was any data exfiltration to cloud storage observed, | plant | ✅ | ✓ | ✓ | list_findings>search>evidence | **Confidence: MODERATE**  **OBSERVATION:** Two raw `Windows. |
| 7 | What process-injection activity was seen, and on whi | plant | ✅ | ✓ | ✓ | list_findings>evidence>search>evidence | **Confidence: HIGH**  **Observations** - **WKS-EVAL01** — At |
| 8 | Was a renamed system utility (e.g. procdump) used fo | plant | ✅ | ✓ | ✓ | search>evidence>pivot | **Confidence: MODERATE**  **OBSERVATION:** `Windows.Hayabusa |
| 9 | Was a golden ticket or forged Kerberos ticket create | plant | ✅ | ✓ | ✓ | search>evidence | **Confidence: MODERATE**  **OBSERVATION:** Two raw `Windows. |
| 10 | What anti-forensic activity occurred (log clearing,  | plant | ✅ | ✓ | ✓ | search>evidence>evidence>evidence>pivot | **Confidence: MODERATE**  **OBSERVATIONS** - **Log clearing: |
| 11 | Was a LOLBin like certutil used to download a payloa | plant | ✅ | ✓ | ✓ | list_findings>search>evidence>pivot | **Confidence: MODERATE**  **OBSERVATION:** A high-severity f |
| 12 | Which host shows the most severe, ransomware-related | plant | ✅ | ✓ | ✓ | list_findings>evidence>search | **WKS-EVAL07** shows the most severe ransomware-related acti |
| 13 | Is there any evidence of cryptocurrency mining (XMRi | neg-ctrl | ✅ | ✓ | ✓ | search>search>list_findings>search | **Confidence: MODERATE**  **OBSERVATION** - Searches for `XM |
| 14 | Was there any macOS or Linux malware activity in thi | neg-ctrl | ✅ | ✓ | ✓ | list_findings>search>search>search | **Conclusion:** No macOS or Linux malware activity was ident |
| 15 | Was there any SQL-injection or web-application attac | neg-ctrl | ✅ | ✓ | ✓ | list_findings>search>evidence>pivot | **Confidence: MODERATE**  **Observation:** The reviewed find |
