# AI investigation accuracy vs simulation

The agentic Investigate loop answered 15 questions about a known simulated incident (25-technique corpus fused into one case). Correct = the grounded answer names the planted activity on the right host; for negative controls, correctly reports no evidence.

**Investigation accuracy: 15/15 (100%)** — present 12/12, negative-control 3/3 (no fabrication).

| # | Question | Type | Correct | KW | Host | Tools | Answer (head) |
|---|---|---|:--:|:--:|:--:|---|---|
| 1 | What credential-dumping activity targeting LSASS occ | plant | ✅ | ✓ | ✓ | list_findings>evidence | **Confidence: HIGH**  **Observation:** Windows Hayabusa evid |
| 2 | Is there evidence of Kerberos abuse such as Kerberoa | plant | ✅ | ✓ | ✓ | list_findings>evidence>search>evidence | ### Confidence: HIGH  **OBSERVATION** - `WKS-EVAL02` generat |
| 3 | Which single account was used across more than one h | plant | ✅ | ✓ | ✓ | list_findings>evidence | **Answer:** `adatumlab\svc_backup`  **OBSERVATION:** Raw Win |
| 4 | Was Windows Defender tampered with or disabled, and  | plant | ✅ | ✓ | ✓ | search>list_findings>evidence>pivot | **Confidence: HIGH**  **OBSERVATION:** Windows Defender real |
| 5 | Is there any evidence of ransomware or anti-recovery | plant | ✅ | ✓ | ✓ | search>list_findings>evidence>evidence | **Confidence: HIGH**  **OBSERVATION** - On `WKS-EVAL07`, Hay |
| 6 | Was any data exfiltration to cloud storage observed, | plant | ✅ | ✓ | ✓ | list_findings>search>search>evidence | **Yes.**  **OBSERVATION:** Raw evidence for finding `f_970cc |
| 7 | What process-injection activity was seen, and on whi | plant | ✅ | ✓ | ✓ | list_findings>evidence>search>evidence | **Confidence: HIGH**  **OBSERVATIONS** - **WKS-EVAL01:** Mal |
| 8 | Was a renamed system utility (e.g. procdump) used fo | plant | ✅ | ✓ | ✓ | list_findings>evidence>search>search>evidence | **Confidence: MODERATE**  **OBSERVATION** - A detection titl |
| 9 | Was a golden ticket or forged Kerberos ticket create | plant | ✅ | ✓ | ✓ | list_findings>evidence>pivot | **Confidence: HIGH**  **OBSERVATION:** Raw Hayabusa evidence |
| 10 | What anti-forensic activity occurred (log clearing,  | plant | ✅ | ✓ | ✓ | list_findings>search>search>evidence>evidence | **Confidence: HIGH**  **OBSERVATIONS** - On **WKS-EVAL01** a |
| 11 | Was a LOLBin like certutil used to download a payloa | plant | ✅ | ✓ | ✓ | search>evidence>pivot | **Answer:** Yes—`certutil`, a Windows LOLBin, was detected p |
| 12 | Which host shows the most severe, ransomware-related | plant | ✅ | ✓ | ✓ | list_findings>evidence>evidence | **Answer: WKS-EVAL07**  **Confidence: HIGH**  **OBSERVATION* |
| 13 | Is there any evidence of cryptocurrency mining (XMRi | neg-ctrl | ✅ | ✓ | ✓ | list_findings>search | **Confidence: LOW**  **OBSERVATION:** The top 10 findings in |
| 14 | Was there any macOS or Linux malware activity in thi | neg-ctrl | ✅ | ✓ | ✓ | list_findings>search>search | **Conclusion: No macOS or Linux malware activity was identif |
| 15 | Was there any SQL-injection or web-application attac | neg-ctrl | ✅ | ✓ | ✓ | search>list_findings>clusters>search>search | **Confidence: MODERATE**  **OBSERVATION** - Searches for `SQ |
