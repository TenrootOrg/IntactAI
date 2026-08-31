# AI investigation accuracy vs simulation

The agentic Investigate loop answered 15 questions about a known simulated incident (25-technique corpus fused into one case). Correct = the grounded answer names the planted activity on the right host; for negative controls, correctly reports no evidence.

**Investigation accuracy: 14/15 (93%)** — present 11/12, negative-control 3/3 (no fabrication).

| # | Question | Type | Correct | KW | Host | Tools | Answer (head) |
|---|---|---|:--:|:--:|:--:|---|---|
| 1 | What credential-dumping activity targeting LSASS occ | plant | ✅ | ✓ | ✓ | list_findings>search>evidence | **Confidence: HIGH**  **OBSERVATION:** The finding `f_c970da |
| 2 | Is there evidence of Kerberos abuse such as Kerberoa | plant | ✅ | ✓ | ✓ | list_findings>evidence>evidence>search>pivot | **Confidence: HIGH for golden-ticket activity on WKS-EVAL02; |
| 3 | Which single account was used across more than one h | plant | ✅ | ✓ | ✓ | list_findings>evidence | **Account:** `adatumlab\svc_backup`  **OBSERVATION:** Raw Wi |
| 4 | Was Windows Defender tampered with or disabled, and  | plant | ✅ | ✓ | ✓ | search>list_findings>evidence>pivot | **Confidence: HIGH**  **OBSERVATION:** The case contains a h |
| 5 | Is there any evidence of ransomware or anti-recovery | plant | ✅ | ✓ | ✓ | list_findings>evidence>search>evidence | **Confidence: HIGH**  **OBSERVATION** - On `WKS-EVAL07`, Hay |
| 6 | Was any data exfiltration to cloud storage observed, | plant | ✅ | ✓ | ✓ | list_findings>search>search>evidence | **Answer:** Yes. Cloud-storage exfiltration was observed fro |
| 7 | What process-injection activity was seen, and on whi | plant | ✅ | ✓ | ✓ | list_findings>evidence>search>evidence | **Confidence: HIGH**  **Observations** - **WKS-EVAL01:** Mal |
| 8 | Was a renamed system utility (e.g. procdump) used fo | plant | ❌ | ✓ | — | search>list_findings>evidence>search>pivot | **Confidence: LOW**  **OBSERVATION:** A critical finding rep |
| 9 | Was a golden ticket or forged Kerberos ticket create | plant | ✅ | ✓ | ✓ | list_findings>evidence>pivot | **Confidence: HIGH**  **OBSERVATION:** Raw `Windows.Hayabusa |
| 10 | What anti-forensic activity occurred (log clearing,  | plant | ✅ | ✓ | ✓ | list_findings>search>evidence>search>evidence | ### Confidence: HIGH  ### Observations - **Security log clea |
| 11 | Was a LOLBin like certutil used to download a payloa | plant | ✅ | ✓ | ✓ | search>evidence>pivot | **Confidence: HIGH**  **OBSERVATION:** A high-severity Hayab |
| 12 | Which host shows the most severe, ransomware-related | plant | ✅ | ✓ | ✓ | list_findings>evidence>search | **WKS-EVAL07** shows the most severe ransomware-related acti |
| 13 | Is there any evidence of cryptocurrency mining (XMRi | neg-ctrl | ✅ | ✓ | ✓ | search>search>list_findings | **Confidence: MODERATE**  **OBSERVATION:** Searches for `XMR |
| 14 | Was there any macOS or Linux malware activity in thi | neg-ctrl | ✅ | ✓ | ✓ | list_findings>search>search>search>clusters | **Assessment:** No macOS or Linux malware activity was ident |
| 15 | Was there any SQL-injection or web-application attac | neg-ctrl | ✅ | ✓ | ✓ | search>list_findings>clusters>search>search | **Assessment:** No evidence of SQL injection or a web-applic |
