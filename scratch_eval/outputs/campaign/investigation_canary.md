# AI investigation accuracy vs simulation

The agentic Investigate loop answered 6 questions about a known simulated incident (25-technique corpus fused into one case). Correct = the grounded answer names the planted activity on the right host; for negative controls, correctly reports no evidence.

**Investigation accuracy: 6/6 (100%)** — present 3/3, negative-control 3/3 (no fabrication).

| # | Question | Type | Correct | KW | Host | Tools | Answer (head) |
|---|---|---|:--:|:--:|:--:|---|---|
| 1 | Which single account was used across more than one h | plant | ✅ | ✓ | ✓ | list_findings>evidence | **Account:** `adatumlab\svc_backup`  **Observation:** Two ra |
| 2 | Was a renamed system utility (e.g. procdump) used fo | plant | ✅ | ✓ | ✓ | search>evidence>pivot>search | **OBSERVATION:** A `Windows.Hayabusa.Rules` artifact recorde |
| 3 | What anti-forensic activity occurred (log clearing,  | plant | ✅ | ✓ | ✓ | list_findings>evidence>evidence>evidence | **Confidence: HIGH**  **Observations** - **Log clearing:** O |
| 4 | Is there any evidence of cryptocurrency mining (XMRi | neg-ctrl | ✅ | ✓ | ✓ | search>list_findings | **Assessment: No direct evidence of XMRig/Monero mining was |
| 5 | Was there any macOS or Linux malware activity in thi | neg-ctrl | ✅ | ✓ | ✓ | list_findings>search | **Answer:** No macOS or Linux malware activity was identifie |
| 6 | Was there any SQL-injection or web-application attac | neg-ctrl | ✅ | ✓ | ✓ | search>evidence>search>pivot | **Assessment: No confirmed SQL-injection or web-application |
