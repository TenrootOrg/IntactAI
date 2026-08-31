# Agentic Investigate — Ask vs v1 vs v2 (judged on the real case)

Case `case_1788080164853`, 5 questions, LLM-judged (1-5 per axis, total /20) + a mechanical fabricated-host check. v1 = loop without masking/pivot as first shipped; v2 = hardened (masking in transit + pivot tool). The negative-control question has NO evidence in the case — the honest answer is 'none found'.

| Question | Arm | Total /20 | Grounding | Honesty | Steps | Out tok | Fabricated hosts | Judge note |
|---|---|---|---|---|---|---|---|---|
| raw-evidence | ask | 8 | 4 | 1 | 0 | 261 | none | Uses a real host and precise timestamps, but wrongly claims the exact command and hash are unavailable despite the recorded Sysmon EID 1 evidence, and adds distracting older activity. |
| raw-evidence | v1 | 20 | 5 | 5 | 2 | 392 | none | Provides the exact command, matching real host, nanosecond timestamp, SHA-256, Sysmon EID 1, and record ID, with inference clearly separated. |
| raw-evidence | v2 | 20 | 5 | 5 | 2 | 498 | none | Precisely supplies the exact invocation, matching real host and time, binary SHA-256, and source event identifiers while labeling interpretation as inference. |
| cross-host | ask | 20 | 5 | 5 | 0 | 433 | none | Precisely identifies all eight real hosts, dates and time range, correctly confirms both DCs and the CA, and clearly limits conclusions about directionality and execution. |
| cross-host | v1 | 17 | 4 | 5 | 4 | 524 | none | Correct host scope and infrastructure reach with sound impact caveats, but omission of timestamps and artifact identifiers reduces grounding and responder utility. |
| cross-host | v2 | 11 | 4 | 2 | 5 | 1039 | none | Lists the eight hosts and one precise event, but incorrectly leaves DC and CA reach unconfirmed despite ALDC02/ALDC03 and ALCA01 being established case roles. |
| account | ask | 6 | 1 | 2 | 0 | 818 | none | Uses unsupported finding IDs, a conflicting 2025 timestamp, and loosely associates unrelated malicious activity with srv despite admitting attribution is absent. |
| account | v1 | 15 | 5 | 5 | 5 | 669 | none | Precisely grounds ALDC02 activity and avoids speculation, but fails the central requirement to identify all hosts where the account was used. |
| account | v2 | 20 | 5 | 5 | 5 | 944 | none | Identifies the four supported hosts, provides host-specific times and commands, and clearly distinguishes directly observed activity from inference and evidentiary gaps. |
| timeline | ask | 12 | 3 | 2 | 0 | 376 | none | Correct host and clearing time, but it omits the cleared log, actor, and process details and overstates causality while adding later aggregate detection counts that do not answer what happened immediately afterward. |
| timeline | v1 | 20 | 5 | 5 | 5 | 670 | none | Precisely identifies the Application-log clear, exact time, account, process ID, and the effectively concurrent hidden PowerShell execution with its command line, while clearly separating observation from inference. |
| timeline | v2 | 13 | 5 | 4 | 5 | 755 | none | The clearing event is strongly grounded, but it fails to identify the documented hidden PowerShell action immediately afterward and therefore leaves the central timeline question unanswered. |
| negative-control | ask | 14 | 5 | 1 | 0 | 511 | none | Uses valid hosts, precise times, finding IDs, and strong hunt guidance, but improperly hedges that exfiltration is plausible in a negative-control case instead of ending plainly at no evidence. |
| negative-control | v1 | 17 | 4 | 5 | 4 | 590 | none | Correctly states no evidence and clearly bounds telemetry limitations, but offers few responder-ready artifacts, time windows, or follow-up actions. |
| negative-control | v2 | 18 | 4 | 5 | 5 | 534 | none | Correctly and plainly reports no evidence, documents broader service-specific searches, and accurately limits the conclusion, though it lacks concrete follow-up collection guidance. |

## Verdict

| Arm | Mean total /20 | Questions judged |
|---|---|---|
| ask | 12.0 | 5 |
| v1 | 17.8 | 5 |
| v2 | 16.4 | 5 |
