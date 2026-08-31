# Timeline robustness + summary-section correctness

| Test | Result | |
|---|---|:--:|
| **B8** timestomping / corrupt times | 8/8 events kept, chronological=True, undated kept=True | ✅ |
| **B9** collapse fidelity @ corpus scale | 36 events → 36 groups; critical shown 11/11 | ✅ |
| **A4** Limitations correctness | quiet-host count: claimed 1, actual 1; quiet host named: named correctly | ✅ |

> B8 note: the 2099 timestomped event is present in the timeline (1 row) and sorts last — it is not dropped, and it is visible as an anomaly rather than silently reordering real events.

