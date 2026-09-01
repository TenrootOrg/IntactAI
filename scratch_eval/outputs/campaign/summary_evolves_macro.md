# Does the summary evolve as the investigation narrows?

Operator spec: the summary should convey the most likely story and CHANGE as chat/timeline narrow during the investigation.

| Stage | Scope | Altitude | Summary chars |
|---|---|---|---|
| full scope | 30 hosts, 1081 findings, 199d span | **macro** | 5,639 |
| narrow window (19d) | 30 hosts, 122 findings, 19d span | **macro** | 6,083 |
| tight window (3d) | 30 hosts, 25 findings, 3d span | **macro** | 6,125 |

- narrative similarity full→window: **0.18** (lower = it changed)
- narrative similarity window→tight: **0.17**

**Altitude transition: macro → macro → macro**

## Read
The summary should move from a ranked triage map (macro) to one explicit theory (focused) as scope narrows, and the text should genuinely differ — a high similarity would mean the summary ignored the narrowing.
