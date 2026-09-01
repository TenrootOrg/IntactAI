# Does the summary evolve as the investigation narrows?

Operator spec: the summary should convey the most likely story and CHANGE as chat/timeline narrow during the investigation.

| Stage | Scope | Altitude | Summary chars |
|---|---|---|---|
| full scope | 8 hosts, 37 findings, 0d span | **focused** | 11,218 |
| narrow window 09:00-09:45 | 8 hosts, 4 findings, 0d span | **focused** | 6,675 |
| tight window 09:10-09:20 | 8 hosts, 2 findings, 0d span | **focused** | 4,650 |

- narrative similarity full→window: **0.10** (lower = it changed)
- narrative similarity window→tight: **0.11**

**Altitude transition: focused → focused → focused**

## Read
The summary should move from a ranked triage map (macro) to one explicit theory (focused) as scope narrows, and the text should genuinely differ — a high similarity would mean the summary ignored the narrowing.
