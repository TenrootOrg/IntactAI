# Track E — synthetic agentic-scale enablement

6/6 checks passed. Proves synth cases can drive evidence()/pivot() (previously report-path only), unblocking Track-B variance testing at 100-host scale.

| Check | Result |
|---|---|
| few_short: pivot resolves events | PASS — 3h/14f -> 42 event entities, pivot total_matches=42 |
| few_short: evidence resolves raw rows | PASS — finding f_ch_0 -> 3 raw rows (e.g. ['EventTime', 'Computer', 'User', 'CommandLine', 'SHA256', 'TargetIP']) |
| few_short: list_findings | PASS — 5 findings |
| many_long: pivot resolves events | PASS — 100h/220f -> 660 event entities, pivot total_matches=660 |
| many_long: evidence resolves raw rows | PASS — finding f_ch_0 -> 3 raw rows (e.g. ['EventTime', 'Computer', 'User', 'CommandLine', 'SHA256', 'TargetIP']) |
| many_long: list_findings | PASS — 5 findings |
