# Medium-SIGMA coverage boundary (E21)

Only high/critical SIGMA is promoted to a finding (correlate.py:776, deliberate noise control). These planted techniques are therefore INVISIBLE to the report and the analyst:

| Technique | ATT&CK | Planted severity |
|---|---|---|
| Encoded PowerShell execution | T1059.001 | medium |
| Scheduled task persistence | T1053.005 | medium |
| AD discovery (net group) | T1069.002 | medium |
| Unauthorized RMM tool (AnyDesk) | T1219 | medium |

**4 of 41 planted techniques are invisible.**

Decision for the morning: promote specific high-value medium rules (discovery, RMM) rather than lowering the threshold globally — a global change reintroduces the medium/informational flood the gate exists to stop.
