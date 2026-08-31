# MASTER RESULTS — attack-simulation accuracy (all runs)

Every run measures our system against KNOWN simulated ground truth (authored PowerShell attack telemetry through the real pipeline). The headline row is how accurately the AI investigation reproduces what was actually simulated.

| Test | Scope | Result | Accuracy |
|---|---|---|:--:|
| Detection recall | 25 scenarios | 21/25 detected; all misses are medium-SIGMA (by design) | 84% |
| Host grounding | 21 detections | 21/21 correct host | 100% |
| Severity correct | 21 detections | 20/21 | 95% |
| Precision (benign input) | benign telemetry | 0 false positive(s) | ✅ PASS |
| Noise robustness | attack + 20× benign | 21/21 survive | ✅ |
| Combined report grounding | 5-host incident | 92/100 grounding | 92% |
| **AI investigation vs simulation** | 10 questions | 7/8 plants found, 2/2 neg-controls clean | **90%** |

## Per-run detail (md in this folder)
- `accuracy_per_scenario.md` — every technique, detected/host/severity
- `accuracy_precision.md` — false positives on benign input
- `accuracy_noise.md` — recall under 20× benign noise
- `accuracy_combined.md` + `accuracy_combined_report.md` — fused incident, LLM-judged
- `investigation_accuracy.md` — the AI investigation's answers vs the answer key
- `ACCURACY_SUMMARY.md` — narrative summary + characterized boundaries
