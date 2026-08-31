# MASTER RESULTS — attack-simulation accuracy (all runs)

Every run measures our system against KNOWN simulated ground truth (authored PowerShell attack telemetry through the real pipeline). The headline row is how accurately the AI investigation reproduces what was actually simulated.

| Test | Scope | Result | Accuracy |
|---|---|---|:--:|
| Detection recall | 33 scenarios | 29/33 detected; all misses are medium-SIGMA (by design) | 88% |
| Host grounding | 29 detections | 29/29 correct host | 100% |
| Severity correct | 29 detections | 27/29 | 93% |
| Precision (benign input) | benign telemetry | 0 false positive(s) | ✅ PASS |
| Noise robustness | attack + 20× benign | 29/29 survive | ✅ |
| Combined report grounding | 5-host incident | 92/100 grounding | 92% |
| **AI investigation vs simulation** | 15 questions | 11/12 plants found, 3/3 neg-controls clean | **93%** |

## Per-run detail (md in this folder)
- `accuracy_per_scenario.md` — every technique, detected/host/severity
- `accuracy_precision.md` — false positives on benign input
- `accuracy_noise.md` — recall under 20× benign noise
- `accuracy_combined.md` + `accuracy_combined_report.md` — fused incident, LLM-judged
- `investigation_accuracy.md` — the AI investigation's answers vs the answer key
- `ACCURACY_SUMMARY.md` — narrative summary + characterized boundaries
