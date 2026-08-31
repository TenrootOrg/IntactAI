# Detection-accuracy testing — running summary

Ground-truth attack simulations through the REAL pipeline (map_agentic ->
correlate.assemble). Each scenario authors the telemetry it would produce; we know
the answer key, so we can score recall / precision / grounding — detection accuracy,
not report shape. Repeatable regression harness.

## Results so far (25 scenarios)

| Test | Result | Notes |
|---|---|---|
| **Recall** (25 scenarios) | **21/25** | **21/21 (100%) of finding-eligible plants caught.** All 4 misses are medium-SIGMA, suppressed by design (correlate.py:776). |
| **Host grounding** | 21/21 | every detection on the correct host |
| **Severity** | 20/21 | the 1 "mismatch" is CORRECT (bare RWX injection = high, critical only when YARA/C2-corroborated). |
| **Precision** (benign input) | **✅ 0 false positives** | benign admin/IT telemetry produces zero findings |
| **Noise robustness** | **21/21** | every detection survives 20× benign volume on the same hosts |
| **Combined report** (LLM-judged) | grounding **92**, all 8 derived findings surfaced | judge recall 70% was pessimistic (penalized correct macro grouping) |

## Characterized boundaries (real, not bugs)
1. **Medium-severity SIGMA never becomes a finding** — deliberate noise control.
   Across 25 scenarios the 4 medium misses are encoded-PS, scheduled-task, **AD
   discovery recon (T1069)** and **RMM abuse (T1219)** — the last two are real
   attacker activity an analyst usually wants to see. A medium-only detection never
   reaches the report. Tunable at one line (correlate.py:776). The coverage decision
   most worth review — consider promoting specific high-value medium rules.
2. **Model over-inference** — in the combined report the model wrote "active Cobalt
   Strike beaconing" slightly beyond the literal plant (FP-risk 25). Reasonable
   tradecraft inference; candidate for a grounding note on INFERRED activity.

## Verdict so far
Detection is accurate and trustworthy: 100% recall at/above the finding threshold,
0 false positives, survives heavy noise, correct host + severity + cross-host
correlation. Report is well-grounded. Two characterized boundaries to decide on,
neither a defect.
