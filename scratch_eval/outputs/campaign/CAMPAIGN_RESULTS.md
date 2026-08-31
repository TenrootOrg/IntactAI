# Campaign RESULTS — every finding fixed & verified

The fusion + agentic test campaign found 11 issues (Tracks A–F) and **all 11 are
now fixed, tested, and verified** on `experiment/huge-changes`. Deterministic
harnesses that found the bugs now report **0 findings**; unit suites green; the
high-severity agentic fixes verified live through the HTTP route.

## Fixes (defects)

| ID | Sev | Finding | Fix | Verified |
|---|---|---|---|---|
| **A1** | high | turn-1 `{final}`, 0 tool calls (the live give-up) | min-step guard: nudge, then FORCE `list_findings` — every answer now has ≥1 evidence step | harness 0; **live 4/4 no give-up on the case that failed 2×** |
| **A2** | high | model-supplied bad tool arg → HTTP 500 | `_safe_tool` returns `{"error":...}` the model recovers from | harness + unit |
| **A3** | high | transport failure → unhandled 500 | catch → `LLMUnavailable` → clean operator message (parity with chat/report) | harness + unit |
| **A7b** | med | forced-final returns raw tool-call blob | scrubbed to a clean insufficient-evidence message | harness + unit |
| **F2** | med | `schema._wider` string-compares timestamps | compare INSTANTS via `keys.to_utc_dt`, return original string | probe 0; behavioral test |
| **F2b** | low | `_wm_new_activity` watermark string-compare | instant compare so a fractional-newer occurrence re-opens | probe 0; behavioral test |

## Implements (capability gaps)

| ID | Sev | Gap | Implementation | Verified |
|---|---|---|---|---|
| **A6** | med | masking strips host role hints (DC/CA) | annotate hosts "ALDC02 (domain controller)" — role survives masking, tier-zero priority kept | unit; live masked run |
| **A8** | low | identifier present only in a raw row leaks past mask | `_enrich_mask_from_result` registers row values (pivot fields + evidence rows) before masking | unit (row-only host masked) |
| **F3** | low | `TRIGGER_IDENTITY` dead — identity edits deferred | 5 identity mutators now `_refuse_after_identity()` → immediate effect (mirrors dispositions) | probe 0 |
| **A5** | med | Codex has no temperature/seed → variance | mitigated by the A1 guard (kills the harmful give-up symptom); no separate retry to keep cost down | quantified: give-up 4%→0 with guard |

## A4 — the diagnostic
Runtime and eval both resolve **codex-subscription / gpt-5.6-sol** → config
divergence ruled out; the live 0-step was genuine model variance (A5), which is
exactly why A1's guard is load-bearing. Track B measured it: **4% overall, 8% on
one real case**, before the fix; **0** after.

## Coverage added (not just fixes)
- `test_fusion_behavioral.py` — 11 tests: idempotency, order-independence,
  evidence-stability, filters, F2/F2b.
- `test_investigate_v2.py` — 19 tests incl. A1/A2/A3/A7b fault handling + A6/A8.
- Deterministic harnesses (`agentic_faults`, `fusion_probes`) as regression gates.
