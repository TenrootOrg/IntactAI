# Campaign BACKLOG — what to fix / implement

Ranked findings from the fusion + agentic test campaign (Tracks A/B/C, deterministic + at-scale). Each links a repro; action is the proposed fix or feature.

**Quantified at scale (Track B, 1 model runs):** turn-1 give-up (A1) **0.0%**, fabricated-host **0.0%**.

## FIX (defects)

| Sev | ID | Track | Finding | Proposed action |
|---|---|---|---|---|
| high | A1 | A | turn-1 {final} give-up with 0 tool calls is not caught/retried | Guard the loop: never accept a turn-1 {final} with 0 tool calls — re-prompt 'call a tool first' (bounded retries), or force one list_findings. |
| high | A2 | A | tool exception propagates out of investigate() -> HTTP 500 | Wrap _tool dispatch in try/except; return {'error':...} to the model instead of letting a model-controlled arg raise a 500. |
| high | A3 | A | transport failure propagates -> unhandled 500 (report path catches it) | Catch LLMUnavailable in investigate() (or the route) and return the typed operator message the report/chat paths already use. |
| medium | A7b | A | forced-final can return raw model text as the analyst answer | On the forced-final path, if the reply still isn't {final}, return a clear 'insufficient evidence' message, never the raw tool-call blob. |
| medium | F2 | C-probes | schema._wider string-compares timestamps (breaks on mixed Z/fractional/epoch) | Make schema._wider compare via keys.to_utc_dt instants (like in_window), not lexicographic strings — mixed Z/fractional/epoch widen wrong. |
| low | F2b | C-probes | _wm_new_activity string-compares the watermark time half | Same for correlate._wm_new_activity's watermark time half — compare instants so a fractional-second-newer occurrence re-opens correctly. |

## IMPLEMENT (capability gaps)

| Sev | ID | Track | Finding | Proposed action |
|---|---|---|---|---|
| medium | A5 | prior-eval | No temperature/seed control on Codex -> irreducible run-to-run variance | Add bounded self-consistency / retry on the loop (Codex has no temperature knob); the min-step guard (A1) also cuts variance impact. |
| medium | A6 | prior-eval | Masking strips hostname role hints (DC/CA), degrading tier-zero priority | Pass a role hint (DC/CA/MECM) through the masked tool output so the model keeps tier-zero priority when hostnames are pseudonymized. |
| low | A8 | prior-eval | Masking is best-effort: an identifier only inside a raw evidence row can leak unmasked | Extend the mask sweep to raw-row values before they reach the model (or redact unknown identifier-shaped tokens in tool output). |
| low | F3 | C-probes | TRIGGER_IDENTITY is a dead constant (identity edits apply only next fuse) | Either wire TRIGGER_IDENTITY to re-fuse on an identity decision (immediate effect) or delete the dead constant + document the deferred-apply semantics. |

## Repros

- **A1** (high): model emits {"final":...} on iteration 0  
  raised=False steps=0 answer='I could not find anything.' — the loop accepted a 0-tool final; nothing forces a lookup or retries.
- **A2** (high): tool raises (bad limit / malformed pivot.window)  
  raised=True (simulated tool crash (e.g. int('abc') on limit)) — _tool() has no try/except; model-controlled args can crash the request.
- **A3** (high): _real_llm raises  
  raised=True (_Boom) — investigate does not catch LLMUnavailable like store.chat/report do.
- **A5** (medium): same question yields 0 vs 2+ tool steps across repeats (Track B)  
  Codex subscription CLI exposes no temperature/seed; A4 confirmed runtime==eval transport (codex-subscription/gpt-5.6-sol), so the live 0-step is genuine sampling variance. Quantified by Track B give-up rate.
- **A6** (medium): see investigate_v1_vs_v2.md cross-host/timeline rows  
  v1-vs-v2 judged eval: v2 scored 11 (cross-host) and 13 (timeline) vs v1's 17/20 because pseudonymizing ALDC02->Hostname7 destroys the 'domain controller' signal carried by the name. Privacy win, correctness regression on tier-zero questions.
- **A7b** (medium): model never returns {final}, even on the forced call  
  answer='{"tool":"list_findings","args":{}}' — after budget, obj.get('final') or raw; a non-final raw blob becomes the answer.
- **F2** (medium): schema._wider('2026-...T12:00:00Z','2026-...T12:00:00.5Z', want_min=False)  
  mismatches vs to_utc_dt ordering: [('2026-06-16T12:00:00Z', '2026-06-16T12:00:00.500Z', 'max', '2026-06-16T12:00:00Z', '2026-06-16T12:00:00.500Z')]
- **A8** (low): raw row contains a hostname absent from graph entities  
  _build_mask_mapping is graph-derived; a value present only in a raw row (not an entity) may not be in the mapping and reaches the provider. Acknowledged in investigate.py docstring.
- **F2b** (low): _wm_new_activity(old='1|...00Z', new fractional ts)  
  same string-compare class as F2; a fractional-second-newer occurrence may not re-open a stale disposition. signature=(stored, current) -> 'bool'
- **F3** (low): grep TRIGGER_IDENTITY in store.py — defined, never emitted  
  defined=True passed_as_trigger=False occurrences=1 — identity mutations persist to identity_links and take effect on the following fuse, not immediately.
