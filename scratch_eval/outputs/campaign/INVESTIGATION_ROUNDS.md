# AI investigation vs simulation — all rounds

| Round | Corpus | Questions | Score | Neg-controls | Notes |
|---|---|---|:--:|:--:|---|
| 1 | 25 scenarios | 10 | 9/10 (90%) | 2/2 clean | Q8 procdump ❌ (host missed, LOW conf) |
| 2 | 27 scenarios | 15 | **15/15 (100%)** | 3/3 clean | Q8 PASSED |
| 3 | 33 scenarios | 15 | 14/15 (93%) | 3/3 clean | Q8 ❌ again |
| **Total** | — | **40** | **38/40 (95%)** | **8/8 clean** | |

## Headline
- **95% accuracy** reproducing the simulated ground truth across 40 questions.
- **8/8 negative controls clean — ZERO fabrication.** Probed for cryptomining,
  macOS/Linux malware and SQL injection (none simulated), it correctly reported no
  evidence every single time.
- Every correct answer was grounded via real tool calls (list_findings / search /
  evidence / pivot) — no answering from memory, no give-ups (the A1 guard holding).

## The one systematic weakness (both failures are the SAME question)
Q8: *"Was a renamed system utility (e.g. procdump) used **for credential theft**? Where?"*
— failed rounds 1 and 3, passed round 2 (2 of 3 failures). Pattern is identical each
time: **technique found (kw ✓), host dropped (✗), confidence LOW**.

Diagnosis: the question embeds an **unverifiable premise** ("for credential theft").
The evidence shows `Renamed ProcDump Execution on WKS-EVAL04` but nothing about
purpose. The model correctly refuses to affirm the purpose — but in hedging it also
**discards the host attribution it had already established**, instead of separating:
- CONFIRMED: renamed procdump executed on WKS-EVAL04
- UNCONFIRMED: that its purpose was credential theft

**Proposed fix:** instruct the investigate prompt to always report established facts
(host/time/artifact) separately from the unproven part of the question, rather than
lowering the whole answer to LOW and omitting them. This is the OBSERVATION vs
INFERENCE split the report prompts already enforce — the investigate prompt doesn't.
