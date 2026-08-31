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

## Fix attempt + measurement (unproven-premise weakness)

Added to `INVESTIGATE_SYSTEM`: when a question assumes something the evidence does
not prove, report the confirmed specifics (host/time/artifact/command) FIRST, then
state which part is unsupported — "an answer that drops established facts because
one premise is unproven is a FAILED answer."

| | host retained | rate |
|---|---|---|
| Before fix (rounds 1-3) | 1/3 | 33% |
| After fix (5× repeat) | **4/5** | **80%** |

**Honest read: improved, NOT solved.** Run 4 reproduced the old signature exactly
(host dropped, LOW confidence), so the instruction reduces the behaviour rather than
eliminating it. Confidence also moved LOW -> MODERATE on the passing runs, which is
the intended shape: still declining to affirm the unproven purpose, while keeping
the established host.

Residual: ~20% of the time the model still hedges away a fact it proved. A prompt
alone cannot guarantee this; a deterministic guard would (e.g. if the answer cites a
finding whose host is known, require the host to appear — or append the established
host/time from the tool trace). Logged as a candidate fix, not applied yet.

## Correction + deterministic-guard attempt (REVERTED)

I built a deterministic guard (record what each `evidence()` call proved; if the
answer names none of those hosts, append an "Established from the evidence" block)
and measured it. **It did not help, and the diagnosis behind it was wrong.**

| Version | Host retained (n=5) |
|---|---|
| Baseline (no fix) | 1/3 (33%) |
| Prompt fix only | 4/5 (80%) |
| Prompt + deterministic guard | **2/5 (40%)** |

**Two corrections to my earlier claims:**

1. **The failure mode is NOT hedging — it is MIS-RETRIEVAL.** A failing answer reads:
   *"A critical finding reported **Mimikatz LSASS Credential Dumping** on
   **WKS-EVAL01**…"* — primed by the phrase "for credential theft", the model
   anchored on the Mimikatz/LSASS finding instead of the renamed-procdump one. It
   did not drop a host it had proved; it investigated the wrong finding. A grounding
   footer cannot fix that — it faithfully appends the WRONG host.

2. **n=5 is under-powered for this measurement.** The guard can only APPEND text, so
   it is logically incapable of reducing host mentions — therefore 2/5 vs 4/5 is pure
   run-to-run variance. Which means 1/3, 4/5 and 2/5 are all within noise of each
   other, and my earlier "33% → 80% improvement" was **over-read**. Given the
   documented Codex variance (no temperature control), distinguishing these needs
   ~20-30 runs per arm, not 5.

**Action:** guard reverted (unproven benefit, added complexity). The prompt fix is
kept — it is harmless and directionally sensible — but it is NOT established as
effective. The honest status of this weakness is UNRESOLVED, with a corrected
understanding of its cause (question-anchoring), not fixed.
