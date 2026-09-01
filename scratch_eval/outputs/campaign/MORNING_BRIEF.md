# Morning brief — overnight fusion + agentic testing

Scope: fusion and agentic only — chat, timeline, identities, and mostly the summary.
Everything below is on `experiment/huge-changes`, committed and pushed. Full
chronology in `NIGHT_LOG.md`; per-test detail in this folder.

---

## 1. What I fixed (all measured, all regression-green)

| # | Defect | Evidence it was real | Fix | Blast radius |
|---|---|---|---|---|
| **F1** | **An actor's lateral movement is invisible when their account is written differently per host** (`corp\u` on one, `u@corp` on another, bare SAM on a third → 3 account entities, each on 1 host) | 3 hosts, 1 actor, **0 cross-host findings**. The Identities view already clustered them, so the two views of the same case disagreed | Derive the finding from the shipped clusterer (`identities.resolve_identities`), fires only when a cluster spans ≥2 hosts and no single entity already does | +4 findings on the real case, all `informational` |
| **F2** | **LLM payload budget silently stops binding at scale** | 120 hosts / 4,321 findings → **2.6 MB** against a 708 KB budget (3.7× over). `MAX_STEPDOWNS=2` caps the halving and ≥high findings are exempt from trimming | Collapse repetition instead of dropping signal (findings, then timeline). **2.6 MB → 137 KB (95%↓)** | **Zero** — all 8 real cases are under budget, payloads byte-identical |
| **F3** | **No transport input cap** — a 1M-token model computes a 2.9 MB payload and *every* report fails | Measured: 1,000,125 chars OK (376,564 tokens); 1,100,000 chars → `Input exceeds the maximum length of 1048576 characters` | `budget.transport_cap_chars()`, clamped after the adaptive raise; CLI transports only | **Zero** — real budget unchanged at 708,000 |

**Your steer changed F1 materially.** I had hard-coded `severity="high"`. Deriving it
from the clustered accounts' own severity turned the 4 real-case findings from
false `high` into correct `informational` — they are ordinary admins on several hosts.
Hard-coding would have shipped 4 false high-severity findings to a customer.

---

## 2. What I tested and found clean

| Area | Result |
|---|---|
| Detection recall (41 scenarios) | **37/37 finding-eligible = 100%** — and identical at informational / medium / **high**, so 100% at your production floor |
| Precision (benign input) | **0 false positives** |
| Noise robustness | 37/37 survive 20×; **37/37 survive 500×** benign volume |
| Evidence-locator integrity | **78/78** resolve to the correct raw row, host-matched (never checked before) |
| Duplicate collection import | entities / findings / evidence all constant — no `+365`-class inflation |
| Incremental collection | two collections == one-shot, exactly |
| Attack-chain correlation | links a 3-host campaign into one cross-host finding |
| Timeline order + patient zero | chronological; patient zero correct |
| Timestomping / corrupt times | 8/8 events kept (incl. undated + garbage); 2099 stamp visible, not reordering real events |
| Chat (Ask path) vs ground truth | **11/11** — plants 8/8, negative controls 3/3 |
| AI investigation vs ground truth | **38/40 (95%)** over 3 rounds, **8/8 negative controls clean** |
| Evidence-gap hallucination (hardest test) | **6/6 honest, 0 fabricated** — states "the graph does not show how" and labels mechanisms as hypotheses |
| **Prompt injection via telemetry** | **14/14 arms still reported the real attack, 0 obeyed**, 2 flagged the attempt |
| Summary coverage (n=10) | mean **79%**, **0 blind spots**, all crown-jewel techniques always mentioned |
| Masking at corpus scale | 0 hosts / 0 accounts leak |
| Edge cases | clock skew, contradictory evidence, 200 KB / RTL / NUL / emoji, single-event case — all pass |

---

## 3. Needs your decision (nothing here is broken)

1. **Set the severity floor to `medium`, not `high`** (likely a one-setting win).
   Measured: stepping medium→high saves **0.6%** of data (151→146 findings) and drops
   **all 15 high-confidence findings**, every one of which is *"Shared binary seen on 2
   hosts"* — cross-host lateral tool transfer. The informational tier is where the real
   volume lives (the code documents 156,017 informational SIGMA rows exhausting a 15 GB
   box) and `medium` already excludes it.
   **Deeper issue:** severity does NOT track likelihood in your data — all 22 `critical`
   findings carry only `medium` confidence, and confidence is 82% `medium` with just two
   values in use. The likelihood axis carries no signal, so severity is doing double duty
   as both impact and certainty. Cutting noise by *confidence* would be the real fix.
2. ~~17 of 34 techniques appear intermittently~~ **RESOLVED — I was measuring the wrong
   thing.** Your spec is "the most possible option", not an inventory. Re-measured for
   NARRATIVE stability instead: the **leading theme is identical in 10/10 runs**
   (`credential theft`), the top host matches in 8/10, and there are only **3 distinct
   leading scenarios** across 10 runs. The main story is stable; only supporting detail
   varies, which is correct for a triage summary. No action needed.
3. **Clock skew is silent.** The timeline orders by recorded time, so a host with a wrong
   clock sits in the wrong place and the report never says so. Candidate Limitations line.
4. **`resolve_identities(merges=…)` docstring is wrong** — says `(name_a, name_b, score)`
   but requires cluster *keys*. Easy to misuse.
5. **`compute_candidates` proposes nothing** for `corp\jdoe` ↔ `corp\john.doe` without
   corroborating context. Defensible conservatism, but worth a deliberate call.

---

## 4. Things I got wrong and corrected (read this — it calibrates the rest)

I had to retract **five** of my own claims tonight. Every one of them was my measurement
being wrong, not the product:

1. **Three scorer bugs**, all *under-reporting* the product: false "3 blind spots" in the
   summary (literal phrases vs the model's synonyms); a false **50% fabrication rate** on
   the evidence-gap test (markdown `**not show**` broke the denial regex); a false chat
   miss ("No **direct** evidence" ≠ "no evidence"). Corrected results: 0 blind spots,
   0 fabricated, 11/11 chat.
2. **A fix built on a wrong diagnosis.** I attributed an investigation failure to
   "hedging away established facts", built a grounding footer, measured it — it didn't
   help (2/5 vs 4/5) — and reverted it. A 20-run A/B then proved the real cause was
   **question anchoring**: a loaded premise steers retrieval to the wrong finding
   (decoy cited 7/10 vs 0/10 with neutral phrasing).
3. **The same mistake twice.** "Titles embed the hostname" made my collapse a no-op — in
   the timeline *and* again in the payload.
4. **Over-read small samples.** I reported a "33% → 80% improvement" that was noise at
   n=5. Everything model-driven is now n≥10, raw counts shown.
5. **Mis-framed the budget finding** as imminent context overflow; with your 1M model it
   was never that. The real issue was the transport cap — which turned out to be a
   genuine latent defect.

**Also cancelled by evidence:** the "~41% more evidence available" opportunity I flagged.
A cheap deterministic pre-check showed payloads are **byte-identical at 708k vs 1M for
every real case**, so raising the budget is not a quality lever. I dropped the 20-call
experiment rather than run it to measure noise.

---

## 5. State of the box

Backend healthy and serving. No synthetic case ever persisted (harnesses stub the
store). 202 stray `/tmp` scripts cleaned earlier. Branch committed and pushed. All
suites green: behavioral 17, altitude 26, investigate 19, host 66.
