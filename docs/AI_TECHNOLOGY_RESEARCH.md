# AI technologies that could add value to Intact.AI (research, 2026-11-08)

A deep-research pass over 2025–2026 LLM / AI technology, looked at through Intact's
constraints: **deterministic and air-gapped by default**, AI only layered on top when
configured and reachable; customer data **masked** before any cloud model sees it; one
appliance VM (~16 GB RAM, CPU, maybe no GPU); cases of hundreds of thousands to millions
of events (a year of CloudTrail for a large company).

**How it was produced.** 5 search angles → 22 sources fetched → 102 claims extracted →
the 25 most relevant checked by 3 independent adversarial verifiers each (2 of 3 refuting
kills a claim) → **21 confirmed, 4 refuted**. Only confirmed claims are recommended
below; refuted ones are listed so nobody re-proposes them.

Related: [DECISION_MODEL.md](DECISION_MODEL.md) (the decision model Intact uses today).

---

## Summary

* **Top recommendation: run Jev-style decision models locally.** llama.cpp now serves
  Jev's own typed-question format, Apache-2.0 open decision models exist, and Intact's
  `decision_model.py` already has a `local` provider that speaks that format. Every
  decision-model feature could run with no cloud, no masking round-trip and no per-call
  cost — once accuracy and CPU speed are benchmarked.
* **Schema-constrained decoding** is a proven, cheap gain wherever Intact still generates
  text (report JSON, chat tool calls).
* **Benchmarks agree LLMs are not reliable as stand-alone triage or investigators** —
  which supports Intact's design: deterministic detection first, a calibrated AI layer
  that ranks and annotates, a human in the loop.
* **Hype for this appliance:** LLM log-anomaly detectors (GPU, labelled data, ~18 h
  training), graph RAG for large cases (plain retrieval wins on lookups), small local LLMs
  as free-form investigators.

---

## Shortlist to decide on (2026-11-08)

Local / offline models (#1 below, and Foundation-Sec-8B, #5) are **parked**: there is no
way to test them on hand yet. These four work with the hosted models Intact already uses.

| Item | What it changes | Why it matters for Intact | Effort | Evidence |
|---|---|---|---|---|
| **A. Structured output for report and chat** (#2) | The LLM can only return JSON that matches our schema — the provider's own structured-output / JSON-schema mode for cloud models, Guidance / llguidance for any local one later | A malformed or half-written section is a lost report section, a retry (time + tokens) or a chat tool call that fails silently. A schema guarantees the shape; the study also saw up to ~4 points better task accuracy and faster output | Low — define schemas for the existing report sections and chat tools; support varies by provider, so keep the current parse-and-retry as the fallback | Medium (one ICML 2025 paper, partly by Guidance's authors; provider modes are documented features) |
| **B. Measure the AI layer on SecAlertBench** (#3) | Run the decision-model features (verdict chips, compromise estimates) over 8,322 real labelled SOC alerts | Today the decision model's accuracy is measured only on our own data. A third-party set gives an honest false-positive / miss rate and calibration — the number that says whether a chip can be trusted, and the baseline any future change (or model) must beat | Low–medium — a script around the existing `scripts/dev/decision_eval.py`; internal use only (the data has no licence) | High (dataset recounted by the verifier) |
| **C. Evidence-first verdicts** (#4) | Before asking the decision model about a finding, code gathers its context from the case graph (the actor's surrounding events, the target, the host, related findings); then one typed question | A model asked about a bare alert guesses; one given the right evidence decides. The study cut false positives from ~25–30% to 14.2%. In Intact the gathering is deterministic code (no agent), so it stays reproducible and cheap | Medium — a context builder per finding type, then re-measure with B | Low–medium (one preprint, no error bars) |
| **D. Retrieval + reranking for free-text evidence in chat** (from the graph-RAG finding) — **not relevant until we have an offline model server** (decided 2026-11-12) | Index report text, attachments and notes; chat retrieves the best passages (rerank) instead of reading everything | Long cases overflow the model's context; retrieval lets chat answer from the right paragraph of a 200-page attachment. For structured events (CloudTrail, EDR) the existing exact queries stay — plain retrieval + rerank beat graph RAG on lookups | Medium — needs an embedding model (a hosted one over masked text, or local later) | Medium (two papers agree on lookups; not tested on logs) |

Not on the shortlist on purpose: LLM log-anomaly detection, graph RAG for large cases and
small LLMs as free-form investigators (see *Not a fit for this appliance*).

**Decisions (2026-11-12).** Work order **B → A → C**, one item at a time. Each is measured
before and after on the same inputs, kept only if it adds value, otherwise reverted to
the commit before it. **D is not relevant until we have an offline model server**: its
embedding model would otherwise be a hosted one over masked case text, so it waits with
the parked local models.

**B result (2026-11-12, kept).** `scripts/dev/secalert_eval.py`, 400 SecAlertBench
alerts (seed 20261112: 138 attack / 262 non-attack), OpenRouter `jev-latest`, three
runs that agree within a point. This is the baseline C must beat:

| Measure | Value |
|---|---|
| Model's choice is "attack" | 379–382 of 400 |
| Attacks caught (recall) | 100% |
| Non-attacks called attack (FPR) | 92–93% |
| Accuracy / Brier | 39–40% / 0.32 (worse than always guessing 50%) |
| **Ranking: AUC of p(attack)** | **0.86–0.87** |
| If "attack" meant p(attack) ≥ 0.80 | accuracy 80%, FPR 23%, recall 86% |

The chosen verdict is skewed to "attack", but the probabilities rank well, so the signal
is there. Caveat: these are network IDS/WAF alerts, not Intact's usual endpoint and cloud
findings, so the numbers say how the verdict question behaves, not how it does on our cases.

**A result (2026-11-12, not built: no value to add).** Measured before writing any code,
on the provider in use (`codex-subscription`, codex-cli 0.163.0), with three imported cases:

- **Chat:** 30/30 answers clean. 13 of the 20 inspected used tool fetches. None showed raw
  tool JSON, none came back empty, none hit a "could not finish" fallback. Median 25 s.
- **Customer checklist** (the only strict-JSON output): complete on every case (10 / 5 /
  20 items), none empty or unparsed.
- **Reports** are Markdown sections, so a JSON schema has nothing to enforce there.

The tolerant parsers (`_chat_tool_call`, `_parse_json`) already absorb the shapes that used
to break. Structured output across all eight agentic providers would protect against
failures we cannot find. If it is ever revisited, it must try each provider's native mode
(`--output-schema` for codex, `response_format` for OpenAI-shaped, `responseSchema` for
Gemini, a forced tool for Claude, `format` for Ollama) and fall back to today's path on any
rejection, changed syntax or invalid reply, so it can only help and never break a call.
Re-measure first: build it only if real failures show up.

---

## Ranked by value for effort

### 1. Local decision models via llama.cpp `/v1/systemone` — high value, low effort

**What.** llama.cpp's server exposes `POST /v1/systemone`, following TypeSafe's Jev
"System One" format: a state plus a map of questions, each typed `choice` / `score` /
`noul` with per-type criteria. Existing Jev clients only need a new base URL.

**Open models** (licences as published):

| Model | Size / base | Licence | Fit on a 16 GB CPU VM |
|---|---|---|---|
| Julia-1 | 144M, mmBERT-small, 50+ languages | Apache-2.0 | Yes — encoder-sized, for high-volume relevance / verdict scoring |
| Laya | 421M, ModernBERT-large | Apache-2.0 | Yes — same role |
| Kev-4B | Qwen3.5-4B-Base, English, refuses state > 65,536 tokens | Apache-2.0 (model card confirms) | Yes as a Q4 GGUF — higher-quality per-finding questions |
| lev | 4B | Apache-2.0 | Likely, as Q4 |
| Clef | 27B, English, images | Apache-2.0 | Probably too heavy without a GPU |
| OpenJev | 27B | **CC BY-NC 4.0** | **Cannot ship** in a commercial product |

Apache-2.0 is compatible with Intact's AGPLv3.

**How it improves Intact.** Timeline verdict chips, identity-match hints, compromise
estimates, grounding checks, the prompt-injection guard and relevance scoring all run
**fully air-gapped**: no data leaves the box, no masking round-trip, no per-call cost.
Small encoder models make **scoring very large numbers of events** affordable.

**Proven vs unproven.**
* Proven: the endpoint and its error codes are documented; `decision_model.py` already
  defines the `local` provider (wire: `jev`, `cloud: False`) — a configuration change.
* Unproven: **accuracy versus hosted Jev** (nobody has published it) and **CPU speed**
  (the published 3 ms Julia-1 / 5 ms Laya / 12 ms Kev-4B / 43 ms OpenJev are median
  per-question times on an NVIDIA RTX PRO 6000 GPU).
* Caveats: pre-release llama.cpp build (b11361, Oct 2026); no streaming; Laya / Clef need
  the whole prompt to fit in `--ubatch-size`, so Intact's 12k–24k-token budgets need
  `-b` / `-ub` raised (one user hit "input (11982 tokens) is too large"); the maximum
  number of choice options differs per model (52 for OpenJev, 2 for minicpm-ocr-jev).

**Before replacing Jev:** benchmark on the fusion scorecard (tune + hold-out + benign)
and on SecAlertBench (below), for accuracy and probability calibration.

Sources: huggingface.co/blog/ggml-org/decision-models-in-llamacpp; llama.cpp server
README (`/v1/systemone`); Kev-4B model card.

### 2. Schema-constrained decoding — medium-high value, low effort

**What.** The model can only emit output that matches a JSON schema (Guidance /
llguidance, XGrammar, Outlines, llama.cpp grammars).

**How it improves Intact.** No malformed report or chat JSON, fewer retries, lower latency
and cost — local or cloud. On Llama-3.1-8B, Guidance raised task accuracy by up to ~4
points (GSM8K 83.8 vs 80.1; Last Letters 54.0 vs 50.7; Shuffle Objects 55.9 vs 52.6) and
cut median time per output token from 15.40 ms to 6.37 ms by skipping tokens the schema
already fixes (~15.7 per output). Across ~10K real-world schemas Guidance had the best
coverage and compliance.

**Caveats.** One paper (JSONSchemaBench, ICML 2025), partly written by Guidance's
maintainers; one model on an A100, no CPU figures. The speed-up is Guidance-specific: the
native llama.cpp grammar and Outlines roughly **doubled** time per token (29.98 / 30.33
ms); Guidance's time to first token is higher (0.24 vs 0.10 s). Re-measure on CPU.

Source: arxiv.org/abs/2501.10868v2

### 3. SecAlertBench as an external accuracy test — medium value, low effort

**What.** 8,322 real alerts from three enterprise SOCs (2,496 attack / 5,826 not;
241 rule names; 23 attack types), processed data public.

**How it improves Intact.** Gives the decision-model layer (hosted Jev or a local model)
a measured precision / recall / false-positive rate on third-party data, next to the
fusion scorecard.

**Caveats.** The repository has **no licence** (all rights reserved): internal
evaluation only, **never bundle it**. Network IDS / WAF alerts only, field names in
Chinese, IPs randomized, timestamps removed.

Source: github.com/Dxsssu/SecAlertBench

### 4. Gather evidence first, then decide (CORTEX pattern) — medium value

**What.** Triage split into evidence-gathering and one reasoning step instead of asking
a model about a bare alert. On a production SOC dataset: false positives 24.9% (ReAct
agent) / 29.8% (prompt-only) → **14.2%**; actionable F1 0.66 → 0.78; non-actionable
0.77 → 0.86.

**How it improves Intact.** Build it deterministically: **code** pulls the related events
for a finding out of the case graph, then the decision model answers **one typed
question**. No free-form agent needed.

**Caveats.** One preprint, no confidence intervals or test-set size; used cloud
gpt-5-mini; ~5.7× the tokens and much higher latency; sensitive to distribution shift and
prompt injection.

Source: arxiv.org/pdf/2510.00311

### 5. Foundation-Sec-8B — low value for now

**What.** Cisco's Llama-3.1-8B with continued pretraining on ~5.1B security tokens; Q4
GGUF ~5.4 GB (third-party estimate), runs on llama.cpp / Ollama.

**How it might help.** Better security wording from a local model writing report or chat
text. CTIBench-RCM 0.630 → 0.720 (above Llama-3.1-70B's 0.709, within error bars);
CTIBench-MCQA 0.623 → 0.662.

**Caveats.** Vendor report only, no replication; threat-intel quizzes, not log triage;
the alert-to-case-notes use is only piloted; it was one of the models averaging a 44%
false-positive rate on SecAlertBench. **Licence not verified** — check before shipping.

Source: arxiv.org/html/2504.21039v1

---

## What the benchmarks say about Intact's design

Three independent 2025–2026 benchmarks agree that LLMs are assistants, not stand-alone
triage or investigators:

* **SecAlertBench** — 16 current LLMs (incl. Claude Sonnet 4.5, GPT-5.1, Gemini-3-flash,
  Qwen3, Foundation-Sec-8B): average TPR 79.71%, F1 70.92%, **FPR 44.13%** on real alerts.
* **SIABench** — 25 incident scenarios, 229 questions (memory, network, malware, misc):
  the best agent (Claude-4.5-Sonnet) partially solved 81.7% but **fully solved 8 of 25**.
* **CyberSOCEval** — threat-intelligence reasoning (588 QA from 45 reports): 43–53%.
* Alert-Bench corroborates: every configuration missed at least 40.4% of attack alerts.

**Consequence:** keep the deterministic default; use AI to rank and annotate, never to
suppress; keep the analyst in the loop (as the case UI already does).

Sources: github.com/Dxsssu/SecAlertBench; arxiv.org/html/2603.06422v1;
arxiv.org/pdf/2509.20166v2

---

## Not a fit for this appliance (verified)

| Idea | Why not |
|---|---|
| **Small local LLM as a free-form investigator** | On SIABench Llama-3.1-8B partially solved **7.03%** (70B 16.53%, 405B 23.28%) and hit the round limit looping on identical commands in 62.9% of questions. Small models suit **narrow typed questions** — the decision-model shape Intact already uses. (A blog figure of Qwen3.5-9B F1 0.952 on bounded alert triage supports that; not independently verified.) |
| **LLM log-anomaly detection (e.g. LogLLM)** | Average F1 0.959 vs 0.893 for NeuralLog, but needs a 48 GB GPU (8–43 GB used), ~17.75 h training, labelled anomalies, and was tested on HPC / system logs, not CloudTrail or EDR. Keep the Sigma / behaviour rules and threshold engine; if anomaly scoring is ever wanted, use light non-LLM detectors. |
| **Graph RAG for large cases** | On fact-retrieval questions plain RAG + rerank scored **60.92** (best), MS-GraphRAG 49.29, LazyGraphRAG 51.65. For "did user X call API Y" over a year of CloudTrail, exact structured queries over the case store win. Use vector retrieval + reranking only for free-text evidence (reports, attachments, notes) in chat. |
| **LazyGraphRAG indexing** | LLM-free indexing (noun-phrase concepts + graph statistics) costs the same as vector RAG and 0.1% of full GraphRAG — plausible on CPU — but the open-source graphrag "Fast" method still uses an LLM at index time, LazyGraphRAG proper ships through Microsoft products, and the extractor is English text, untested on JSON logs. |

Sources: arxiv.org/html/2603.06422v1; arxiv.org/html/2411.08561v5;
arxiv.org/pdf/2506.05690; microsoft.com/en-us/research/blog/lazygraphrag-...

---

## Refuted claims (do not re-propose)

| Claim | Vote |
|---|---|
| CyberSOCEval malware analysis: LLMs score only 23–34% | 1–2 refuted |
| Reasoning models with test-time scaling get no boost on security analysis | 0–3 refuted |
| LazyGraphRAG matches GraphRAG global search at >700× lower query cost | 0–3 refuted |
| GraphRAG clearly beats plain RAG on complex reasoning and summarization | 0–3 refuted |

---

## Recommended next steps

1. **Benchmark local decision models on the appliance.** Julia-1, Laya and Kev-4B (Q4
   GGUF) behind llama.cpp `/v1/systemone`: RAM, per-question latency, throughput at
   12k–24k-token budgets, and accuracy + calibration versus hosted Jev on the fusion
   scorecard and SecAlertBench. If they hold up, offer Local as the air-gapped default
   for decision-model features.
2. **Constrained decoding for report and chat JSON** (Guidance / llguidance), measured on
   CPU first.
3. **Evidence-first verdicts:** code gathers each finding's context from the case graph,
   then one typed decision-model question.

## Gaps — no verified claims in this run

ML entity resolution / identity linking; local PII detection and pseudonymization models
(sources found on privacy filters and GLiNER2-based PII detection, none survived
verification); calibration methods for detection scores (temperature scaling, conformal
prediction); long-context models for million-event cases; agent frameworks beyond CORTEX;
Timesketch's AI agent (found as a source, not in the verified set). Each needs its own
focused pass before any recommendation.

## Caveats on the evidence

Most findings rest on a single primary source, and several carry conflicts of interest
(Guidance authors on their engine, Cisco on its model, Microsoft on its method). **No
surviving claim measured CPU-only hardware** — every latency figure is from data-centre
GPUs. The llama.cpp `/v1/systemone` support and the open decision models are weeks old
(Sept–Oct 2026) with no published accuracy against hosted Jev. Rankings date quickly.

## Sources

Primary:
* https://huggingface.co/blog/ggml-org/decision-models-in-llamacpp
* https://arxiv.org/abs/2501.10868v2 (JSONSchemaBench)
* https://arxiv.org/html/2504.21039v1 (Foundation-Sec-8B)
* https://arxiv.org/pdf/2509.20166v2 (CyberSOCEval)
* https://github.com/Dxsssu/SecAlertBench
* https://arxiv.org/html/2603.06422v1 (SIABench)
* https://arxiv.org/pdf/2510.00311 (CORTEX)
* https://arxiv.org/html/2411.08561v5 (LogLLM)
* https://www.microsoft.com/en-us/research/blog/lazygraphrag-setting-a-new-standard-for-quality-and-cost/
* https://arxiv.org/pdf/2506.05690 (GraphRAG-Bench)
* https://i.blackhat.com/Asia-26/Presentations/BHAS26-Tomonaga-Graph-Aware.pdf
* https://elie.net/talk/autonomous-timeline-analysis-and-threat-hunting-an-ai-agent-for-timesketch
* https://newreleases.io/project/github/google/timesketch/release/20250929
* https://www.ndss-symposium.org/wp-content/uploads/wosoc26-02.pdf
* https://arxiv.org/pdf/2609.19241
* https://arxiv.org/html/2509.23573v3

Secondary / blogs (context only):
* https://pyshine.com/Ollaya-Run-Open-Decision-Models-Locally/
* https://www.elastic.co/security-labs/blog/alert-triage-agentic-soc-self-correcting-agents
* https://pypi.org/project/iflow-mcp-socfortress-velociraptor-mcp-server/
* https://www.vectra.ai/blog/ai-agents-in-the-soc-moving-from-ai-hype-to-operational-reality
* https://pioneer.ai/blog/gliner2-pii-open-source-privacy-filtering-with-pii-detection
* https://openai.com/index/introducing-openai-privacy-filter/ (rated unreliable by the pass)
