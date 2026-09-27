# Jev in Intact.AI

Jev is TypeSafe's "System One" model. It does not write text. You give it a
`state` (any JSON) and a set of named closed questions:

- **noul**: a yes/no question, answered with a probability from 0 to 1.
- **choice**: pick one of up to 255 options, answered with the chosen option
  and the full probability distribution.
- **score**: an ordered scale of 2–10 levels.

Each answer comes back typed, with probabilities attached. Intact reaches Jev
through OpenRouter's Decisions endpoint (`POST
https://openrouter.ai/api/v1/systemone`, model `jev-latest`). Measured from the
appliance: about 0.5–0.8 s per call, with up to 50 items per call, at roughly
$0.00002 per call.

All of this lives on branch **`jev-test`**. `main` has none of it.

## Ground rules

These apply to every feature below and to any new one.

1. **Deterministic and air-gapped by default.** Every feature is off until
   *Settings → Agentic → Fast decisions (Jev)* is enabled with an OpenRouter
   key and the box is in Online mode. If Jev is off, unreachable or returns an
   answer we cannot use, the feature falls back silently to exactly what
   Intact did before. No broken badge and no empty section.
2. **Jev suggests; the analyst decides.** Nothing sets a verdict, merges an
   identity or edits a report on Jev's word. A chip click is the same click as
   the manual button.
3. **Masked data only.** When a case has masking on, what Jev receives is
   masked the same way as the LLM payload. If masking is required but fails,
   Jev is sent nothing.
4. **One switch per feature.** Each use has its own tickbox under Fast
   decisions.

## Configuration

| Setting (`frontend_config.agentic.jev`) | Default | Meaning |
|---|---|---|
| `enabled` | `false` | Master switch |
| `api_key` | `""` | Jev's own OpenRouter key. If empty, Jev uses the main key, but only while OpenRouter is the chat provider |
| `model` | `jev-latest` | |
| `min_confidence` | `0.8` | Minimum confidence for a suggestion to be shown (chips, notice, chat verdicts) |
| `uses.<name>` | `true` | Per-feature switch (names in the table below) |

- The key is masked on `GET /api/config`, kept when the masked value is saved
  back, redacted from the `.db` download and the JSON export, and cannot be
  set by `/api/db/import`.
- Offline mode always disables Jev, whatever keys are stored.

## Features

| `uses.` key | What the analyst sees | Where it runs | When it runs |
|---|---|---|---|
| `disposition` | A chip on each Timeline row nobody has judged: **"Jev: likely Known · 91%"**. Clicking it calls the normal `tlValidate` | `jev.suggest_dispositions`, `store.get_timeline`, `cases.html _tlJev` | After every fuse, off the fuse lock, for findings that are new or have changed occurrences |
| `disposition` | An Analysis-tab line: **"Jev: 2 findings look malicious and are not reviewed yet — …"**, plus one case-log entry per newly flagged finding | `jev.unreviewed_notice`, `GET /api/cases/<id>` → `jev_unreviewed`, `cases.html _jevNote` | Rebuilt on every post-fuse pass |
| `identity` | **"Jev: 87% same"** beside each uncertain identity suggestion (Merge / Dismiss unchanged). Skipped when masking is on, because masking removes the names | `jev.suggest_identities`, `store.identity_view` | After every fuse, once per new pair |
| `chat_intent` | Reads whether a chat message *states* a verdict (malicious / benign / none) in place of the keyword list, including Hebrew. Applying it still needs the literal word "confirm" | `jev.chat_verdict` → `llm_sim.detect_disposition(verdict_hint=)` | Each chat message that is not a question |
| `chat_confidence` | Under a chat answer about risk: **"kobia (account): 15% likely involved in malicious activity — from 1 finding on 2 hosts"**, one line per matching account or host | `jev.entity_estimates`, `store.chat_case` | Chat questions about risk that name an account or host |
| `grounding` | The report's Grounding note lists statements the evidence does not support. Skipped (and logged) when the evidence is larger than one Jev call can take | `jev.unsupported_claims`, `llm_sim.generate_report` | Each LLM report |
| `injection` | Evidence text aimed at an AI model is withheld from the LLM and shown in a **"Prompt-injection guard"** note plus the case log. The pattern layer and the system-prompt warning always run, with no network; Jev adds paraphrase detection | `injection.py`, `llm_sim._real_llm` (every fusion LLM call) | Each LLM call |
| `relevance` | **Timeline → "Score collected rows"** starts a Settings → Actions job. It scores every raw collected row (Velociraptor results, cached Timesketch events) and shows the 200 most relevant above the Timeline | `jev.score_relevance`, `POST/GET /api/cases/<id>/relevance` | On demand |
| `scopes` | Each scope card of a broad case shows **"Jev: 82% likely attacker activity"** | `jev.suggest_scopes`, `store.scope_cards`, `GET /zoom_targets`, `cases.html _ztJev` | After every fuse, cached per exact set of findings |

Also on the branch:

- **Chat grounding fix** (`llm_sim.detect_disposition`). A verdict now attaches to the finding it names, not to the host every title ends with.
- **Offline eval** (`scripts/dev/jev_eval.py`). It scores Jev's suggested verdicts against the analysts' Timeline verdicts and prints accuracy, Brier score and a reliability table. It needs labelled findings, and today's box has none.

## Case data Jev writes

These are all case `details` keys, all additive. They are ignored when Jev is off.

| Key | Holds |
|---|---|
| `jev_suggestions` | `{finding_id: {wm, label, p, confidence}}` |
| `jev_notice` | `[{id, title}]`: confident true positives |
| `jev_identity` | `{candidate_id: p}` |
| `jev_scopes` | `{window_signature: p}` |
| `jev_relevance` | `{scored_at, rows_scored, rows_total, rows: [...]}` |

## Files touched (4c45ddea..jev-test)

Backend:
- `services/fusion/jev.py`: new; all Jev logic.
- `services/fusion/injection.py`: new; the injection guard.
- `services/fusion/store.py`: after-fuse hook, timeline chip, identity hint, chat hooks, `scope_cards()`.
- `services/fusion/llm_sim.py`: `_real_llm` guard, grounding note, `is_question`, `detect_disposition` hint and grounding fix.
- `services/fusion/render.py`: scope windows carry `finding_ids`.
- `routes/case_routes.py`: relevance routes, `jev_unreviewed`, scope estimates on `zoom_targets`.
- `routes/config_routes.py`: `jev` defaults, key masking.
- `routes/db_routes.py`, `services/storage/export_import.py`: key redaction and protection.
- `services/workflow_service.py`: `jev_relevance` is a System action.

Frontend:
- `cases.html`: chip, notice, relevance list, scope-card line.
- `partials/settings.html`, `js/stores/settings.js`: the Fast decisions block (with `jev` added to the `load()` whitelist).
- `js/stores/workflows.js`: action colour.
- Cache chain: `index.html`, `partial-loader.js`, `partials/case-analysis.html`, `partials/cases.html`.

Tests:
- `tests/test_jev_*.py` (client, config route, key not leaked, disposition, identity, chat intent, grounding, relevance, scopes)
- `tests/test_injection_guard.py`

Tool:
- `scripts/dev/jev_eval.py`

## Measured quality (2026-09-24, on the appliance)

Known-answer tests, with made-up items whose answers were set in advance:

| Use | Result |
|---|---|
| Grounding | 8/8 fabricated claims flagged, 0/8 true claims flagged |
| Relevance | 10/10 attack rows relevant, 1/10 noise rows at exactly 0.50. Every attack row ranked above every noise row |
| Chat verdicts | 16/18 correct with Jev against 10/18 for keywords alone. Both misses were phrased as IT attribution ("…created by helpdesk") |
| Identity | 13/16 correct. The misses: `admin`/`administrator`, `mlevi`/`moshe.levin`, `rgold`/`ron.goldman` |
| Suggested verdict | **Unproven.** Jev agreed with the box's LLM on only 2 of 24 real findings. The LLM called 22 of 24 "known" (a test-lab reading), while Jev called 20 "attack". There is no analyst ground truth yet |
| Scope cards | All six estimates sat between 0.72 and 0.79, so they separate the phases only weakly |

---

# Proposals — not built yet

Status: written 2026-09-27 for choosing what comes next. Nothing below exists.
The references come from surveying `jev-test` at `5f4a0c3a`; `main` is identical
in `services/fusion`.

## Why "accurate" needs changes to fusion, not just more Jev calls

Three findings from the survey decide the direction.

1. **Every judgment fusion makes is a keyword count or a fixed per-rule
   value.**
   - Severity comes from `anomaly.score_row`, which counts keyword hits
     (+100 for RWX, +10 per LOLBin or path term), from hard-coded mapper
     constants, or is fixed per rule.
   - Examples of fixed rules: any account seen on 2 or more hosts is always
     high/high; a coordinated burst is always high/high.
   - `Finding.confidence` (high/medium/low) is never shown in the UI.
   - The HIGH/MODERATE/LOW grades in reports are written by the LLM with
     nothing measured behind them.
2. **Keyword scores also decide what the analyst ever sees.** The biggest
   silent cuts are:
   - The severity floor at assembly (`correlate.assemble`, the case default is
     `medium`). Events below it vanish unless linked to a kept one, and then
     at most 50 are kept, first come first served.
   - The SIGMA fold. N occurrences collapse to one "loudest" exemplar, and it
     is the only one with a drill-down locator.
   - The memory trim: the top 250 rows per plugin by keyword score.
   - CloudTrail: the first 500 events per region by recency, and non-SIGMA
     events are never fused.
   - The LLM payload: `top_entities` is sorted by keyword anomaly.
3. **There is almost no ground truth to measure against.**
   - `timeline_validations` is the only rich label source. It has 3 classes,
     which match Jev's, but it records no timestamp and no author.
   - Nothing marks a case as a real incident.
   - IRIS is not connected back to Intact.
   - `activity_log` holds the only timestamps, is capped at 500 entries, and
     is stripped on export.
   - `jev_suggestions` already sits next to `timeline_validations`, so
     (prediction, label) pairs build up for free once analysts triage.

Without (3) no percentage Jev shows can be called accurate. The live test
proved it: the suggested verdict agreed with the LLM on 2 of 24 findings, and
nobody can say which one was right. So group A comes first.

The same rules apply as for the built features: the deterministic value stays
the stored value, Jev adds a secondary number, sort key or annotation, and it
is ignored when Jev is off or offline.

## A. Measure first: labels and calibration

| ID | Change | Where | What the analyst sees | Effort |
|---|---|---|---|---|
| **A1** | **Labels with time and author.** Add `at`, `by` and a feature snapshot to every Timeline verdict, identity decision and disposition. Add a per-box **Jev ledger** (a workflow row type like `fusion_baseline`) recording prediction, answer, label, use and date, which survives case export and deletion | `store.validate_timeline:4712`, `decide_identity_link`, `set_disposition`; new ledger row | Nothing new; it makes everything below measurable | S |
| **A2** | **Case outcome.** One field on the case: *confirmed incident / false alarm / test or exercise / undetermined*. This is the strongest label, and it resolves the "test lab vs attack" disagreement seen live | case header, `set_analysis_config` | A dropdown in the case header | S |
| **A3** | **Per-box calibration.** From the ledger, compute per-use accuracy and a reliability table. Choose each use's display threshold from data (conformal-style), not the fixed 0.8. Below about 30 labels, numbers show as *"uncalibrated"* | new `jev.calibration()`, `frontend_config.agentic.jev.calibration` | Settings: *"Suggested verdict: 87% right over 140 verdicts on this box"*. Chips say *uncalibrated* until then | M |
| **A4** | **Eval for every use**, not only verdicts. Identity uses `identity_links`, scopes use case outcome, relevance uses analyst-pinned rows | `scripts/dev/jev_eval.py` | A report run on the box | S |

## B. Fusion judgments get a calibrated second opinion

| ID | Change | Where | What the analyst sees | Effort |
|---|---|---|---|---|
| **B1** | **`p_attack` per finding as a first-class field.** It reuses the suggestion pass and becomes a secondary sort key wherever findings are ordered: Timeline "order: most likely malicious", the report trim `_trim_findings:1027`, the LLM payload order, and the chat fill | `render._distilled_at`, `_trim_findings`, `cases.html` order dropdown | A Timeline sort that puts the likeliest real attacks first, and reports built around them | M |
| **B2** | **Host compromise probability.** Today's tier is the worst finding, and "high is the norm" (134 of 148 findings on one case), so hosts barely separate. Add a per-host score (2–10 levels) as a column and as a tie-break *within* the existing band | `correlate._score_assets:569`, `render.risk_table:1942`, report focal host and Containment list | Risk tab: *"P(compromised) 0.91"*; the containment order changes within a band | M |
| **B3** | **Second opinion on false-positive-prone rules.** One targeted question per rule, asked in the same per-finding call: *lateral movement or routine admin?* (cross-host account, fixed high/high); *attacker burst or provisioning/patch?* (`_coordinated_activity`); *malicious or benign use?* (keyword "suspicious process", renamed binary, service, DLL hijack). This annotates and can lower `confidence`; it never deletes | `correlate._cross_host_findings:881`, `_coordinated_activity:1639`, `_derive_findings` | *"Jev: likely routine admin (84%)"* on the finding; the LLM gets a real confidence instead of a fixed "medium" | M |
| **B4** | **Severity second opinion.** A 5-level Jev score beside the rule's severity; flag large disagreements | `severity.py`, post-fuse pass | *"Rule: high · Jev: low"* flag | S |
| **B5** | **MITRE phase when the keyword cascade falls back.** `render._phase` defaults to "Execution / Injection" when no keyword fires; Jev picks from `_PHASES` and the ATT&CK tactics instead | `render._phase:75`, `_host_tactics:2119` | Correct phases on the Timeline and in the report | S |
| **B6** | **Show `Finding.confidence`**, which is never rendered today, as the calibrated probability once A3 exists | finding detail, Timeline | A confidence column that means something | S |
| **B7** | **Report confidence grades from numbers.** The Key Judgements HIGH/MODERATE/LOW grades are LLM-written. Anchor each judgment to the grounding check's support probability plus the underlying findings' `p_attack` | `llm_sim` synthesis prompt, `jev.unsupported_claims` | Grades an analyst can trace back to evidence | M |

## C. Keep the right data, not the first or the loudest

| ID | Change | Where | Impact | Effort |
|---|---|---|---|---|
| **C1** | **Rescue events below the floor.** Held events are scored by Jev relevance against the case findings, and the top-k come back as context instead of the first 50 per neighbour | `correlate.assemble:213/:242` | Recovers data that is invisible to the analyst today; the largest silent loss | M |
| **C2** | **SIGMA occurrences by relevance.** Keep the top-k occurrences of each rule by Jev, with locators, instead of one loudest exemplar | `mappers/agentic.py:984/:1279`, `store.get_evidence_rows:1243` | Drill-down and report evidence show the rows that matter | M |
| **C3** | **LLM payload by relevance.** `top_entities` and the chat entity fill are ranked by Jev relevance to the case (or the question) rather than keyword anomaly | `render._distilled_at:1068`, `chat_subgraph:1704` | Better reports and chat from the same token budget | S |
| **C4** | **Memory rows by relevance.** Keep the top 250 per plugin by Jev, not by `_row_severity` | `memory/analyzers._trim_artefacts:95` | Suspicious processes survive on busy hosts | S |
| **C5** | **Cloud events Sigma missed.** Score non-SIGMA CloudTrail events and promote relevant ones as low-severity cloud events; revisit the first-500 recency cap | `aws/cloudtrail_runner.py:267`, `store._cloud_contribution:1128` | A cloud attack no rule matched becomes visible | L |
| **C6** | **Relevance job without the 20k first-come cut.** Stream all rows with a cost preview, or sample fairly across artifacts | `jev.score_relevance` | The scored list covers the whole case | S |

## D. Analyst flow

| ID | Change | Impact | Effort |
|---|---|---|---|
| **D1** | **Triage queue**: "Next to review", unreviewed findings ordered by `p_attack` × severity, one click per verdict (builds on B1 and A1) | The fastest path through a 130-finding case | M |
| **D2** | **Baseline safety.** An environment-wide suppression (`_promote_disposition_to_baseline`) hides a title everywhere on one verdict. Jev checks each suppressed recurrence ("still normal?") and flags the ones that look different | Catches an attacker hiding behind a baselined title | M |
| **D3** | **Cross-case memory with verdicts.** `kb.py` stores prior sightings with no verdict. Add the verdict and feed *"marked false positive in 3 prior cases"* to Jev as context | Fewer repeated false alarms, better priors | M |
| **D4** | **"Collect next"**: pick from the blueprint's Velociraptor artifacts given the findings | Guides the next collection | S |

## Recommended order

1. **A1 + A2 + A3.** Without labels no number can be called accurate, and
   they are cheap.
2. **B1 + D1.** Order everything by likelihood; the largest daily effect for
   analysts, and low risk because it only reorders.
3. **C1 + C3.** Stop losing the right data before anyone looks.
4. **B3 + B2.** Correct the known false-positive-prone rules and separate
   hosts within a band.
5. The rest as needed.
