# Overnight test-and-fix log

Scope: **fusion + agentic** — chat, timeline, identities, and mostly the summary.
Discipline: deterministic tests are authoritative; model-driven claims need n ≥ 10
per arm; no improvement claimed below that; fixes that don't demonstrably help get
reverted with the reason recorded.

| Time (UTC) | Item | Result | Action |
|---|---|---|---|
| 19:47 | E18 evidence-locator audit | ✅ PASS — 78/78 locators resolve to the correct row, all host-matched | none needed; new deterministic gate |
| 19:47 | E19 duplicate collection import | ✅ PASS — entities 50/50, findings 37/37, evidence 90/90 (no inflation) | none |
| 19:47 | E20 extreme noise 500× benign | ✅ PASS — 37/37 detections survive | none |
| 19:47 | E21 medium-SIGMA boundary | Quantified: **4 of 41** techniques invisible (encoded-PS, sched-task, AD recon, RMM) | for morning decision |
| 19:54 | E17 attack-chain correlation | ✅ 1 cross-host finding spanning 3 hosts — fusion does link a campaign | none |
| 19:54 | B7 timeline order + patient zero | ✅ chronological, patient-zero = WKS-CHAIN01 (correct) | none |
| 19:54 | C10 identity clustering (uniform account) | ✅ 1 entity spanning 3 hosts | none |
| 19:54 | **C11 account-form equivalence** | ❌ **REAL GAP** — same person as `DOMAIN\u`/`u@domain`/bare SAM = 3 entities, **0 cross-host findings**; actor's lateral movement invisible as a finding | **FIXED** — see below |
| 19:54 | C11 fix + FP guard | ✅ now 1 cross-host finding; different-domain same-stem correctly yields 0 (guard) | committed w/ 3 regression tests |
| 19:55 | B8 timestomping / corrupt timestamps | ✅ 8/8 events kept (incl. undated + garbage), chronological; the 2099 timestomp sorts last and stays visible rather than reordering real events | none |
| 19:55 | B9 collapse fidelity @ corpus scale | ✅ critical shown 11/11 (the critical-hiding fix holds); no invented counts. Note: 36→36 groups here because corpus titles are unique — collapse only bites on real repeat-heavy data (real case: 131→61) | none |
| 19:55 | A4 Limitations correctness | ✅ every claim verified TRUE against the graph (quiet-host count 1=1, host named correctly) | none |
| 19:56 | A6 regression on REAL adatumlab case | ✅ 9 hosts, 151→155 findings (+4 identity cross-host from tonight's fix); body 10,890c; collapse 131→61; **all 5 criticals shown**; Limitations correct | none |
| 20:00 | A1/A2 summary accuracy + reproducibility (n=10) | ⚠️ **First pass WRONG** — scorer used one literal phrase per technique, under-counting badly (shadowcopy 1/10 vs "shadow"/"vssadmin" in 10/10; byovd 2/10 vs "byovd" 8/10; "bloodhound" 0/10 while the model writes "SharpHound") | **Scorer rewritten**, summaries re-scored offline |
| 20:00 | A1/A2 CORRECTED | Mean coverage **26.8/34 (79%)**; **0 never-mentioned** (the "3 blind spots" were scorer artifacts); 17 always incl. every crown-jewel technique; 17 intermittent (1/10–9/10) | documented as a characteristic |
| 20:03 | D14/D16 chat accuracy vs ground truth | ✅ **11/11** — plants 8/8, negative controls 3/3 clean. Chat has NO fetch-to-cite loop yet never fabricated; denials explain *why* ("none of the 37 findings mention spoolsv.exe") | scorer bug fixed (below) |
| 20:03 | ⚠️ scorer bug #2 | "No **direct** evidence…" didn't match the literal keyword "no evidence" → scored 2/3. Same class as the A1 scorer bug | Replaced literal phrases with a regex denial detector; re-scored 3/3 |
| 20:03 | D15 chat vs investigate | Investigate 38/40 (95%, 3 rounds) · Chat 11/11 on the matched set. Both strong; chat is ~1 call vs 3-6 | documented |
| 20:05 | C13 identity decisions round-trip | ✅ PASS — analyst **split** honoured (3 accts → 2+1) and **merge** honoured (2 clusters → 1). My first attempt failed only because I passed names/stems instead of cluster keys | 2 doc notes below |
| 20:05 | C13 note (doc) | `resolve_identities(merges=...)` docstring says "(name_a, name_b, score)" but it actually requires cluster **keys** (`account:domain:corp\\jdoe`) — misleading docstring, easy to misuse | logged for morning |
| 20:05 | C13 note (behaviour) | `compute_candidates` proposes 0 links for `corp\\jdoe` vs `corp\\john.doe` (the first.last↔flast convention). Defensible — it wants corroborating context before suggesting — but worth a decision | logged for morning |
| 20:08 | **Severity made generic (user guidance)** | My identity finding hard-coded `severity="high"`. Now DERIVED from the clustered accounts' own severity. On the real case the 4 findings drop `high`→`informational` — they are ordinary admins on several hosts | **4 false "high" findings on a real case avoided** |
| 20:08 | A5 evidence-gap hallucination (n=6) | ⚠️ scorer bug #3 → then ✅ **6/6 honest, 0/6 fabricated** | harness fixed (markdown-aware) |
| 20:08 | ⚠️ scorer bug #3 | markdown emphasis broke the denial regex — "does \*\*not show\*\*" ≠ "does not show" → 3 FALSE "fabricated" verdicts (would have reported a 50% fabrication rate) | strip `[*`_]` before matching |
| 20:08 | A3 scale (deterministic) | 120 hosts / 5,280 rows: map 0.1s, assemble 0.3s → 4,321 findings; altitude=macro ✅; facts_md 0.1s → 9,948c; collapse 4,320→36 groups; 11 criticals shown; host-risk capped at 15 + tail | ⚠️ payload 2.6 MB — see next |
| 20:13 | **A3 scale — LLM payload budget silently stops binding** | ❌ **REAL (latent) DEFECT** — 120 hosts/4,321 findings produced a **2.6 MB** payload against a 708 KB budget (3.7× over). `MAX_STEPDOWNS=2` caps the halving and `_trim_findings` never drops ≥high, so the budget cannot bind once a case has thousands of high findings | **FIXED** — see below |
| 20:13 | A3 fix — collapse instead of drop | Repeated detections collapse to one row (count + hosts + span), findings then timeline. **2.6 MB → 137 KB (95%↓), 0.19× budget.** Payload now scales with DISTINCT detections, not host count. No signal dropped: all 37 distinct detections + both severities preserved | +3 regression tests (altitude 26 green) |
| 20:13 | A3 blast radius | All 8 REAL cases **byte-identical** — they are under budget so the pass never fires. Zero impact today; prevents a future context overflow | verified |
| 20:13 | ⚠️ my own repeat mistake | First collapse attempt was a NO-OP (4,321→4,321) because titles embed the host — the exact mistake I made on the timeline earlier tonight. Then the timeline stayed 87% because its rows use `host` (string) not `hosts` (list) | both fixed; normalizer handles either shape |
| 20:54 | Context-window claim checked empirically (operator: "model is 1M") | Catalog says gpt-5.6-sol = **272,000** tok. MEASURED: **376,564 input tokens SUCCEEDED** (catalog under-reports); 1,100,000 chars failed instantly with `Input exceeds the maximum length of **1048576** characters` | see below |
| 20:54 | **Root cause: transport cap, not model context** | The Codex CLI reads the prompt from stdin and hard-rejects >1 MiB of CHARACTERS — independent of the model's token window. A 1M-token model still cannot receive >1 MiB through this CLI | **FIXED** |
| 20:54 | **Latent defect fixed** | `adaptive_budget` had NO transport ceiling: a 1M-token model computes **2,892,000 chars** → every report would fail with `input_too_large`. Added `budget.transport_cap_chars()`, clamped in `_llm_payload_budget` | +3 tests; real case unchanged (708,000) |
| 20:54 | Headroom noted (not taken) | Current budget is 708,000 of a proven-safe ~1,000,576 → **~41% more evidence per report is available**. NOT raised tonight: it changes every report and needs an n≥10 quality measurement first | for morning decision |
| 21:01 | **E21 recalibrated (operator input)** | Operators run min_severity **≥ high** in practice. So the "4 of 41 techniques invisible via medium-SIGMA suppression" finding is **largely moot** — those findings would be filtered by the severity floor anyway. Priority drops from "coverage decision" to "aligned with real usage" | de-prioritised |
| 21:01 | Follow-on | All my tests ran at min_severity=**informational** — NOT the production operating point. Re-running the accuracy sweep at **high** to measure what operators actually see | in progress |
| 21:01 | Accuracy at production floor (≥high) | ✅ recall **identical at every floor** (37/41 at informational, medium AND high) → at your operating point detection is **37/37 = 100%** of what is detectable; benign@high = 0 findings | E21 closed as moot |
| 21:01 | 📌 Severity is not discriminating (real cases) | case_853: 151 findings, **146 are high+**. Floor=high → 146 (a ~3% cut); floor=critical → 9. So the severity floor has only two useful positions: "everything" or "almost nothing". Severity grading is too top-heavy to triage with | **for morning — product observation** |
| 21:12 | **Prompt injection via telemetry** (security) | Injection text DOES reach the LLM payload. Across 2 runs / 14 arms: **14/14 still reported the real attack**, **0 genuinely obeyed**, 2 explicitly flagged the injection. The one regex "obeyed" hit was verified by reading the text — a quote, not compliance | ✅ robust; no change needed |
| 21:12 | Budget-raise experiment **cancelled by pre-check** | Cheap deterministic check before spending 20 model calls: payload is **byte-identical at 708k vs 1M for every real case**. Only a narrow band (raw payload 708k–1M, e.g. 40 hosts) differs; above it the collapse lands far below either budget | "41% more evidence" is **theoretical, not a quality lever** — de-prioritised with evidence |
| 21:13 | M1 masking at corpus scale | ✅ **0 real hosts / 0 accounts leak** into the masked payload across all 41 scenarios | none |
| 21:13 | X1 clock skew (hosts 6h apart) | ✅ both hosts present, no crash, ordered by stamp. 📌 *Observation*: ordering is by RECORDED time, so a skewed host sits in the wrong real-world position — unavoidable without clock correction, but the report never says so | morning: consider a Limitations line |
| 21:13 | X2 contradictory evidence | ✅ conflicting cmdlines both KEPT with provenance + `conflict` flag — forensic integrity holds, no silent overwrite | none |
| 21:13 | X3 hostile strings (200 KB cmdline, RTL override, NUL, emoji) | ✅ no crash; payload bounded to 719 chars (oversized value truncated correctly) | none |
| 21:13 | X4 single-event case | ✅ 1 finding → focused altitude, timeline + Limitations both present | none |
| 21:13 | 📌 M1 note | mask revert is not byte-identical (`round_trip_ok=False`) — the known JSON backslash-escaping nuance already covered by a unit test. **Not a leak**; the masked text contains no real identifier | documented |
| 05:49 | **#4 answered + fixed** | Traced the real caller: `store.identity_view` correctly passes **account IDs**, so merges work in production — only the **docstring** was wrong (said "name_a, name_b"). Fixed the docstring; no functional change | ✅ |
| 05:49 | **#5 answered — it was structurally disabled** | Cross-name identity links required **≥2 infrastructure buckets**. Velociraptor-only = ONE bucket → the pass never ran, so `corp\\jdoe` ↔ `corp\\john.doe` (`_match` scores it **0.65**) was **never offered to the analyst**. The code's own comment said name-only candidates "are left as suggestions" — they were left as nothing | **FIXED** |
| 05:49 | #5 fix + safety choice | Gate relaxed to run for single-bucket cases, but same-bucket pairs are forced to **suggestion-only (auto=False)** — within one infrastructure, colleagues share hosts, so "similar name + shared host" is weak evidence for one PERSON and a wrong merge is an attribution error. Real cases: **3 suggestions, 0 auto-merges** (e.g. `adim` ~ `adim_std`) | +3 tests, 20 green |
| — | **#1 answered with data: severity ≠ likelihood** | Cross-tab over 7 real cases: **all 22 `critical` findings have only `medium` confidence**; 268 high×medium; and **15 findings are medium-severity but HIGH-confidence**. Confidence is 82% `medium` (2 values only) → the likelihood axis is effectively unused, which is why severity *feels* like possibility | **for morning** |
| — | #1 consequence | At `min_severity=high` those **15 high-confidence findings are filtered out** — the noise valve discards the most-confirmed findings because it reads impact, not certainty | **for morning** |
| — | **#1 concrete recommendation: floor should be `medium`, not `high`** | The 15 high-confidence findings lost at `high` are ALL **"Shared binary seen on 2 hosts"** — cross-host lateral tool transfer, the signal fusion exists to produce. Stepping medium→high saves **0.6%** of data (151→146 findings, 389k→387k payload) and costs **every** shared-binary cross-host finding (5 per multi-host case) | **for morning — likely a one-setting win** |
| 07:01 | C12 identity attribution in the summary | ✅ **6/6** attribute to ONE actor, 6/6 name the identity, 0/6 treat them as separate people. Case now has **1 cross-host finding (0 before tonight fix)** | closes the loop on F1 |
| — | Summary EVOLVES as scope narrows (operator spec) | ✅ focused case: 37→4→2 findings, summary 11.2KB→6.7KB→4.7KB, narrative similarity **0.10 / 0.11** (≈90% different each step) — it genuinely re-tells the story, not re-words it | none |
| — | Macro-eligible case (30 hosts, 1081 findings, 199d) | ✅ correctly resolves **macro**; narrowing keeps macro because cross-host findings genuinely span all 30 hosts — the verdict is right for that data | my "time-narrowing can never reach focused" claim was WRONG |
| — | Altitude host-count refinement | `_resolve_altitude` counted ALL graph assets incl. hosts with zero in-scope findings; now counts in-scope hosts. **Verified: no real case changes altitude** (old==new on all 6) | latent-correctness only, NOT a live fix — kept, labelled honestly |
| — | ⚠️ my over-claims #6 and #7 | (a) claimed time-narrowing could never reach focused — disproved by the fixture; (b) claimed case 933758 flipped macro→focused — it was focused either way (10 assets < 12 threshold) | corrected in the record |
| — | ⚠️ harness mismatch found | my summary coverage/stability runs hard-coded the MACRO prompt on a case the system renders as FOCUSED — those numbers measure the macro prompt, not this case's production output | documented |
| — | **UI-reported #1: cross-host finding had `ts: null`** | Root cause = the SAME identity-notation problem: `adatumlab\giladt` gets a GLOBAL id and carries **no first_seen** (named by a user/SAM listing, not an event), while two dated bare-SAM `giladt` records existed all along. `_cross_host_findings` used `ts=e.first_seen` directly → null → the report could not establish sequence or direction | **FIXED** — generic `_entity_ts` falls back to the earliest time for the same normalized label + type. Default case null_ts 1→0, giladt now dated 2026-03-18T20:31:06 |
| — | **UI-reported #2: remove the "Next" column** | It restated the same three canned strings on every row (escalate / deep-done / triage) — width without information | **REMOVED**; the recommended action stays in the narrative's case-specific Priority actions |
| — | **UI-reported #3: coverage shows "agentic"** | A Velociraptor collection and a Velociraptor hunt are ONE collector to the analyst; showing the internal split overstates coverage | **FIXED** generically via `_COLLECTOR_LABEL` map + `_collectors()` — coverage now reads `memory, velociraptor` (was `agentic, memory, velociraptor`) |
| — | Full harness sweep after tonight's 6 fixes | ✅ ALL GREEN — recall 37/41 (37/37 eligible), precision PASS, incremental==one-shot, duplicate no-inflation, chain 4/4, agentic faults 0, fusion probes 0, evidence audit PASS, edge cases 5/5 | nothing regressed |
| — | Cross-case contamination (new) | ✅ PASS — 8 cases, **0 foreign-host leaks** into any case payload. 10 hosts legitimately appear in >1 case (same environment); 24 findings reference other cases via the by-design cross-case IOC note | none |
| — | Low-and-slow 2-year campaign (new) | ✅ 4 hosts / 39 findings / **663d span** → correctly **macro** on SPAN alone (host + finding counts are both under threshold). Shared account links all 4 hosts; gap-splitting yields 4 distinct zoom windows instead of one meaningless 2-year block; 11 criticals shown | validates the span threshold for APT-style dwell |
| — | **Chat accuracy, properly powered (n=3 rounds, 33 questions)** | ✅ **33/33** — plants 24/24, negative controls **9/9 clean**, 0 failures. Chat has NO tool loop (one distilled payload) yet never invented an attack across 9 probes for things never simulated | supersedes the earlier n=11 sample |

## Search retrieval defect — found, fixed, measured (post-wake session)

**How it surfaced.** Investigation round 4 (first run with the six overnight fixes
applied) scored 13/15. Two genuine misses:
- Q3 (cross-host account) — burned all 6 tool calls, answered LOW, never named
  `svc_backup`. Passed in rounds 1-3, so variance.
- Q10 (anti-forensic) — named log clearing on WKS-EVAL01 but reported that
  "searches for shadow-copy deletion returned no findings", when
  `SIGMA: Volume Shadow Copy Deletion via Vssadmin on WKS-EVAL07` exists as a
  **high** finding.

**Two hypotheses I tested and REJECTED before finding the real cause:**
1. *My own `_identity_cross_host_findings` made Q3 ambiguous by adding competing
   cross-host findings.* Measured: 1 cross-host finding with the fix, 1 without —
   identical. The fix adds nothing on this corpus. Not the cause.
2. *Q10 is a scorer bug (multi-part question, several valid hosts).* Partly true —
   my keyword grep had missed "Security Eventlog Cleared" on WKS-EVAL01, so the
   question does have two valid hosts. But that did not explain the model claiming
   shadow-copy search returned nothing.

**Real cause** — `investigate.py` `_tool("search")` was a whole-phrase substring
match: `q in (title + summary).lower()`. Analyst phrasing almost never appears
verbatim in a rule title.

**Measured on the 41-scenario corpus, 15 realistic queries:**

| matcher | right finding top-1 | top-5 | results/query |
|---|---|---|---|
| exact phrase (before) | 3/15 | 3/15 | 0.2 |
| token-AND | 8/15 | 8/15 | 0.6 |
| **ranked token overlap (shipped)** | **13/15** | **15/15** | 2.1 of 37 |

The two non-top-1 cases are the answer key being wrong, not the search:
`secure delete tool` -> "MFT: SDelete secure deletion tool"; `process injection`
-> "Injected process with C2 - explorer.exe". Both better than what I keyed.

**Shipped** (`c0da82d9`): score = fraction of query terms present (light suffix trim
so "clearing"->"Cleared"), ties broken by SEVERITY — generic, no attack vocabulary
encoded. Search results now also carry `hosts`, which `list_findings` already did;
without them the model had to infer attribution from the title, the observed cause
of Q10's wrong host. An unrelated query still returns 0.

**Scope correction:** this tool is used ONLY by the agentic Investigate loop. Chat
sends one distilled full-context payload with no tool calls, so chat and the summary
are unaffected.

**Fourth scorer bug (all four under-reported the product).** The investigation
harness scored negative controls against a literal phrase list, so a correct refusal
phrased "returned no findings ... does not establish" scored as a miss. Now matches
the shape of a denial as well (literal OR regex — strictly more permissive, cannot
regress a passing case; verified it does not match affirmative answers). Round 4
rescored 12/15 -> 13/15: one negative control, no plant affected.

**Result.** Round 5 (post-fix, same scorer): **15/15** — plants 12/12, negative
controls 3/3. Q10, the failure the fix was diagnosed from, flipped to correct-host.
Caveat: one round is not n>=10; the deterministic 3/15 -> 15/15 recall measurement is
the load-bearing evidence, not the round score.

Regression: investigate_v2 24 (5 new SearchRanking tests), behavioral 23,
altitude 26, host suite 662 passed / 2 skipped.

## ts:null on cross_host — verified on the REAL Default case (read-only)

Loaded `case_1787641933758` without writing. Of 8 cross_host findings exactly one
had `ts=None` — `adatumlab\giladt` used across 3 hosts, the one in the screenshot.
The shipped `_entity_ts` fallback resolves it to `2026-03-18T20:31:06` from the same
identity's other records; the other 7 are byte-identical. Blast radius on real data:
1 finding changed, 7 untouched. Seeing it in the UI needs a Refusion — a write to a
real case, left for the user to trigger.

## Silent truncation — the model stated a sampled count as fact

**How it surfaced (via a test that was itself wrong).** I built a scale test to
attack my OWN ranked-search change: recall had been measured on a 37-finding graph,
so at 3,000 findings a two-term query might match hundreds and the 15-cap would
return whatever severity-sorts highest. The test reported top-5 dropping from 4/5 to
3/5 at scale.

**That result was an artifact.** Instrumenting it showed the synthetic haystack
already contained 41 findings titled "Security Event Log Cleared on WKS0xx" — the
same activity as my planted needle. So `log clearing` correctly returned 42
genuinely relevant findings and my needle was the 42nd equally valid one. Search was
right; the test was wrong.

**A fix I did NOT ship.** I had diagnosed the (non-existent) problem as weak suffix
trimming plus coarse score granularity, and built IDF weighting + real stemming.
Measured against the same scale test: **top1 9/15, top5 10/15 — byte-identical to
the unchanged code.** Discarded rather than shipped. This is the second time this
campaign that measuring a fix before believing it prevented shipping one that does
nothing.

**The real defect, found by instrumenting the false one.** `list_findings` and
`search` returned a capped list with no signal that more existed (`pivot` already
returned `{total_matches, shown, events}` — the inconsistency was the tell).
Verified by execution on 42 hosts that ALL had cleared event logs:

| | before | after |
|---|---|---|
| "on how many hosts were event logs cleared?" | **"15 hosts"** | **"42 hosts"** |
| confidence | MODERATE | HIGH |
| steps | search>evidence | search>search>list_findings>clusters |

A 64% understatement of incident scope, stated as fact. For a DFIR tool this is the
most damaging error shape there is: it makes a large incident look contained.

**Shipped** (`ddba63a3`): both tools return `{total_*, shown, findings:[...]}`, and
the system prompt states that `shown < total` means a SAMPLE and the sampled count
must never be reported as the true count. Confidence rose to HIGH *because* the
grounding became complete — it now enumerates via `clusters` instead of stopping.

Regression: investigate_v2 27 (3 new), behavioral 23, altitude 26, host 670 passed.
