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
