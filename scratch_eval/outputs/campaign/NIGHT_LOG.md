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
