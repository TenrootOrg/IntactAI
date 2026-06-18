# Entity-Fusion layer (`services/fusion`)

Cross-module + cross-host DFIR correlation. Each host-centric module's raw output
maps into ONE shared typed entity graph, is correlated **deterministically in code**
(no LLM), then narrated into a 3-altitude case report + interactive chat. Cost scales
with *signal*, not raw data; the LLM only narrates a distilled, in-window graph.

Strictly additive — a **Case is a workflow row** (`automation_type='case'`); no existing
pipeline is modified, no new database.

## Modules
| file | role |
|---|---|
| `schema.py` | `Asset/Entity/Relationship/Finding/FusionGraph` + forensic-integrity merge (conflicting facts kept with provenance) |
| `keys.py` | natural keys — `asset:endpoint:{client_id}` anchor, `process:{asset}:{pid}:{createtime-bucket}` (PID-reuse guard), **global** IOC/domain-account/hash (→ cross-host) |
| `severity.py` | one 5-level scale across memory(numeric)/SIGMA(str)/CVE(CVSS) |
| `anomaly.py` | reuses `memory._row_severity` (bundled fallback) |
| `mappers/fieldspec.py` | `get(row,*aliases)` — tames Velociraptor per-artifact naming (`Hostname/HostName/host`, `Pid/PID`…) |
| `mappers/{memory,agentic,timesketch,cve,cloud}.py` | raw module output → entities+relationships (agentic splits N clients by `_client_id`; **cloud bridges UPN/source-IP to endpoint accounts** for cross-domain correlation) |
| `mappers/details.py` | parses the Hayabusa `Details` KV string → links each SIGMA detection to the **process/account/IOC** it names + reconstructs short-lived processes Pstree missed |
| `correlate.py` | assemble + PID-reuse + cross-host (lateral movement) + derived findings (injected+C2, yara, persistence) + severity rollup |
| `render.py` | 3 altitudes: macro / **infrastructural attack timeline** / per-asset; + IOC table + MITRE |
| `llm_sim.py` | **LLM engine — flag-gated** (`agentic.fusion_llm_mode` = `simulated`/`real`). Real path narrates `distilled()` via `call_llm(run_id=…)`; **any failure → deterministic fallback**. Default simulated. |
| `budget.py` | tokenizer-free `chars/4` budget guard + per-altitude caps (report/chat); `distilled()` step-down |
| `calibrate.py` | finding-level precision/recall/F1 scorer + `build_baseline` + threshold `sweep` over the labeled fixtures |
| `kb.py` | cross-case knowledge base on the running ES — index case entities, enrich new cases with prior sightings (**enrichment-only**, degrades silently without ES) |
| `store.py` | Case CRUD + `fuse_case` (map → assemble w/ baseline+window → narrate → token A/B → KB) + `capture_baseline`/`load_baseline` + `watch_and_fuse` |

## API (`routes/case_routes.py`)
```
POST /api/cases                 create {name, time_window, initial_access, min_severity}
POST /api/cases/quick           0->1: create + attach + fuse + report in one call
POST /api/cases/<id>/attach     {run_ids, fuse|watch}
POST /api/cases/<id>/fuse       (re)build graph + report
POST /api/cases/<id>/chat       {question} -> grounded answer
GET  /api/cases[/<id>]          list / detail
GET  /api/cases/runs            attachable module runs (UI picker)
GET  /api/cases/<id>/report|graph|timeline
```
**UI:** `/<host>/cases.html` — pick runs, fuse, view report (chips/IOC/MITRE), chat.

## Use a real LLM
Set `agentic.fusion_llm_mode = "real"` in `frontend_config` (with an API key in
`agentic.online_llm`, or an offline Ollama). `generate_report`/`chat` then narrate the
**distilled graph** via `call_llm(run_id=case_id)` — real token/cost land on the case's
`llm_metrics`, and the deterministic **fact tables (IOC/MITRE/per-host) are appended
verbatim, never sent to the model** (so they can't be hallucinated and cost no tokens).
Any LLM failure → deterministic fallback. Default `simulated` (airgap-safe, no key).

## Cross-module / cross-host "combining" (the join points)
Independent observations fuse through **global natural keys**, so correlation spans modules
and hosts in one graph:
- **Detection→entity linking** — Hayabusa `Details` (PID/Proc/User/ParentPID/Hashes/TgtIP)
  attaches every SIGMA detection to the process/account/IOC it's about (no more orphan
  events) and reconstructs short-lived attack processes that exited before Pstree ran.
- **Cross-host indicators** — same `ip`/`domain`/`hash`/domain-`account`/`yarahit` on ≥2
  hosts → a lateral-movement / shared-C2 finding. Benign anomaly-0 telemetry IPs are gated
  out so cloud noise on many hosts never false-alarms.
- **Hash-identity bridge** — the same binary keyed by SHA1 (Amcache), SHA256 (Pslist), or
  MD5+SHA256 (Hayabusa) collapses to ONE node (`correlate._bridge_hashes`), so cross-host
  binary tracking works regardless of which algo each source reported.
- **Auth / Kerberos** — `LogonSessions`/`CondensedAccountUsage` enrich the
  `account→authenticated→asset` edge (src_ip, auth_package, logon_process); domain accounts
  are global-keyed → cross-host lateral movement; `Kerberos.GoldenTicketTriage` `Suspicious`
  → a Golden/Silver-Ticket finding (T1558).

## Accuracy: baseline-subtraction (the FP fix)
Provisioning/automation produces attack-like SIGMA bursts. Capture a known-clean
snapshot as a baseline (`store.capture_baseline`, an `automation_type='fusion_baseline'`
row keyed by host); `fuse_case` then **subtracts** baseline SIGMA titles before emitting
findings (never suppresses ≥critical), and the window-scoped **coordinated-activity**
finding counts only *non-baseline* detections. On the committed purple-team fixtures this
takes macro-F1 from 0.143 → **1.0** (clean silent, simulated attack fully recognized).

## Test
```
# full suite (8 modules, 62 tests) + calibration F1 — the fix-test loop:
docker exec -w /app intact_backend python3 -m services.fusion.tests.run_all
# calibration only (precision/recall on the real clean/attack fixtures) + threshold sweep:
docker exec -w /app intact_backend python3 -m services.fusion.calibrate --sweep
```
Suites: `test_fusion` (correlation), `test_budget` (token caps + facts-not-sent),
`test_llm_contract` (mocked real-LLM seam), `test_baseline_fp` + `test_baseline_subtraction`
(the FP regression gate), `test_chat_retrieval`, `test_kb_enrichment`, `test_fuzz_mappers`.
Fixtures `tests/fixtures/{clean,attack}.json` are real Velociraptor purple-team data.
Validated end-to-end on real VolWeb evidence-6 (isolates the MsMpEng + powershell_ise
RWX injections) and on a multi-host fixture (cross-module process merge, cross-host
C2 IP + admin account → lateral movement, cross-host file hash, injected-process-with-C2).

## Workflow fit (staged triage → escalation)
Real flow: **Phase 1** = Velociraptor + AWS/Azure across everything → the report's
**Escalation** section ranks hosts and flags which look extremely malicious. **Phase 2** =
run memory + Timesketch only on those hosts → attach to the same Case → re-fuse enriches
them. The Case is a living workspace (`attach {watch:true}` auto-fuses on completion).

## Roadmap
- **Done:** memory/agentic/cve/timesketch/cloud(AWS+Azure) mappers; cross-module +
  cross-host + cross-domain (cloud↔endpoint) correlation; triage/escalation; report+chat+UI.
- Phase 3: `engagement/builder.py` consumes the case graph (retires the regex fusion).
- Wire the real LLM (one line in `llm_sim.py`); validate mappers on a live hunt.
- Cross-case ELK knowledge base (threat-intel / baseline over all cases); launch-runs-
  from-a-case (the `watch_and_fuse` plumbing is already in place).
