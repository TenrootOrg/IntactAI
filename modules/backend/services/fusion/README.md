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
| `mappers/{memory,agentic,cve}.py` | raw module output → entities+relationships (agentic splits N clients by `_client_id`) |
| `correlate.py` | assemble + PID-reuse + cross-host (lateral movement) + derived findings (injected+C2, yara, persistence) + severity rollup |
| `render.py` | 3 altitudes: macro / **infrastructural attack timeline** / per-asset; + IOC table + MITRE |
| `llm_sim.py` | **LLM engine — SIMULATED** (real `call_llm` commented; deterministic narrator + grounded chat). One-line swap to live. |
| `store.py` | Case CRUD + `fuse_case` (fetch members → map → assemble → narrate) + `watch_and_fuse` |

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
In `llm_sim.py`: uncomment `_real_llm` (it wires `services.agentic.analyzers.call_llm` +
`memory.pipeline._llm_config_from_runtime`), set the LLM config/API key, and route
`generate_report`/`chat` through it. Nothing else changes — the graph/correlation are
LLM-free; only this boundary swaps. Token deltas auto-record via `call_llm(run_id=…)`.

## Test
```
docker exec -w /app intact_backend python3 -m services.fusion.tests.test_fusion   # prints demo report + chat
# (pytest if installed) python3 -m pytest services/fusion/tests/
```
Validated end-to-end on real VolWeb evidence-6 (isolates the MsMpEng + powershell_ise
RWX injections) and on a multi-host fixture (cross-module process merge, cross-host
C2 IP + admin account → lateral movement, cross-host file hash, injected-process-with-C2).

## Roadmap
- Phase 2: timesketch mapper (window-bounded ES projection); CVE live-fetch.
- Phase 3: `engagement/builder.py` consumes the case graph (retires the regex fusion).
- Future: AWS/Azure mappers (`asset:cloud_*` keys, same engine) + cross-case ELK
  knowledge base (threat-intel / baseline over all cases).
- Launch-under-case (start a run *in* a case) + auto-fuse-on-completion (the
  `watch_and_fuse` plumbing is already in place).
