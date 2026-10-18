# Detection-coverage harness (dev only)

Scripts that measured log-data detection on Splunk's attack_data recordings and
on benign captures. They read data that is **never** in the repo:

- `~/datasets/splunk-attack-data/` — the recordings, one folder per technique/dataset
  (downloaded by `run_cov.py`; `escu-tests/` is `escu_prove.py`'s cache).
- `~/datasets/splunk-attack-data/_work/` — `sc.jsonl` (Splunk security_content
  detections + macros, from `fetch_sc.py`), `meta.jsonl` (dataset index, from
  `fetch_meta.py`), `prove_latest.jsonl` (last prove result per rule) and
  `results/` (coverage runs `cov*.jsonl`, benign runs).
- `~/datasets/work/flat/benign_nextron_*/` — the 1.24 M benign Windows events.
- `~/datasets/external-logs/` — vendor samples and real benign web logs (Squid, Apache).

Paths are hard-coded to `/home/tenroot/wt-detect`; adjust `sys.path` at the top of
each script for another checkout. Downloaded data is untrusted: read it, never run it,
and run these with `python3 -I` when they read it.

| Script | What it does |
|---|---|
| `run_cov.py meta.jsonl out.jsonl [filter]` | every recording through the whole pipeline; one line per file with its detections |
| `why.py <dir> sc.jsonl` | why each undetected recording is missed (skip reason / low only / silent) -> `why.json` |
| `diag.py rule.yml...` | the values a silent rule's fields take in its recording |
| `benign_files.py rules_dir file...` | rules over real log files (web, firewall) -> hits per rule |
| `burst_benign.py events.jsonl...` | the whole pipeline over the benign Windows corpus -> detections + bursts |
| `pipe_file.py` / `any_level.py file...` | one file through the pipeline, medium+ / every level |

The rule pipeline itself is `scripts/dev/escu_to_sigma.py` -> `escu_prove.py` ->
`escu_benign.py` -> `escu_install.py`; see `docs/DETECTION_COVERAGE_STATUS.md`.
