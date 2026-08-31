# Track B — Agentic variance & quality at scale

cases=['case_1788080164853', 'case_1788078295586'] questions=['raw-evidence', 'cross-host', 'account', 'timeline', 'negative-control'] arms=['v1', 'v2'] repeats=5; 100 runs. Transport codex-subscription/gpt-5.6-sol (no temp control).

| Question | Arm | N | Give-up % | Fabricated % | Steps mean±sd | Out tok mean±sd | Errors |
|---|---|---|---|---|---|---|---|
| account | v1 | 10 | 10.0 | 0.0 | 5.1±1.8 | 708.0±196.1 | 0 |
| account | v2 | 10 | 0.0 | 10.0 | 5.5±0.7 | 805.0±130.7 | 0 |
| cross-host | v1 | 10 | 0.0 | 0.0 | 5±0.6 | 828.0±119.6 | 0 |
| cross-host | v2 | 10 | 0.0 | 10.0 | 5.3±0.8 | 893.0±114.5 | 0 |
| negative-control | v1 | 10 | 0.0 | 0.0 | 4.7±0.6 | 515±94.4 | 0 |
| negative-control | v2 | 10 | 0.0 | 0.0 | 4.6±0.5 | 516±82.3 | 0 |
| raw-evidence | v1 | 10 | 20.0 | 0.0 | 1.6±0.8 | 398.0±100.1 | 0 |
| raw-evidence | v2 | 10 | 0.0 | 0.0 | 2±0.0 | 465±47.4 | 0 |
| timeline | v1 | 10 | 0.0 | 0.0 | 3.7±0.6 | 616.0±96.9 | 0 |
| timeline | v2 | 10 | 10.0 | 0.0 | 3.8±1.5 | 717.0±208.1 | 0 |

## Headline
- **Turn-1 give-up (A1) rate: 4/100 = 4.0%** across loop arms — quantifies the live bug; each is a wasted, unhelpful investigation.
- **Fabricated-host rate: 2/100 = 2.0%** (deterministic check).
- Step/token spread columns show run-to-run variance (Codex has no temperature control, so this is irreducible without a min-step guard + retries).
