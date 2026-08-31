# Report outputs — the size × timeframe grid

Each `.md` here is a **generated Case Analysis report** for one scope point, so you
can read what the altitude ladder actually produces as the case gets bigger/longer.

Filenames encode the scope: `synth_h<hosts>_d<days>_f<findings>__<strategy>.md`.

- **`S2-macro2` / `S3-final`** = the **shipped** method (the macro/focused fork now
  wired into `generate_report`). `S3-final` picks macro-vs-focused automatically.
- **`S0-baseline`** = the **old** frozen prompt (single "reconstruct ONE story",
  `detail=explicit`), kept as the before/after comparison.

There is **no public big-org Velociraptor dataset** (client data is always private),
so the large cells are **synthetic** (`synth_graph.py`); `case_*` files are the one
*real* multi-host case on the box (`adatumlab`, ~10 hosts).

## The grid (production method per cell)

| Scope (hosts × timeframe) | Findings | Altitude | Report (shipped method) | out tok |
|---|---|---|---|---|
| **100 hosts × 1 year** (many_long) | 220 | MACRO | [synth_h100_d365_f220__S2-macro2.md](synth_h100_d365_f220__S2-macro2.md) | 2022 |
| **100 hosts × 2 days** (many_short) | 70 | MACRO | [synth_h100_d3_f70__S3-final.md](synth_h100_d3_f70__S3-final.md) | 2043 |
| **25 hosts × 2 months** (mid) | 90 | MACRO | [synth_h25_d60_f90__S3-final.md](synth_h25_d60_f90__S3-final.md) | 2435 |
| **3 hosts × 1 year** (few_long) | 45 | MACRO | [synth_h3_d365_f45__S2-macro2.md](synth_h3_d365_f45__S2-macro2.md) | ~1900 |
| **3 hosts × 1 week** (few_short) | 14 | **focused** | [synth_h3_d7_f14__S3-final.md](synth_h3_d7_f14__S3-final.md) | 2036 |

Read the grid **down**: 100/25/3-host broad cases → a *macro triage map* (ranked
candidate scenarios + zoom targets); the 3-host/1-week case → a *single focused
theory*. That flip is the altitude ladder.

## Before / after (same cell, old vs new prompt)

| Cell | Old frozen prompt | Shipped altitude prompt |
|---|---|---|
| 100h × 1yr | [__S0-baseline](synth_h100_d365_f220__S0-baseline.md) (39 KB, forces one story) | [__S2-macro2](synth_h100_d365_f220__S2-macro2.md) (7.6 KB, ranked scenarios) |
| 3h × 1yr | [__S0-baseline](synth_h3_d365_f45__S0-baseline.md) | [__S2-macro2](synth_h3_d365_f45__S2-macro2.md) |
| 3h × 1wk | [__S0-baseline](synth_h3_d7_f14__S0-baseline.md) | [__S3-final](synth_h3_d7_f14__S3-final.md) |

## Real case (adatumlab, on the box)

`case_1788080164853__*` — the real ~10-host broad case, rendered under every
strategy (S0/S1/S2/S4) with the judge verdict in `..._verdict.json` /
`..._compare.html`. This is the eval that chose the shipped design (macro S2 = 23
vs baseline S0 = 13).

## Regenerate

```
docker exec intact_backend sh -lc \
  'cd /app/scratch_eval && EVAL_ONLY=S3-final PYTHONPATH=/app python3 \
   eval_report_strategies.py synth <shape>'   # shape: many_long|many_short|mid|few_long|few_short
```
