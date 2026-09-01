"""A1+A2 — SUMMARY accuracy vs ground truth, and summary REPRODUCIBILITY (n>=10).

The report is the product's main deliverable and has only ever had a single judged
run. This generates the summary N times over the same known incident (the full
authored attack corpus) and measures, deterministically against the answer key:

  A1 accuracy      — of the finding-eligible planted techniques, how many does the
                     summary actually surface (keyword present, and the right host)?
  A2 reproducibility— across N runs, which techniques appear EVERY time vs only
                     sometimes? A technique that appears 4/10 times is a coverage
                     lottery, and that instability is invisible in a single run.

Deterministic scoring (no judge): keyword + host match against the corpus answer key,
so the number is repeatable and cheap. Nothing is persisted to the store.

  cd /app/scratch_eval && PYTHONPATH=/app python3 campaign/eval_summary_accuracy.py [N]
"""
import json
import os
import sys
from collections import Counter

sys.path.insert(0, "/app")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from services.fusion.mappers.agentic import map_agentic  # noqa: E402
from services.fusion import correlate, render, store, llm_sim  # noqa: E402
import attack_corpus as corpus  # noqa: E402
from rescore_summaries import SYN as _SYN  # noqa: E402

OUT = "/tmp/eval_out/campaign"
os.makedirs(OUT, exist_ok=True)
ws = store._ws()
N = int(sys.argv[1]) if sys.argv[1:] else 10


def _fuse():
    tele = corpus.build_all_telemetry()
    ents, rels = map_agentic(tele, run_id="evalrun", hostnames={})
    return correlate.assemble("gt_summary", [(ents, rels)], ["evalrun"])


def _eligible(g):
    """Planted scenarios that DID become findings (medium-SIGMA is suppressed by
    design, so scoring the summary on them would be scoring the wrong layer)."""
    texts = [f"{f.title} {' '.join(render._host_label(g, a) for a in (f.asset_ids or []))}".lower()
             for f in g.findings]
    out = []
    for s in corpus.SCENARIOS:
        kws = [k.lower() for k in s["expect"]["find"]]
        if any(all(k in t for k in kws) for t in texts):
            out.append(s)
    return out


def main():
    g = _fuse()
    elig = _eligible(g)
    print(f"case: {len(g.by_type('asset'))} hosts, {len(g.findings)} findings; "
          f"{len(elig)} finding-eligible plants to look for", flush=True)
    payload = json.dumps(render.distilled(g, max_entities=500, budget_chars=90000,
                                          detail="summary"), default=str)
    hits = Counter()
    runs = []
    for i in range(1, N + 1):
        rid = ws.create_automation_run("summary_acc", f"run{i}")
        try:
            rep = llm_sim._real_llm(llm_sim.REPORT_SYSTEM_PROMPT_MACRO, payload, run_id=rid)
        except Exception as e:  # noqa: BLE001
            rep = f"(ERROR {e})"
        low = rep.lower()
        found = []
        for s in elig:
            # expect.find holds DETECTION keywords (rule-title fragments like
            # "wevtutil"). A summary is narrative prose -- it says "the security log
            # was cleared" -- so scoring it on detection keywords under-reports the
            # product. This was found once and fixed only in rescore_summaries.py;
            # importing SYN from there keeps ONE source of truth so the live harness
            # cannot drift from the re-score again.
            kws = _SYN.get(s["id"]) or [k.lower() for k in s["expect"]["find"]]
            if any(k in low for k in kws):
                found.append(s["id"])
                hits[s["id"]] += 1
        m = (ws.get_automation_run(rid) or {}).get("llm_metrics") or {}
        runs.append({"run": i, "found": found, "n_found": len(found),
                     "chars": len(rep), "out_tok": m.get("output_tokens")})
        print(f"[{i}/{N}] surfaced {len(found)}/{len(elig)} plants, {len(rep)}c, "
              f"out={m.get('output_tokens')}", flush=True)
        open(f"{OUT}/summary_run_{i}.md", "w").write(rep)

    n_elig = len(elig)
    mean = sum(r["n_found"] for r in runs) / len(runs) if runs else 0
    always = [s["id"] for s in elig if hits[s["id"]] == N]
    never = [s["id"] for s in elig if hits[s["id"]] == 0]
    flaky = [(s["id"], hits[s["id"]]) for s in elig if 0 < hits[s["id"]] < N]

    md = ["# Summary accuracy + reproducibility vs ground truth", "",
          f"Same known incident ({len(g.by_type('asset'))} hosts, {len(g.findings)} "
          f"findings, **{n_elig} finding-eligible planted techniques**), summary "
          f"generated **{N} times**. Deterministic scoring against the answer key.", "",
          f"**Mean coverage: {mean:.1f}/{n_elig} techniques per summary "
          f"({100*mean/n_elig:.0f}%).**", "",
          f"- **Always mentioned ({len(always)}/{n_elig})** — reliable: "
          f"{', '.join(always) or 'none'}",
          f"- **Never mentioned ({len(never)}/{n_elig})** — a blind spot: "
          f"{', '.join(never) or 'none'}",
          f"- **Intermittent ({len(flaky)}/{n_elig})** — a coverage lottery: "
          + (", ".join(f"{i} ({c}/{N})" for i, c in sorted(flaky, key=lambda x: x[1]))
             or "none"), "",
          "| Run | Techniques surfaced | Chars | Out tok |", "|---|:--:|---|---|"]
    for r in runs:
        md.append(f"| {r['run']} | {r['n_found']}/{n_elig} | {r['chars']} | {r['out_tok']} |")
    md += ["", "## Read",
           "A macro summary is a TRIAGE MAP, not an inventory — it is not expected to "
           "list every technique. What matters is (a) the mean, (b) whether the "
           "*critical* ones are in the ALWAYS set, and (c) how large the intermittent "
           "set is: an intermittent technique means two analysts running the same case "
           "get different pictures."]
    open(f"{OUT}/summary_accuracy.md", "w").write("\n".join(md) + "\n")
    json.dump({"n": N, "eligible": n_elig, "mean": mean, "hits": dict(hits),
               "always": always, "never": never, "flaky": flaky, "runs": runs},
              open(f"{OUT}/summary_accuracy.json", "w"), indent=2, default=str)
    print("\n".join(md[:12]))


if __name__ == "__main__":
    main()
