"""A/B test of the QUESTION-ANCHORING hypothesis (properly powered).

Finding so far: asked "was a renamed utility used FOR CREDENTIAL THEFT? Where?", the
investigation sometimes answers about the Mimikatz/LSASS finding (WKS-EVAL01) instead
of the renamed-procdump finding (WKS-EVAL04) — i.e. the loaded phrase ANCHORS
retrieval on the wrong finding. n=5 was too noisy to conclude anything.

Two arms, N runs each, same case, same corpus:
  A "loaded"  : "Was a renamed system utility (e.g. procdump) used for credential theft? Where?"
  B "neutral" : "Was a renamed system utility such as procdump executed? On which host and when?"

If B >> A, the cause is question framing (anchoring), NOT a model/grounding defect —
and the fix belongs in how questions are posed / how the loop disambiguates, not in a
grounding footer (which was already measured and reverted).

  cd /app/scratch_eval && PYTHONPATH=/app python3 campaign/eval_anchoring_ab.py [N]
"""
import json
import os
import sys

sys.path.insert(0, "/app")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from services.fusion.mappers.agentic import map_agentic  # noqa: E402
from services.fusion import correlate, store, investigate  # noqa: E402
import attack_corpus as corpus  # noqa: E402
from eval_investigation_accuracy import _evidence_resolver, _Patch  # noqa: E402

OUT = "/tmp/eval_out/campaign"
os.makedirs(OUT, exist_ok=True)
ws = store._ws()

ARMS = {
    "loaded": "Was a renamed system utility (e.g. procdump) used for credential theft? Where?",
    "neutral": "Was a renamed system utility such as procdump executed? On which host and when?",
}
TARGET_HOST = "wks-eval04"      # renamed-procdump lives here
DECOY_HOST = "wks-eval01"       # Mimikatz/LSASS lives here (the anchor)
N = int(sys.argv[1]) if sys.argv[1:] else 10


def main():
    tele = corpus.build_all_telemetry()
    ents, rels = map_agentic(tele, run_id="evalrun", hostnames={})
    g = correlate.assemble("gt_incident", [(ents, rels)], ["evalrun"])
    case = {"masking": {"enabled": False}, "time_window": None,
            "min_severity": "informational"}
    results = {a: [] for a in ARMS}
    with _Patch(store, load_graph=lambda c: g, get_case=lambda c: case,
                get_evidence_rows=_evidence_resolver(tele)):
        for arm, q in ARMS.items():
            for i in range(1, N + 1):
                rid = ws.create_automation_run("anchor_ab", f"{arm}{i}")
                try:
                    res = investigate.investigate("gt_incident", q, run_id=rid, max_steps=6)
                    ans = res.get("answer", "")
                except Exception as e:  # noqa: BLE001
                    ans = f"(ERROR {e})"
                a = ans.lower()
                rec = {"run": i, "target": TARGET_HOST in a, "decoy": DECOY_HOST in a,
                       "procdump": "procdump" in a, "answer": ans[:200]}
                results[arm].append(rec)
                print(f"[{arm} {i}/{N}] target={rec['target']} decoy={rec['decoy']} "
                      f":: {ans[:70].strip()}", flush=True)

    md = ["# Question-anchoring A/B (properly powered)", "",
          "Tests whether a loaded phrase (\"used **for credential theft**\") anchors "
          "retrieval on the wrong finding (Mimikatz/LSASS on WKS-EVAL01) instead of "
          "the renamed-procdump finding (WKS-EVAL04).", "",
          f"N = {N} runs per arm.", "",
          "| Arm | Question | Target host found | Decoy host cited |", "|---|---|:--:|:--:|"]
    summary = {}
    for arm in ARMS:
        rs = results[arm]
        t = sum(r["target"] for r in rs)
        d = sum(r["decoy"] for r in rs)
        summary[arm] = {"target": t, "decoy": d, "n": len(rs)}
        md.append(f"| **{arm}** | {ARMS[arm][:54]}… | **{t}/{len(rs)}** | {d}/{len(rs)} |")
    md += ["", "## Read",
           f"- loaded: {summary['loaded']['target']}/{N} correct host",
           f"- neutral: {summary['neutral']['target']}/{N} correct host",
           "",
           "If neutral >> loaded, the weakness is QUESTION FRAMING (anchoring), not a "
           "grounding/hedging defect — which is what the reverted footer assumed."]
    open(f"{OUT}/anchoring_ab.md", "w").write("\n".join(md) + "\n")
    json.dump({"n": N, "summary": summary, "results": results},
              open(f"{OUT}/anchoring_ab.json", "w"), indent=2, default=str)
    print("\n" + "\n".join(md[-6:]))


if __name__ == "__main__":
    main()
