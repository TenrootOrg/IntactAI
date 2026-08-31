"""Focused repeat test for the unproven-premise weakness (Q8).

Q8 — "Was a renamed system utility (e.g. procdump) used FOR CREDENTIAL THEFT? Where?"
— failed 2 of 3 investigation rounds with an identical signature: technique found,
HOST DROPPED, confidence LOW. The question embeds a premise the evidence does not
prove (purpose), and the model hedged away facts it HAD established.

Runs the same question N times and reports how often the established host survives.
Baseline before the prompt fix: 1/3. Run after the fix to measure the change.

  cd /app/scratch_eval && PYTHONPATH=/app python3 campaign/eval_q8_repeat.py [N]
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

Q = ("Was a renamed system utility (e.g. procdump) used for credential theft? Where?")
HOST = "wks-eval04"
KW = ["procdump", "renamed"]
N = int(sys.argv[1]) if sys.argv[1:] else 5


def main():
    tele = corpus.build_all_telemetry()
    ents, rels = map_agentic(tele, run_id="evalrun", hostnames={})
    g = correlate.assemble("gt_incident", [(ents, rels)], ["evalrun"])
    case = {"masking": {"enabled": False}, "time_window": None,
            "min_severity": "informational"}
    rows = []
    with _Patch(store, load_graph=lambda c: g, get_case=lambda c: case,
                get_evidence_rows=_evidence_resolver(tele)):
        for i in range(1, N + 1):
            rid = ws.create_automation_run("q8_repeat", f"run{i}")
            try:
                res = investigate.investigate("gt_incident", Q, run_id=rid, max_steps=6)
                ans = res.get("answer", "")
            except Exception as e:  # noqa: BLE001
                ans = f"(ERROR {e})"
            a = ans.lower()
            kw_ok = any(k in a for k in KW)
            host_ok = HOST in a
            rows.append({"run": i, "kw": kw_ok, "host": host_ok, "ok": kw_ok and host_ok,
                         "answer": ans[:300]})
            print(f"[{i}/{N}] {'✅' if kw_ok and host_ok else '❌'} "
                  f"technique={kw_ok} host={host_ok} :: {ans[:90].strip()}", flush=True)
    ok = sum(r["ok"] for r in rows)
    hosts = sum(r["host"] for r in rows)
    md = ["# Q8 unproven-premise repeat test", "",
          "Q: *\"Was a renamed system utility (e.g. procdump) used **for credential "
          "theft**? Where?\"* — the evidence proves the execution on WKS-EVAL04 but "
          "NOT the purpose. A correct answer reports the confirmed host/time and "
          "separately flags the unproven purpose.", "",
          f"**Baseline (before prompt fix): host retained 1/3 runs.**", "",
          f"**This run: {ok}/{N} fully correct; host retained {hosts}/{N}.**", "",
          "| Run | Technique | Host kept | Answer (head) |", "|---|:--:|:--:|---|"]
    for r in rows:
        md.append(f"| {r['run']} | {'✓' if r['kw'] else '—'} | "
                  f"{'✓' if r['host'] else '❌'} | {r['answer'][:70].replace(chr(10),' ')} |")
    open(f"{OUT}/q8_repeat.md", "w").write("\n".join(md) + "\n")
    json.dump({"n": N, "ok": ok, "host_kept": hosts, "rows": rows},
              open(f"{OUT}/q8_repeat.json", "w"), indent=2, default=str)
    print(f"\nQ8 repeat: {ok}/{N} correct, host retained {hosts}/{N} -> {OUT}/q8_repeat.md")


if __name__ == "__main__":
    main()
