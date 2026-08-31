"""AI-investigation accuracy vs the simulation ground truth.

Fuses the full attack corpus into one in-memory incident (NOT persisted to the box),
then runs the agentic Investigate loop with questions whose answers we KNOW from the
answer key, and scores whether the AI's grounded answer matches. This measures how
accurate the AI investigation is compared to what was actually simulated.

  cd /app/scratch_eval && PYTHONPATH=/app python3 campaign/eval_investigation_accuracy.py

Nothing is written to the store or fusion_graphs — store.load_graph/get_case/
get_evidence_rows are stubbed to the in-memory case, so the appliance stays clean.
"""
import json
import os
import re
import sys

sys.path.insert(0, "/app")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from services.fusion.mappers.agentic import map_agentic  # noqa: E402
from services.fusion import correlate, store, investigate  # noqa: E402
import attack_corpus as corpus  # noqa: E402

OUT = "/tmp/eval_out/campaign"
os.makedirs(OUT, exist_ok=True)
ws = store._ws()

# Ground-truth questions: each answer is known from the corpus answer key.
# present=True -> the AI must name the activity + host; present=False (negative
# control) -> the AI must say there is no evidence (fabrication check).
QUESTIONS = [
    {"q": "What credential-dumping activity targeting LSASS occurred, and on which host?",
     "kw": ["mimikatz"], "host": "wks-eval01", "present": True},
    {"q": "Is there evidence of Kerberos abuse such as Kerberoasting or a golden ticket? Which hosts?",
     "kw": ["rubeus", "kerber", "golden"], "host": "wks-eval02", "present": True},
    {"q": "Which single account was used across more than one host (possible lateral movement)?",
     "kw": ["svc_backup"], "host": "wks-eval04", "present": True},
    {"q": "Was Windows Defender tampered with or disabled, and where?",
     "kw": ["defender"], "host": "wks-eval02", "present": True},
    {"q": "Is there any evidence of ransomware or anti-recovery activity (shadow copy deletion)?",
     "kw": ["ransomware", "shadow"], "host": "wks-eval07", "present": True},
    {"q": "Was any data exfiltration to cloud storage observed, and from which host?",
     "kw": ["rclone", "exfil"], "host": "wks-eval04", "present": True},
    {"q": "What process-injection activity was seen, and on which host(s)?",
     "kw": ["inject", "explorer", "svchost"], "host": "wks-eval01", "present": True},
    {"q": "Was a renamed system utility (e.g. procdump) used for credential theft? Where?",
     "kw": ["procdump", "renamed"], "host": "wks-eval04", "present": True},
    # NEGATIVE CONTROLS — not in the simulation; the AI must NOT invent them.
    {"q": "Is there any evidence of cryptocurrency mining (XMRig / Monero) in this case?",
     "kw": ["no evidence", "not find", "none", "no indication", "no sign", "did not", "not observed"],
     "present": False},
    {"q": "Was there any macOS or Linux malware activity in this environment?",
     "kw": ["no evidence", "not find", "none", "no indication", "windows", "did not", "not observed"],
     "present": False},
]


def _fuse():
    tele = corpus.build_all_telemetry()
    ents, rels = map_agentic(tele, run_id="evalrun", hostnames={})
    g = correlate.assemble("gt_incident", [(ents, rels)], ["evalrun"])
    return g, tele


def _evidence_resolver(raw):
    def get_evidence_rows(case_id, finding_id, *, max_rows=10):
        g = store.load_graph(case_id)
        f = next((x for x in g.findings if x.id == finding_id), None)
        if not f:
            return []
        out = []
        refs = list(f.evidence or [])
        for eid in (f.entity_ids or []):
            e = g.entities.get(eid)
            if e:
                refs += list(e.evidence or [])
        for ref in refs:
            loc = getattr(ref, "locator", "")
            if "/row=" not in loc:
                continue
            art, _, idx = loc.partition("/row=")
            rows = raw.get(art) or []
            try:
                i = int(idx)
            except ValueError:
                continue
            if 0 <= i < len(rows):
                out.append({"run_id": "evalrun", "artifact": art, "row_index": i, "row": rows[i]})
            if len(out) >= max_rows:
                break
        return out
    return get_evidence_rows


class _Patch:
    def __init__(self, obj, **a):
        self.obj, self.a, self.s = obj, a, {}

    def __enter__(self):
        for k, v in self.a.items():
            self.s[k] = getattr(self.obj, k, None)
            setattr(self.obj, k, v)
        return self

    def __exit__(self, *_):
        for k, v in self.s.items():
            setattr(self.obj, k, v)


def score(ans, qd):
    a = (ans or "").lower()
    kw_ok = any(k in a for k in qd["kw"])
    if qd["present"]:
        host_ok = qd["host"] in a
        return kw_ok and host_ok, kw_ok, host_ok
    # negative control: correct iff it declines / says no evidence
    return kw_ok, kw_ok, True


def main():
    g, raw = _fuse()
    case = {"masking": {"enabled": False}, "time_window": None, "min_severity": "informational"}
    rows = []
    with _Patch(store, load_graph=lambda c: g, get_case=lambda c: case,
                get_evidence_rows=_evidence_resolver(raw)):
        for i, qd in enumerate(QUESTIONS, 1):
            rid = ws.create_automation_run("inv_acc", f"q{i}")
            try:
                res = investigate.investigate("gt_incident", qd["q"], run_id=rid, max_steps=6)
                ans, steps = res.get("answer", ""), [s["tool"] for s in res.get("steps", [])]
            except Exception as e:  # noqa: BLE001
                ans, steps = f"(ERROR {e})", []
            ok, kw_ok, host_ok = score(ans, qd)
            m = (ws.get_automation_run(rid) or {}).get("llm_metrics") or {}
            rows.append({"q": qd["q"], "present": qd["present"], "correct": ok,
                         "kw_ok": kw_ok, "host_ok": host_ok, "steps": steps,
                         "out_tok": m.get("output_tokens"), "answer": ans})
            print(f"[{i}/{len(QUESTIONS)}] {'✅' if ok else '❌'} present={qd['present']} "
                  f"kw={kw_ok} host={host_ok} steps={'>'.join(steps)} "
                  f":: {ans[:90].strip()}", flush=True)

    correct = sum(r["correct"] for r in rows)
    n = len(rows)
    pres = [r for r in rows if r["present"]]
    neg = [r for r in rows if not r["present"]]
    md = ["# AI investigation accuracy vs simulation", "",
          f"The agentic Investigate loop answered {n} questions about a known "
          "simulated incident (25-technique corpus fused into one case). Correct = "
          "the grounded answer names the planted activity on the right host; for "
          "negative controls, correctly reports no evidence.", "",
          f"**Investigation accuracy: {correct}/{n} ({round(100*correct/n)}%)** — "
          f"present {sum(r['correct'] for r in pres)}/{len(pres)}, "
          f"negative-control {sum(r['correct'] for r in neg)}/{len(neg)} "
          "(no fabrication).", "",
          "| # | Question | Type | Correct | KW | Host | Tools | Answer (head) |",
          "|---|---|---|:--:|:--:|:--:|---|---|"]
    for i, r in enumerate(rows, 1):
        md.append(f"| {i} | {r['q'][:52]} | {'plant' if r['present'] else 'neg-ctrl'} | "
                  f"{'✅' if r['correct'] else '❌'} | {'✓' if r['kw_ok'] else '—'} | "
                  f"{'✓' if r['host_ok'] else '—'} | {'>'.join(r['steps']) or '—'} | "
                  f"{(r['answer'] or '')[:60].strip().replace(chr(10),' ')} |")
    open(f"{OUT}/investigation_accuracy.md", "w").write("\n".join(md) + "\n")
    json.dump({"correct": correct, "n": n, "rows": rows},
              open(f"{OUT}/investigation_accuracy.json", "w"), indent=2, default=str)
    print(f"\nInvestigation accuracy {correct}/{n} -> {OUT}/investigation_accuracy.md")


if __name__ == "__main__":
    main()
