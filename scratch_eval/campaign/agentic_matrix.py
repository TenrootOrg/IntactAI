"""Track B — agentic variance & quality at scale (real cases, model-driven).

Runs investigate() many times across (case × question × arm × repeat) to QUANTIFY
what the deterministic Track A can't: how OFTEN the turn-1 give-up (A1) happens,
run-to-run variance (A5 — Codex has no temperature control), tool-choice
distribution, fabrication rate, and cost. Resumable — every run is cached in
matrix_results.json, so an interrupted exhaustive sweep continues.

  cd /app/scratch_eval && PYTHONPATH=/app python3 campaign/agentic_matrix.py run
  cd /app/scratch_eval && PYTHONPATH=/app python3 campaign/agentic_matrix.py report

Scale knobs (env): MX_CASES, MX_QIDS, MX_ARMS, MX_REPEATS.
"""
import json
import os
import re
import statistics
import sys

sys.path.insert(0, "/app")
from services.fusion import store, llm_sim, investigate  # noqa: E402

OUT = "/tmp/eval_out/campaign"
os.makedirs(OUT, exist_ok=True)
RESULTS = f"{OUT}/matrix_results.json"
ws = store._ws()

# real multi-host + single-host cases (event-bearing); big ones first
ALL_CASES = ["case_1788080164853", "case_1788078295586", "case_1787641933758",
             "case_1788082359821", "case_1788080164355"]
# questions tagged by the tool class they should exercise
QUESTIONS = {
    "raw-evidence": "What exact command line ran Rubeus, on which host and when? Include the binary SHA-256 if recorded.",
    "cross-host": "Which hosts show suspicious cross-host lateral movement, and did it reach any domain controller or CA?",
    "account": "Pick the most-abused account. Which hosts was it used on and for what activity?",
    "timeline": "What is the earliest suspicious activity, and what happened in the hour after it?",
    "negative-control": "Is there any evidence of exfiltration to rclone, MEGA, or Dropbox in this case?",
}

CASES = (os.environ.get("MX_CASES") or "").split(",") if os.environ.get("MX_CASES") else ALL_CASES[:2]
QIDS = (os.environ.get("MX_QIDS") or "").split(",") if os.environ.get("MX_QIDS") else list(QUESTIONS)
ARMS = (os.environ.get("MX_ARMS") or "").split(",") if os.environ.get("MX_ARMS") else ["v1", "v2"]
REPEATS = int(os.environ.get("MX_REPEATS") or 5)


def _metrics(rid):
    return (ws.get_automation_run(rid) or {}).get("llm_metrics") or {}


def _hosts(cid):
    return sorted(e.label for e in store.load_graph(cid).by_type("asset"))


def _fabricated(ans, real):
    cited = set(re.findall(r"\bAL[A-Za-z]+\d+\b", ans or "", re.I))
    low = {h.lower() for h in real}
    return sorted(c for c in cited if c.lower() not in low)


def _one(cid, qid, arm):
    q = QUESTIONS[qid]
    if arm == "ask":
        rid = ws.create_automation_run("mx", "ask")
        g = store.load_graph(cid); d = store.get_case(cid) or {}
        ans = llm_sim.chat(g, q, history=[], window=d.get("time_window") or None,
                           min_severity=d.get("min_severity", "informational"),
                           run_id=rid, full_context=True, require_llm=True, mask=None)
        steps, trace, trunc = 0, [], False
    else:
        rid = ws.create_automation_run("mx", arm)
        kw = dict(use_mask=(arm == "v2"), enable_pivot=(arm == "v2"))
        prior = (store.get_case(cid) or {}).get("masking")
        if arm == "v2":
            store._merge_case_details(cid, {"masking": {"enabled": True}})
        try:
            res = investigate.investigate(cid, q, run_id=rid, max_steps=6, **kw)
        finally:
            if arm == "v2":
                store._merge_case_details(cid, {"masking": prior})
        ans = res["answer"]; steps = len(res["steps"])
        trace = [s["tool"] for s in res["steps"]]; trunc = res.get("truncated")
    m = _metrics(rid)
    return {"answer": ans, "steps": steps, "trace": trace, "truncated": trunc,
            "giveup": (steps == 0 and not trunc and arm != "ask"),
            "out_tok": m.get("output_tokens"),
            "fabricated": _fabricated(ans, _hosts(cid))}


def cmd_run():
    try:
        R = json.load(open(RESULTS))
    except Exception:
        R = {}
    total = len(CASES) * len(QIDS) * len(ARMS) * REPEATS
    done = 0
    for cid in CASES:
        for qid in QIDS:
            for arm in ARMS:
                for i in range(REPEATS):
                    key = f"{cid}|{qid}|{arm}|{i}"
                    done += 1
                    if key in R:
                        continue
                    try:
                        R[key] = _one(cid, qid, arm)
                    except Exception as e:  # noqa: BLE001
                        R[key] = {"error": str(e)[:200], "giveup": False}
                    json.dump(R, open(RESULTS, "w"), default=str)
                    r = R[key]
                    print(f"[{done}/{total}] {cid[-4:]}/{qid}/{arm}#{i} "
                          f"steps={r.get('steps')} giveup={r.get('giveup')} "
                          f"out={r.get('out_tok')} fab={r.get('fabricated')} "
                          f"trace={'>'.join(r.get('trace') or [])}", flush=True)
    print("MATRIX RUN COMPLETE", flush=True)


def cmd_report():
    R = json.load(open(RESULTS))
    # aggregate per (question, arm)
    agg = {}
    for key, r in R.items():
        cid, qid, arm, _i = key.split("|")
        a = agg.setdefault((qid, arm), {"n": 0, "giveup": 0, "fab": 0, "steps": [],
                                        "out": [], "err": 0})
        a["n"] += 1
        if r.get("error"):
            a["err"] += 1; continue
        a["giveup"] += 1 if r.get("giveup") else 0
        a["fab"] += 1 if r.get("fabricated") else 0
        if isinstance(r.get("steps"), int):
            a["steps"].append(r["steps"])
        if isinstance(r.get("out_tok"), (int, float)):
            a["out"].append(r["out_tok"])

    def _sd(xs):
        return round(statistics.pstdev(xs), 1) if len(xs) > 1 else 0.0

    rows = ["# Track B — Agentic variance & quality at scale", "",
            f"cases={CASES} questions={QIDS} arms={ARMS} repeats={REPEATS}; "
            f"{len(R)} runs. Transport codex-subscription/gpt-5.6-sol (no temp control).", "",
            "| Question | Arm | N | Give-up % | Fabricated % | Steps mean±sd | Out tok mean±sd | Errors |",
            "|---|---|---|---|---|---|---|---|"]
    tot_giveup = tot_n = tot_fab = 0
    for (qid, arm), a in sorted(agg.items()):
        n = a["n"]; ok = n - a["err"]
        tot_giveup += a["giveup"]; tot_n += ok; tot_fab += a["fab"]
        sm = round(statistics.mean(a["steps"]), 1) if a["steps"] else "—"
        om = round(statistics.mean(a["out"]), 0) if a["out"] else "—"
        rows.append(f"| {qid} | {arm} | {n} | "
                    f"{round(100*a['giveup']/ok,1) if ok else '—'} | "
                    f"{round(100*a['fab']/ok,1) if ok else '—'} | "
                    f"{sm}±{_sd(a['steps'])} | {om}±{_sd(a['out'])} | {a['err']} |")
    rows += ["", "## Headline",
             f"- **Turn-1 give-up (A1) rate: {tot_giveup}/{tot_n} = "
             f"{round(100*tot_giveup/tot_n,1) if tot_n else 0}%** across loop arms — "
             "quantifies the live bug; each is a wasted, unhelpful investigation.",
             f"- **Fabricated-host rate: {tot_fab}/{tot_n} = "
             f"{round(100*tot_fab/tot_n,1) if tot_n else 0}%** (deterministic check).",
             "- Step/token spread columns show run-to-run variance (Codex has no "
             "temperature control, so this is irreducible without a min-step guard + retries)."]
    open(f"{OUT}/agentic_matrix.md", "w").write("\n".join(rows) + "\n")
    print("\n".join(rows[:4]))
    print(f"\nwrote {OUT}/agentic_matrix.md — give-up {tot_giveup}/{tot_n}, fab {tot_fab}/{tot_n}")


if __name__ == "__main__":
    {"run": cmd_run, "report": cmd_report}.get(sys.argv[1] if sys.argv[1:] else "", cmd_run)()
