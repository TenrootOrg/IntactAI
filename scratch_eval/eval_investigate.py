"""Ask vs v1 vs v2 — the agentic-investigate verdict table.

Five questions against the REAL case, three arms each:
  ask — single-shot chat baseline (full distilled context, 1 call)
  v1  — the agentic loop as first shipped (no mask, no pivot)
  v2  — the hardened loop (masking in transit + pivot tool)

The negative-control question ("was there X?" where X is absent) exists to catch
fabrication — the correct answer is "no evidence".

Masking is per-case opt-in, so the script enables it on the case for the v2 arms
ONLY and restores the prior setting in a finally (ask/v1 pass mask=None /
use_mask=False regardless). Mechanical grounding check: hostnames cited in an
answer must exist in the graph (env hosts all match AL*), independent of the judge.

Usage (in the backend container):
  cd /app/scratch_eval && PYTHONPATH=/app python3 eval_investigate.py run   # arms
  cd /app/scratch_eval && PYTHONPATH=/app python3 eval_investigate.py judge # table
"""
import json
import os
import re
import sys

sys.path.insert(0, "/app")
from services.fusion import store, llm_sim, investigate  # noqa: E402

CASE = os.environ.get("EVAL_CASE", "case_1788080164853")
OUT = "/tmp/eval_out"
RESULTS = f"{OUT}/investigate_results.json"
ws = store._ws()

QUESTIONS = [
    ("raw-evidence", "What exact command line was used to run Rubeus, on which host "
     "and when? Include the SHA-256 of the binary if it is recorded."),
    ("cross-host", "Which hosts did the suspicious EPMAP activity on 2026-06-20 and "
     "2026-06-21 touch? Did it reach the domain controllers or the certificate "
     "authority?"),
    ("account", "What did the account adatumlab\\srv do in this environment — which "
     "hosts was it used on, and for what activity?"),
    ("timeline", "When were event logs cleared on ALClient04, and what happened on "
     "that host immediately afterwards?"),
    ("negative-control", "Is there any evidence of data exfiltration to cloud "
     "storage services (rclone, MEGA, Dropbox) in this case?"),
]

JUDGE_SYSTEM = (
    "You are a PRINCIPAL DFIR reviewer grading three candidate ANSWERS to the same "
    "investigative question about one case. You get the question, the case's REAL "
    "host list, and the answers. Score each 1-5 (integers) on:\n"
    "- grounding: concrete claims carry real hosts/times/values; an answer citing a "
    "host NOT in the real host list, or inventing values, scores 1.\n"
    "- correctness_completeness: answers the question fully and precisely.\n"
    "- calibrated_honesty: states what is unknown; for a question where the case "
    "holds no evidence, the right answer says NO EVIDENCE plainly — hedging toward "
    "a positive finding scores 1.\n"
    "- actionability: a responder can act on it (specific artifacts, hosts, times).\n"
    "Be harsh. Return STRICT JSON only:\n"
    '{"scores":[{"arm":"ask|v1|v2","grounding":n,"correctness_completeness":n,'
    '"calibrated_honesty":n,"actionability":n,"total":n,"rationale":"one line"}],'
    '"winner":"arm","why":"one line"}'
)


def _metrics(rid):
    return (ws.get_automation_run(rid) or {}).get("llm_metrics") or {}


def _hosts():
    g = store.load_graph(CASE)
    return sorted(e.label for e in g.by_type("asset"))


def _fabricated_hosts(answer, real):
    """AL*-style names cited in the answer that do not exist in the graph."""
    cited = set(re.findall(r"\bAL[A-Za-z]+\d+\b", answer or "", re.I))
    low = {h.lower() for h in real}
    return sorted(c for c in cited if c.lower() not in low)


def run_ask(q):
    g = store.load_graph(CASE)
    d = store.get_case(CASE) or {}
    rid = ws.create_automation_run("eval_inv", "ask")
    ans = llm_sim.chat(g, q, history=[], window=d.get("time_window") or None,
                       min_severity=d.get("min_severity", "informational"),
                       run_id=rid, full_context=True, require_llm=True, mask=None)
    return ans, {"steps": 0, "trace": [], **_metrics(rid)}


def run_loop(q, arm):
    rid = ws.create_automation_run("eval_inv", arm)
    kw = (dict(use_mask=False, enable_pivot=False) if arm == "v1"
          else dict(use_mask=True, enable_pivot=True))
    res = investigate.investigate(CASE, q, run_id=rid, max_steps=5, **kw)
    return res["answer"], {"steps": len(res["steps"]),
                           "trace": [s["tool"] for s in res["steps"]],
                           "truncated": res.get("truncated"), **_metrics(rid)}


def cmd_run():
    os.makedirs(OUT, exist_ok=True)
    try:
        results = json.load(open(RESULTS))
    except Exception:
        results = {}
    real_hosts = _hosts()
    prior_masking = (store.get_case(CASE) or {}).get("masking")
    try:
        for key, q in QUESTIONS:
            results.setdefault(key, {"question": q, "arms": {}})
            for arm in ("ask", "v1", "v2"):
                if arm in results[key]["arms"]:
                    print(f"[{key}/{arm}] cached, skipping", flush=True)
                    continue
                # masking engages only for v2 (v1/ask force it off regardless)
                store._merge_case_details(CASE, {"masking": {"enabled": arm == "v2"}})
                print(f"[{key}/{arm}] running…", flush=True)
                try:
                    ans, m = run_ask(q) if arm == "ask" else run_loop(q, arm)
                except Exception as e:  # noqa: BLE001 — record, keep evaluating
                    ans, m = f"(ARM FAILED: {e})", {"steps": 0, "trace": []}
                m["fabricated_hosts"] = _fabricated_hosts(ans, real_hosts)
                results[key]["arms"][arm] = {"answer": ans, "metrics": m}
                json.dump(results, open(RESULTS, "w"), default=str)
                print(f"[{key}/{arm}] done: steps={m.get('steps')} "
                      f"out={m.get('output_tokens')} trace={'>'.join(m.get('trace') or [])} "
                      f"fabricated={m['fabricated_hosts']}", flush=True)
    finally:
        store._merge_case_details(CASE, {"masking": prior_masking})
    print("RUN COMPLETE", flush=True)


def cmd_judge():
    results = json.load(open(RESULTS))
    real_hosts = _hosts()
    for key, entry in results.items():
        if "verdict" in entry:
            continue
        parts = [f"QUESTION ({key}): {entry['question']}",
                 f"REAL HOSTS IN CASE: {', '.join(real_hosts)}", ""]
        for arm in ("ask", "v1", "v2"):
            a = entry["arms"].get(arm) or {}
            parts += [f"===== ANSWER [{arm}] =====", a.get("answer") or "(missing)", ""]
        rid = ws.create_automation_run("eval_inv", f"judge:{key}")
        raw = llm_sim._real_llm(JUDGE_SYSTEM, "\n".join(parts), run_id=rid)
        try:
            v = json.loads(raw[raw.index("{"): raw.rindex("}") + 1])
        except Exception:
            v = {"error": (raw or "")[:300]}
        entry["verdict"] = v
        json.dump(results, open(RESULTS, "w"), default=str)
        print(f"[{key}] winner={v.get('winner')} — {v.get('why')}", flush=True)

    # ---- the comparison table ----
    lines = ["# Agentic Investigate — Ask vs v1 vs v2 (judged on the real case)", "",
             f"Case `{CASE}`, {len(QUESTIONS)} questions, LLM-judged (1-5 per axis, "
             "total /20) + a mechanical fabricated-host check. v1 = loop without "
             "masking/pivot as first shipped; v2 = hardened (masking in transit + "
             "pivot tool). The negative-control question has NO evidence in the case "
             "— the honest answer is 'none found'.", "",
             "| Question | Arm | Total /20 | Grounding | Honesty | Steps | Out tok | Fabricated hosts | Judge note |",
             "|---|---|---|---|---|---|---|---|---|"]
    sums = {a: [0, 0] for a in ("ask", "v1", "v2")}
    for key, _q in QUESTIONS:
        entry = results.get(key) or {}
        scores = {s.get("arm"): s for s in (entry.get("verdict") or {}).get("scores", [])}
        for arm in ("ask", "v1", "v2"):
            s = scores.get(arm) or {}
            m = ((entry.get("arms") or {}).get(arm) or {}).get("metrics") or {}
            tot = s.get("total")
            if isinstance(tot, (int, float)):
                sums[arm][0] += tot
                sums[arm][1] += 1
            fab = m.get("fabricated_hosts") or []
            lines.append(
                f"| {key} | {arm} | {tot if tot is not None else '—'} | "
                f"{s.get('grounding', '—')} | {s.get('calibrated_honesty', '—')} | "
                f"{m.get('steps', '—')} | {m.get('output_tokens', '—')} | "
                f"{', '.join(fab) or 'none'} | {s.get('rationale', '')} |")
    lines += ["", "## Verdict", "",
              "| Arm | Mean total /20 | Questions judged |", "|---|---|---|"]
    for arm in ("ask", "v1", "v2"):
        tot, n = sums[arm]
        mean = round(tot / n, 1) if n else "—"
        lines.append(f"| {arm} | {mean} | {n} |")
    md = "\n".join(lines) + "\n"
    open(f"{OUT}/investigate_v1_vs_v2.md", "w").write(md)
    print(f"\nwrote {OUT}/investigate_v1_vs_v2.md", flush=True)


if __name__ == "__main__":
    {"run": cmd_run, "judge": cmd_judge}.get(sys.argv[1] if sys.argv[1:] else "",
                                             lambda: print(__doc__))()
