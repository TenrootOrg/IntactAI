"""Track A — agentic fault-injection (deterministic, no real model).

Scripts investigate._real_llm / _tool (monkeypatch) to force each catalogued
failure mode and assert the loop degrades gracefully. Every unmet assertion is a
ranked finding. Emits campaign/agentic_faults.{md,json} for the Track-F backlog.

The bar per scenario ("graceful" means ALL of):
  - investigate() does NOT raise (a raise = HTTP 500 at the route),
  - it returns a dict with an 'answer' string and a 'steps' list,
  - failure-shaped scenarios surface an explicit signal (an error/insufficient-data
    answer, or truncated), never a confident fabricated answer with 0 evidence.

Run (in the backend container):
  cd /app/scratch_eval && PYTHONPATH=/app python3 campaign/agentic_faults.py
"""
import json
import os
import sys
import types

sys.path.insert(0, "/app")
from services.fusion import investigate, llm_sim, schema  # noqa: E402

OUT = "/tmp/eval_out/campaign"
os.makedirs(OUT, exist_ok=True)


class _Patch:
    def __init__(self, obj, **attrs):
        self.obj, self.attrs, self.saved = obj, attrs, {}

    def __enter__(self):
        for k, v in self.attrs.items():
            self.saved[k] = getattr(self.obj, k, None)
            setattr(self.obj, k, v)
        return self

    def __exit__(self, *a):
        for k, v in self.saved.items():
            setattr(self.obj, k, v)


def _scripted_llm(replies):
    """A fake _real_llm returning canned strings in order; repeats the last."""
    seq = list(replies)

    def f(system, user, **kw):
        return seq.pop(0) if len(seq) > 1 else seq[0]
    return f


def _real_tool_ok(case_id, name, args):
    if name == "list_findings":
        return [{"id": "f1", "title": "t", "severity": "high", "hosts": ["H"], "ts": "2026-01-01T00:00:00Z", "kind": "single"}]
    if name == "evidence":
        return [{"artifact": "X", "row": "raw row"}]
    return []


FINDINGS = []


def check(fid, title, severity, cond, detail, repro):
    """cond True = graceful (PASS); False = a finding."""
    ok = bool(cond)
    FINDINGS.append({"id": fid, "title": title, "severity": severity,
                     "status": "PASS" if ok else "FINDING", "detail": detail,
                     "repro": repro})
    print(f"  [{fid}] {'PASS ' if ok else 'FINDING'} — {title}")
    return ok


def _run(replies, tool=_real_tool_ok, mask=None, **kw):
    """Drive investigate.investigate with a scripted model + stubbed store/tool.
    Returns (result_or_exc, raised_bool)."""
    with _Patch(investigate.llm_sim, _real_llm=_scripted_llm(replies)), \
         _Patch(investigate, _tool=tool, _mask_for_case=lambda d, g, r: mask), \
         _Patch(investigate.store, get_case=lambda c: {"id": c},
                load_graph=lambda c: schema.FusionGraph(case_id=c)):
        try:
            return investigate.investigate("case_t", "what happened?", max_steps=4, **kw), False
        except Exception as e:  # noqa: BLE001
            return e, True


def scenario_A1_turn1_giveup():
    # model returns {"final"} on turn 1, zero tools. The live bug.
    res, raised = _run(['{"final":"I could not find anything."}'])
    steps = [] if raised else res.get("steps", [])
    ans = "" if raised else res.get("answer", "")
    check("A1", "turn-1 {final} give-up with 0 tool calls is not caught/retried",
          "high",
          # graceful would be: at least one tool forced, OR the answer explicitly
          # flags it never looked. Today it returns the give-up verbatim, 0 steps.
          cond=(not raised) and (len(steps) >= 1),
          detail=f"raised={raised} steps={len(steps)} answer={ans[:80]!r} — the loop "
                 "accepted a 0-tool final; nothing forces a lookup or retries.",
          repro="model emits {\"final\":...} on iteration 0")


def scenario_A2_tool_exception():
    def boom(case_id, name, args):
        raise ValueError("simulated tool crash (e.g. int('abc') on limit)")
    res, raised = _run(['{"tool":"list_findings","args":{"limit":"abc"}}',
                        '{"final":"done"}'], tool=boom)
    check("A2", "tool exception propagates out of investigate() -> HTTP 500",
          "high",
          cond=(not raised),
          detail=f"raised={raised} ({res if raised else ''}) — _tool() has no "
                 "try/except; model-controlled args can crash the request.",
          repro="tool raises (bad limit / malformed pivot.window)")


def scenario_A3_transport_raises():
    class _Boom(Exception):
        pass

    def raise_llm(system, user, **kw):
        raise _Boom("simulated transport failure (auth/timeout/CLI)")
    with _Patch(investigate.llm_sim, _real_llm=raise_llm), \
         _Patch(investigate, _tool=_real_tool_ok, _mask_for_case=lambda d, g, r: None), \
         _Patch(investigate.store, get_case=lambda c: {"id": c},
                load_graph=lambda c: schema.FusionGraph(case_id=c)):
        try:
            r = investigate.investigate("case_t", "q", max_steps=3)
            raised, res = False, r
        except Exception as e:  # noqa: BLE001
            raised, res = True, e
    check("A3", "transport failure propagates -> unhandled 500 (report path catches it)",
          "high",
          cond=(not raised),
          detail=f"raised={raised} ({type(res).__name__}) — investigate does not "
                 "catch LLMUnavailable like store.chat/report do.",
          repro="_real_llm raises")


def scenario_A7a_malformed_storm():
    # every reply is junk -> should not raise; should end truncated, not confident.
    res, raised = _run(["not json", "still not json", "nope", "garbage"])
    ans = "" if raised else res.get("answer", "")
    check("A7a", "malformed-JSON storm burns budget without a separate retry counter",
          "medium",
          cond=(not raised),
          detail=f"raised={raised} truncated={getattr(res,'get',lambda *_:None) and res.get('truncated')} "
                 f"answer={ans[:80]!r} — nudges consume max_steps; no distinct retry budget.",
          repro="model never emits valid JSON")


def scenario_A7b_forced_final_returns_raw():
    # never final within budget, and the forced-final is ALSO junk -> raw returned.
    res, raised = _run(['{"tool":"list_findings","args":{}}'] * 6 + ["still junk"])
    ans = "" if raised else res.get("answer", "")
    # graceful = the returned answer is not a raw tool-call blob / junk
    looks_raw = ans.strip().startswith("{") or "tool" in ans[:20].lower() or ans == "still junk"
    check("A7b", "forced-final can return raw model text as the analyst answer",
          "medium",
          cond=(not raised) and (not looks_raw),
          detail=f"answer={ans[:80]!r} — after budget, obj.get('final') or raw; a "
                 "non-final raw blob becomes the answer.",
          repro="model never returns {final}, even on the forced call")


def scenario_A_toolNone():
    res, raised = _run(['{"args":{"x":1}}', '{"final":"ok"}'])
    trace = [] if raised else [s.get("tool") for s in res.get("steps", [])]
    check("A11", "non-final object with no 'tool' key -> bogus 'unknown tool None' step",
          "low",
          cond=(not raised),
          detail=f"raised={raised} trace={trace} — degraded but non-fatal.",
          repro="model returns an object with neither 'tool' nor 'final'")


def scenario_A_unknown_tool():
    res, raised = _run(['{"tool":"nosuch","args":{}}', '{"final":"ok"}'])
    check("A_unknown", "unknown tool name is handled (error fed back, not fatal)",
          "info",
          cond=(not raised),
          detail=f"raised={raised} — _tool returns an error dict the model can recover from.",
          repro="model calls a tool that doesn't exist")


def scenario_A_empty_completion():
    res, raised = _run(["", "", "", ""])
    check("A6c", "empty/None model completion degrades to malformed (no crash)",
          "medium",
          cond=(not raised),
          detail=f"raised={raised} — '' parses to None -> treated as malformed, burns a step.",
          repro="transport returns an empty string")


def main():
    print("=== Track A — agentic fault-injection ===")
    for fn in (scenario_A1_turn1_giveup, scenario_A2_tool_exception,
               scenario_A3_transport_raises, scenario_A7a_malformed_storm,
               scenario_A7b_forced_final_returns_raw, scenario_A_toolNone,
               scenario_A_unknown_tool, scenario_A_empty_completion):
        try:
            fn()
        except Exception as e:  # noqa: BLE001 — a harness crash is itself a finding
            FINDINGS.append({"id": fn.__name__, "title": "harness crashed",
                             "severity": "high", "status": "FINDING",
                             "detail": repr(e), "repro": fn.__name__})
            print(f"  [{fn.__name__}] HARNESS-CRASH {e!r}")

    findings = [f for f in FINDINGS if f["status"] == "FINDING"]
    json.dump({"track": "A", "findings": FINDINGS}, open(f"{OUT}/agentic_faults.json", "w"), indent=2)
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    rows = ["# Track A — Agentic fault-injection (deterministic)", "",
            f"{len(findings)} findings / {len(FINDINGS)} scenarios. No real model.", "",
            "| Sev | ID | Status | Finding | Repro |", "|---|---|---|---|---|"]
    for f in sorted(FINDINGS, key=lambda x: (order.get(x["severity"], 9), x["status"] != "FINDING")):
        rows.append(f"| {f['severity']} | {f['id']} | {f['status']} | {f['title']} | {f['repro']} |")
    rows += ["", "## Detail", ""]
    for f in sorted(findings, key=lambda x: order.get(x["severity"], 9)):
        rows.append(f"- **[{f['severity']}] {f['id']} — {f['title']}**  \n  {f['detail']}")
    open(f"{OUT}/agentic_faults.md", "w").write("\n".join(rows) + "\n")
    print(f"\n{len(findings)} findings -> {OUT}/agentic_faults.md")


if __name__ == "__main__":
    main()
