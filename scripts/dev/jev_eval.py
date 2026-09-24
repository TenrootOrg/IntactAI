#!/usr/bin/env python3
"""How good is Jev's suggested verdict on THIS box's cases? Measure before trusting.

Replays every finding an analyst has already judged on the Timeline
(true_positive / known / false_positive) through the SAME state builder
production uses (jev.finding_state), and compares Jev's pick with the
analyst's. Prints per-class accuracy, a Brier score and a reliability table —
"when Jev says 90%, is it right 90% of the time?". (Cost is on the OpenRouter
activity page; this script records none.)

Label leak: the stored graph is post-verdict. A finding judged benign has its
severity forced to informational and "[operator: …]" appended to its summary,
which would hand Jev the answer. Both are removed here, and severity is dropped
for EVERY finding so the classes are treated alike — so this measures a
slightly harder task than production (which does send severity).

Sends masked case data to OpenRouter, exactly like the live feature, and needs
Jev enabled with an OpenRouter key in Settings → Agentic.

    docker cp scripts/dev/jev_eval.py intact_backend:/tmp/jev_eval.py
    docker exec intact_backend sh -lc 'cd /app && python3 /tmp/jev_eval.py [--limit N]'
"""
import argparse
import re
import sys

sys.path.insert(0, "/app")

from services import workflow_service as ws          # noqa: E402
from services.fusion import jev, store                # noqa: E402

_LEAK = re.compile(r"\s*\[(operator|re-opened)[^\]]*\](\s*\(≥critical[^)]*\))?")


def labelled():
    """(case_id, details, graph, finding, analyst_label) for every judged finding."""
    for r in ws.get_all_automation_runs():
        if r.get("automation_type") != store.CASE_TYPE:
            continue
        cid = r.get("run_id")
        d = store.get_case(cid)
        labels = {v.get("finding_id"): v.get("status")
                  for v in (d.get("timeline_validations") or [])
                  if v.get("status") in jev.VERDICTS}
        if not labels:
            continue
        g = store.view_graph(cid, d, scoped=False)
        for f in g.findings:
            if f.id in labels:
                yield cid, d, g, f, labels[f.id]


def state(g, f):
    s = jev.finding_state(g, f)
    s.pop("severity", None)
    s["summary"] = _LEAK.sub("", s.get("summary") or "")
    return s


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=0, help="stop after N findings")
    a = ap.parse_args()
    if not jev.enabled("disposition"):
        sys.exit("Jev is off: enable it (and 'Suggested verdict') in Settings → Agentic, "
                 "with the OpenRouter provider and key.")
    items = list(labelled())
    if a.limit:
        items = items[:a.limit]
    if not items:
        sys.exit("No findings have a Timeline verdict yet — nothing to measure against.")
    print(f"{len(items)} judged findings: "
          + ", ".join(f"{k}={sum(1 for *_, y in items if y == k)}" for k in jev.VERDICTS))

    results = []                                    # (truth, answer)
    by_case = {}
    for it in items:
        by_case.setdefault(it[0], []).append(it)
    for cid, rows in by_case.items():
        d, g = rows[0][1], rows[0][2]
        mask = jev.mask_for(d, g)
        answers = jev.ask_each([r[3] for r in rows], lambda f: jev.masked(state(g, f), mask),
                               jev._verdict_question)
        results += [(r[4], ans) for r, ans in zip(rows, answers)]

    failed = sum(1 for _, a_ in results if not isinstance(a_, dict))
    ok = [(y, a_) for y, a_ in results if isinstance(a_, dict)]
    if failed:
        print(f"{failed} findings got no answer (call failed) — excluded below")
    if not ok:
        sys.exit("No answers came back.")
    print("\nPer class (analyst label → Jev right):")
    for k in jev.VERDICTS:
        n = [a_ for y, a_ in ok if y == k]
        if n:
            right = sum(1 for a_ in n if a_.get("choice") == k)
            print(f"  {k:15s} {right}/{len(n)}  ({right / len(n):.0%})")
    acc = sum(1 for y, a_ in ok if a_.get("choice") == y) / len(ok)
    brier = sum(sum(((a_.get("probabilities") or {}).get(k, 0.0) - (1.0 if y == k else 0.0)) ** 2
                    for k in jev.VERDICTS) for y, a_ in ok) / len(ok)
    print(f"\nOverall accuracy {acc:.0%}   Brier {brier:.3f}  (0 is perfect, 0.667 is a uniform guess)")

    print("\nReliability — Jev's stated confidence vs how often it was right:")
    bins = {}
    for y, a_ in ok:
        c = float(a_.get("confidence") or 0.0)
        bins.setdefault(min(int(c * 10), 9), []).append(a_.get("choice") == y)
    for b in sorted(bins):
        hits = bins[b]
        print(f"  confidence {b / 10:.1f}–{(b + 1) / 10:.1f}: right {sum(hits)}/{len(hits)} ({sum(hits) / len(hits):.0%})")
    thr = jev.min_confidence()
    shown = [(y, a_) for y, a_ in ok if float(a_.get("confidence") or 0) >= thr]
    if shown:
        good = sum(1 for y, a_ in shown if a_.get("choice") == y)
        print(f"\nAt the Settings threshold ({thr}): {len(shown)}/{len(ok)} findings get a chip, "
              f"{good / len(shown):.0%} of those chips are right.")
    else:
        print(f"\nAt the Settings threshold ({thr}) no finding would get a chip.")


if __name__ == "__main__":
    main()
