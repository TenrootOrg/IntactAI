#!/usr/bin/env python3
"""The decision model's suggested verdict on OUR OWN finding types, with ground truth.

secalert_eval.py measures the verdict question on third-party IDS/WAF alerts;
decision_eval.py needs analyst verdicts a box may not have. This uses the committed
real purple-team fixtures (services/fusion/fixtures, labels.json):

  * not attack -- every finding that fires on the CLEAN box with no baseline
                  (a real benign machine: provisioning noise, admin tooling);
  * attack     -- the expected_findings of the attack fixtures (after baseline).

Each finding is sent exactly as production sends it: decision_model.finding_state(g, f),
masked with decision_model.mask_for, asked _verdict_question through ask_each. Scoring
is secalert_eval.score (same metrics). Runs are saved for before/after comparison.

    docker cp scripts/dev/fixture_verdict_eval.py scripts/dev/secalert_eval.py intact_backend:/tmp/
    docker exec intact_backend sh -lc 'cd /app && python3 /tmp/fixture_verdict_eval.py [--tag before]'
"""
import argparse
import importlib.util
import json
import os
import sys
import time

sys.path.insert(0, "/app")


def _score_module():
    p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "secalert_eval.py")
    spec = importlib.util.spec_from_file_location("secalert_eval", p)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def labelled():
    """[(fixture, graph, finding, is_attack)] -- the 34 findings with a known answer."""
    from services.fusion import calibrate as cal
    lab, out = cal.load_labels(), []
    g = cal.fuse("clean", baseline=None, window=lab["clean"].get("window"))
    out += [("clean", g, f, False) for f in g.findings]
    for name in ("attack", "attack2"):
        L = lab[name]
        base = cal.build_baseline(L["baseline"]) if L.get("baseline") else None
        g = cal.fuse(name, baseline=base, window=L.get("window"))
        out += [(name, g, f, True) for f in g.findings
                if any(cal._matches(f, s) for s in L.get("expected_findings") or [])]
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tag", default="run", help="label for the saved file, e.g. before / after")
    ap.add_argument("--out", default="/app/data/fixture-verdict-eval")
    a = ap.parse_args()
    from services.fusion import decision_model as dm
    E = _score_module()
    if not dm.enabled("disposition"):
        sys.exit("The decision model is off: enable it (and 'Suggested verdict') in Settings -> Agentic.")
    items = labelled()
    print(f"{len(items)} findings: {sum(1 for *_, y in items if y)} attack, "
          f"{sum(1 for *_, y in items if not y)} not attack")
    pairs, saved, t0 = [], [], time.time()
    for g in {id(it[1]): it[1] for it in items}.values():           # one mask + call batch per graph
        rows = [it for it in items if it[1] is g]
        mask = dm.mask_for({}, g)
        answers = dm.ask_each([r[2] for r in rows], lambda f: dm.masked(dm.finding_state(g, f), mask),
                               dm._verdict_question)
        pairs += [(r[3], E.as_shown(dm, ans)) for r, ans in zip(rows, answers)]
        saved += [{"fixture": r[0], "title": r[2].title, "attack": r[3], "answer": ans}
                  for r, ans in zip(rows, answers)]
    s = E.score(pairs, dm.min_confidence())
    s["seconds"] = round(time.time() - t0, 1)
    print(E.report(s))
    os.makedirs(a.out, exist_ok=True)
    path = os.path.join(a.out, time.strftime("%Y%m%d-%H%M%S") + f"-{a.tag}.json")
    json.dump({"summary": s, "answers": saved}, open(path, "w", encoding="utf-8"), default=str)
    print(f"saved {path}")


if __name__ == "__main__":
    main()
