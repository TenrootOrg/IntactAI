"""One scorecard for every fusion change: tuning, hold-out and benign, side by side.

    docker cp scripts/dev/{fusion_scorecard,groundtruth_eval}.py scripts/dev/groundtruth_steps.json intact_backend:/tmp/
    docker exec -w /app intact_backend python3 /tmp/fusion_scorecard.py <label> \\
        tune:szechuan=<case> tune:apt29_day1=<case> ... holdout:<dataset>=<case> ... \\
        benign:<case> ... scale:<case>

Three questions, because a change that only raises the first is fitted to the test data:
  tune     -- the datasets the fixes were designed on: key steps in graph / in report, false claims
  holdout  -- datasets NEVER looked at while tuning: the same score, read only after a change is done
  benign   -- clean environments + the calibration fixtures: findings and high+ findings per host
              must not grow (scale: the 108-host lab, same per-host numbers)
Each run is appended to /app/data/fusion_scorecard.jsonl under <label>; the previous run is shown
beside it, so before/after is one command. Read-only otherwise.
"""
import json
import os
import sys
import time

sys.path[:0] = ["/app", os.path.dirname(os.path.abspath(__file__))]
from services.fusion import calibrate, store  # noqa: E402
import groundtruth_eval  # noqa: E402

HISTORY = "/app/data/fusion_scorecard.jsonl"


def noise(cid) -> dict:
    g = store.load_graph(cid)
    hosts = max(1, sum(1 for e in g.entities.values() if e.type == "asset"))
    hi = sum(1 for f in g.findings if f.severity in ("high", "critical"))
    return {"case": cid, "hosts": hosts, "findings": len(g.findings), "high": hi,
            "per_host": round(len(g.findings) / hosts, 2), "high_per_host": round(hi / hosts, 2)}


def main():
    label, specs = sys.argv[1], sys.argv[2:]
    out = {"label": label, "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "tune": {},
           "holdout": {}, "benign": {}, "scale": {}}
    for sp in specs:
        kind, rest = sp.split(":", 1)
        if kind in ("tune", "holdout"):
            ds, cid = rest.split("=", 1)
            r = groundtruth_eval.score(ds, cid)
            out[kind][ds] = {k: r[k] for k in ("case", "steps", "in_graph", "in_report", "traps", "traps_hit")}
        else:
            out[kind][rest] = noise(rest)
    out["fixtures"] = {k: {m: v[m] for m in ("precision", "recall")}
                       for k, v in calibrate.evaluate(verbose=False).items() if isinstance(v, dict)}
    prev = None
    try:
        with open(HISTORY) as fh:
            prev = [json.loads(x) for x in fh if x.strip()][-1]
    except (OSError, ValueError, IndexError):
        pass
    with open(HISTORY, "a") as fh:
        fh.write(json.dumps(out) + "\n")

    def was(kind, key, field):
        try:
            return prev[kind][key][field]
        except (TypeError, KeyError):
            return None

    def cell(now, old):
        return f"{now}" if old is None or old == now else f"{old}->{now}"

    print(f"scorecard '{label}'" + (f"   (previous: '{prev['label']}' {prev['at']})" if prev else ""))
    for kind in ("tune", "holdout"):
        for ds, r in out[kind].items():
            print(f"  {kind:<8} {ds:<12} graph {cell(r['in_graph'], was(kind, ds, 'in_graph'))}/{r['steps']}  "
                  f"report {cell(r['in_report'], was(kind, ds, 'in_report'))}/{r['steps']}  "
                  f"false claims {cell(len(r['traps_hit']), len(was(kind, ds, 'traps_hit') or []) if prev else None)}"
                  f"/{r['traps']}")
    for kind in ("benign", "scale"):
        for cid, r in out[kind].items():
            print(f"  {kind:<8} {cid:<22} {r['hosts']} hosts  findings/host "
                  f"{cell(r['per_host'], was(kind, cid, 'per_host'))}  high/host "
                  f"{cell(r['high_per_host'], was(kind, cid, 'high_per_host'))}")
    for k, v in out["fixtures"].items():
        print(f"  fixture  {k:<12} P={v['precision']} R={v['recall']}")


if __name__ == "__main__":
    main()
