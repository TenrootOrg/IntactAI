#!/usr/bin/env python3
"""Run the proven ESCU rules over benign Windows activity; a rule that fires
there is noise on a real network. Prints {rule file: benign hits} as JSON.

  python3 scripts/dev/escu_benign.py <rules dir> <prove results.jsonl> <events.jsonl>...
"""
import collections, json, os, sys
here = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(here, "../../tests"), os.path.join(here, "../../modules/backend")]
import _optional_deps  # noqa
import yaml
from services.fusion import external_logs as X, sigma_eval as S
rules_dir, proven = sys.argv[1], sys.argv[2]
keep = {json.loads(l)["file"] for l in open(proven) if json.loads(l).get("result") == "fires"}
rules, by_title = [], {}
for f in sorted(keep):
    with open(os.path.join(rules_dir, f)) as fh:
        r = S.compile_rule(yaml.safe_load(fh))
    rules.append(r)
    by_title[r["title"]] = f
hits, n, ex = collections.Counter(), 0, {}
for path in sys.argv[3:]:
    with open(path) as fh:
        for line in fh:
            try:
                ev = X._flat(json.loads(line))
            except ValueError:
                continue
            n += 1
            for h in S.evaluate(ev, rules, None):
                f = by_title.get(h["title"])
                hits[f] += 1
                ex.setdefault(f, {k: str(ev.get(k))[:160] for k in ("Image", "CommandLine", "TargetObject",
                                                                       "TargetFilename") if ev.get(k)})
            if n % 200000 == 0:
                print(f"{n:,} events", file=sys.stderr, flush=True)
print(json.dumps({"events": n, "hits": hits, "examples": ex}, indent=1))
