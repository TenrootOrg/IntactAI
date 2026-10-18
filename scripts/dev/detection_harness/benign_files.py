"""Rules over real-world benign log FILES (read as the pipeline reads them).
  python3 benign_files.py <rules dir> <file>...   -> {rule file: {file: hits}} + examples"""
import json, os, sys, collections
sys.path[:0] = ["/home/tenroot/wt-detect/tests", "/home/tenroot/wt-detect/modules/backend"]
import _optional_deps  # noqa
import yaml
from services.fusion import external_logs as X, sigma_eval as S
rd = sys.argv[1]
rules, fname = [], {}
for f in sorted(os.listdir(rd)):
    r = S.compile_rule(yaml.safe_load(open(os.path.join(rd, f))))
    rules.append(r); fname[r["title"]] = f
hits, ex = collections.defaultdict(collections.Counter), {}
for p in sys.argv[2:]:
    text = X.read_text(p)
    fm, rows, left = X.read(text)
    evs = [X.sigma_event(X._flat(r)) for r in rows] + [X.sigma_event(r["raw"]) for r in X.indicator_rows(left if rows else text.splitlines())]
    cache = {}
    for e in evs:
        for h in S.evaluate(e, rules, cache):
            hits[fname[h["title"]]][os.path.basename(p)] += 1
            ex.setdefault(fname[h["title"]], {k: v for k, v in e.items() if k != "_line"})
    print(f"{os.path.basename(p)}: {fm or 'text'} {len(evs):,} rows", file=sys.stderr, flush=True)
print(json.dumps({"hits": hits, "examples": {k: str(v)[:400] for k, v in ex.items()}}, indent=1, default=str))
