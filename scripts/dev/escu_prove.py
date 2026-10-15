#!/usr/bin/env python3
"""Prove each translated ESCU rule on the attack recording its detection was
written for: it must fire there, through the same reader and Sigma engine an
attachment goes through. Prints one JSON line per rule; recordings are cached
outside the repo (~/datasets/splunk-attack-data/escu-tests), never executed.

  python3 scripts/dev/escu_prove.py <rules dir> <results.jsonl>
"""
import hashlib, json, os, re, sys, urllib.request
here = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(here, "../../tests"), os.path.join(here, "../../modules/backend")]
import _optional_deps  # noqa
import yaml
from services.fusion import external_logs as X, sigma_eval as S
CACHE = os.path.expanduser("~/datasets/splunk-attack-data/escu-tests")
MAX = 150 * 1024 * 1024        # a longer recording is read up to here (marked truncated)
rules_dir, out = sys.argv[1], sys.argv[2]
part, parts = (int(x) for x in (sys.argv[3] if len(sys.argv) > 3 else "0/1").split("/"))
done = set()
for o in [out] + sys.argv[4:]:                       # other slices' results count as done too
    if os.path.exists(o):
        done |= {json.loads(l)["file"] for l in open(o)}
rows_cache = {}


def rows_of(url):
    if url in rows_cache:
        return rows_cache[url]
    p = os.path.join(CACHE, hashlib.sha1(url.encode()).hexdigest()[:16] + "_" + os.path.basename(url))
    # The coverage run (one folder per technique / dataset) may hold it already.
    m = re.search(r"/attack_techniques/([^/]+)/([^/]+)/([^/]+)$", url)
    if m and os.path.exists(os.path.join(os.path.dirname(CACHE), *m.groups())):
        p = os.path.join(os.path.dirname(CACHE), *m.groups())
    if os.path.exists(p + ".truncated"):
        p += ".truncated"
    if not os.path.exists(p):
        os.makedirs(CACHE, exist_ok=True)
        with urllib.request.urlopen(url, timeout=300) as r:
            data = r.read(MAX + 1)
        if len(data) > MAX:
            data = data[:data.rfind(b"\n", 0, MAX) + 1]
            p += ".truncated"
        with open(p, "wb") as f:
            f.write(data)
    text = X.read_text(p)
    fm, rows, left = X.read(text)
    ev = [X.sigma_event(X._flat(r)) for r in rows]   # the form sigma_pass matches
    # Lines no reader took go on as text (the pipeline's no-model path), as does a
    # file no reader took at all.
    ev += [X.sigma_event(r["raw"]) for r in X.indicator_rows(left if rows else text.splitlines())]
    if len(rows_cache) > 30:
        rows_cache.clear()
    rows_cache[url] = ev
    return ev


for i, f in enumerate(sorted(os.listdir(rules_dir))):
    if not f.endswith(".yml") or f in done or i % parts != part:
        continue
    with open(os.path.join(rules_dir, f)) as fh:
        doc = yaml.safe_load(fh)
    rec = {"file": f, "title": doc.get("title")}
    try:
        rule = S.compile_rule(doc)
        tests = (doc.get("x-escu") or {}).get("tests") or []
        if not tests:
            rec["result"] = "no test"
        else:
            hits = rows = 0
            for url in tests:
                ev = rows_of(url)
                rows += len(ev)
                cache = {}
                hits += sum(1 for e in ev if S.evaluate(e, [rule], cache))
            rec.update(result="fires" if hits else "silent", hits=hits, rows=rows)
    except S.Unsupported as e:
        rec.update(result="unsupported", why=str(e)[:150])
    except Exception as e:  # noqa: BLE001
        rec.update(result="error", why=f"{type(e).__name__}: {e}"[:150])
    with open(out, "a") as fh:
        fh.write(json.dumps(rec) + "\n")
    print(rec["result"], f, rec.get("hits", ""), flush=True)
