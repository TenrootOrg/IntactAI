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
from services.fusion import external_logs as X, sigma_eval as S, keys
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
    # As the pipeline does: a structure that yields nothing usable is not one (a short
    # syslog file can pass for a CSV), and then every line is read as text.
    norm = X.normalize(rows, X.detect_columns(rows)) if rows else []
    if not (rows and X.recognized(norm)):
        rows, left, norm = [], text.splitlines(), []
    ev = [X.sigma_event(X._flat(r)) for r in rows]   # the form sigma_pass matches
    ts = [r["n"].get("ts") for r in norm]
    ind = X.indicator_rows(left)
    ev += [X.sigma_event(r["raw"]) for r in ind]     # lines no reader took (no-model path)
    ts += [r["n"].get("ts") for r in ind]
    # Each row's time, as correlation_pass reads it: a count is over a window.
    epochs = [(lambda d: d.timestamp() if d else None)(keys.to_utc_dt(t) if t else None) for t in ts]
    if len(rows_cache) > 30:
        rows_cache.clear()
    rows_cache[url] = (ev, epochs)
    return ev, epochs


for i, f in enumerate(sorted(os.listdir(rules_dir))):
    if not f.endswith(".yml") or f in done or i % parts != part:
        continue
    with open(os.path.join(rules_dir, f)) as fh:
        docs = [d for d in yaml.safe_load_all(fh) if isinstance(d, dict)]
    doc = next((d for d in docs if "correlation" in d), docs[0])
    rec = {"file": f, "title": doc.get("title")}
    try:
        if "correlation" in doc:                     # a count over a window: over the whole recording
            refs = {str(r): d for d in docs if "detection" in d for r in (d.get("name"), d.get("id")) if r}
            corr = S.compile_correlation(doc, refs)
        else:
            rule = S.compile_rule(doc)
        tests = (doc.get("x-escu") or {}).get("tests") or []
        if not tests:
            rec["result"] = "no test"
        else:
            hits = rows = 0
            for url in tests:
                ev, epochs = rows_of(url)
                rows += len(ev)
                if "correlation" in doc:
                    hits += len(S.correlate(list(zip(epochs, ev)), [corr]))
                else:
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
