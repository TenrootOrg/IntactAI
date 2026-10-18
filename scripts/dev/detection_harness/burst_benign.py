import sys, json, collections, itertools
sys.path[:0] = ["/home/tenroot/wt-detect/tests", "/home/tenroot/wt-detect/modules/backend"]
import _optional_deps  # noqa
from services.fusion import external_logs as X, behaviour as B
det = collections.Counter(); n = 0; ex = []
for path in sys.argv[1:]:
    with open(path) as fh:
        while True:
            chunk = list(itertools.islice(fh, 100000))
            if not chunk:
                break
            fm, rows, _ = X.read("".join(chunk))
            norm = X.normalize(rows, X.detect_columns(rows)) if rows else []
            X.sigma_pass(norm)
            found = B.run(norm)
            n += len(rows)
            for r in norm:
                if r["n"].get("severity") in ("medium", "high", "critical"):
                    det[r["n"].get("rule")] += 1
            for f in found:
                det["[behaviour] " + f["n"]["rule"]] += 1
                if "burst" in f["raw"]["behaviour"]:
                    ex.append(f["n"]["message"][:300])
            print(f"{n:,} rows", file=sys.stderr, flush=True)
print(json.dumps({"rows": n, "detections": det.most_common(40), "burst_examples": ex[:10]}, indent=1))
