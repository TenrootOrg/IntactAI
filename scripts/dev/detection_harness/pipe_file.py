"""One log file through the whole pipeline: what comes out at medium+."""
import sys, collections, time
sys.path[:0] = ["/home/tenroot/wt-detect/tests", "/home/tenroot/wt-detect/modules/backend"]
import _optional_deps  # noqa
from services.fusion import external_logs as X, behaviour as B, sigma_eval as SE
for p in sys.argv[1:]:
    t0 = time.time()
    text = X.read_text(p)
    fmt, rows, left = X.read(text)
    norm = X.normalize(rows, X.detect_columns(rows)) if rows else []
    if not (norm and X.recognized(norm)):
        norm = X.indicator_rows(text.splitlines())
    X.sigma_pass(norm)
    norm += B.run(norm)
    al = [r["n"] for r in norm if r["n"].get("severity") in ("medium", "high", "critical")]
    print(f"== {p.rsplit('/',1)[-1]}: {fmt or 'text'} {len(norm):,} rows, {len(al)} detections, {time.time()-t0:.0f}s")
    for k, v in collections.Counter(str(a.get("rule"))[:100] for a in al).most_common(12):
        print(f"   {v:6} {k}")
    ex = {}
    for a in al:
        ex.setdefault(str(a.get("rule"))[:100], {k: a.get(k) for k in ("url", "src_ip", "dst_ip", "user", "http_method")})
    for k, v in list(ex.items())[:8]:
        print("   e.g.", k[:50], v)
