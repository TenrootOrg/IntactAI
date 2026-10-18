import sys, collections, re
sys.path[:0] = ["/home/tenroot/wt-detect/tests", "/home/tenroot/wt-detect/modules/backend"]
import _optional_deps  # noqa
from services.fusion import external_logs as X, behaviour as B
for p in sys.argv[1:]:
    text = X.read_text(p); fmt, rows, left = X.read(text)
    norm = X.normalize(rows, X.detect_columns(rows)) if rows else []
    if not (norm and X.recognized(norm)):
        norm = X.indicator_rows(text.splitlines())
    X.sigma_pass(norm); norm += B.run(norm)
    c = collections.Counter((r["n"].get("severity"), str(r["n"].get("rule"))[:70]) for r in norm if r["n"].get("severity"))
    ids = collections.Counter(str((r.get("raw") or {}).get("EventID") or (r.get("raw") or {}).get("EventCode") or "") for r in norm)
    print(f"== {p.split('splunk-attack-data/')[-1][:70]} {fmt} {len(norm)} rows ids={dict(ids.most_common(5))}")
    for (sev, rule), n in c.most_common(4):
        print(f"     {n:4} {sev:8} {rule}")
