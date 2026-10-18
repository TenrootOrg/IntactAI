"""Every Splunk attack_data recording through the log-data pipeline: does a
detection come out? One JSON line per data file. Data only, never executed;
each file in its own folder under ~/datasets/splunk-attack-data."""
import json, os, sys, time, urllib.request, collections
sys.path[:0] = ["/home/tenroot/wt-detect/tests", "/home/tenroot/wt-detect/modules/backend"]
import _optional_deps  # noqa
from services.fusion import external_logs as X, behaviour as B, sigma_eval as SE
ROOT = os.path.expanduser("~/datasets/splunk-attack-data")
MAX = 40 * 1024 * 1024
meta, out_path = sys.argv[1], sys.argv[2]
only = sys.argv[3] if len(sys.argv) > 3 else ""
SE.load()
done = set()
if os.path.exists(out_path):
    done = {json.loads(l)["url"] for l in open(out_path) if l.strip()}
ALERT = ("medium", "high", "critical")
for line in open(meta):
    m = json.loads(line)
    if "error" in m or (only and only not in m["path"]):
        continue
    for f in m["files"]:
        url = f.get("path") or ""
        if url.startswith("/"):                     # repo-relative; the data is in Git LFS
            url = "https://media.githubusercontent.com/media/splunk/attack_data/master" + url
        if not url.startswith("http") or url in done:
            continue
        rec = {"url": url, "tech": m["tech"], "dataset": m["name"], "sourcetype": f.get("sourcetype"),
               "source": f.get("source")}
        t0 = time.time()
        try:
            d = os.path.join(ROOT, m["tech"], m["name"])
            os.makedirs(d, exist_ok=True)
            p = os.path.join(d, os.path.basename(url))
            if not os.path.exists(p):
                with urllib.request.urlopen(url, timeout=120) as r:
                    size = int(r.headers.get("Content-Length") or 0)
                    if size > MAX:
                        raise ValueError(f"too big ({size // 1048576} MB)")
                    data = r.read(MAX + 1)
                    if len(data) > MAX:
                        raise ValueError("too big")
                with open(p, "wb") as fh:
                    fh.write(data)
            text = X.read_text(p)
            fmt, rows, left = X.read(text)
            norm = X.normalize(rows, X.detect_columns(rows)) if rows else []
            if not (norm and X.recognized(norm)):
                norm = X.indicator_rows(text.splitlines())
            X.sigma_pass(norm)
            norm += B.run(norm)
            al = [r["n"] for r in norm if r["n"].get("severity") in ALERT]
            rec.update(format=fmt or "text", rows=len(norm), detections=len(al),
                       top=collections.Counter(str(a.get("rule"))[:90] for a in al).most_common(5))
        except Exception as e:  # noqa: BLE001
            rec["error"] = f"{type(e).__name__}: {e}"[:200]
        rec["seconds"] = round(time.time() - t0, 1)
        with open(out_path, "a") as fh:
            fh.write(json.dumps(rec, default=str) + "\n")
        print(f"{rec.get('detections', 'ERR'):>5} {m['tech']:12} {m['name'][:40]:40} {str(f.get('sourcetype'))[:30]}", flush=True)
