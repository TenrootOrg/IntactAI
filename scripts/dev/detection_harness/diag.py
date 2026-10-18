"""Why is a rule silent on its recording: the values its fields take there."""
import sys, os, re, json, yaml, glob, collections
sys.path[:0] = ["/home/tenroot/wt-detect/tests", "/home/tenroot/wt-detect/modules/backend"]
import _optional_deps  # noqa
from services.fusion import external_logs as X, sigma_eval as S
for path in sys.argv[1:]:
    doc = yaml.safe_load(open(path))
    fields = set()
    for k, v in doc["detection"].items():
        if isinstance(v, dict):
            fields |= {f.split("|")[0] for f in v}
    url = (doc.get("x-escu") or {}).get("tests", [""])[0]
    m = re.search(r"/datasets/(?:attack_techniques/)?(.+)$", url)
    cand = glob.glob(os.path.expanduser("~/datasets/splunk-attack-data/" + m.group(1))) if m else []
    if not cand:
        cand = glob.glob(os.path.expanduser("~/datasets/splunk-attack-data/escu-tests/*_" + url.rsplit("/", 1)[-1]))
    print("==", os.path.basename(path), doc["logsource"], "->", cand[:1])
    if not cand:
        continue
    text = X.read_text(cand[0]); fm, rows, left = X.read(text)
    if not (rows and X.recognized(X.normalize(rows, X.detect_columns(rows)))):
        rows = [r["raw"] for r in X.indicator_rows(text.splitlines())]
    vals = collections.defaultdict(collections.Counter); profs = collections.Counter()
    for r in rows[:5000]:
        e = X.sigma_event(X._flat(r)); ev = S.Event(e)
        profs[str(sorted(map(str, S.profiles(e))))[:110]] += 1
        for f in fields:
            vals[f][str(ev.get(f))[:90]] += 1
    print("   format", fm or "text", len(rows), "rows; profiles", profs.most_common(2))
    for f in sorted(fields):
        print("  ", f, vals[f].most_common(4))
