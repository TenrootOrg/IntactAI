import json, sys, urllib.request, concurrent.futures as cf, yaml
t = json.load(open(sys.argv[1]))
paths = [i["path"] for i in t["tree"] if (i["path"].startswith("detections/") and i["path"].endswith(".yml")
         and "/deprecated/" not in i["path"]) or (i["path"].startswith("macros/") and i["path"].endswith(".yml"))]
def get(p):
    try:
        with urllib.request.urlopen("https://raw.githubusercontent.com/splunk/security_content/develop/" + p, timeout=30) as r:
            return {"path": p, "doc": yaml.safe_load(r.read())}
    except Exception as e:
        return {"path": p, "error": str(e)}
with cf.ThreadPoolExecutor(16) as ex, open(sys.argv[2], "w") as out:
    for r in ex.map(get, paths):
        out.write(json.dumps(r, default=str) + "\n")
