import json, sys, urllib.request, concurrent.futures as cf, yaml
paths = open(sys.argv[1]).read().split()
def get(p):
    url = "https://raw.githubusercontent.com/splunk/attack_data/master/" + p
    try:
        with urllib.request.urlopen(url, timeout=30) as r:
            d = yaml.safe_load(r.read()) or {}
    except Exception as e:
        return {"path": p, "error": str(e)}
    ds = d.get("datasets") or []
    return {"path": p, "tech": p.split("/")[2], "name": d.get("name") or p.split("/")[3],
            "desc": str(d.get("description") or "")[:300],
            "files": [{"name": x.get("name"), "path": x.get("path"), "sourcetype": x.get("sourcetype"),
                       "source": x.get("source")} for x in ds if isinstance(x, dict)]}
with cf.ThreadPoolExecutor(16) as ex, open(sys.argv[2], "w") as out:
    for i, r in enumerate(ex.map(get, paths)):
        out.write(json.dumps(r) + "\n")
        if i % 200 == 0:
            print(i, flush=True)
