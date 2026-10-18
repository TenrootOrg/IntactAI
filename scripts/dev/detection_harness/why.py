"""Why is each undetected attack_data recording undetected? Per recording, the
Splunk detections that test on it and what happened to each: not translated
(reason), translated but silent, or fires only at low."""
import json, glob, os, sys, re, collections
sys.path[:0] = ["/home/tenroot/wt-detect/scripts/dev", "/home/tenroot/wt-detect/tests", "/home/tenroot/wt-detect/modules/backend"]
import escu_to_sigma as T
S = sys.argv[1]
d = {}
for p in sorted(glob.glob(S + '/cov*.jsonl'), key=os.path.getmtime):
    for l in open(p):
        r = json.loads(l)
        if 'error' in r and r['url'] in d: continue
        d[r['url']] = r
miss = {u: r for u, r in d.items() if 'error' not in r and not r.get('detections')}
dets, macros = T.load_docs(sys.argv[2]) if len(sys.argv) > 2 else (None, None)
prove = {}
for l in open(S + '/prove_latest.jsonl'):
    r = json.loads(l); prove[r['file']] = r['result']
inst = set(os.listdir('/home/tenroot/wt-detect/modules/backend/config/sigma-escu'))
by_url = collections.defaultdict(list)
for x in dets:
    for t in x.get('tests') or []:
        for a in t.get('attack_data') or []:
            u = a.get('data') or ''
            by_url[u.split('/datasets/')[-1]].append(x)
out = []
for u, r in miss.items():
    why = []
    for x in by_url.get(u.split('/datasets/')[-1], []):
        if x.get('type') not in ('TTP', 'Anomaly') or str(x.get('status')) == 'deprecated':
            why.append((x['name'], 'type ' + str(x.get('type')))); continue
        f = 'escu_' + re.sub(r'[^a-z0-9]+', '_', x['name'].lower()).strip('_') + '.yml'
        if f in inst:
            why.append((x['name'], 'installed, ' + ('low only' if 'level: low' in open('/home/tenroot/wt-detect/modules/backend/config/sigma-escu/' + f).read() else 'silent in pipeline')))
            continue
        try:
            T.translate(x, macros); why.append((x['name'], 'translated, ' + str(prove.get(f, 'unproved'))))
        except T.Skip as e:
            why.append((x['name'], 'skip: ' + str(e)[:80]))
        except Exception as e:
            why.append((x['name'], 'error: ' + type(e).__name__))
    out.append({'url': u, 'st': r['sourcetype'], 'dataset': r['dataset'], 'tech': r['tech'], 'why': why})
json.dump(out, open(S + '/why.json', 'w'), indent=0)
c = collections.Counter()
for o in out:
    ks = {w.split(':')[0].split(',')[0] if not w.startswith('installed') else w for _, w in o['why']} or {'no detection names it'}
    best = 'low only' if any('low only' in k for k in ks) else sorted(ks)[0]
    c[(o['st'], best)] += 1
for (st, b), n in sorted(c.items(), key=lambda x: (-x[1])):
    if n >= 2: print(f"{n:4} {st:32} {b}")
