"""Synthetic identity-resolution accuracy harness.

Generates N people with realistic cross-infra account variants + name collisions +
corroboration, builds a FusionGraph, runs the SAME resolution the Identities tab does
(deterministic clustering + evidence-corroborated auto-merge), and scores it against the
known ground truth with pairwise precision / recall / F1.

Usage: python3 idbench.py [N]
"""
import sys, random
sys.path.insert(0, "/app")
random.seed(1337)

from services.fusion.schema import Entity, Relationship, FusionGraph
from services.fusion import identities as I

N = int(sys.argv[1]) if len(sys.argv) > 1 else 1000

FIRST = ["john","jane","alon","amir","noa","dana","yossi","maya","omer","tal","gil","roni",
         "ido","shira","adam","lena","mark","sara","paul","rita","kobi","nir","liat","eran",
         "guy","hila","oren","efrat","asaf","noga"]
LAST  = ["smith","cohen","levi","katz","mizrahi","peretz","biton","dahan","avraham","friedman",
         "gross","klein","weiss","adler","stern","roth","kaplan","segal","barak","noff","tal",
         "shani","azoulay","gabay","malka","ovadia","yosef","david","moshe","chen"]
DOMAINS = ["adatumlab","contoso","corp","tenroot"]
COMPANY = "tenroot"


def variants(user, dom, f, l, host_id):
    """Realistic cross-infra forms of ONE person. Cloud accounts carry a DOMAIN-bearing
    email/UPN (so u@contoso.com vs u@corp.com distinguish different-domain same-stem
    people); the local bare account lives on the person's home host (host corroboration)."""
    return [
        (f"{dom}\\{user}", ["velociraptor"], None, [host_id]),                              # AD account
        (user, ["velociraptor"], None, [host_id]),                                          # local (bare) on home host
        (f"{user}@{dom}.com", ["cloud"], "aws", ["asset:cloud_account:aws:111111111111"]),  # aws (email w/ domain)
        (f"azuread\\{user}@{dom}.onmicrosoft.com", ["cloud"], "azure",
         ["asset:cloud_account:azure:tenant-1"]),                                            # azure UPN
    ]


def build():
    g = FusionGraph("case:bench")
    g.upsert(Entity(id="asset:cloud_account:aws:111111111111", type="asset", label="aws:111111111111",
                    attrs={"provider": "aws", "kind": "cloud_account"}, sources=["cloud"]))
    g.upsert(Entity(id="asset:cloud_account:azure:tenant-1", type="asset", label="azure:tenant-1",
                    attrs={"provider": "azure", "kind": "cloud_account"}, sources=["cloud"]))
    truth = {}            # account_id -> person_id
    stems = {}            # base stem -> count, to make GLOBALLY-UNIQUE usernames (one org)
    for i in range(N):
        f, l = random.choice(FIRST), random.choice(LAST)
        base = f[0] + l
        n = stems.get(base, 0); stems[base] = n + 1
        user = base if n == 0 else f"{base}{n}"   # jsmith, jsmith1, jsmith2 ... globally unique
        dom = random.choice(DOMAINS)              # one org, a few forest domains
        # realistic Windows hostnames (NOT username-derived) — real hosts are DESKTOP-XXXX /
        # dept-NN, so one person's host never falsely "embeds" another's username.
        host_label = f"DESKTOP-{i:05d}" if random.random() < 0.5 else f"WKS-{i:04d}"
        host_id = f"asset:endpoint:C.h{i}"
        g.upsert(Entity(id=host_id, type="asset", label=host_label, sources=["velociraptor"]))
        ip = f"10.{i//256%256}.{i%256}.{random.randint(2,250)}"
        ioc_id = f"ioc:ip:{ip}"
        g.upsert(Entity(id=ioc_id, type="ioc", label=ip, attrs={"ioc_kind": "ip"}, sources=["velociraptor"]))
        # ~20% also get a DIFFERENT-form aws account (first.last@dom) that only a shared
        # host/IP + domain can link back — the hard, evidence-only case.
        vs = variants(user, dom, f, l, host_id)
        if user == base and random.random() < 0.2:   # first.last form (initials == flast)
            vs.append((f"{f}.{l}@{dom}.com", ["cloud"], "aws", ["asset:cloud_account:aws:111111111111"]))
        for j, (label, srcs, prov, assets) in enumerate(vs):
            aid = f"account:p{i}:{j}:{label.lower()}"
            attrs = {"_assets": list(assets)}
            if prov:
                attrs["provider"] = prov
            g.upsert(Entity(id=aid, type="account", label=label, attrs=attrs, sources=srcs))
            truth[aid] = i
            # link every account of this person to the person's shared IP (corroboration)
            g.relate(Relationship(aid, ioc_id, "event_about", sources=["bench"]))
    return g, truth


def resolve(g):
    """Replicate the Identities-tab resolution: deterministic clusters + auto-merges."""
    nz = I._norm_user
    cands = I.compute_candidates(g)
    fuzzy = [c for c in cands if c["kind"] == "same_identity" and nz(c["a_label"]) != nz(c["b_label"])]
    merges = [(c["a_id"], c["b_id"], c.get("score", 1.0)) for c in fuzzy if c.get("auto")]
    idents = I.resolve_identities(g, merges=merges)
    acct_cluster = {}
    for ci, it in enumerate(idents):
        for a in it["accounts"]:
            acct_cluster[a["id"]] = ci
    return acct_cluster, idents, len(merges)


def pairwise(truth, pred):
    from collections import defaultdict
    from math import comb
    # same-truth pairs
    tclust = defaultdict(list)
    for aid, p in truth.items():
        tclust[p].append(aid)
    same_truth = sum(comb(len(v), 2) for v in tclust.values() if len(v) > 1)
    # same-pred pairs
    pclust = defaultdict(list)
    for aid, c in pred.items():
        pclust[c].append(aid)
    same_pred = sum(comb(len(v), 2) for v in pclust.values() if len(v) > 1)
    # TP = pairs same in BOTH: within each predicted cluster, count by truth-person
    tp = 0
    for v in pclust.values():
        by_truth = defaultdict(int)
        for aid in v:
            by_truth[truth[aid]] += 1
        tp += sum(comb(n, 2) for n in by_truth.values() if n > 1)
    prec = tp / same_pred if same_pred else 1.0
    rec = tp / same_truth if same_truth else 1.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    return prec, rec, f1, tp, same_pred, same_truth


g, truth = build()
print(f"people={N} accounts={len(truth)} graph_entities={len(g.entities)}", flush=True)
import time
t = time.time()
pred, idents, nmerge = resolve(g)
print(f"resolved in {time.time()-t:.1f}s -> {len(idents)} identities ({nmerge} auto-merges)", flush=True)
prec, rec, f1, tp, sp, st = pairwise(truth, pred)
print(f"PAIRWISE  precision={prec:.4f}  recall={rec:.4f}  f1={f1:.4f}  (tp={tp} pred_pairs={sp} truth_pairs={st})", flush=True)

# failure examples: a predicted cluster mixing >1 real person (precision error)
from collections import defaultdict
pclust = defaultdict(list)
for aid, c in pred.items():
    pclust[c].append(aid)
contaminated = [(c, v) for c, v in pclust.items() if len({truth[a] for a in v}) > 1]
print(f"contaminated clusters (merged different people): {len(contaminated)}", flush=True)
for c, v in contaminated[:5]:
    ppl = defaultdict(list)
    for a in v:
        ppl[truth[a]].append(next(e.label for e in g.entities.values() if e.id == a))
    print("   WRONG-MERGE:", {p: lbls for p, lbls in ppl.items()}, flush=True)
# recall misses: a person whose accounts are split across >1 cluster
tclust = defaultdict(list)
for aid, p in truth.items():
    tclust[p].append(aid)
split_people = sum(1 for p, v in tclust.items() if len({pred[a] for a in v}) > 1)
print(f"people split across clusters (recall miss): {split_people}/{N}", flush=True)
print("DONE", flush=True)
