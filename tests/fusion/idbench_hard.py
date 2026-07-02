"""Adversarial identity-resolution tests — the cases that threaten PRECISION or recall.

Each scenario builds a tiny graph with KNOWN truth and checks the resolver did the right
thing. Focus: never wrongly merge two different people; resolve the same person when
there's real evidence; leave genuinely-uncertain ones for manual (no wrong auto-merge).
"""
import sys
sys.path.insert(0, "/app")
from services.fusion.schema import Entity, Relationship, FusionGraph
from services.fusion import identities as I

AWS = "asset:cloud_account:aws:111111111111"


def _resolve(g):
    nz = I._norm_user
    cands = I.compute_candidates(g)
    fuzzy = [c for c in cands if c["kind"] == "same_identity" and nz(c["a_label"]) != nz(c["b_label"])]
    merges = [(c["a_id"], c["b_id"], c.get("score", 1.0)) for c in fuzzy if c.get("auto")]
    idents = I.resolve_identities(g, merges=merges)
    a2c = {}
    for ci, it in enumerate(idents):
        for a in it["accounts"]:
            a2c[a["id"]] = ci
    return a2c


def _acc(g, aid, label, assets, srcs, prov=None, ip=None):
    at = {"_assets": list(assets)}
    if prov:
        at["provider"] = prov
    g.upsert(Entity(id=aid, type="account", label=label, attrs=at, sources=srcs))
    if ip:
        iid = "ioc:ip:" + ip
        g.upsert(Entity(id=iid, type="ioc", label=ip, attrs={"ioc_kind": "ip"}, sources=["velociraptor"]))
        g.relate(Relationship(aid, iid, "event_about", sources=["t"]))


def _host(g, hid, label):
    g.upsert(Entity(id=hid, type="asset", label=label, sources=["velociraptor"]))


def _base(g):
    g.upsert(Entity(id=AWS, type="asset", label="aws:x", attrs={"provider": "aws", "kind": "cloud_account"}, sources=["cloud"]))


results = []


def check(name, cond, detail=""):
    results.append(cond)
    print(f"  {'PASS' if cond else 'FAIL'} {name}" + (f"  :: {detail}" if detail and not cond else ""))


# 1) PRECISION: two DIFFERENT people share a host + names initials-match (colleagues on one
#    machine). Must NOT auto-merge (no other evidence that they're the same human).
g = FusionGraph("c"); _base(g); _host(g, "asset:endpoint:C.shared", "SHARED-PC")
_acc(g, "a:1", "john.smith", [AWS], ["cloud"], "aws")            # person A (cloud, no host)
_acc(g, "a:2", "CONTOSO\\jsmith", ["asset:endpoint:C.shared"], ["velociraptor"])  # person B on shared host
_acc(g, "a:3", "CONTOSO\\asmith", ["asset:endpoint:C.shared"], ["velociraptor"])  # person C on shared host
r = _resolve(g)
check("colleagues on one host not merged (A vs B)", r.get("a:1") != r.get("a:2"))
check("different people on one host stay separate (B vs C)", r.get("a:2") != r.get("a:3"))

# 2) RECALL(evidence): same person, first.last (aws) + flast (endpoint), SHARE an IP -> auto-merge.
g = FusionGraph("c"); _base(g); _host(g, "asset:endpoint:C.h", "H")
_acc(g, "b:1", "john.smith", [AWS], ["cloud"], "aws", ip="10.0.0.9")
_acc(g, "b:2", "CONTOSO\\jsmith", ["asset:endpoint:C.h"], ["velociraptor"], ip="10.0.0.9")
r = _resolve(g)
check("same person first.last+flast w/ shared IP -> merged", r.get("b:1") == r.get("b:2"))

# 3) SAFE-MISS: same person first.last + flast but NO shared evidence -> must NOT auto-merge
#    (correctly left for manual; would be a suggestion, never a wrong link).
g = FusionGraph("c"); _base(g); _host(g, "asset:endpoint:C.h2", "H2")
_acc(g, "c:1", "john.smith", [AWS], ["cloud"], "aws")            # no ip
_acc(g, "c:2", "CONTOSO\\jsmith", ["asset:endpoint:C.h2"], ["velociraptor"])  # different ip/none
r = _resolve(g)
check("first.last+flast with NO evidence -> NOT auto-merged", r.get("c:1") != r.get("c:2"))

# 4) single-org default: the same username IS one person (merged); a rare wrong collision is
#    RECOVERABLE via the analyst Split (never a silent unfixable merge).
g = FusionGraph("c"); _base(g)
_acc(g, "d:1", "CONTOSO\\jsmith", ["asset:endpoint:C.d1"], ["velociraptor"], ip="10.0.0.1")
_host(g, "asset:endpoint:C.d1", "D1")
_acc(g, "d:2", "CORP\\jsmith", ["asset:endpoint:C.d2"], ["velociraptor"], ip="10.0.0.2")
_host(g, "asset:endpoint:C.d2", "D2")
r = _resolve(g)
check("same username merges by default (one org)", r.get("d:1") == r.get("d:2"))
after = I.resolve_identities(g, splits={"d:2"})
own = [it for it in after if any(a["id"] == "d:2" for a in it["accounts"])]
check("Split recovers a wrong collision", len(own) == 1 and len(own[0]["accounts"]) == 1)

# 5) RECALL: one person's forms unite via domain root — contoso\jsmith + jsmith@contoso.com
#    + azuread\jsmith@contoso.onmicrosoft.com -> one identity, no evidence needed.
g = FusionGraph("c"); _base(g)
_acc(g, "e:1", "CONTOSO\\jsmith", ["asset:endpoint:C.e"], ["velociraptor"])
_host(g, "asset:endpoint:C.e", "E")
_acc(g, "e:2", "jsmith@contoso.com", [AWS], ["cloud"], "aws")
_acc(g, "e:3", "azuread\\jsmith@contoso.onmicrosoft.com", [AWS], ["cloud"], "azure")
r = _resolve(g)
check("one person's forms unite via domain root", r.get("e:1") == r.get("e:2") == r.get("e:3"))

print(f"\n{sum(results)}/{len(results)} adversarial checks passed")
sys.exit(0 if all(results) else 1)
