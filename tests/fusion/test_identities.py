"""Cross-infrastructure identity correlation (services/fusion/identities.py + store apply).

Guards: bucket detection, cross-infra candidate generation (exact/prefix/fuzzy),
auto-vs-ambiguous gating (unique → auto, multiple → manual), machine-account +
stopword exclusion, operates (user↔host) matching, stable link ids, and that a
confirmed decision applies a graph edge while a declined one does not.
"""

import sys

if "/app" not in sys.path:
    sys.path.insert(0, "/app")

from services.fusion import identities as I           # noqa: E402
from services.fusion import store as S                # noqa: E402
from services.fusion.schema import Entity, FusionGraph  # noqa: E402

AWS_ASSET = "asset:cloud_account:aws:111122223333"
EP_ASSET = "asset:endpoint:C.h1"


def _g(*, cloud_users=(), ep_users=(), ep_hosts=()):
    g = FusionGraph("case:id")
    if cloud_users:                                    # only a real AWS scan adds the cloud asset
        g.upsert(Entity(id=AWS_ASSET, type="asset", label="aws:111122223333",
                        attrs={"provider": "aws", "kind": "cloud_account"}, sources=["cloud"]))
    g.upsert(Entity(id=EP_ASSET, type="asset", label="H1", sources=["velociraptor"]))
    for u in cloud_users:
        g.upsert(Entity(id=f"account:cloud:{u.lower()}", type="account", label=u,
                        attrs={"_assets": [AWS_ASSET]}, sources=["cloud"]))
    for u in ep_users:
        g.upsert(Entity(id=f"account:asset:endpoint:C.h1:{u.lower()}", type="account", label=u,
                        attrs={"_assets": [EP_ASSET]}, sources=["velociraptor"]))
    for h in ep_hosts:
        g.upsert(Entity(id=f"asset:endpoint:C.{h.lower()}", type="asset", label=h,
                        sources=["velociraptor"]))
    return g


def _same(cands):
    return [c for c in cands if c["kind"] == "same_identity"]


# ---------------------------------------------------------------- buckets

def test_buckets_endpoint_is_velo_memory_timesketch():
    g = _g(cloud_users=["alon"], ep_users=["alonm"])
    assert I.case_buckets(g) == ["aws", "endpoint"]


def test_single_bucket_no_same_identity():
    # only endpoint accounts -> no cross-infra same-identity candidates
    g = _g(ep_users=["alon", "alonm"])
    assert I.case_buckets(g) == ["endpoint"]
    assert _same(I.compute_candidates(g)) == []


# ------------------------------------------------ same-identity matching

def test_exact_cross_infra_unique_is_auto():
    g = _g(cloud_users=["alon"], ep_users=["alon"])
    c = _same(I.compute_candidates(g))
    assert len(c) == 1
    assert c[0]["reason"] == "exact username"
    assert c[0]["auto"] is True and c[0]["ambiguous"] is False


def test_prefix_without_corroboration_is_suggestion_not_auto():
    # name-only prefix (no shared host/IP) is a SUGGESTION, never auto — this is where
    # big-org collisions (AlonM/AlonN/AlonT) live.
    uniq = _same(I.compute_candidates(_g(cloud_users=["alon"], ep_users=["alonm"])))
    assert len(uniq) == 1 and uniq[0]["auto"] is False
    amb = _same(I.compute_candidates(_g(cloud_users=["alon"], ep_users=["AlonM", "AlonN", "AlonT"])))
    assert len(amb) == 3 and all(not x["auto"] for x in amb)


def test_prefix_with_shared_host_auto_merges():
    # cloud `nofl` operates NofLaptop by name; endpoint `noflevi` is RESIDENT on NofLaptop
    # -> shared host corroborates the prefix match -> auto (evidence-led).
    g = _g(cloud_users=["nofl"], ep_hosts=["NofLaptop"])
    aid = "asset:endpoint:C.noflaptop"
    g.upsert(Entity(id="account:asset:endpoint:C.noflaptop:noflevi", type="account",
                    label="noflevi", attrs={"_assets": [aid]}, sources=["velociraptor"]))
    c = [x for x in _same(I.compute_candidates(g))
         if "noflevi" in (x["a_label"] + x["b_label"]).lower()]
    assert c and c[0]["auto"] is True
    assert "shares host" in c[0]["reason"]


def test_same_name_across_hosts_is_not_ambiguous():
    # `nofl` (cloud) matching `nofl` on 3 endpoints = ONE identity across machines, NOT a
    # conflict — must be auto (same name), distinguishable by host context, not 3 ambiguous
    # review rows. (Different NAMES like AlonM/AlonN would be ambiguous — see test above.)
    g = _g(cloud_users=["nofl"], ep_users=["nofl"], ep_hosts=[])
    # add the same 'nofl' on two more hosts
    for h in ("h2", "h3"):
        aid = f"asset:endpoint:C.{h}"
        g.upsert(Entity(id=aid, type="asset", label=h.upper(), sources=["velociraptor"]))
        g.upsert(Entity(id=f"account:asset:endpoint:C.{h}:nofl", type="account", label="nofl",
                        attrs={"_assets": [aid]}, sources=["velociraptor"]))
    c = _same(I.compute_candidates(g))
    assert len(c) == 3
    assert all(not x["ambiguous"] and x["auto"] for x in c), "same name/many hosts -> auto, not ambiguous"
    # host context set so the UI can tell the rows apart
    assert {x["b_ctx"] for x in c} == {"H1", "H2", "H3"}


def test_email_localpart_match_is_strong():
    c = _same(I.compute_candidates(_g(cloud_users=["AlonM@gmail.com"], ep_users=["AlonM"])))
    assert len(c) == 1 and c[0]["auto"] is True
    assert "email" in c[0]["reason"]


def test_machine_accounts_excluded():
    # HOST$ is the computer's own account, not a person — no same-identity, no operates
    g = _g(cloud_users=["aldc02"], ep_users=["ALDC02$"], ep_hosts=["ALDC02"])
    cands = I.compute_candidates(g)
    assert all("$" not in c["a_label"] and "$" not in c["b_label"] for c in cands)


def test_generic_names_excluded():
    # 'admin' is a generic role, not a personal identity
    g = _g(cloud_users=["admin"], ep_users=["admin"])
    assert _same(I.compute_candidates(g)) == []


# ------------------------------------------------------ operates (user↔host)

def test_operates_user_to_host_by_name():
    g = _g(cloud_users=["alon"], ep_hosts=["ALON-PC"])
    ops = [c for c in I.compute_candidates(g) if c["kind"] == "operates"]
    assert any(c["b_label"] == "ALON-PC" and c["a_label"] == "alon" for c in ops)


def test_operates_matches_concatenated_hostname():
    # 'nofl' operates 'NofLaptop' — hostname embeds the username with NO separator
    # (nofl + laptop). Prefix-concatenation match (needs a >=4-char username).
    g = _g(cloud_users=["nofl"], ep_hosts=["NofLaptop"])
    ops = [c for c in I.compute_candidates(g) if c["kind"] == "operates"]
    assert any(c["b_label"] == "NofLaptop" and c["a_label"] == "nofl" for c in ops)


def test_operates_short_username_no_prefix_false_positive():
    # 'srv' (3 chars) must NOT prefix-match 'srvexchange' — short prefixes over-link.
    g = _g(ep_users=["srv"], ep_hosts=["srvexchange"])
    ops = [c for c in I.compute_candidates(g)
           if c["kind"] == "operates" and c["b_label"] == "srvexchange"]
    assert ops == []


# ----------------------------------------------------------- link ids

def _card_named(ids, name):
    return next(it for it in ids if it["name"] == name)


def test_resolve_identities_clusters_and_excludes_system():
    # cloud `nofl` + endpoint `nofl`/`adatumlab\nofl` -> ONE person card; Windows service
    # accounts are excluded from the people list.
    g = _g(cloud_users=["nofl"],
           ep_users=["nofl", "adatumlab\\nofl", "NETWORK SERVICE", "defaultaccount"],
           ep_hosts=["NofLaptop"])
    ids = I.resolve_identities(g)
    names = {it["name"] for it in ids}
    assert "nofl" in names
    assert "networkservice" not in names and "network service" not in names
    assert "defaultaccount" not in names
    nofl = _card_named(ids, "nofl")
    assert set(nofl["buckets"]) == {"aws", "endpoint"}          # cloud + endpoint merged
    assert len(nofl["accounts"]) >= 3
    assert any(h["label"] == "NofLaptop" for h in nofl["hosts"])  # operates NofLaptop


def test_resolve_identities_confirmed_merge_unions_people():
    # merges are SPECIFIC account-id pairs (norm alone is ambiguous under collisions).
    g = _g(cloud_users=["nofl"], ep_users=["noflevi"])
    assert len(I.resolve_identities(g)) == 2                     # different names -> 2 people
    merged = I.resolve_identities(g, merges=[
        ("account:cloud:nofl", "account:asset:endpoint:C.h1:noflevi", 1.0)])
    assert len(merged) == 1                                      # confirmed same-person -> 1


def test_resolve_identities_split_isolates_account():
    # cloud `nofl` + endpoint `nofl` = one card (2 accounts); splitting the cloud account
    # ('not this person') gives it its own identity.
    g = _g(cloud_users=["nofl"], ep_users=["nofl"])
    assert len(_card_named(I.resolve_identities(g), "nofl")["accounts"]) == 2
    after = I.resolve_identities(g, splits={"account:cloud:nofl"})
    owning = [it for it in after if any(a["id"] == "account:cloud:nofl" for a in it["accounts"])]
    assert len(owning) == 1 and len(owning[0]["accounts"]) == 1  # isolated


def test_merged_card_confidence_reflects_fuzzy_score():
    g = _g(cloud_users=["nofl"], ep_users=["noflevi"])
    card = I.resolve_identities(g, merges=[
        ("account:cloud:nofl", "account:asset:endpoint:C.h1:noflevi", 0.6)])[0]
    assert card["confidence"] < 1.0                              # a fuzzy merge lowers it
    assert any(a["conf"] == 0.6 for a in card["accounts"])       # folded-in account carries the score


def test_host_exclude_removes_operated_host():
    g = _g(cloud_users=["nofl"], ep_hosts=["NofLaptop"])
    assert any(h["label"] == "NofLaptop"
               for it in I.resolve_identities(g) for h in it["hosts"])
    after = I.resolve_identities(g, host_excludes={("nofl", "asset:endpoint:C.noflaptop")})
    assert not any(h["label"] == "NofLaptop" for it in after for h in it["hosts"])


def test_link_id_is_order_independent():
    assert I.link_id("a", "b", "same_identity") == I.link_id("b", "a", "same_identity")
    assert I.link_id("a", "b", "same_identity") != I.link_id("a", "b", "operates")


# ------------------------------------------- apply edges on fuse (store)

def test_confirmed_applies_edge_declined_does_not():
    g = _g(cloud_users=["alon"], ep_users=["AlonM", "AlonN"])   # ambiguous -> manual
    cands = _same(I.compute_candidates(g))
    target = cands[0]
    d = {"identity_links": [{"id": target["id"], "decision": "confirmed",
                             "a_id": target["a_id"], "b_id": target["b_id"],
                             "kind": target["kind"], "origin": "human"}]}
    S._apply_identity_links(g, d)
    edges = [r for r in g.relationships if r.attrs.get("identity_link")]
    assert len(edges) == 1 and edges[0].attrs.get("origin") == "human"
    # now decline it -> no edge
    g2 = _g(cloud_users=["alon"], ep_users=["AlonM", "AlonN"])
    d2 = {"identity_links": [{"id": target["id"], "decision": "declined"}]}
    S._apply_identity_links(g2, d2)
    assert [r for r in g2.relationships if r.attrs.get("identity_link")] == []


def test_auto_link_applies_without_human():
    g = _g(cloud_users=["alon"], ep_users=["alon"])   # exact unique -> auto
    S._apply_identity_links(g, {"identity_links": []})
    edges = [r for r in g.relationships if r.attrs.get("identity_link")]
    assert len(edges) == 1 and edges[0].attrs.get("origin") == "auto"


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn(); print(f"PASS {fn.__name__}")
    print(f"\n{len(fns)} passed")
