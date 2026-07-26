"""A known cross-host identity must reach the chat/report LLM even with zero
anomaly on every one of its accounts.

2026-07-26: a real 5-account, 4-host identity (visible and correctly clustered
in the Identities tab) was invisible to Case Analysis chat. `_distilled_at`
ranks entities purely by anomaly score and truncates to `max_entities`; every
one of that person's per-host account records had anomaly=0 (no finding
attached to them directly), so all five ranked near the bottom of ~18k
entities and were cut. The model's answer — "no such user in the evidence" —
was honest given what it was shown; the payload builder was the actual bug.
"""

import sys
if "/app" not in sys.path:
    sys.path.insert(0, "/app")

from services.fusion import store, render, calibrate  # noqa: E402
from services.fusion.schema import FusionGraph, Entity  # noqa: E402


def _graph_with_quiet_cross_host_identity():
    """A person present on 4 hosts with NO finding attached to any of their
    accounts — anomaly=0 everywhere, exactly the shape that got lost."""
    g = FusionGraph(case_id="c")
    hosts = ["ALClient09", "ALDC02", "ALDC03", "ALMECM01"]
    for i, h in enumerate(hosts):
        aid = f"asset:endpoint:C.host{i}"
        g.upsert(Entity(id=aid, type="asset", label=h, attrs={"_assets": [aid]}))
        g.upsert(Entity(id=f"account:{aid}:nofl", type="account", label="nofl",
                        severity="informational", anomaly=0,
                        attrs={"_assets": [aid]}))
    # A LOUD, high-anomaly account elsewhere, so max_entities=1 still has
    # something to prefer over the quiet identity — proving the identity
    # survives truncation via the identities list, not by accident.
    aid2 = "asset:endpoint:C.loud"
    g.upsert(Entity(id=aid2, type="asset", label="LOUDHOST", attrs={"_assets": [aid2]}))
    g.upsert(Entity(id="account:loud:attacker", type="account", label="attacker",
                    severity="critical", anomaly=999, attrs={"_assets": [aid2]}))
    return g


def test_quiet_cross_host_identity_survives_even_max_entities_1():
    g = _graph_with_quiet_cross_host_identity()
    payload = render.distilled(g, max_entities=1)   # brutal truncation on purpose
    names = {i["name"] for i in payload.get("identities", [])}
    assert "nofl" in names, \
        "a real cross-host identity with anomaly=0 did not survive distillation"
    entry = next(i for i in payload["identities"] if i["name"] == "nofl")
    assert entry["accounts"] == 4
    assert set(entry["seen_on_hosts"]) == {"ALClient09", "ALDC02", "ALDC03", "ALMECM01"}
    # the loud account should ALSO be present — this isn't a regression on the
    # existing anomaly-ranked behaviour, it's additive
    assert any(e["label"] == "attacker" for e in payload["top_entities"])


def test_identities_field_present_on_the_real_fixture():
    """Sanity check against a real (not synthetic) fused graph, matching what
    Case Analysis actually loads."""
    contrib = calibrate._contribution(calibrate.load_fixture("attack2"))
    from services import workflow_service as ws
    for r in ws.get_all_automation_runs() or []:
        if r.get("automation_type") == store.CASE_TYPE and \
                (r.get("details") or {}).get("name") == "identities-payload-check":
            store.delete_case(r.get("run_id"))
    cid = store.create_case("identities-payload-check", min_severity="informational")
    store.fuse_case(cid, contributions_override=[contrib])
    g = store.load_graph(cid)
    payload = render.distilled(g, max_entities=60)
    assert "identities" in payload
    assert isinstance(payload["identities"], list)
    store.delete_case(cid)


def test_a_person_with_no_accounts_produces_no_crash():
    """Empty graph — the 'clean' shape — must not crash identity resolution."""
    g = FusionGraph(case_id="c")
    payload = render.distilled(g, max_entities=10)
    assert payload.get("identities") == []


# ---------------------------------------------------------------------------
# The 'Identity limit' case setting (Case Analysis -> Configuration).
# ---------------------------------------------------------------------------
# It is a CEILING INSIDE the entity budget, never a separate side-channel: a
# huge value can't push identities past the same context-safe budget that
# governs everything else in the payload, and a stepdown shrinks both together.

def test_identity_limit_can_lower_but_never_raise_past_the_entity_budget():
    g = _graph_with_quiet_cross_host_identity()
    # 4 quiet accounts cluster to 1 identity; add more distinct people to count against
    for i in range(6):
        aid = f"asset:endpoint:C.extra{i}"
        g.upsert(Entity(id=aid, type="asset", label=f"HOST{i}", attrs={"_assets": [aid]}))
        g.upsert(Entity(id=f"account:{aid}:person{i}", type="account", label=f"person{i}",
                        severity="informational", anomaly=0, attrs={"_assets": [aid]}))

    all_n = len(render.distilled(g, max_entities=100)["identities"])
    assert all_n >= 5, f"fixture should yield several identities, got {all_n}"

    # LOWER: an explicit small ceiling wins
    assert len(render.distilled(g, max_entities=100, max_identities=2)["identities"]) == 2

    # HIGHER: cannot exceed the entity budget — that is the whole safety property
    capped = render.distilled(g, max_entities=3, max_identities=999999)["identities"]
    assert len(capped) <= 3, \
        "a large Identity limit escaped the entity budget — it must be a ceiling INSIDE it"

    # UNSET: tied to the entity budget
    assert len(render.distilled(g, max_entities=100, max_identities=None)["identities"]) == all_n


def test_identity_limit_zero_means_none():
    g = _graph_with_quiet_cross_host_identity()
    assert render.distilled(g, max_entities=100, max_identities=0)["identities"] == []


def test_identity_limit_setting_round_trips_through_the_case_config():
    """The knob must persist and clear like every other Configuration field."""
    from services import workflow_service as ws
    for r in ws.get_all_automation_runs() or []:
        if r.get("automation_type") == store.CASE_TYPE and \
                (r.get("details") or {}).get("name") == "identity-limit-roundtrip":
            store.delete_case(r.get("run_id"))
    cid = store.create_case("identity-limit-roundtrip", min_severity="informational")
    try:
        store.set_analysis_config(cid, {"max_identities": 7})
        assert store._llm_identity_budget(store.get_case(cid)) == 7
        store.set_analysis_config(cid, {"max_identities": None})
        assert store._llm_identity_budget(store.get_case(cid)) is None, \
            "clearing the field must mean 'tied to the Entity limit', not 0"
        # garbage must not corrupt the case
        store.set_analysis_config(cid, {"max_identities": "not-a-number"})
        assert store._llm_identity_budget(store.get_case(cid)) is None
    finally:
        store.delete_case(cid)


def test_truncation_keeps_the_identities_that_matter():
    """When the budget forces a cut, keep people tied to FINDINGS — not merely
    the ones spanning the most systems.

    resolve_identities() sorts for the Identities tab (infrastructure breadth,
    then account count), which is right for browsing and wrong for a budget cut:
    it would keep a quiet admin on many hosts and drop the person named in a
    critical finding. _known_identities re-ranks by risk for the LLM payload.
    """
    from services.fusion.schema import Finding

    g = FusionGraph(case_id="c")
    aid = "asset:endpoint:C.h"
    g.upsert(Entity(id=aid, type="asset", label="H1", attrs={"_assets": [aid]}))

    # BROAD but quiet: many accounts across many hosts, zero findings.
    for i in range(6):
        h = f"asset:endpoint:C.broad{i}"
        g.upsert(Entity(id=h, type="asset", label=f"B{i}", attrs={"_assets": [h]}))
        g.upsert(Entity(id=f"account:{h}:broaduser", type="account", label="broaduser",
                        severity="informational", anomaly=0, attrs={"_assets": [h]}))

    # NARROW but implicated: one account, one host, tied to a critical finding.
    g.upsert(Entity(id="account:risky", type="account", label="riskyuser",
                    severity="informational", anomaly=0, attrs={"_assets": [aid]}))
    g.add_finding(Finding(id="f_crit", title="Credential theft on H1", severity="critical",
                          confidence="high", summary="x", entity_ids=["account:risky"],
                          asset_ids=[aid], mitre=[]))

    only_one = render.distilled(g, max_entities=1)["identities"]
    assert len(only_one) == 1
    assert only_one[0]["name"] == "riskyuser", (
        "truncation dropped the identity tied to a critical finding and kept the "
        f"merely-broad one: got {only_one[0]['name']!r}")
