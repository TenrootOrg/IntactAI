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

def test_identity_limit_is_independent_of_the_entity_budget():
    """Identities are capped on their OWN axis, not by max_entities.

    They were briefly clamped to min(limit, max_entities), which looked safe but
    reintroduced the original bug at a higher threshold: chat's entity budget is
    60, so the 61st person in a large environment became invisible to the exact
    path where "who is X" is asked. Identities cost ~27 tokens each (vs ~500 for
    an entity row) and answer a different question, so they get their own ceiling;
    budget_chars remains the real overflow guard (see the stepdown test below).
    """
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

    # A TINY entity budget must NOT starve identities — this is the regression
    # that made person #61 invisible in chat.
    assert len(render.distilled(g, max_entities=1)["identities"]) == all_n, \
        "a small entity budget suppressed identities — they must be independent"

    # UNSET: the generous default, not the entity count
    assert len(render.distilled(g, max_entities=100, max_identities=None)["identities"]) == all_n


def test_identities_still_shrink_when_the_payload_genuinely_overflows():
    """The independence above must not become an unbounded escape hatch: when
    budget_chars can't fit the payload, identities step down with entities."""
    g = FusionGraph(case_id="c")
    for i in range(300):
        aid = f"asset:endpoint:C.big{i}"
        g.upsert(Entity(id=aid, type="asset", label=f"BIGHOST{i}", attrs={"_assets": [aid]}))
        g.upsert(Entity(id=f"account:{aid}:person{i:03d}", type="account",
                        label=f"person{i:03d}", severity="informational", anomaly=0,
                        attrs={"_assets": [aid]}))
    roomy = render.distilled(g, max_entities=60, budget_chars=None)["identities"]
    tight = render.distilled(g, max_entities=60, budget_chars=8000)["identities"]
    assert len(tight) < len(roomy), \
        "a tight char budget did not shrink the identity block — it can overflow the context"


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

    only_one = render.distilled(g, max_entities=1, max_identities=1)["identities"]
    assert len(only_one) == 1
    assert only_one[0]["name"] == "riskyuser", (
        "truncation dropped the identity tied to a critical finding and kept the "
        f"merely-broad one: got {only_one[0]['name']!r}")


# ---------------------------------------------------------------------------
# 'Use the model's full context' flag.
# ---------------------------------------------------------------------------
# The static budget constants are written for a ~128k-context model and never
# consult the model actually selected — wrong in both directions (a 272k model
# is trimmed to ~37% of what fits; an 8k local model would be overflowed). The
# flag derives the budget from the real context window instead.

def test_adaptive_budget_scales_with_the_real_context_window():
    from services.fusion import budget

    big = budget.adaptive_budget(272_000, 4_000)
    mid = budget.adaptive_budget(128_000, 8_000)
    small = budget.adaptive_budget(8_192, 2_048)
    assert big and mid and small
    assert big[1] > mid[1] > small[1], "budget must scale with the context window"

    # output cap is subtracted — context is shared input+output, and over-filling
    # is rejected by the provider rather than degrading gracefully
    assert budget.adaptive_budget(100_000, 50_000)[1] < \
           budget.adaptive_budget(100_000, 1_000)[1]

    # headroom: never claim the whole window (approx_tokens is a chars/4 estimate)
    assert big[1] < 272_000

    # unknown context -> None, so the caller keeps the safe static constants
    assert budget.adaptive_budget(None, 4_000) is None
    assert budget.adaptive_budget(0, 4_000) is None


def test_full_context_defaults_on_but_an_explicit_false_is_honoured():
    """Default ON (key absent). An operator who deliberately unticked it to cap
    cost must not have it silently switched back on."""
    from services import workflow_service as ws
    for r in ws.get_all_automation_runs() or []:
        if r.get("automation_type") == store.CASE_TYPE and \
                (r.get("details") or {}).get("name") == "full-context-default":
            store.delete_case(r.get("run_id"))
    cid = store.create_case("full-context-default", min_severity="informational")
    try:
        d = store.get_case(cid)
        assert "llm_use_full_context" not in d or d.get("llm_use_full_context") is None, \
            "fixture assumption: a fresh case leaves the key unset"
        _, unset = store._llm_payload_budget(d)

        d_off = dict(d); d_off["llm_use_full_context"] = False
        _, off = store._llm_payload_budget(d_off)
        assert unset >= off, "unset must behave as ON, not OFF"

        d_on = dict(d); d_on["llm_use_full_context"] = True
        _, on = store._llm_payload_budget(d_on)
        assert unset == on, "an unset flag must match an explicit True"
    finally:
        store.delete_case(cid)


def test_full_context_flag_only_ever_raises_the_ceiling():
    """A model whose window resolves small must not SHRINK the payload when the
    operator ticks 'use the full context' — that is the opposite of the ask."""
    from services import workflow_service as ws
    for r in ws.get_all_automation_runs() or []:
        if r.get("automation_type") == store.CASE_TYPE and \
                (r.get("details") or {}).get("name") == "full-context-flag":
            store.delete_case(r.get("run_id"))
    cid = store.create_case("full-context-flag", min_severity="informational")
    try:
        d = dict(store.get_case(cid))
        d["llm_use_full_context"] = False
        _, off = store._llm_payload_budget(d)
        d["llm_use_full_context"] = True
        _, on = store._llm_payload_budget(d)
        assert on >= off, "the flag lowered the budget instead of raising it"

        # and it must round-trip through the case config like any other setting
        store.set_analysis_config(cid, {"llm_use_full_context": True})
        assert store.get_case(cid).get("llm_use_full_context") is True
        store.set_analysis_config(cid, {"llm_use_full_context": False})
        assert store.get_case(cid).get("llm_use_full_context") is False
    finally:
        store.delete_case(cid)
