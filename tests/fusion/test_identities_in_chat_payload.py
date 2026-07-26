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
