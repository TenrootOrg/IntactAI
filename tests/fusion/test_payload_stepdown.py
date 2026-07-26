"""The over-budget stepdown must trim what the payload is MADE OF.

Measured on a real 9-host case before this fix: findings 51% + timeline 43% =
94% of the payload, entities 3.4%. The stepdown halved only entities, so on a
99,664-char payload against a 32,000-char budget it reclaimed ~1,700 chars,
crushed entities 60 -> 15 (destroying the cheapest, most useful context — the
part that makes "who/what is X" answerable), then shipped 3x over budget anyway.

It now trims findings (and the timeline derived from them) first, entities last,
and never drops anything >= high.
"""

import sys
if "/app" not in sys.path:
    sys.path.insert(0, "/app")

import json  # noqa: E402

from services.fusion import render, severity as sev  # noqa: E402
from services.fusion.schema import FusionGraph, Entity, Finding  # noqa: E402


def _big_graph(n_low=120, n_high=6):
    """A payload dominated by low-severity findings, plus a few criticals that
    must survive any squeeze."""
    g = FusionGraph(case_id="c")
    for h in range(4):
        aid = f"asset:endpoint:C.h{h}"
        g.upsert(Entity(id=aid, type="asset", label=f"HOST{h}", attrs={"_assets": [aid]}))
    for i in range(80):                       # entity fill (the cheap context)
        aid = "asset:endpoint:C.h0"
        g.upsert(Entity(id=f"account:e{i}", type="account", label=f"user{i:03d}",
                        severity="informational", anomaly=100 - (i % 90),
                        attrs={"_assets": [aid]}))
    for i in range(n_high):
        g.add_finding(Finding(id=f"f_crit{i}", title=f"Critical detection {i}",
                              severity="critical", confidence="high",
                              summary="C" * 200, entity_ids=[], mitre=["T1059"],
                              asset_ids=["asset:endpoint:C.h0"],
                              ts=f"2026-01-01T00:{i:02d}:00Z"))
    for i in range(n_low):
        g.add_finding(Finding(id=f"f_low{i}", title=f"Low noise {i}", severity="low",
                              confidence="low", summary="L" * 200, entity_ids=[],
                              mitre=[], asset_ids=["asset:endpoint:C.h0"],
                              ts=f"2026-01-02T00:{i % 60:02d}:00Z"))
    # correlate.assemble sorts by severity; mirror that here since we build directly
    g.findings.sort(key=lambda f: (-sev.rank(f.severity), f.ts or "9999"))
    return g


def test_stepdown_trims_findings_not_entities():
    g = _big_graph()
    roomy = render.distilled(g, max_entities=60, budget_chars=None)
    tight = render.distilled(g, max_entities=60, budget_chars=20_000)

    assert len(tight["findings"]) < len(roomy["findings"]), \
        "the stepdown did not trim findings — the 94% of the payload"
    assert len(tight["top_entities"]) == len(roomy["top_entities"]), \
        ("entities were sacrificed while findings could still be trimmed; they are "
         "3.4% of the payload and the most useful context per char")


def test_high_and_critical_findings_are_never_trimmed():
    """More criticals than the stepdown floor, so a naive head-slice WOULD drop
    some. With 8 criticals and a floor of 20 the exemption is untestable — the
    slice keeps them by accident because they sort first. The real case has 116
    high/critical findings, so this is the shape that actually occurs."""
    # The trim must actually reach BELOW the critical count for the exemption to
    # be exercised: MAX_STEPDOWNS=2 only halves twice, so with 200 lows it stops
    # at ~57 and a head-slice would keep all criticals by luck. Sized so two
    # halvings land on the floor (_MIN_FINDINGS), which is < n_crit.
    n_crit = render._MIN_FINDINGS + 10          # 30
    g = _big_graph(n_low=40, n_high=n_crit)     # 70 -> 35 -> 20 (floor) < 30
    squeezed = render.distilled(g, max_entities=60, budget_chars=5_000)
    kept_crit = [f for f in squeezed["findings"] if sev.at_least(f["severity"], "high")]
    assert len(kept_crit) == n_crit, \
        (f"a budget squeeze dropped high/critical findings (kept {len(kept_crit)} of "
         f"{n_crit}) — token cost must never hide a critical detection")


def test_timeline_never_references_a_dropped_finding():
    """findings and timeline are the same set; trimming one must trim the other or
    the payload cites finding_ids it never sent."""
    g = _big_graph()
    p = render.distilled(g, max_entities=60, budget_chars=20_000)
    assert len(p["timeline"]) == len(p["findings"]), \
        f"timeline ({len(p['timeline'])}) and findings ({len(p['findings'])}) diverged"


def test_stepdown_actually_reduces_the_payload():
    g = _big_graph()
    roomy = len(json.dumps(render.distilled(g, max_entities=60, budget_chars=None)))
    tight = len(json.dumps(render.distilled(g, max_entities=60, budget_chars=20_000)))
    assert tight < roomy * 0.75, \
        (f"stepdown reclaimed too little ({roomy:,} -> {tight:,}); before this fix it "
         "reclaimed under 2% while claiming to enforce a budget")


def test_a_payload_under_budget_is_untouched():
    """No stepdown when it already fits — the report path must not regress."""
    g = _big_graph(n_low=5, n_high=2)
    free = render.distilled(g, max_entities=60, budget_chars=None)
    generous = render.distilled(g, max_entities=60, budget_chars=5_000_000)
    assert len(generous["findings"]) == len(free["findings"])
    assert len(generous["top_entities"]) == len(free["top_entities"])
