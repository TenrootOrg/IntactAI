"""Host risk scoring is tier-dominant and fleet-relative.

Two operator-reported requirements:
  1. A 'critical' host can NEVER rank below a 'high' host, no matter how many
     high/medium findings the latter accumulates (the old additive score let
     3 highs (3x40) beat 1 critical (100)).
  2. Cross-host weighting is FLAT for small fleets and scales with prevalence
     (k affected / N total) only above FLEET_RELATIVE_MIN hosts — '2 of 100'
     must not weigh the same as '2 of 3'.

Guards services/fusion/correlate.py (_score_assets, _cross_host_factor).
"""

import sys
if "/app" not in sys.path:
    sys.path.insert(0, "/app")

from services.fusion import correlate  # noqa: E402
from services.fusion.schema import Entity, Finding, FusionGraph  # noqa: E402


def _asset(aid, severity):
    return Entity(id=aid, type="asset", label=aid.split(":")[-1], severity=severity)


def _finding(fid, severity, asset_ids, kind="single"):
    return Finding(id=fid, title=fid, severity=severity, confidence="high",
                   summary="", asset_ids=list(asset_ids), kind=kind)


def test_critical_host_outranks_high_host_with_many_findings():
    g = FusionGraph("case:test")
    A, B = "asset:endpoint:A", "asset:endpoint:B"
    g.upsert(_asset(A, "critical"))
    g.upsert(_asset(B, "high"))
    g.add_finding(_finding("c1", "critical", [A]))            # ONE critical
    for i in range(15):                                       # FIFTEEN highs
        g.add_finding(_finding(f"h{i}", "high", [B]))
    correlate._score_assets(g)
    ra = g.entities[A].attrs["risk_score"]
    rb = g.entities[B].attrs["risk_score"]
    assert ra > rb, f"critical host ({ra}) must outrank high host ({rb})"
    assert ra >= correlate._BAND_BASE["critical"], "critical host sits in the 80-100 band"
    assert rb < correlate._BAND_BASE["critical"], "a high host can never reach the critical band"
    assert 0 <= rb <= 100 and 0 <= ra <= 100, "scores are on a 0-100 scale"


def test_intensity_orders_hosts_within_the_same_tier():
    g = FusionGraph("case:test")
    A, B = "asset:endpoint:A", "asset:endpoint:B"
    g.upsert(_asset(A, "critical"))
    g.upsert(_asset(B, "critical"))
    g.add_finding(_finding("a1", "critical", [A]))
    g.add_finding(_finding("b1", "critical", [B]))
    g.add_finding(_finding("b2", "high", [B]))               # B has more going on
    correlate._score_assets(g)
    assert g.entities[B].attrs["risk_score"] > g.entities[A].attrs["risk_score"]


def test_cross_host_factor_is_flat_below_the_fleet_gate():
    f = _finding("x", "high", ["a", "b"], kind="cross_host")
    # small fleet -> historical flat x2 regardless of how many hosts it touches
    assert correlate._cross_host_factor(f, n_hosts=3) == correlate._CROSS_HOST_FLAT
    assert correlate._cross_host_factor(f, n_hosts=correlate.FLEET_RELATIVE_MIN - 1) == \
        correlate._CROSS_HOST_FLAT


def test_cross_host_factor_is_prevalence_relative_above_the_gate():
    big = correlate.FLEET_RELATIVE_MIN * 10
    sparse = _finding("x", "high", [f"h{i}" for i in range(2)], kind="cross_host")
    wide = _finding("y", "high", [f"h{i}" for i in range(big)], kind="cross_host")
    fs = correlate._cross_host_factor(sparse, n_hosts=big)
    fw = correlate._cross_host_factor(wide, n_hosts=big)
    assert 1.0 < fs < 1.1, f"2-of-{big} should be barely boosted, got {fs}"
    assert fw > fs, "widespread cross-host must weigh more than sparse in a big fleet"
    assert fw <= 2.0, "the boost stays bounded at the historical x2 ceiling"


def test_non_cross_host_finding_has_no_boost():
    f = _finding("s", "high", ["a"], kind="single")
    assert correlate._cross_host_factor(f, n_hosts=999) == 1.0


def test_adaptive_ref_spreads_a_heavy_breached_fleet():
    # 30 critical hosts, intensities far above the REF_FLOOR and widely varied.
    # A fixed floor would peg most at 100; the p95-adaptive REF must spread them.
    g = FusionGraph("case:test")
    for i in range(30):
        aid = f"asset:endpoint:H{i:02d}"
        g.upsert(_asset(aid, "critical"))
        g.add_finding(_finding(f"c{i}", "critical", [aid]))
        for j in range(5 + i * 3):                 # rising high counts -> rising intensity
            g.add_finding(_finding(f"h{i}_{j}", "high", [aid]))
    correlate._score_assets(g)
    scores = [g.entities[f"asset:endpoint:H{i:02d}"].attrs["risk_score"] for i in range(30)]
    assert scores.count(100) < 15, f"adaptive REF must not peg most hosts at 100 (got {scores.count(100)}/30)"
    assert len(set(scores)) >= 8, "scores must spread across the band, not collapse"
    intens = [g.entities[f"asset:endpoint:H{i:02d}"].attrs["risk_intensity"] for i in range(30)]
    assert len(set(intens)) == 30, "raw intensity is a strict tiebreaker for hosts that share a display score"


def test_small_calm_fleet_stays_absolute_via_floor():
    # p95 (130) < REF_FLOOR (900) -> REF=floor -> a mild worst-host is NOT inflated to ~100.
    g = FusionGraph("case:test")
    A = "asset:endpoint:A"
    g.upsert(_asset(A, "critical"))
    g.add_finding(_finding("c", "critical", [A]))
    for j in range(4):
        g.add_finding(_finding(f"h{j}", "high", [A]))   # intensity 50 + 80 = 130 << 900
    correlate._score_assets(g)
    assert g.entities[A].attrs["risk_score"] < 90, "calm fleet must stay absolute, not inflate to 100"
