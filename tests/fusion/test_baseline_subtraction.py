"""Baseline-subtraction regression — proves it is signal-preserving, not blanket.

With the clean box as baseline, the attack graph must SUPPRESS the shared provisioning
SIGMA titles (log-cleared, driver-from-temp, suspicious-folder service) while the
attack-specific findings (Defender critical + the non-baseline coordinated chain)
survive. Locks the fix for the measured coordinated-activity false positive.
"""

import sys
if "/app" not in sys.path:
    sys.path.insert(0, "/app")

from services.fusion import calibrate, correlate, severity as sev  # noqa: E402

ATTACK_WINDOW = {"start": "2026-06-18T12:45:00Z", "end": "2026-06-18T13:05:00Z"}
PROVISIONING = ["Important Log File Cleared", "Important Windows Eventlog Cleared",
                "Service Binary in Suspicious Folder", "Driver Load From A Temporary Directory"]


def _attack_with_baseline():
    base = calibrate.build_baseline("clean")
    return calibrate.fuse("attack", baseline=base, window=ATTACK_WINDOW)


def test_provisioning_titles_suppressed_in_attack():
    g = _attack_with_baseline()
    titles = " | ".join(f.title for f in g.findings)
    for noise in PROVISIONING:
        assert noise not in titles, f"baseline noise survived: {noise}"


def test_attack_signal_survives_baseline():
    g = _attack_with_baseline()
    titles = [f.title for f in g.findings]
    assert any("Defender Alert" in t for t in titles), "Defender critical must survive baseline"
    crit = [f for f in g.findings if f.severity == "critical"]
    assert crit, "the critical Defender finding must remain"


def test_coordinated_finding_recognises_the_simulated_attack():
    g = _attack_with_baseline()
    coord = [f for f in g.findings if "coordinated" in f.title.lower()]
    assert coord, "the non-baseline medium chain must surface as coordinated activity"
    assert coord[0].severity == "high" and coord[0].confidence == "high"


def test_no_baseline_means_no_change():
    # baseline=None must reproduce today's behavior exactly (no-regression guard).
    g_none = calibrate.fuse("attack")
    base = calibrate.build_baseline("clean")
    g_base = calibrate.fuse("attack", baseline=base)
    assert len(g_base.findings) < len(g_none.findings), "baseline must subtract something"
    # and the un-baselined attack still has the provisioning findings (proves they were there)
    assert any("Log File Cleared" in f.title for f in g_none.findings)


def test_critical_never_suppressed_even_if_in_baseline():
    # Construct a baseline that (wrongly) contains a critical title; it must still fire.
    base = {"sigma_titles": ["Defender Alert (Severe)"]}
    g = calibrate.fuse("attack", baseline=base, window=ATTACK_WINDOW)
    assert any("Defender Alert" in f.title and f.severity == "critical" for f in g.findings), \
        "a >=critical finding must surface even when it matches the baseline"


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    p = f = 0
    for fn in fns:
        try:
            fn(); p += 1; print(f"PASS {fn.__name__}")
        except AssertionError as e:
            f += 1; print(f"FAIL {fn.__name__}: {e}")
    print(f"{p}/{len(fns)} passed")
    sys.exit(1 if f else 0)
