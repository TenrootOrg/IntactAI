"""False-positive canary on the REAL clean fixture.

The clean box's findings are vagrant PROVISIONING noise (log-cleared, driver-from-
temp, suspicious-folder service) — measured this session to be indistinguishable from
an attack by volume/diversity. With the clean box as its OWN baseline, a self-fuse must
subtract to silence. This test FAILS today (no baseline-subtraction) and turns GREEN at
Phase 3 — a permanent regression gate on the coordinated-activity false positive.

Run inside the backend container:
    python3 -m tests.fusion.test_baseline_fp
"""

import sys
if "/app" not in sys.path:
    sys.path.insert(0, "/app")

from services.fusion import calibrate, severity as sev  # noqa: E402

# GREEN since Phase 3 (baseline-subtraction). The clean box now subtracts to silence
# against its own baseline — the coordinated-activity false positive is regression-locked.
EXPECTED_RED = False


def test_clean_box_is_silent_against_its_own_baseline():
    baseline = calibrate.build_baseline("clean")
    g = calibrate.fuse("clean", baseline=baseline)
    high = [f for f in g.findings if sev.at_least(f.severity, "high")]
    assert not high, (
        f"clean box must be silent against its own baseline, but {len(high)} "
        f">=high finding(s) fired: {[f.title for f in high]}")


def test_no_coordinated_activity_finding_on_clean():
    baseline = calibrate.build_baseline("clean")
    g = calibrate.fuse("clean", baseline=baseline,
                       window={"start": "2026-06-16T00:00:00Z", "end": "2026-06-17T00:00:00Z"})
    coord = [f for f in g.findings if "coordinated" in f.title.lower()]
    assert not coord, f"provisioning must not read as coordinated activity: {[f.title for f in coord]}"


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    p = xf = hard = 0
    for fn in fns:
        try:
            fn(); p += 1; print(f"PASS {fn.__name__}")
        except AssertionError as e:
            if EXPECTED_RED:
                xf += 1; print(f"XFAIL {fn.__name__} (expected until Phase 3): {e}")
            else:
                hard += 1; print(f"FAIL {fn.__name__}: {e}")
    print(f"{p} passed, {xf} xfail, {hard} failed")
    sys.exit(1 if hard else 0)
