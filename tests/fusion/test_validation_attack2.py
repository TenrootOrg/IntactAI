"""Real-data validation — the richer purple-team run (attack2.json) exercises the
new detection-linking + blind-spot typing on a REAL Velociraptor collection.

The attack: cmd.exe->svchost.exe masquerade, powershell->updater.exe rename, a
DLL-sideload bait (version.dll), a service + scheduled-task, domain recon, a download
cradle. Baseline = the clean box. Proves the new pipeline catches it with no false
positives (regression-locks the gains).
"""

import sys
if "/app" not in sys.path:
    sys.path.insert(0, "/app")

from services.fusion import calibrate, severity as sev  # noqa: E402

WINDOW = {"start": "2026-06-18T17:50:00Z", "end": "2026-06-18T18:20:00Z"}


def _g():
    base = calibrate.build_baseline("clean")
    return calibrate.fuse("attack2", baseline=base, window=WINDOW)


def test_masquerade_and_rename_recognized():
    titles = " | ".join(f.title for f in _g().findings)
    assert "Masquerading As SvcHost" in titles, "cmd->svchost.exe masquerade caught"
    assert "Renamed PowerShell" in titles or "Rename Of Highly Relevant Binaries" in titles


def test_dll_sideloading_blindspot_fires_on_real_data():
    g = _g()
    assert any("DLL sideloading" in f.title and "T1574" in f.mitre for f in g.findings), \
        "the new HijackLibs handler must produce a real DLL-sideload finding"


def test_service_persistence_caught_both_ways():
    titles = " | ".join(f.title for f in _g().findings)
    assert "New Service Creation" in titles or "Suspicious service" in titles


def test_coordinated_activity_and_defender_critical():
    g = _g()
    assert any(f.severity == "critical" and "Defender" in f.title for f in g.findings)
    assert any("coordinated" in f.title.lower() for f in g.findings), \
        "the non-baseline chain must surface as coordinated activity"


def test_detection_linking_connects_the_graph():
    """Detections attach to processes instead of orphaning.

    This asserted `>= 50`, a number calibrated before ingest-time filtering
    landed. `_g()` passes a 30-minute WINDOW: the mapper still emits 93
    event_about edges on this fixture, but only 20 survive the window — so the
    threshold was failing on a deliberate feature, not a regression.

    Assert the structural invariant the test is named for instead. The `all()`
    clause is the part with teeth: it catches edges pointing at entities that
    do not exist or are of the wrong type, which a bare count never could.
    """
    g = _g()
    proc_ids = {e.id for e in g.by_type("process")}
    ev_ids = {e.id for e in g.by_type("event")}
    ea = [r for r in g.relationships if r.kind == "event_about"]
    assert ea, "detections must be linked to processes (not orphan events)"
    assert all(r.src in proc_ids and r.dst in ev_ids for r in ea), \
        "every event_about must connect a real process to a real event"
    assert len(ea) >= 10, f"detection linking collapsed: only {len(ea)} edges"


def test_no_provisioning_false_positives():
    g = _g()
    for noise in ("Important Log File Cleared", "Important Windows Eventlog Cleared"):
        assert not any(noise in f.title for f in g.findings), f"baseline noise survived: {noise}"


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
