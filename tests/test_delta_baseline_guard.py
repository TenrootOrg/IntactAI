"""A delta package is only valid for the baseline it was built against.

WHY
---
A delta carries only the modules whose pins moved between two consecutive
releases. Applied to a box on a DIFFERENT baseline, every module that moved in
the gap it skipped is simply absent -- and the run reports SUCCESS, because the
orchestrator can only skip modules it was handed. Measured on this repo's real
history for intact-20260803:

    vs intact-20260802 : elk 9.4.2 -> 9.4.4, backend_tusd v2.9.2 -> v2.10.0
    vs intact-20260615 : 14 modules moved

A 20260615 box given a delta built against 20260802 keeps a dozen stale modules
and is told it worked. The packager's own docstring has warned about this since
the first delta release; documenting a trap is not the same as closing it.

Full packages are always allowed -- they carry every module, and the apply side
already skips ones whose installed version matches, so a full package
self-deltas on arrival. That asymmetry is the point: full is the
correctness-bearing artifact, delta is only a bandwidth optimisation.

Run: docker exec intact_backend python /app/workdir/tests/test_delta_baseline_guard.py
"""

import os
import sys
import tempfile

if "/app" not in sys.path:
    sys.path.insert(0, "/app")

import services.upgrade.base as base  # noqa: E402

failures = []


def check(name, cond, detail=""):
    if cond:
        print(f"  PASS  {name}")
    else:
        failures.append(f"{name}: {detail}")
        print(f"  FAIL  {name}: {detail}")


def _box(version):
    """A WORKDIR whose VERSION says `version` (None = no VERSION file)."""
    d = tempfile.mkdtemp(prefix="baseline_")
    if version is not None:
        with open(os.path.join(d, "VERSION"), "w") as f:
            f.write(version + "\n")
    return d


def _guard(manifest, installed):
    d = _box(installed)
    prev = base.WORKDIR
    base.WORKDIR = d
    try:
        return base._reject_delta_on_wrong_baseline(
            manifest, logger=lambda m, l="info": None)
    finally:
        base.WORKDIR = prev


def _delta(baseline="intact-20260802"):
    return {"contents": {"package_kind": "delta", "delta_from": baseline,
                         "source_commit": "a" * 40}}


def test_a_delta_on_the_wrong_baseline_is_refused():
    """The whole point. 20260615 box, delta built against 20260802."""
    err = _guard(_delta("intact-20260802"), "intact-20260615")
    check("it refuses", err is not None, "the package was accepted")
    check("it names both versions",
          err and "intact-20260802" in err and "intact-20260615" in err, str(err))
    check("it explains the consequence",
          err and "stale" in err and "reported success" in err, str(err))
    check("it says what to use instead", err and "full package" in err, str(err))


def test_a_delta_on_the_right_baseline_is_allowed():
    check("a matching baseline proceeds",
          _guard(_delta("intact-20260802"), "intact-20260802") is None,
          "a valid delta was refused")


def test_a_full_package_is_allowed_from_any_baseline():
    """Full carries every module and the apply side skips the unchanged ones,
    so it self-deltas on arrival. It must never be gated on a baseline."""
    full = {"contents": {"package_kind": "full", "source_commit": "b" * 40}}
    for installed in ("intact-20260615", "intact-20260802", "intact-99999999"):
        check(f"full is allowed on {installed}",
              _guard(full, installed) is None, "full was refused")


def test_a_package_with_no_kind_is_treated_as_full():
    """Every package built before this field existed was full, so that is the
    truthful reading -- and refusing them would brick the upgrade path for
    anything already published."""
    check("a legacy manifest is allowed",
          _guard({"contents": {}}, "intact-20260615") is None,
          "an existing published package would now be refused")
    check("even with no contents block at all",
          _guard({}, "intact-20260615") is None, "refused")


def test_a_delta_that_forgot_its_baseline_is_refused():
    """package_kind: delta with no delta_from cannot be validated against
    anything. Fail closed -- the alternative is applying a subset to an unknown
    baseline, which is the exact failure this guard exists to prevent."""
    err = _guard({"contents": {"package_kind": "delta"}}, "intact-20260802")
    check("it refuses", err is not None, "accepted an unvalidatable delta")
    check("and says why", err and "delta_from" in err, str(err))


def test_a_box_with_no_version_file_cannot_take_a_delta():
    """A pre-VERSION install has no baseline to compare, so a delta cannot be
    shown to be safe. Fail closed rather than guessing."""
    err = _guard(_delta(), None)
    check("it refuses", err is not None, "accepted a delta on an unknown baseline")
    check("it says the baseline is unconfirmable",
          err and "VERSION" in err, str(err))


def test_the_guard_runs_inside_package_verification():
    """A guard nobody calls is a comment. It has to run during verification,
    BEFORE any module is touched."""
    import inspect
    import re
    src = inspect.getsource(base.verify_upgrade_package)
    src = re.sub(r'"""[\s\S]*?"""', '', src)
    src = "\n".join(l.split("#")[0] for l in src.splitlines())
    check("verify_upgrade_package calls the guard",
          "_reject_delta_on_wrong_baseline(" in src, "no live call site")
    check("and aborts on its error",
          '"success": False' in src, "the result is not acted on")


def test_the_installed_version_is_read_from_the_version_file():
    d = _box("intact-20260726")
    prev = base.WORKDIR
    base.WORKDIR = d
    try:
        check("it reads VERSION",
              base.installed_release_version() == "intact-20260726",
              base.installed_release_version())
    finally:
        base.WORKDIR = prev
    d2 = _box(None)
    base.WORKDIR = d2
    try:
        check("a missing VERSION yields empty, not an exception",
              base.installed_release_version() == "", "")
    finally:
        base.WORKDIR = prev


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            print(f"\n{name}")
            fn()
    print("\n" + ("FAILED: " + "; ".join(failures) if failures else "ALL PASSED"))
    sys.exit(1 if failures else 0)
