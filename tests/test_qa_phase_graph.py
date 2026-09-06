"""Every phase must be registered before the phases that need it.

The runner walks phases in REGISTRATION ORDER and skips any whose `needs` have
not passed yet. So a phase that names a dependency registered after it is not a
crash -- it is a permanent silent skip, which is exactly the failure mode this
whole batch of work exists to remove: `hunt` has been skipping on every Linux
run since it was written, because it needs `kape_gate` from a Windows chain that
never runs here.

This registers the real phase modules against a stub runner, so it checks the
actual registration code rather than a second copy of the phase list.
"""

import os
import sys
import types
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
QA = os.path.join(ROOT, "qa")


class _Tl:
    def __getattr__(self, _n):
        return lambda *a, **k: None


class _Ctx:
    def __init__(self):
        self.tl = _Tl()
        self.results = {}
        self.run_dir = "/tmp/qa-stub"

    def get(self, *_a, **_k):
        return None

    def set(self, **_k):
        pass

    def check(self, *_a, **_k):
        pass


class _Runner:
    def __init__(self):
        self.ctx = _Ctx()
        self.order = []

    def phase(self, name, _title, needs=(), critical=False, always=False):
        self.order.append((name, tuple(needs)))
        return lambda fn: fn


class _Cfg:
    """Every attribute answers something plausible; register() only reads
    config to decide what to register, and we want it all registered."""
    scenario = "cli-upgrade"
    repo_dir = "/mnt/intact"
    hop_via = ""
    downgrade_tag = ""
    upgrade_to = "intact-20260903"
    plant_evidence = True
    sudo_password = ""

    def __getattr__(self, _n):
        return ""

    def timeout(self, _stage, default=30):
        return default

    def secrets(self):
        return []


def _register_all():
    sys.path.insert(0, QA)
    r = _Runner()
    cfg = _Cfg()
    from phases import analysis, hunts, maintenance, memory_plumbing
    for mod in (hunts, memory_plumbing, analysis, maintenance):
        mod.register(r, cfg)
    return r


class ThePhaseGraphMustResolve(unittest.TestCase):
    """Only the phases this batch added — the pre-existing ones register
    conditionally on config this stub cannot honestly supply."""

    def setUp(self):
        self.r = _register_all()
        self.names = [n for n, _ in self.r.order]

    def test_every_new_phase_registered(self):
        for expected in ("hunt_linux", "memory_plumbing", "case_read",
                         "case_report", "case_pdf", "case_mutations",
                         "purge_scan", "purge_run"):
            self.assertIn(expected, self.names)

    def test_no_phase_is_registered_twice(self):
        self.assertEqual(len(self.names), len(set(self.names)), self.names)

    def test_internal_dependencies_come_first(self):
        """A need registered later than its dependent is a permanent skip."""
        seen = set()
        for name, needs in self.r.order:
            for need in needs:
                if need in self.names:          # internal to this batch
                    self.assertIn(need, seen,
                                  f"{name} needs {need}, which registers after it")
            seen.add(name)

    def test_external_dependencies_are_real_phases(self):
        """A typo'd need never resolves and the phase skips forever."""
        known_external = {"install", "auth", "enrol_linux", "features",
                          "pipelines", "collect", "report"}
        for name, needs in self.r.order:
            for need in needs:
                self.assertTrue(need in self.names or need in known_external,
                                f"{name} needs unknown phase {need!r}")

    def test_purge_run_is_last(self):
        """It deletes the evidence every other phase asserts on."""
        self.assertEqual(self.names[-1], "purge_run", self.names)

    def test_the_coverage_floor_lists_every_new_phase(self):
        """A phase absent from the floor can skip silently, which is the bug."""
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "qa_cov", os.path.join(QA, "coverage.py"))
        cov = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cov)
        required = set(cov.required_for("cli"))
        for name in self.names:
            self.assertIn(name, required,
                          f"{name} is not in the coverage floor, so a silent "
                          f"skip would still pass")
