"""A green scenario that skipped the phases it exists to prove is worse than a red one.

Run 34018978136 reported TWELVE successes while every scenario silently skipped
seven phases -- kape, kape_gate, hunt, timesketch, volweb and fusion all
cascading from "activity did not run" -- and refuse-and-repeat additionally
skipped the downgrade half it is named after, because its tag resolved empty.
`run_end pass=15 fail=0 skip=7` was reported as success.

The skips were invisible precisely because they were CONSTANT: seven every time,
in every scenario, so nothing stood out and a genuinely new one would have looked
identical.
"""

import importlib.util
import io
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _mod(name):
    spec = importlib.util.spec_from_file_location(
        f"qa_{name}", os.path.join(ROOT, "qa", f"{name}.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


class _Res:
    def __init__(self, status, because=None):
        self.status, self.skipped_because = status, because


def _all_passing(cov, route):
    return {n: _Res("pass") for n in cov.required_for(route)}


class ARequiredPhaseMayNotSkip(unittest.TestCase):
    def setUp(self):
        self.cov = _mod("coverage")

    def test_a_clean_run_reports_nothing(self):
        gaps, unexpected = self.cov.audit(_all_passing(self.cov, "cli"), "cli")
        self.assertEqual((gaps, unexpected), ([], []))

    def test_a_skipped_required_phase_is_reported(self):
        results = _all_passing(self.cov, "cli")
        results["pipelines"] = _Res("skip", "activity did not run")
        gaps, _ = self.cov.audit(results, "cli")
        self.assertIn("pipelines", [n for n, _ in gaps])

    def test_a_phase_that_never_registered_is_not_a_pass(self):
        """The worst shape: a scenario the harness does not recognise registers
        no upgrade phases at all and reports a clean install."""
        results = _all_passing(self.cov, "cli")
        del results["upgrade"]
        gaps, _ = self.cov.audit(results, "cli")
        self.assertIn("upgrade", [n for n, _ in gaps])
        self.assertIn("never registered", [st for _, st in gaps])

    def test_every_upgrade_route_must_prove_the_upgrade_landed(self):
        for route in ("bootstrap", "cli", "ui_online", "ui_import"):
            self.assertIn("upgrade", self.cov.required_for(route), route)
            self.assertIn("verify_upgrade", self.cov.required_for(route), route)

    def test_the_linux_pipeline_is_required(self):
        """`pipelines` is what plants Linux evidence, collects it and FUSES it --
        the only place fusion is exercised in CI."""
        self.assertIn("pipelines", self.cov.required_for(""))


class AnUndocumentedSkipFailsTheRun(unittest.TestCase):
    def setUp(self):
        self.cov = _mod("coverage")

    def test_a_new_skip_is_unexpected(self):
        results = _all_passing(self.cov, "cli")
        results["some_new_phase"] = _Res("skip", "because=something broke")
        _, unexpected = self.cov.audit(results, "cli")
        self.assertEqual([n for n, _ in unexpected], ["some_new_phase"])

    def test_a_documented_gap_is_not_unexpected(self):
        results = _all_passing(self.cov, "cli")
        results["timesketch"] = _Res("skip", "needs the Windows endpoint")
        _, unexpected = self.cov.audit(results, "cli")
        self.assertEqual(unexpected, [])

    def test_every_known_gap_carries_a_reason(self):
        """The list is documentation of coverage we do NOT have; an entry with
        no reason is just a silenced failure."""
        for name, why in self.cov.KNOWN_GAPS.items():
            self.assertTrue(why and len(why) > 10, name)

    def test_a_known_gap_may_not_also_be_required(self):
        """Contradictory declarations would let a required phase skip silently."""
        for route in ("", "cli", "ui_online"):
            for name in self.cov.required_for(route):
                self.assertNotIn(name, self.cov.KNOWN_GAPS, name)

    def test_the_windows_chain_is_recorded_as_not_exercised(self):
        """Stated plainly because the workflow header claims otherwise."""
        for name in ("kape", "timesketch", "volweb"):
            self.assertIn(name, self.cov.KNOWN_GAPS)


class TheStrongestAssertionMustNotBeOptionalInCI(unittest.TestCase):
    """`Fusion: the planted evidence was detected` is the only check in the suite
    that proves the detection engine RECOGNISED something rather than merely
    built a graph. It is guarded by `cfg.plant_evidence`, which defaults to
    FALSE — and when it is off the check does not run, the phase still passes,
    and the remaining fusion checks fall back to `relationships > 0`, which the
    process tree satisfies on any Linux box, working or not.

    Operators may legitimately disable planting: it writes to /etc/cron.d and
    /etc/passwd. CI may not, and that is what this pins.
    """

    def _workflow(self):
        return io.open(os.path.join(ROOT, ".github/workflows/e2e.yml"),
                       encoding="utf-8").read()

    def test_ci_enables_evidence_planting(self):
        self.assertIn("QA_PLANT_EVIDENCE: '1'", self._workflow(),
                      "with this off the suite loses its primary detection "
                      "assertion and still reports green")

    def test_a_run_without_planting_says_so(self):
        src = io.open(os.path.join(ROOT, "qa/phases/pipelines.py"),
                      encoding="utf-8").read()
        self.assertIn("the detection assertion ran", src,
                      "a missing check is indistinguishable from a passing one; "
                      "the run must state that it did not assert")


class TheAuditMustNotFailOnItself(unittest.TestCase):
    """The audit runs INSIDE the report phase, so `report` has no status yet.
    Requiring it to have passed made the check fail on itself and reported
    "report (never registered)" on an otherwise clean run of 20 passing phases."""

    def setUp(self):
        self.cov = _mod("coverage")

    def test_report_is_not_required_of_itself(self):
        self.assertNotIn("report", self.cov.required_for("cli"))

    def test_a_phase_still_running_is_not_counted_as_missing(self):
        results = {n: _Res("pass") for n in self.cov.required_for("cli")}
        results["report"] = _Res(None)          # mid-flight, as it really is
        gaps, unexpected = self.cov.audit(results, "cli")
        self.assertEqual((gaps, unexpected), ([], []))

    def test_a_genuinely_absent_phase_is_still_caught(self):
        """The fix must not blunt the check it was protecting."""
        results = {n: _Res("pass") for n in self.cov.required_for("cli")}
        del results["pipelines"]
        gaps, _ = self.cov.audit(results, "cli")
        self.assertIn("pipelines", [n for n, _ in gaps])
