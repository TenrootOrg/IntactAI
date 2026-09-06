"""The e2e's failure annotations pointed at the wrong thing entirely.

The workflow reads results.json and posts a GitHub ::error for each failed
check. The loop was written correctly and then INDENTED WRONG: the print sat at
module level, outside both loops, so it ran exactly once on whatever `ph` and
`chk` were still bound when the loops finished -- the last check of the last
phase, pass or fail.

The visible symptom on every run was

    ##[error] report written expected=None actual=.../REPORT.md

which is a PASSING check. Meanwhile every genuinely failed check went
un-annotated. A red mark on a green check, and silence on the real ones.

This extracts the workflow's own embedded script and runs it, so the test cannot
drift from what CI actually executes.
"""

import io
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WF = os.path.join(ROOT, ".github/workflows/e2e.yml")

RESULTS = {
    "phases": [
        {"phase": "case_read", "checks": [
            {"name": "risk table ranks a host", "ok": True,
             "expected": ">0", "actual": 3},
            {"name": "identities were clustered", "ok": False,
             "expected": "list", "actual": "None"}]},
        {"phase": "purge_scan", "checks": [
            {"name": "no section reports zero", "ok": False,
             "expected": "bytes", "actual": "velociraptor scanned 0"}]},
        # LAST phase, LAST check, and it PASSES -- the exact shape that was
        # being posted as the run's only error.
        {"phase": "report", "checks": [
            {"name": "report written", "ok": True,
             "expected": None, "actual": "/tmp/REPORT.md"}]},
    ],
    "counts": {"pass": 2, "fail": 2, "error": 0, "skip": 1},
}


def _embedded_script():
    src = io.open(WF, encoding="utf-8").read()
    m = re.search(r'python3 - "\$RUN_DIR/results\.json" <<\'PY\'\n(.*?)\n          PY',
                  src, re.S)
    assert m, "the annotation step is not where this test expects it"
    return "\n".join(line[10:] for line in m.group(1).splitlines())


class AnnotationsMustNameTheChecksThatFailed(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="annot-")
        self.script = os.path.join(self.tmp, "annot.py")
        io.open(self.script, "w", encoding="utf-8").write(_embedded_script())
        self.results = os.path.join(self.tmp, "results.json")
        io.open(self.results, "w", encoding="utf-8").write(json.dumps(RESULTS))
        self.out = subprocess.run([sys.executable, self.script, self.results],
                                  capture_output=True, text=True, timeout=60).stdout

    def test_every_failed_check_is_annotated(self):
        self.assertIn("identities were clustered", self.out)
        self.assertIn("no section reports zero", self.out)

    def test_a_passing_check_is_never_annotated(self):
        self.assertNotIn("report written", self.out,
                         "a passing check posted as ::error — the indentation "
                         "bug is back")

    def test_one_annotation_per_failure_not_one_in_total(self):
        self.assertEqual(self.out.count("::error"), 2,
                         "the print must be INSIDE both loops")

    def test_each_annotation_names_its_phase(self):
        self.assertIn("title=case_read::", self.out)
        self.assertIn("title=purge_scan::", self.out)

    def test_the_verdict_notice_still_reports_the_counts(self):
        self.assertIn("2 passed, 2 failed, 0 errored, 1 skipped", self.out)
