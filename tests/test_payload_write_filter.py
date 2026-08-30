"""Half the evidence store is artifacts fusion can never read.

Measured across this appliance's stored payloads: 581 MB of 1,158 MB is
artifacts SUPPORTED_ARTIFACTS excludes and always will. Two runs were 100%
waste — a 403 MB Windows.NTFS.MFT dump (354,831 rows) and a 172 MB run that is
almost entirely NTFS.MFT + Forensics.Usn. Both map to zero entities even when
admitted. Not writing them halves the store and halves the json.load cost that
OOM-killed the backend.

But raw_results.json is what every RE-fuse reads, so filtering is only safe
where Velociraptor still holds the data and Fetch can re-pull it. An
offline-collector upload has no such source — the zip is the only copy and is
usually gone after import. So the filter is OPT-IN: callers that can recover
ask for it, and anything that forgets keeps everything.
"""

import ast
import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND = os.path.join(ROOT, "modules/backend")
WRITER = os.path.join(BACKEND, "services/agentic/collectors/_base.py")

# path -> may it filter?  False means the data is unrecoverable once dropped.
CALLERS = {
    "services/agentic/pipeline/_runners.py": True,   # live collection
    "services/fusion/store.py": True,                # refetch re-snapshot
    "routes/dashboard_routes.py": True,              # the Fetch worker
    "routes/velociraptor_routes.py": True,           # adopt
    "routes/upload_routes.py": False,                # offline collector zip
}


def _calls(path):
    src = open(os.path.join(BACKEND, path), encoding="utf-8").read()
    return [l.strip() for l in src.splitlines()
            if "persist_pipeline_artifacts(" in l
            and not l.lstrip().startswith(("#", "def ", "from ", "import "))]


class TestTheFilterIsOptIn(unittest.TestCase):

    def test_the_default_keeps_everything(self):
        """A caller that forgets must not silently drop evidence."""
        src = open(WRITER, encoding="utf-8").read()
        sig = re.search(r"def persist_pipeline_artifacts\(([^)]*)\)", src).group(1)
        self.assertIn("fusion_only=False", sig.replace(" ", ""),
                      "the filter must default OFF")

    def test_a_failure_to_filter_still_writes(self):
        """The filter is an optimisation; losing it must never lose the write."""
        src = open(WRITER, encoding="utf-8").read()
        i = src.index("def persist_pipeline_artifacts")
        body = src[i:i + 3000]
        self.assertIn("except Exception", body)
        self.assertIn("storing everything", body)


class TestOnlyRecoverablePathsFilter(unittest.TestCase):

    def test_recoverable_callers_opt_in(self):
        for path, may in CALLERS.items():
            if not may:
                continue
            with self.subTest(path=path):
                calls = _calls(path)
                self.assertTrue(calls, f"no call found in {path}")
                for c in calls:
                    self.assertIn("fusion_only=True", c,
                                  f"{path} can re-fetch from Velociraptor and "
                                  f"should not store unfusable bulk")

    def test_the_offline_upload_keeps_everything(self):
        """The zip is the only copy. Filtering here makes excluded artifacts
        unrecoverable if the allowlist ever widens — and its own comment invites
        widening: 'add a line here when a new artifact gets a mapper'."""
        for c in _calls("routes/upload_routes.py"):
            self.assertNotIn("fusion_only=True", c,
                             "an offline-collector upload has no second source; "
                             "its payload must be stored whole")


class TestItFiltersWhatFusionCannotRead(unittest.TestCase):
    """Execute the real filter against the artifacts actually measured."""

    def setUp(self):
        """Code only. The docstring and comments NAME the wasted artifacts
        (Windows.NTFS.MFT, Forensics.Usn) while explaining the measurement, so a
        raw substring check matches the explanation instead of the logic."""
        src = open(WRITER, encoding="utf-8").read()
        fn = next(n for n in ast.parse(src).body
                  if isinstance(n, ast.FunctionDef)
                  and n.name == "persist_pipeline_artifacts")
        body = fn.body[1:] if (isinstance(fn.body[0], ast.Expr)
                               and isinstance(fn.body[0].value, ast.Constant)) else fn.body
        code = "\n".join(ast.get_source_segment(src, n) or "" for n in body)
        self.filter_src = "\n".join(l for l in code.splitlines()
                                     if not l.lstrip().startswith("#"))

    def test_the_bulk_artifacts_that_wasted_581mb_are_dropped(self):
        for name in ("Windows.NTFS.MFT", "Windows.Forensics.Usn",
                     "Generic.Forensic.SQLiteHunter/Chromium Browser History_Visits",
                     "Windows.Nirsoft.LastActivityView/Upload"):
            with self.subTest(artifact=name):
                self.assertNotIn(name, self.filter_src,
                                 "the filter must not special-case artifact names — "
                                 "it defers to SUPPORTED_ARTIFACTS")

    def test_it_defers_to_the_allowlist_rather_than_a_local_list(self):
        """A second copy of the rule would drift from the one fusion enforces."""
        self.assertIn("SUPPORTED_ARTIFACTS", self.filter_src)
        self.assertIn("_artifact_base", self.filter_src)

    def test_dropping_is_announced(self):
        """Silently discarding evidence is never acceptable, even when correct."""
        self.assertIn("not storing", self.filter_src)
        self.assertIn("Fetch re-pulls", self.filter_src)
