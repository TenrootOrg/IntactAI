"""The raw-vs-fusion token figure must not re-read the run's rows.

It loaded and re-serialized every raw_results.json for one headline number:
12 x 568 MB on a 108-host case, ~200 s of a 493 s fuse. The file is already the
JSON, so its size gives the same estimate.
"""
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (os.path.join(ROOT, "tests"), os.path.join(ROOT, "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import budget, store  # noqa: E402


class TokenFigureFromFileSize(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.rows = {"Windows.Hayabusa.Rules": [{"Title": f"rule {i}", "Details": "ä ¦ x" * i} for i in range(300)]}
        with open(os.path.join(self.dir, "raw_results.json"), "w") as f:
            json.dump(self.rows, f)
        self.run = {"run_id": "velociraptor_upload_test_x", "automation_type": "velociraptor_upload",
                    "details": {"output_dir": self.dir}}

    def test_same_figure_as_loading_it(self):
        self.assertEqual(budget.approx_tokens(self.rows), store._raw_payload_size(self.run))

    def test_the_rows_are_not_parsed(self):
        with mock.patch.object(store, "_agentic_collected_data", side_effect=AssertionError("parsed")):
            self.assertGreater(store._raw_payload_size(self.run), 0)

    def test_no_file_is_zero(self):
        self.run["details"] = {}
        self.assertEqual(0, store._raw_payload_size(self.run))


if __name__ == "__main__":
    unittest.main()
