"""A Refusion's re-snapshot never replaces collected raw data it could not read.

Fleet audit F1: _resnapshot_without_losing_rows merged freshly fetched fusion sources
over _agentic_collected_data(), which returns {} both for "no file" and for "too big to
load / unreadable". On a large hunt the merge then rewrote raw_results.json with only
the fetched sources -- every other collected artifact deleted, silently.
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
from services.fusion import store  # noqa: E402

FETCHED = {"Windows.Hayabusa.Rules": [{"Title": "new"}]}


class ReSnapshot(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.fp = os.path.join(self.dir, "raw_results.json")
        self.det = {"output_dir": self.dir}
        self.written = []

    def run_it(self, content=None, too_big=False):
        if content is not None:
            with open(self.fp, "w") as f:
                f.write(content)
        with mock.patch.object(store, "_payload_too_big", lambda fp, log=None: too_big), \
             mock.patch("services.agentic.collectors.persist_pipeline_artifacts",
                        lambda rid, data: self.written.append(data)):
            store._resnapshot_without_losing_rows("r1", self.det, FETCHED)

    def test_a_snapshot_too_big_to_load_is_not_rewritten(self):
        raw = json.dumps({"Windows.NTFS.MFT": [{"x": 1}], "Windows.Hayabusa.Rules": [{"Title": "old"}]})
        self.run_it(raw, too_big=True)
        self.assertEqual([], self.written)
        self.assertEqual(raw, open(self.fp).read())

    def test_an_unreadable_snapshot_is_not_rewritten(self):
        self.run_it("{not json", too_big=False)
        self.assertEqual([], self.written)

    def test_a_readable_snapshot_keeps_every_other_artifact(self):
        self.run_it(json.dumps({"Windows.NTFS.MFT": [{"x": 1}], "Windows.Hayabusa.Rules": [{"Title": "old"}]}))
        self.assertEqual(1, len(self.written))
        self.assertEqual([{"x": 1}], self.written[0]["Windows.NTFS.MFT"])
        self.assertEqual(FETCHED["Windows.Hayabusa.Rules"], self.written[0]["Windows.Hayabusa.Rules"])

    def test_no_snapshot_yet_writes_the_fetched_rows(self):
        self.run_it(None)
        self.assertEqual([FETCHED], self.written)


if __name__ == "__main__":
    unittest.main()
