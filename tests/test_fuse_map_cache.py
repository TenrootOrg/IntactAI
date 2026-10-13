"""A Refusion does not re-read and re-map runs that have not changed.

Every Refusion re-parsed each member run's raw_results.json (~19 s for a 568 MB
run, ~234 s on a 108-host test case) although an imported run never changes. The
mapped result is now cached beside the file; these tests hold what must
invalidate it, and that a cache hit is indistinguishable from a fresh map.
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
from services.fusion import schema, store  # noqa: E402

ROWS = {"Windows.Hayabusa.Rules": [
    {"Timestamp": "2026-01-02T03:04:05Z", "Computer": "WS01.corp.local", "Channel": "Security",
     "EID": 4625, "Level": "high", "Title": "Password Spray", "RecordID": 7,
     "Details": "TgtUser: bob ¦ SrcIP: 203.0.113.9", "_hostname": "WS01", "_client_id": "C.1"}]}


class MapCache(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.fp = os.path.join(self.dir, "raw_results.json")
        with open(self.fp, "w") as f:
            json.dump(ROWS, f)
        self.det = {"output_dir": self.dir, "hostnames": {"C.1": "WS01"}}
        self.loads = 0

    def load(self):
        self.loads += 1
        return ROWS

    @staticmethod
    def mapper(rows):
        return [schema.Entity(id="asset:ws01", type="asset", label="WS01")], []

    def call(self, det=None, mapper=None):
        return store._cached_map(self.fp, det or self.det, self.load, mapper or self.mapper)

    def test_second_fuse_does_not_read_the_file(self):
        a, b = self.call(), self.call()
        self.assertEqual(1, self.loads)
        self.assertEqual([e.__dict__ for e in a[0]], [e.__dict__ for e in b[0]])

    def test_a_changed_file_is_mapped_again(self):
        self.call()
        st = os.stat(self.fp)
        os.utime(self.fp, ns=(st.st_atime_ns, st.st_mtime_ns + 1_000_000))
        self.call()
        self.assertEqual(2, self.loads)

    def test_new_hostnames_are_mapped_again(self):
        self.call()
        self.call(det=dict(self.det, hostnames={"C.1": "WS01-renamed"}))
        self.assertEqual(2, self.loads)

    def test_a_code_change_is_mapped_again(self):
        self.call()
        with mock.patch.object(store, "_code_hash", "another release"):
            self.call()
        self.assertEqual(2, self.loads)

    def test_a_corrupt_cache_is_a_miss_not_an_error(self):
        self.call()
        with open(os.path.join(self.dir, store.MAP_CACHE_NAME), "wb") as f:
            f.write(b"\x80garbage")
        ents, _ = self.call()
        self.assertEqual(2, self.loads)
        self.assertEqual("asset:ws01", ents[0].id)

    def test_an_unreadable_run_is_not_cached(self):
        self.load = lambda: {}                         # too big / unreadable right now
        self.call()
        self.assertFalse(os.path.exists(os.path.join(self.dir, store.MAP_CACHE_NAME)))

    def test_skipped_rows_are_still_reported_on_a_hit(self):
        def mapper(rows):
            schema.map_skip("Windows.Hayabusa.Rules", ValueError("bad row"))
            return self.mapper(rows)
        for _ in range(2):
            box = {}
            tok = schema._MAP_SKIPS.set(box)
            try:
                self.call(mapper=mapper)
            finally:
                schema._MAP_SKIPS.reset(tok)
            self.assertEqual(1, box["Windows.Hayabusa.Rules"][0])
        self.assertEqual(1, self.loads)


class RealRunUsesTheCache(unittest.TestCase):
    def test_contribution_for_run_hit_equals_fresh_map(self):
        d = tempfile.mkdtemp()
        with open(os.path.join(d, "raw_results.json"), "w") as f:
            json.dump(ROWS, f)
        run = {"run_id": "velociraptor_upload_cache_t", "automation_type": "velociraptor_upload",
               "details": {"output_dir": d, "hostnames": {"C.1": "WS01"}}}
        fresh = store._contribution_for_run(run)
        self.assertTrue(os.path.exists(os.path.join(d, store.MAP_CACHE_NAME)))
        with mock.patch.object(store, "_agentic_collected_data", side_effect=AssertionError("re-read")):
            hit = store._contribution_for_run(run)
        self.assertTrue(fresh[0])
        self.assertEqual([e.__dict__ for e in fresh[0]], [e.__dict__ for e in hit[0]])
        self.assertEqual([r.__dict__ for r in fresh[1]], [r.__dict__ for r in hit[1]])


if __name__ == "__main__":
    unittest.main()
