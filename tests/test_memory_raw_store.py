"""One folder for every kept memory image (raw_memory/), dated, no duplicates.

Reported 2026-09-28: the same MemoryDump_Lab6.raw was stored twice — each
browser upload got its own _uploads/<id>/ — and acquisitions sat at the top of
the volume. Every image now lands in raw_memory/, named by the date it arrived;
an identical one is not stored again; the operator can remove images.
"""
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

for _p in (os.path.dirname(os.path.abspath(__file__)),
           os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.memory import raw_store  # noqa: E402

MB = 1024 * 1024


class Store(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)

    def img(self, rel, fill=b"A", size=2 * MB):
        p = os.path.join(self.d, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as fh:
            fh.write(fill * size)
        return p

    def test_an_upload_moves_into_the_folder_dated_and_its_staging_dir_goes(self):
        src = self.img("_uploads/abc/MemoryDump_Lab6.raw")
        new, dup = raw_store.adopt(src, source="upload", original_name="MemoryDump_Lab6.raw",
                                   when="2026-09-23T08:24:25Z", origin={"client_name": "VIRUS-PC"},
                                   dumps_dir=self.d)
        self.assertFalse(dup)
        self.assertEqual(os.path.basename(new), "2026-09-23_082425__MemoryDump_Lab6.raw")
        self.assertEqual(os.path.dirname(new), os.path.join(self.d, "raw_memory"))
        self.assertFalse(os.path.exists(os.path.join(self.d, "_uploads", "abc")))
        e = raw_store.listing(self.d)[0]
        self.assertEqual((e["source"], e["origin"]["client_name"]), ("upload", "VIRUS-PC"))

    def test_the_same_image_twice_is_stored_once_and_marked_shared(self):
        first, _ = raw_store.adopt(self.img("_uploads/a/m.raw"), source="upload", dumps_dir=self.d)
        again, dup = raw_store.adopt(self.img("_uploads/b/m.raw"), source="upload", dumps_dir=self.d)
        self.assertTrue(dup)
        self.assertEqual(again, first)
        self.assertEqual(len(raw_store.listing(self.d)), 1)
        self.assertEqual(raw_store.listing(self.d)[0]["also_arrived"], 1)
        self.assertTrue(raw_store.is_shared(first, self.d))
        self.assertFalse(os.path.exists(os.path.join(self.d, "_uploads", "b")))

    def test_same_size_but_different_content_are_both_kept(self):
        raw_store.adopt(self.img("_uploads/a/m.raw", b"A"), source="upload", dumps_dir=self.d)
        _, dup = raw_store.adopt(self.img("_uploads/b/m.raw", b"B"), source="upload", dumps_dir=self.d)
        self.assertFalse(dup)
        self.assertEqual(len(raw_store.listing(self.d)), 2)

    def test_an_image_already_in_the_folder_stays_where_it_is(self):
        p, _ = raw_store.adopt(self.img("x.raw"), source="velociraptor", dumps_dir=self.d)
        self.assertEqual(raw_store.adopt(p, source="upload", dumps_dir=self.d), (p, False))

    def test_a_file_off_the_dumps_volume_is_left_where_it_is(self):
        other = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, other, ignore_errors=True)
        p = os.path.join(other, "m.raw")
        with open(p, "wb") as fh:
            fh.write(b"A" * 2 * MB)
        self.assertEqual(raw_store.adopt(p, source="upload", dumps_dir=self.d), (p, False))
        self.assertTrue(os.path.exists(p))

    def test_remove_and_its_guards(self):
        p, _ = raw_store.adopt(self.img("x.raw"), source="velociraptor", dumps_dir=self.d)
        name = os.path.basename(p)
        for bad in ("../x.raw", "index.json", "", "nope.raw"):
            self.assertIn("error", raw_store.remove(bad, self.d), bad)
        self.assertEqual(raw_store.remove(name, self.d, by="analyst1")["removed"], name)
        self.assertFalse(os.path.exists(p))
        self.assertEqual(raw_store.listing(self.d), [])
        # removing evidence leaves a trace (Lab6 vanished with none, 2026-09-28)
        import json
        with open(os.path.join(self.d, "raw_memory", "removed.log")) as fh:
            rec = json.loads(fh.read().splitlines()[-1])
        self.assertEqual((rec["name"], rec["by"]), (name, "analyst1"))
        self.assertIn("error", raw_store.remove("removed.log", self.d))

    def test_migration_moves_the_old_places_skips_busy_and_small_files(self):
        self.img("_uploads/c06/MemoryDump_Lab6.raw")
        self.img("_uploads/6bd/MemoryDump_Lab6.raw")                  # the same dump again
        self.img("DESKTOP-566AT85-F.DAPQED.raw", b"D", 3 * MB)
        busy = self.img("_uploads/zzz/in-use.raw", b"Z")
        self.img("tiny.txt", b"t", 10)
        moved = raw_store.migrate({}, in_use=[busy], dumps_dir=self.d)
        self.assertEqual(len(moved), 3)
        self.assertEqual(sum(1 for *_x, dup in moved if dup), 1)
        self.assertEqual(sorted(e["original_name"] for e in raw_store.listing(self.d)),
                         ["DESKTOP-566AT85-F.DAPQED.raw", "MemoryDump_Lab6.raw"])
        self.assertTrue(os.path.exists(busy))                          # a running run's image is left alone
        self.assertEqual(raw_store.migrate({}, in_use=[busy], dumps_dir=self.d), [])   # once only


class Cleanup(unittest.TestCase):
    def test_a_run_never_deletes_an_image_another_run_arrived_with(self):
        from services.memory import cleanup
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        src = os.path.join(d, "a.raw")
        with open(src, "wb") as fh:
            fh.write(b"A" * 2 * MB)
        kept, _ = raw_store.adopt(src, source="upload", dumps_dir=d)
        src2 = os.path.join(d, "b.raw")
        with open(src2, "wb") as fh:
            fh.write(b"A" * 2 * MB)
        raw_store.adopt(src2, source="upload", dumps_dir=d)
        with mock.patch.object(raw_store, "is_shared", lambda p, dumps_dir=d: raw_store._load(d).get(
                os.path.basename(p), {}).get("shared", False)):
            cleanup.cleanup_after_run(client_id=None, flow_id=None, host_path=kept, evidence_id=None,
                                      evidence_filename=None, volweb_client=None)
        self.assertTrue(os.path.exists(kept))


class OnePathForBothArrivals(unittest.TestCase):
    """An acquired image and an uploaded one take the SAME path after arrival:
    into raw_memory/, registered with VolWeb where it actually is. The acquire
    branch had its own copy and registered the old top-level name after the
    image had moved — memory_1790581789967 failed on it (2026-09-28)."""

    def run_pipeline(self, *, upload, client_name="DESKTOP-3LRFS8Q"):
        from services.memory import pipeline as pm
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        registered = []

        class Client:
            def __init__(self, **_kw): pass
            def ensure_case(self, _n): return 1
            def register_existing_file(self, rel, **_kw):
                assert os.path.isfile(os.path.join(d, rel)), f"VolWeb told to read a missing file: {rel}"
                registered.append(rel)
                return 7
            def upload_evidence(self, *_a, **_k): raise AssertionError("an image on the volume is never uploaded")
            def get_evidence(self, _i): return {"name": "x"}
            def stage_media_dir(self, _i): return None
            def yarascan_history(self, _i): return []
            def list_plugins(self, _i): return []
            def fetch_plugin(self, *_a, **_k): return None
            def trigger_extraction(self, *_a): return "T"
            def wait_for_plugin_results(self, *_a, **_k): return ({}, True)
            def harvest_symbols(self): return 0

        def fake_acquire(client_id, dumps_dir, **_kw):
            p = os.path.join(dumps_dir, "DESKTOP-3LRFS8Q-F.DAT1O9TNB5BD2.raw")
            with open(p, "wb") as fh:
                fh.write(b"M" * 2 * MB)
            return {"flow_id": "F.DAT1O9TNB5BD2", "host_path": p, "hostname": "DESKTOP-3LRFS8Q",
                    "size_bytes": 2 * MB, "shared_volume": True,
                    "shared_basename": "DESKTOP-3LRFS8Q-F.DAT1O9TNB5BD2.raw"}
        up = None
        if upload:
            up = os.path.join(d, "_uploads", "abc", "MemoryDump_Lab6.raw")
            os.makedirs(os.path.dirname(up))
            with open(up, "wb") as fh:
                fh.write(b"U" * 2 * MB)
        fakes = {"add_log_to_run": lambda *a, **k: None, "update_run_status": lambda *a, **k: None,
                 "mutate_run_details": lambda *a, **k: None, "register_cleanup": lambda *a, **k: None,
                 "unregister_cancel": lambda *a, **k: None, "cleanup_after_run": lambda **k: None,
                 "register_cancel_event": lambda _r: type("E", (), {"is_set": staticmethod(lambda: False)})(),
                 "acquire_memory_dump": fake_acquire, "_estimate_client_memory_bytes": lambda _c: 0,
                 "_disk_preflight": lambda *a, **k: None, "VolWebClient": Client}
        saved = {k: getattr(pm, k) for k in fakes}
        for k, v in fakes.items():
            setattr(pm, k, v)
        try:
            pm.run_memory_pipeline(run_id="r1", client_id="C.1", client_name=client_name,
                                   mode="plugin", dumps_dir=d, from_upload_path=up, case_name="c")
        finally:
            for k, v in saved.items():
                setattr(pm, k, v)
        return d, registered

    def test_an_acquisition_is_registered_where_the_image_is_now(self):
        d, registered = self.run_pipeline(upload=False)
        self.assertEqual(len(registered), 1, "the run never reached VolWeb")
        self.assertRegex(registered[0], r"^raw_memory/\d{4}-\d\d-\d\d_\d{6}__DESKTOP-3LRFS8Q-F\.DAT1O9TNB5BD2\.raw$")
        self.assertEqual([e["origin"]["client_name"] for e in raw_store.listing(d)], ["DESKTOP-3LRFS8Q"])

    def test_a_run_started_without_the_hostname_is_named_after_the_host(self):
        # "Memory (plugin) — C.002c28886e7feff2" (2026-09-28): the page's client
        # lookup came back empty; Velociraptor reports the hostname anyway.
        from services import workflow_service
        renamed = []
        with mock.patch.object(workflow_service, "rename_run", lambda rid, n: renamed.append(n)):
            d, registered = self.run_pipeline(upload=False, client_name=None)
        self.assertEqual(renamed, ["Memory (plugin) — DESKTOP-3LRFS8Q"])
        self.assertRegex(registered[0], r"__DESKTOP-3LRFS8Q-F\.DAT1O9TNB5BD2\.raw$")

    def test_an_upload_takes_the_same_path(self):
        d, registered = self.run_pipeline(upload=True)
        self.assertRegex(registered[0], r"^raw_memory/.*__MemoryDump_Lab6\.raw$")
        self.assertEqual([e["source"] for e in raw_store.listing(d)], ["upload"])


if __name__ == "__main__":
    unittest.main()
