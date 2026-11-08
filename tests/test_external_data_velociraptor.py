"""A Velociraptor offline collection added under Case Analysis -> External data is
recognised and imported like Velociraptor -> Offline collection -> Import.

QA 2026-11-08: External data read the collection's zip as generic logs ("Other
logs", 0 rows, sent to the model as text). It now goes through the import's own
path (import into Velociraptor, then fuse) on a velociraptor_upload run, and the
case keeps its own copy of the file.
"""
import io
import os
import shutil
import sys
import tempfile
import threading
import unittest
import zipfile
from unittest import mock

_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (_HERE, os.path.join(os.path.dirname(_HERE), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services import workflow_service  # noqa: E402
from services.fusion import case_files, external_logs, store  # noqa: E402


def _zip(*names):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for n in names:
            zf.writestr(n, "{}")
    return buf.getvalue()


COLLECTION = _zip("collection_context.json", "client_info.json", "results/Windows.System.Pslist.json")
ENCRYPTED = _zip("data.zip", "metadata.json")
OTHER_ZIP = _zip("readme.txt", "export.csv")


class Recognise(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def path(self, data):
        p = os.path.join(self.tmp, "f")
        with open(p, "wb") as f:
            f.write(data)
        return p

    def test_collections_plain_and_encrypted(self):
        self.assertTrue(case_files.is_velociraptor_collection(self.path(COLLECTION)))
        self.assertTrue(case_files.is_velociraptor_collection(self.path(ENCRYPTED)))

    def test_other_files_are_not(self):
        self.assertFalse(case_files.is_velociraptor_collection(self.path(OTHER_ZIP)))
        self.assertFalse(case_files.is_velociraptor_collection(self.path(b"ts,host\n1,a\n")))


class AddAsExternalData(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.d = {"name": "qa"}

        def mut(cid, field, fn):
            self.d[field] = fn(self.d.get(field) or [])
        self.velo = mock.Mock(return_value="velociraptor_upload_1")
        self.logs = mock.Mock(return_value="external_log_1")
        for t, a, v in ((case_files, "DATA_DIR", self.tmp), (store, "get_case", lambda cid: self.d),
                        (store, "_mutate_list_field", mut), (store, "log_case_event", mock.Mock()),
                        (store, "_report_behind", mock.Mock()),
                        (case_files, "_start_velociraptor_import", self.velo),
                        (external_logs, "start", self.logs),
                        (workflow_service, "get_automation_run", lambda *a, **k: {})):
            p = mock.patch.object(t, a, v)
            p.start()
            self.addCleanup(p.stop)

    def add(self, name, data, data_type="auto"):
        return case_files.add("c1", io.BytesIO(data), name, name="x", description="y", data_type=data_type)

    def test_a_collection_goes_to_the_velociraptor_import_whatever_type_was_picked(self):
        for dt in ("auto", "other", "siem"):
            item = self.add("Collection-HOST1.zip", COLLECTION, dt)
            self.assertEqual((item["data_type"], item["source"], item["run_id"]),
                             ("velociraptor", "velociraptor", "velociraptor_upload_1"))
        self.assertEqual(3, self.velo.call_count)
        self.logs.assert_not_called()

    def test_log_data_and_notes_keep_their_own_path(self):
        self.assertEqual("external_log_1", self.add("fw.csv", b"ts,src\n1,a\n")["run_id"])
        self.assertEqual("external_log_1", self.add("other.zip", OTHER_ZIP)["run_id"])
        self.add("chat.zip", COLLECTION, "notes")          # notes are never a collection
        self.assertEqual(3, self.logs.call_count)
        self.velo.assert_not_called()

    def test_the_report_names_it(self):
        self.d["case_files"] = [{"id": "a" * 12, "name": "HOST1", "file_name": "c.zip", "data_type": "velociraptor",
                                 "ai": True, "run_id": "r", "sha256": "s"}]
        with mock.patch.object(case_files, "with_log_status", lambda items: [
                dict(x, log={"status": "completed", "rows": 1200, "artifact_count": 7}) for x in items]):
            md = case_files.with_data_sources("# R\n\n## Findings\n- x\n", self.d)
        self.assertIn("Velociraptor offline collection · 1,200 row(s) from 7 artifact(s)", md)


class BigCollectionsUploadedStraightIn(unittest.TestCase):
    """Over 100 MB a collection goes through the Velociraptor page's resumable
    upload; the tus hook lists it under External data with no stored copy."""
    def test_listed_with_its_run_and_no_file(self):
        d = {"name": "qa"}

        def mut(cid, field, fn):
            d[field] = fn(d.get(field) or [])
        with mock.patch.object(store, "get_case", lambda cid: d), \
                mock.patch.object(store, "_mutate_list_field", mut), \
                mock.patch.object(store, "log_case_event", mock.Mock()), \
                mock.patch.object(store, "_report_behind", mock.Mock()):
            case_files.add_velociraptor_upload("c1", "velociraptor_upload_9", "HOST2", "big one",
                                               "Collection-HOST2.zip", 3_000_000_000)
        it = case_files.listing(d)[0]
        self.assertEqual(("velociraptor", "velociraptor_upload_9", False, True, "velociraptor"),
                         (it["data_type"], it["run_id"], it["stored"], it["ai"], it["source"]))
        self.assertIsNone(case_files.path_of("c1", it["id"]))

    def test_stored_items_say_so(self):
        it = case_files.listing({"case_files": [{"id": "0123456789ab", "name": "x"}]})[0]
        self.assertTrue(it["stored"])


class ImportKeepsTheEvidenceFile(unittest.TestCase):
    def test_the_importer_gets_a_link_and_the_case_keeps_the_file(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        path = os.path.join(tmp, "abcdef012345")
        with open(path, "wb") as f:
            f.write(COLLECTION)
        seen, done = {}, threading.Event()

        def fake_import(p, original_filename, run_id, password=None):
            seen.update(path=p, name=original_filename, run=run_id, exists=os.path.exists(p))
            os.remove(p)                                   # the real importer deletes its input
            done.set()
        # routes/ needs Flask, which the test run does not install: a stand-in module.
        import types
        upload_routes = types.ModuleType("routes.upload_routes")
        upload_routes.import_offline_collection = None
        routes_pkg = types.ModuleType("routes")
        routes_pkg.upload_routes = upload_routes
        mods = mock.patch.dict(sys.modules, {"routes": routes_pkg, "routes.upload_routes": upload_routes})
        mods.start()
        self.addCleanup(mods.stop)
        created = {}
        with mock.patch.object(workflow_service, "create_automation_run",
                               lambda t, n, details=None, case_id=None: created.update(t=t, case=case_id,
                                                                                        det=details) or "vr_1"), \
                mock.patch.object(workflow_service, "add_log_to_run", mock.Mock()), \
                mock.patch.object(workflow_service, "update_run_status", mock.Mock()), \
                mock.patch.object(upload_routes, "import_offline_collection", fake_import):
            rid = case_files._start_velociraptor_import(
                "c1", {"name": "HOST1", "file_name": "Collection-HOST1.zip", "id": "abcdef012345", "size": 9}, path)
            self.assertTrue(done.wait(5))
        self.assertEqual(("vr_1", "velociraptor_upload", "c1"), (rid, created["t"], created["case"]))
        self.assertTrue(created["det"]["use_in_analysis"])
        self.assertEqual(("Collection-HOST1.zip", True), (seen["name"], seen["exists"]))
        self.assertNotEqual(path, seen["path"])
        self.assertTrue(os.path.exists(path), "the case's evidence copy must survive the import")


class UseInAnalysisSwitch(unittest.TestCase):
    def test_switched_out_runs_add_nothing_to_the_fuse(self):
        run = {"automation_type": "velociraptor_upload", "run_id": "r", "details": {"use_in_analysis": False}}
        self.assertEqual(([], []), store._contribution_for_run(run))


if __name__ == "__main__":
    unittest.main()
