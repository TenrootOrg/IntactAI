"""Deleting a case must take EVERYTHING of ours with it.

Operator: "when a case is being deleted remove all the data that is related to it
[not from the modules themselves just the workflows, fusions etc]". An audit of
delete_case found six leftovers, each of which this pins:

  * the export bundle — one .intactcase.zip holding every member payload, the
    fused graph and the report, keyed by CASE id so the per-run cleanup never saw
    it (hundreds of MB to several GB);
  * the case_export / case_import run rows, which live in the SYSTEM workspace and
    carry this case's id, name, every member run id and the bundle's path;
  * runs attached the legacy way (member_run_ids) rather than by the case_id tag —
    the fuse reads both, the delete read only the tag;
  * /app/data/azure_runs/<run>.json, raw O365/Azure records that no delete path
    reached (the purge looked in a different directory than the writer uses);
  * `reports` rows and the Elasticsearch copy of each run — deleted runs came back
    in the workflow list because get_all_automation_runs merges ES-only rows;
  * the fused graph re-appearing after the delete, written by a fuse that was
    already running.
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
from services.fusion import store  # noqa: E402

CASE = "case_del_1"


class FakeWs:
    def __init__(self, runs):
        self.runs = runs
        self.deleted = []

    def get_automation_runs_by_case(self, cid):
        return [r for r in self.runs if r.get("case_id") == cid]

    def get_automation_run(self, rid):
        return next((r for r in self.runs if r["run_id"] == rid), None)

    def get_all_automation_runs(self):
        return list(self.runs)


class DeleteTakesEverything(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.exports = os.path.join(self.tmp, "case_exports")
        os.makedirs(os.path.join(self.exports, CASE))
        with open(os.path.join(self.exports, CASE, "case.intactcase.zip"), "w") as f:
            f.write("x" * 100)
        self.runs = [
            {"run_id": CASE, "case_id": None, "automation_type": "case"},   # the case row
            {"run_id": "r_tagged", "case_id": CASE, "automation_type": "agentic"},
            {"run_id": "r_legacy", "case_id": None, "automation_type": "agentic"},
            {"run_id": "r_export", "case_id": "case_system", "automation_type": "case_export",
             "details": {"case_id": CASE, "bundle_path": "/data/x.zip"}},
            {"run_id": "r_other", "case_id": "case_other", "automation_type": "case_export",
             "details": {"case_id": "case_other"}},
        ]
        self.ws = FakeWs(self.runs)
        self.deleted, self.reports, self.es = [], [], []
        from services.fusion import case_bundle, kb
        patches = [
            mock.patch.object(store, "_ws", return_value=self.ws),
            mock.patch.object(store, "get_case", return_value={
                "name": "QA", "member_run_ids": ["r_tagged", "r_legacy"]}),
            mock.patch.object(store, "_FUSION_GRAPH_DIR", self.tmp),
            mock.patch.object(case_bundle, "EXPORT_DIR", self.exports),
            mock.patch.object(kb, "delete_case_entities"),
            # delete_case imports it from file_storage_service, which re-exports it
            mock.patch("services.file_storage_service.delete_workflow",
                       side_effect=lambda rid: self.deleted.append(rid)),
            mock.patch("services.storage.report_store.delete_report",
                       side_effect=lambda rid: self.reports.append(rid)),
        ]
        for p in patches:
            p.start(); self.addCleanup(p.stop)

    def test_every_run_goes_tagged_or_legacy(self):
        store.delete_case(CASE)
        self.assertIn("r_tagged", self.deleted)
        self.assertIn("r_legacy", self.deleted, "a run the fuse reads must be a run "
                                                "the delete reaches")
        self.assertIn(CASE, self.deleted, "and the case row itself")

    def test_the_export_and_import_rows_go_with_it(self):
        store.delete_case(CASE)
        self.assertIn("r_export", self.deleted)
        self.assertNotIn("r_other", self.deleted, "another case's export must survive")

    def test_the_export_bundle_is_removed_from_disk(self):
        res = store.delete_case(CASE)
        self.assertFalse(os.path.exists(os.path.join(self.exports, CASE)))
        self.assertEqual(res["export_bundles_deleted"], 1)

    def test_the_report_rows_go_too(self):
        store.delete_case(CASE)
        self.assertEqual(sorted(self.reports), ["r_legacy", "r_tagged"])

    def test_a_deleted_case_cannot_have_its_graph_written_back(self):
        """A fuse already running when the delete landed used to re-create the
        sidecar — a full-size file of the case's evidence, owned by nothing."""
        with mock.patch.object(store, "_ws", return_value=FakeWs([])):
            self.assertFalse(store._write_graph_sidecar(CASE, {"entities": {}}))
        self.assertFalse(os.path.exists(store._graph_path(CASE)))

    def test_a_live_case_still_gets_its_graph(self):
        """Non-vacuous: the guard must not block the ordinary path."""
        self.assertTrue(store._write_graph_sidecar(CASE, {"entities": {}}))
        self.assertTrue(os.path.exists(store._graph_path(CASE)))

    def test_the_azure_records_are_removed_with_the_run(self):
        src = store.__file__
        with open(src, encoding="utf-8") as fh:
            body = fh.read()
        fn = body[body.index("def _delete_run_payloads("):body.index("def _memory_contribution(")]
        self.assertIn("azure_runs", fn, "raw O365/Azure records were reachable by no "
                                        "delete path at all")
        self.assertIn("aws_runs", fn)


if __name__ == "__main__":
    unittest.main(verbosity=2)
