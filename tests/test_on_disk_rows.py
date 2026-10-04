"""A detection that FOUND FILES on disk says so (QA TASK-12666).

"MFT: Erasing Tools fired 4× on DESKTOP" read as "sdelete ran four times": it only
meant four sdelete files sat on the disk, dated by when each was written there.
That artifact is no longer fused at all -- a tool on disk is not activity, so it
has no place on the Timeline or in the report -- and is gone from the agentic
blueprint. Rows still built from files on disk (ISE autosave) name their files,
say the time is the file's own, say whether anything collected shows them
running, and each file takes its own verdict.
"""
import os
import sys
import unittest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (os.path.dirname(os.path.abspath(__file__)), os.path.join(_ROOT, "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import correlate, store  # noqa: E402
from services.fusion.mappers.agentic import SUPPORTED_ARTIFACTS, map_agentic  # noqa: E402

ERASING = "DetectRaptor.Windows.Detection.MFT.Erasing.Tools"
ISE = "DetectRaptor.Windows.Detection.Powershell.ISEAutoSave"
RULE = "T1059.001-Mimikatz Execution via PowerShell"
PATHS = [r"C:\Users\a\ise\dump.exe", r"C:\Users\b\ise\dump.exe", r"C:\Users\c\ise\run64.exe"]


def _ise(path):
    return {"Detection": {"Name": RULE}, "FileInfo": {"OSPath": path, "Mtime": "2025-12-05T02:47:30Z"},
            "_hostname": "HOSTA", "_client_id": "C.HOSTA"}


def _fuse(extra=None):
    ents, rels = map_agentic({ISE: [_ise(p) for p in PATHS], **(extra or {})}, run_id="r1")
    g = correlate.assemble("c", [(ents, rels)], ["r1"])
    return next(f for f in g.findings if RULE in f.title)


class ErasingToolsIsNotFused(unittest.TestCase):
    def test_not_supported_and_dropped_at_ingest(self):
        self.assertNotIn(ERASING.lower(), SUPPORTED_ARTIFACTS)
        self.assertEqual(store._filter_supported({ERASING: [{"x": 1}], ISE: [{"y": 1}]}), {ISE: [{"y": 1}]})

    def test_no_finding_even_if_handed_to_the_mapper(self):
        row = {"Detection": {"Name": "Erasing Tools", "Criticality": "Medium"}, "OSPath": r"C:\sdelete.exe",
               "FNTimestamps": {"Created0x30": "2025-12-05T02:47:30Z"}, "_hostname": "HOSTA", "_client_id": "C.HOSTA"}
        ents, rels = map_agentic({ERASING: [row]}, run_id="r1")
        g = correlate.assemble("c", [(ents, rels)], ["r1"])
        self.assertEqual([f.title for f in g.findings if "Erasing" in f.title], [])

    def test_not_in_the_agentic_blueprint(self):
        with open(os.path.join(_ROOT, "modules/backend/config/default_blueprints.yaml"), encoding="utf-8") as fh:
            y = fh.read()
        agentic = y[y.index('name: "Velociraptor Agentic QuickWins Windows"'):y.index('name: "Velociraptor Agentic QuickWins Linux"')]
        self.assertIn("DetectRaptor.Windows.Detection.MFT\n", agentic)
        self.assertNotIn("Erasing.Tools", agentic)


class OnDisk(unittest.TestCase):
    def test_the_row_names_its_files_and_does_not_say_it_ran(self):
        f = _fuse()
        self.assertIn("(3 files: dump.exe, dump.exe, run64.exe) on", f.title)
        self.assertIn("3 files found on disk", f.summary)
        self.assertIn("the file's own timestamp", f.summary)
        self.assertIn("not that it ran", f.summary)
        self.assertIn("for any of them was collected", f.summary)
        self.assertNotIn("fired", f.summary)

    def test_each_file_is_a_part(self):
        f = _fuse()
        self.assertEqual(sorted(p["title"] for p in f.parts), sorted(PATHS))
        self.assertEqual({p.get("kind") for p in f.parts}, {"file"})

    def test_the_detection_name_ignores_the_file_list(self):
        # cross-host groups, routines and risk reasons key on it
        self.assertEqual(correlate._detection_name(_fuse()), "ISE autosave: " + RULE)

    def test_a_collected_execution_record_is_named(self):
        amcache = {"DetectRaptor.Windows.Detection.Amcache": [{
            "EntryPath": r"C:\Users\c\ise\run64.exe", "EntryName": "run64.exe",
            "KeyMTime": "2025-12-05T02:50:00Z", "_hostname": "HOSTA", "_client_id": "C.HOSTA"}]}
        f = _fuse(amcache)
        self.assertIn("Collected records show it ran: run64.exe (Amcache)", f.summary)
        self.assertNotIn("not that it ran", f.summary)


if __name__ == "__main__":
    unittest.main()
