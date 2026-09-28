"""A detection that FOUND FILES on disk says so (QA TASK-12666).

"MFT: Erasing Tools fired 4× on DESKTOP" read as "sdelete ran four times": it only
means four sdelete files sit on the disk, dated by when each was written there. The
row now names its files, says the time is the file's own, says whether anything
collected shows them running, and each file takes its own verdict.
"""
import os
import sys
import unittest

for _p in (os.path.dirname(os.path.abspath(__file__)),
           os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import correlate  # noqa: E402
from services.fusion.mappers.agentic import map_agentic  # noqa: E402

MFT = "DetectRaptor.Windows.Detection.MFT.Erasing.Tools"
PATHS = [r"C:\Windows\Temp\chef\cache\sdelete\sdelete.exe",
         r"C:\Windows\Temp\chef\cache\sdelete\sdelete64.exe",
         r"C:\Windows\System32\sdelete.exe"]


def _mft(path):
    return {"Detection": {"Name": "Erasing Tools", "Criticality": "Medium"}, "OSPath": path,
            "FNTimestamps": {"Created0x30": "2025-12-05T02:47:30Z"},
            "_hostname": "HOSTA", "_client_id": "C.HOSTA"}


def _fuse(extra=None):
    ents, rels = map_agentic({MFT: [_mft(p) for p in PATHS], **(extra or {})}, run_id="r1")
    g = correlate.assemble("c", [(ents, rels)], ["r1"])
    return next(f for f in g.findings if "Erasing Tools" in f.title)


class OnDisk(unittest.TestCase):
    def test_the_row_names_its_files_and_does_not_say_it_ran(self):
        f = _fuse()
        self.assertIn("(3 files: sdelete.exe, sdelete.exe, sdelete64.exe) on", f.title)
        self.assertIn("3 files found on disk", f.summary)
        self.assertIn("the file's own timestamp", f.summary)
        self.assertIn("not that it ran", f.summary)
        self.assertNotIn("fired", f.summary)

    def test_each_file_is_a_part(self):
        f = _fuse()
        self.assertEqual(sorted(p["title"] for p in f.parts), sorted(PATHS))
        self.assertEqual({p.get("kind") for p in f.parts}, {"file"})

    def test_the_detection_name_ignores_the_file_list(self):
        # cross-host groups, routines and risk reasons key on it
        self.assertEqual(correlate._detection_name(_fuse()), "MFT: Erasing Tools")

    def test_a_collected_execution_record_is_named(self):
        amcache = {"DetectRaptor.Windows.Detection.Amcache": [{
            "EntryPath": r"C:\Windows\Temp\chef\cache\sdelete\sdelete64.exe", "EntryName": "sdelete64.exe",
            "KeyMTime": "2025-12-05T02:50:00Z", "_hostname": "HOSTA", "_client_id": "C.HOSTA"}]}
        f = _fuse(amcache)
        self.assertIn("Collected records show it ran: sdelete64.exe (Amcache)", f.summary)
        self.assertNotIn("not that it ran", f.summary)


if __name__ == "__main__":
    unittest.main()
