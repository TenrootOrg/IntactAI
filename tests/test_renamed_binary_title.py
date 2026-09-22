"""A binary that was never renamed must not be called renamed.

The BinaryRename detection set flags two different things: a file whose internal
original name differs from its name on disk (a real masquerade), and a file whose
name is simply a known attacker tool (AdFind, ProcessHacker, procdump). Both came
out as "Renamed binary: X copied as X" — on a real case 14 of 18 said the SAME
name on both sides, which reads as nonsense and buried the four real renames.
"""
import os
import sys
import unittest

for _p in (os.path.dirname(os.path.abspath(__file__)),
           os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import correlate, schema  # noqa: E402


def _titles(original_name, name, host="ALClient01"):
    ents = [schema.Entity(id="asset:a", type="asset", label=host),
            schema.Entity(id=f"ev:{name}", type="event", label=name, severity="high",
                          first_seen="2025-05-27T11:17:01Z",
                          flags=["detection", "masquerading"],
                          attrs={"_assets": ["asset:a"], "title": f"Renamed binary: {name}",
                                 "original_name": original_name, "name": name,
                                 "path": rf"C:\Tenroot\Bin\{name}",
                                 "full_hash": "842737b5c36f624c9420a005239b04876990a2c40"},
                          evidence=[schema.EvidenceRef(
                              "velociraptor", "r1",
                              "DetectRaptor.Windows.Detection.BinaryRename/row=1")])]
    g = correlate.assemble("c", [(ents, [])], ["r1"], min_severity="medium")
    return [f.title for f in g.findings], g.findings


class OnlyARealRenameSaysRenamed(unittest.TestCase):

    def test_the_same_name_on_both_sides_is_a_known_tool(self):
        # Verbatim from the live case QA screenshotted.
        for n in ("AdFind.exe", "ProcessHacker.exe", "pythonw.exe"):
            titles, _ = _titles(n, n)
            self.assertEqual([f"Known tool on disk: {n} on ALClient01"], titles)

    def test_the_extension_alone_is_not_a_rename(self):
        titles, _ = _titles("procdump", "procdump.exe")
        self.assertEqual(["Known tool on disk: procdump.exe on ALClient01"], titles)

    def test_a_real_rename_still_says_so(self):
        """Non-vacuous: the four that WERE renamed must keep their wording."""
        titles, _ = _titles("procdump", "procdump64.exe")
        self.assertEqual(["Renamed binary: procdump copied as procdump64.exe on ALClient01"],
                         titles)

    def test_the_summary_follows_the_title(self):
        _, f_known = _titles("AdFind.exe", "AdFind.exe")
        _, f_ren = _titles("procdump", "procdump64.exe")
        self.assertIn("under its own name", f_known[0].summary)
        self.assertNotIn("exists under 1 name", f_known[0].summary)
        self.assertIn("originally procdump", f_ren[0].summary)


if __name__ == "__main__":
    unittest.main(verbosity=2)
