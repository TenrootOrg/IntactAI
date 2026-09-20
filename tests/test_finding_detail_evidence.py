"""The finding detail must show every artifact its evidence came from.

QA: the Timeline was filtered by one artifact; the row matched, but its detail
showed a single evidence row from a different artifact, so nothing explained the
match. The panel kept only the FIRST evidence row of each entity.
"""
import os
import sys
import unittest
from unittest import mock

for _p in (os.path.dirname(os.path.abspath(__file__)),
           os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import schema, store  # noqa: E402


def _graph():
    g = schema.FusionGraph(case_id="c")
    ev = [schema.EvidenceRef("velociraptor", "r1", "DetectRaptor.Windows.Detection.BinaryRename/row=36"),
          schema.EvidenceRef("velociraptor", "r1", "Windows.Hayabusa.Rules/row=8"),
          schema.EvidenceRef("velociraptor", "r1", "DetectRaptor.Windows.Detection.Amcache/row=2")]
    g.upsert(schema.Entity(id="ioc:hash:ab", type="ioc", label="ab" * 32, evidence=ev,
                           first_seen="2025-12-05T02:54:10Z",
                           attrs={"source_name": "mstsc.exe",
                                  "artifact_observations": [{"value": "Windows.Hayabusa.Rules", "source": "prior"}]}))
    g.findings = [schema.Finding(id="f1", title="Shared binary seen on 2 hosts", severity="medium",
                                 confidence="high", summary="", entity_ids=["ioc:hash:ab"],
                                 ts="2025-12-05T02:54:10Z", kind="cross_host")]
    return g


class DetailShowsAllEvidence(unittest.TestCase):
    def _detail(self):
        with mock.patch.object(store, "get_case", return_value={"name": "c"}), \
             mock.patch.object(store, "load_graph", return_value=_graph()):
            return store.get_finding_detail("c", "f1")

    def test_every_artifact_is_listed(self):
        occ = self._detail()["occurrences"][0]
        self.assertEqual(occ["artifacts"], ["DetectRaptor.Windows.Detection.Amcache",
                                            "DetectRaptor.Windows.Detection.BinaryRename",
                                            "Windows.Hayabusa.Rules"])

    def test_every_row_is_listed_and_counted(self):
        occ = self._detail()["occurrences"][0]
        self.assertEqual(occ["evidence_rows"], 3)
        self.assertIn("Windows.Hayabusa.Rules/row=8", occ["locators"])

    def test_the_first_locator_is_still_there_for_older_pages(self):
        self.assertEqual(self._detail()["occurrences"][0]["locator"],
                         "DetectRaptor.Windows.Detection.BinaryRename/row=36")


if __name__ == "__main__":
    unittest.main()
