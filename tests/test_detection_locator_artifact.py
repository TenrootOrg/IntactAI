"""Entities pulled out of a detection's fields must cite the artifact that produced it.

QA on the Timeline: the artifact filter and the chips listed the same collector
twice -- "Windows.Hayabusa.Rules" for the detections themselves and a second
"hayabusa" for the process/account/IP/hash extracted from their Details, because
that locator was hardcoded "hayabusa/details".
"""
import os
import sys
import unittest

for _p in (os.path.dirname(os.path.abspath(__file__)),
           os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion.mappers import map_agentic  # noqa: E402
from services.fusion import render, schema, correlate  # noqa: E402

CID = "C.1234567890abcdef"
CID2 = "C.fedcba0987654321"
HOSTNAMES = {CID: "HOSTA"}
# The real Hayabusa shape: " \u00a6 "-delimited key: value (see mappers/details.py)
DETAILS = (u"Cmdline: rundll32.exe x \u00a6 Proc: C:\\Windows\\System32\\rundll32.exe \u00a6 "
           u"User: ADATUMLAB\\srv \u00a6 PID: 4242 \u00a6 TgtIP: 10.1.2.3 \u00a6 "
           u"Hashes: MD5=" + "cd" * 16 + ",SHA256=" + "ab" * 32)


def _rows(artifact):
    return {artifact: [{"ClientId": CID, "Timestamp": "2026-09-01T07:20:51Z", "Computer": "HOSTA",
                        "Channel": "Security", "EID": 1102, "Level": "high", "RecordID": 1,
                        "Title": "Credential Dumping Tools Accessing LSASS Memory",
                        "Details": DETAILS}]}


def _locators(artifact):
    ents, _ = map_agentic(_rows(artifact), run_id="r1", hostnames=HOSTNAMES)
    # the host node cites "asset", which the Timeline already ignores
    return {ev.locator for e in ents for ev in (e.evidence or []) if ev.locator != "asset"}


class DetectionEntitiesCiteTheirArtifact(unittest.TestCase):

    def test_the_fixture_reaches_the_detection_entities(self):
        """Guard: without the process/account/IP/hash pulled from Details, the rest
        of this file would pass against the bug it pins."""
        ents, _ = map_agentic(_rows("Windows.Hayabusa.Rules"), run_id="r1", hostnames=HOSTNAMES)
        kinds = {e.type for e in ents if any("/details" in (ev.locator or "") for ev in (e.evidence or []))}
        self.assertTrue({"process", "account", "ioc"} <= kinds, kinds)

    def test_no_invented_artifact_name(self):
        locs = _locators("Windows.Hayabusa.Rules")
        self.assertTrue(locs)
        self.assertNotIn("hayabusa/details", locs)
        self.assertEqual({l.split("/")[0] for l in locs}, {"Windows.Hayabusa.Rules"})

    def test_a_different_artifact_is_cited_as_itself(self):
        locs = _locators("DetectRaptor.Windows.Detection.Evtx")
        self.assertEqual({l.split("/")[0] for l in locs}, {"DetectRaptor.Windows.Detection.Evtx"})

    def test_a_cross_host_finding_chips_one_artifact(self):
        """QA's row: a cross-host finding has no row of its own, so its chips come
        from the entities' evidence -- which is where the invented name showed up."""
        rows = _rows("Windows.Hayabusa.Rules")["Windows.Hayabusa.Rules"]
        second = dict(rows[0], ClientId=CID2, Computer="HOSTB")
        ents, rels = map_agentic({"Windows.Hayabusa.Rules": rows + [second]}, run_id="r1",
                                 hostnames={**HOSTNAMES, CID2: "HOSTB"})
        g = correlate.assemble("c", [(ents, rels)], ["r1"], min_severity="medium")
        cross = [f for f in g.findings if f.kind == "cross_host"]
        self.assertTrue(cross, "the fixture must produce a cross-host finding")
        chips = {a for f in cross for a in render._artifacts_of(g, f)}
        self.assertEqual(chips, {"Windows.Hayabusa.Rules"}, chips)


if __name__ == "__main__":
    unittest.main()
