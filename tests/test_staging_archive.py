"""Archive-staging (T1560.001) surfaces ONLY when corroborated.

DetectRaptor's "Suspicious Location" MFT rule flags an archive in a world-writable
path (Public/ProgramData/Temp) — but that fires on benign backups, installers and
cloud-sync files too, so the mapper keeps it a quiet timeline event. The rule
promotes it to a finding only when other attack activity hit the same host within
the hour. A lone archive must stay quiet; a clean host has no attack to corroborate."""
import os
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (_HERE, os.path.join(os.path.dirname(_HERE), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import correlate  # noqa: E402
from services.fusion.schema import Entity, Finding, FusionGraph  # noqa: E402

ARCHIVE = "\\\\.\\C:\\Users\\Public\\exfil_stage.zip"


def _stage_findings(*, with_attack):
    g = FusionGraph(case_id="c")
    g.upsert(Entity(id="host1", type="asset", label="HOST1", attrs={"_assets": ["host1"]}))
    g.upsert(Entity(id="ev1", type="event", label="MFT: Suspicious Location",
                    attrs={"path": ARCHIVE, "_assets": ["host1"]},
                    flags=["mft_detection"], severity="high",
                    first_seen="2026-10-08T15:12:39Z", last_seen="2026-10-08T15:12:39Z"))
    if with_attack:                                    # a high finding on the same host, same window
        g.add_finding(Finding(id="f1", title="SIGMA: Security Eventlog Cleared on HOST1",
                              severity="high", confidence="high", summary="log clear",
                              asset_ids=["host1"],
                              ts="2026-10-08T15:11:57Z", kind="single"))
    correlate._staging_archive_findings(g, window=None)
    return [f for f in g.findings if "T1560.001" in (f.mitre or [])]


class StagingArchive(unittest.TestCase):
    def test_lone_archive_is_not_a_finding(self):
        self.assertEqual([], _stage_findings(with_attack=False))

    def test_archive_amid_attack_surfaces_as_T1560(self):
        hits = _stage_findings(with_attack=True)
        self.assertEqual(1, len(hits), [f.title for f in hits])
        self.assertIn("exfil_stage.zip", hits[0].title)

    def test_benign_path_archive_never_promotes(self):
        # even WITH nearby attack, an archive under Program Files is not a staging path
        g = FusionGraph(case_id="c")
        g.upsert(Entity(id="host1", type="asset", label="HOST1", attrs={"_assets": ["host1"]}))
        g.upsert(Entity(id="ev1", type="event", label="MFT",
                        attrs={"path": "\\\\.\\C:\\Program Files\\App\\backup.zip", "_assets": ["host1"]},
                        flags=["mft_detection"], severity="high",
                        first_seen="2026-10-08T15:12:39Z", last_seen="2026-10-08T15:12:39Z"))
        g.add_finding(Finding(id="f1", title="x on HOST1", severity="high", confidence="high",
                              summary="x", asset_ids=["host1"], ts="2026-10-08T15:11:57Z", kind="single"))
        correlate._staging_archive_findings(g, window=None)
        self.assertEqual([], [f for f in g.findings if "T1560.001" in (f.mitre or [])])


if __name__ == "__main__":
    unittest.main()
