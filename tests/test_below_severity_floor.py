"""An artifact that is collected but contributes nothing must say so.

QA (TASK-12677, "missing artifacts"): DetectRaptor.Windows.Detection.Applications
collected 6 rows, mapped to 10 entities, and appeared nowhere — installed software
is "low" and the case's floor is medium, so ingest dropped every row silently.
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

ASSET = "asset:endpoint:C.1"


def _ent(eid, sev_, artifact, ts="2026-06-18T08:01:45Z"):
    return schema.Entity(id=eid, type="event", label=eid, severity=sev_, first_seen=ts,
                         attrs={"_assets": [ASSET]},
                         evidence=[schema.EvidenceRef("velociraptor", "r1", f"{artifact}/row=1")])


def _assemble(min_severity):
    ents = [schema.Entity(id=ASSET, type="asset", label="HOSTA"),
            _ent("event:app", "low", "DetectRaptor.Windows.Detection.Applications"),
            _ent("event:sigma", "high", "Windows.Hayabusa.Rules")]
    return correlate.assemble("c", [(ents, [])], ["r1"], min_severity=min_severity)


class BelowTheFloorIsReported(unittest.TestCase):
    def test_what_the_floor_dropped_is_counted_per_artifact(self):
        g = _assemble("medium")
        self.assertNotIn("event:app", g.entities)
        self.assertEqual(g.below_floor, {"DetectRaptor.Windows.Detection.Applications": 1})

    def test_nothing_is_reported_when_the_floor_keeps_everything(self):
        g = _assemble("informational")
        self.assertIn("event:app", g.entities)
        self.assertEqual(g.below_floor, {})

    def test_the_fuse_logs_it(self):
        src = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                "modules/backend/services/fusion/store.py"), encoding="utf-8").read()
        self.assertIn("Refusion · below the severity floor", src)
        self.assertIn("lower Severity in Configuration to include them", src)


class TheHuntCapAllowsTheWholeCatalogue(unittest.TestCase):
    def test_all_artifacts_blueprint_is_runnable(self):
        src = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                "modules/backend/routes/velociraptor_routes.py"), encoding="utf-8").read()
        self.assertIn("len(artifacts) > 2000", src)
        self.assertNotIn("len(artifacts) > 500", src)


if __name__ == "__main__":
    unittest.main()
