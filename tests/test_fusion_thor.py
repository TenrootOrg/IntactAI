"""THOR results from an adopted hunt reach Case Analysis as Alerts and Warnings.

The log lines follow Nextron's published jsonlog formats (v1, v2, v3). Intact does
not ship or run THOR, so it must stay out of every blueprint.
"""
import json
import os
import sys
import unittest

import yaml

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (os.path.dirname(os.path.abspath(__file__)), os.path.join(_ROOT, "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import correlate, store  # noqa: E402
from services.fusion.mappers.agentic import _thor_finding, map_agentic  # noqa: E402

JSON_SOURCE = "Generic.Scanner.ThorZIP/ThorResultsJson"
EXEC_SOURCE = "Generic.Scanner.ThorZIP/ThorExec"

V1 = {"time": "2024-09-24T12:35:41Z", "hostname": "h", "level": "Alert", "module": "FileScan",
      "message": "Malware file found", "file": r"C:\Temp\a.exe", "score": 95, "sha256": "aa" * 32,
      "reason_1": "YARA rule Bad_Tool / Detects a bad tool SUBSCORE: 90 MATCHED: password=hunter2",
      "log_version": "v1.0.0"}
V2 = {"time": "2024-09-24T12:37:04Z", "hostname": "h", "level": "Warning", "module": "Autoruns",
      "message": "Suspicious autorun", "file": r"C:\Users\Public\b.dll", "score": 70,
      "reasons": [{"reason": "Odd location", "rulename": "Autorun_Public"}], "log_version": "v2.0.0"}
V3 = {"type": "THOR assessment",
      "meta": {"time": "2025-07-01T12:05:12.123456789+02:00", "level": "Alert", "module": "ProcessCheck",
               "scan_id": "S-1", "event_id": "e", "hostname": "h"},
      "message": "Suspicious process", "score": 88,
      "subject": {"type": "process", "pid": 4, "image": {"type": "file", "path": r"C:\x\evil.exe",
                                                          "hashes": {"sha256": "bb" * 32}}},
      "reasons": [{"type": "reason", "summary": "Bad process",
                   "signature": {"score": 88, "origin": "internal", "kind": "YARA Rule", "rule_name": "Evil_Proc"},
                   "matched": [{"data": "secret-token"}]}],
      "log_version": "v3.0.0"}


def _row(line):
    return {"Line": json.dumps(line) if isinstance(line, dict) else line,
            "_client_id": "C.1", "_hostname": "HOSTA"}


def _fuse(lines):
    data = {JSON_SOURCE: [_row(x) for x in lines]}
    ents, rels = map_agentic(store._filter_supported(data), run_id="r1")
    return ents, correlate.assemble("c", [(ents, rels)], ["r1"])


class Formats(unittest.TestCase):
    def test_v1(self):
        f = _thor_finding(json.dumps(V1))
        self.assertEqual((f["severity"], f["rule"], f["path"], f["score"]),
                         ("high", "YARA rule Bad_Tool / Detects a bad tool", r"C:\Temp\a.exe", 95))

    def test_v2(self):
        f = _thor_finding(json.dumps(V2))
        self.assertEqual((f["severity"], f["rule"], f["path"]), ("medium", "Autorun_Public", r"C:\Users\Public\b.dll"))

    def test_v3_with_local_offset_and_nanoseconds(self):
        f = _thor_finding(json.dumps(V3))
        self.assertEqual((f["severity"], f["rule"], f["path"], f["sha256"], f["ts"]),
                         ("high", "Evil_Proc", r"C:\x\evil.exe", "bb" * 32, "2025-07-01T10:05:12Z"))

    def test_everything_else_is_dropped(self):
        status = {"type": "THOR message", "meta": {"level": "Warning", "module": "Startup"}, "message": "x"}
        for line in ({**V1, "level": "Notice"}, {**V1, "level": "Info"}, status,
                     {"level": "Warning", "module": "Startup", "message": "low disk"},
                     "not json", "", None, "[1, 2]"):
            self.assertIsNone(_thor_finding(json.dumps(line) if isinstance(line, dict) else line), line)


class Findings(unittest.TestCase):
    def test_all_formats_become_findings(self):
        _, g = _fuse([V1, V2, V3])
        self.assertEqual(sorted((f.severity, f.title) for f in g.findings), [
            ("high", "THOR: Evil_Proc on HOSTA"),
            ("high", "THOR: YARA rule Bad_Tool / Detects a bad tool on HOSTA"),
            ("medium", "THOR: Autorun_Public on HOSTA")])

    def test_matched_strings_never_reach_the_case(self):
        ents, _ = _fuse([V1, V3])
        text = str([(e.label, e.attrs) for e in ents])
        self.assertNotIn("hunter2", text)
        self.assertNotIn("secret-token", text)

    def test_one_rule_on_thousands_of_files_is_one_bounded_finding(self):
        lines = [{**V2, "file": fr"C:\Temp\{i}.dll"} for i in range(3000)]
        ents, g = _fuse(lines)
        ev = [e for e in ents if e.type == "event"]
        self.assertEqual((len(ev), len(g.findings), g.findings[0].occ_count), (1, 1, 3000))
        self.assertEqual(len(ev[0].attrs["entries"]), 10)
        self.assertIn("+2,990 more", ev[0].attrs["details"])

    def test_an_alert_raises_a_warning_for_the_same_rule(self):
        _, g = _fuse([V2, {**V2, "level": "Alert", "score": 90}])
        self.assertEqual([f.severity for f in g.findings], ["high"])

    def test_the_run_summary_source_adds_nothing(self):
        data = {EXEC_SOURCE: [{"Alerts": "3", "Warnings": "1", "_client_id": "C.1", "_hostname": "HOSTA"}]}
        ents, rels = map_agentic(store._filter_supported(data), run_id="r1")
        self.assertEqual(correlate.assemble("c", [(ents, rels)], ["r1"]).findings, [])


class NotShipped(unittest.TestCase):
    def test_no_blueprint_runs_it(self):
        with open(os.path.join(_ROOT, "modules/backend/config/default_blueprints.yaml"), encoding="utf-8") as fh:
            blueprints = yaml.safe_load(fh)["velociraptor"]
        self.assertEqual([b["id"] for b in blueprints if "Generic.Scanner.ThorZIP" in b["artifacts"]], [])


if __name__ == "__main__":
    unittest.main()
