"""The proactive blueprint's extra artifacts reach Case Analysis as exposure findings.

They report current state, so a row must not become activity, a benign row must
stay quiet, and one large hosts file must not flood a case.
"""
import os
import sys
import unittest

import yaml

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (os.path.dirname(os.path.abspath(__file__)), os.path.join(_ROOT, "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import correlate  # noqa: E402
from services.fusion.mappers.agentic import SUPPORTED_ARTIFACTS, _artifact_base, map_agentic  # noqa: E402

RMM = "DetectRaptor.Windows.Detection.LolRMM"
CRITICAL = "Windows.System.CriticalServices"
HOSTS = "Windows.System.HostsFile"
WDIGEST = "Windows.Registry.WDigest"
HIDDEN = "Windows.Registry.TaskCache.HiddenTasks"
ROLE = "Windows.System.DomainRole"


def _row(**kw):
    return {"_client_id": "C.1", "_hostname": "HOSTA", "_ts": "2026-11-23T10:00:00Z", **kw}


def _fuse(data):
    ents, rels = map_agentic(data, run_id="r1")
    return ents, correlate.assemble("c", [(ents, rels)], ["r1"])


def _titles(data):
    return [f.title for f in _fuse(data)[1].findings]


class Blueprint(unittest.TestCase):
    def test_every_artifact_is_fused(self):
        with open(os.path.join(_ROOT, "modules/backend/config/default_blueprints.yaml"), encoding="utf-8") as fh:
            blueprints = {b["id"]: b for b in yaml.safe_load(fh)["velociraptor"]}
        new = blueprints["agentic_proactive_windows"]["artifacts"]
        self.assertEqual(new[:20], blueprints["agentic_quick_wins"]["artifacts"])
        self.assertEqual([a for a in new if _artifact_base(a) not in SUPPORTED_ARTIFACTS], [])


class Findings(unittest.TestCase):
    def test_rmm_sources_fold_into_one_presence_finding(self):
        data = {RMM: [_row(Name="ToolX", Source="Windows.Sys.Programs", Event={"DisplayVersion": "1"})],
                RMM + "/Processes": [_row(Name="ToolX", Source="Windows.System.Pslist", Pid=9,
                                          Event={"Exe": r"C:\x.exe", "CommandLine": "--key SECRET"})]}
        ents, g = _fuse(data)
        self.assertEqual([f.title for f in g.findings], ["Remote access tool present: ToolX on HOSTA"])
        self.assertEqual([e for e in ents if e.type == "process"], [])
        self.assertNotIn("SECRET", str([e.attrs for e in ents]))

    def test_stopped_security_service_but_not_windows_update(self):
        data = {CRITICAL: [_row(Name="WinDefend", DisplayName="Defender", State="Stopped",
                                Created="2020-01-01T00:00:00Z"),
                           _row(Name="wuauserv", DisplayName="Windows Update", State="Stopped")]}
        _, g = _fuse(data)
        self.assertEqual([f.title for f in g.findings], ["Security service not running: Defender on HOSTA"])
        self.assertTrue(str(g.findings[0].ts).startswith("2026-11-23"))

    def test_state_finding_is_dated_at_collection(self):
        row = {"_client_id": "C.1", "_hostname": "HOSTA", "Name": "WinDefend", "State": "Stopped",
               "Created": "2020-01-01T00:00:00Z"}
        ents, rels = map_agentic({CRITICAL: [row]}, run_id="r1", collected_at="2026-11-23T10:00:00.123456")
        g = correlate.assemble("c", [(ents, rels)], ["r1"])
        self.assertTrue(str(g.findings[0].ts).startswith("2026-11-23T10:00:00"))

    def test_wdigest_only_on_use_logon_credential(self):
        self.assertEqual(_titles({WDIGEST: [_row(KeyName="Negotiate", KeyValue=1)]}), [])
        self.assertEqual(_titles({WDIGEST: [_row(KeyName="UseLogonCredential", KeyValue=0)]}), [])
        self.assertEqual(len(_titles({WDIGEST: [_row(KeyName="UseLogonCredential", KeyValue=1)]})), 1)

    def test_hidden_task_is_high(self):
        _, g = _fuse({HIDDEN: [_row(Path=r"\Evil", TaskID="{1}", TaskXML=[{"Command": "cmd.exe"}])]})
        self.assertEqual([f.severity for f in g.findings], ["high"])

    def test_domain_role_is_context_only(self):
        ents, g = _fuse({ROLE: [_row(DomainRole="Member Server", Domain="corp.test")]})
        self.assertEqual(g.findings, [])
        self.assertEqual(next(e for e in g.by_type("asset")).attrs["domain_role"], "Member Server")


class HostsFile(unittest.TestCase):
    def test_only_risky_entries_surface(self):
        self.assertEqual(_titles({HOSTS: [_row(Hostname="intranet", Resolution="10.0.0.5"),
                                          _row(Hostname="ads.test", Resolution="0.0.0.0"),
                                          _row(Hostname="localhost", Resolution="127.0.0.1")]}), [])
        self.assertEqual(len(_titles({HOSTS: [_row(Hostname="login.test", Resolution="8.8.8.8")]})), 1)
        self.assertEqual(len(_titles({HOSTS: [_row(Hostname="update.vendor.test", Resolution="127.0.0.1")]})), 1)

    def test_mapped_name_is_not_taken_for_the_machine(self):
        row = {"_client_id": "C.1", "Hostname": "fake-dc", "Resolution": "127.0.0.1"}
        ents, _ = map_agentic({HOSTS: [row]}, run_id="r1", hostnames={"C.1": "HOSTA"})
        self.assertEqual([e.label for e in ents if e.type == "asset"], ["HOSTA"])
        row.pop("_client_id")
        ents, _ = map_agentic({HOSTS: [row]}, run_id="r1")
        self.assertNotIn("fake-dc", [e.label for e in ents if e.type == "asset"])

    def test_large_blocklist_is_one_bounded_finding(self):
        rows = [_row(Hostname=f"h{i}.update.test", Resolution="0.0.0.0") for i in range(5000)]
        ents, g = _fuse({HOSTS: rows})
        ev = [e for e in ents if e.type == "event"]
        self.assertEqual((len(ev), len(g.findings)), (1, 1))
        self.assertEqual(ev[0].attrs["entry_count"], 5000)
        self.assertEqual(len(ev[0].attrs["entries"]), 25)


if __name__ == "__main__":
    unittest.main()
