"""EDR exports' telemetry reaches SigmaHQ's rules, per product and event type.

The 2026-10-20 severity audit: file_event (15 critical), registry (11 critical),
pipe_created (8 critical), image_load (3 critical) and dns_query rules were fed by
Sysmon alone -- an export from Defender XDR, CrowdStrike FDR, Carbon Black Cloud,
Elastic Defend or SentinelOne reached none of them. And process creation read Carbon
Black's and SentinelOne's PARENT as the new process. Rule bodies are SigmaHQ's.
"""
import json
import os
import sys
import unittest

for _p in (os.path.dirname(os.path.abspath(__file__)),
           os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import external_logs as X, sigma_eval as S  # noqa: E402

IFEO = "\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\"


def r(title, level, logsource, detection):
    return S.compile_rule({"title": title, "id": title, "level": level, "logsource": logsource, "detection": detection})


W = {"product": "windows"}
RULES = [
    r("Sticky Key Like Backdoor Usage - Registry", "critical", {**W, "category": "registry_event"},
      {"sel": {"TargetObject|endswith": [IFEO + "sethc.exe\\Debugger", IFEO + "utilman.exe\\Debugger"]},
       "condition": "sel"}),
    r("CobaltStrike Named Pipe Pattern Regex", "critical", {**W, "category": "pipe_created"},
      {"sel": [{"PipeName|re": "\\\\MsFteWds[0-9a-f]{2}"}, {"PipeName|re": "\\\\ntsvcs[0-9a-f]{2}"}],
       "condition": "sel"}),
    r("Potential DCOM InternetExplorer.Application DLL Hijack - Image Load", "critical", {**W, "category": "image_load"},
      {"sel": {"Image|endswith": "\\Internet Explorer\\iexplore.exe",
               "ImageLoaded|endswith": "\\Internet Explorer\\iertutil.dll"}, "condition": "sel"}),
    r("Suspicious Cobalt Strike DNS Beaconing - Sysmon", "critical", {**W, "category": "dns_query"},
      {"selection1": {"QueryName|startswith": ["aaa.stage.", "post.1"]},
       "selection2": {"QueryName|contains": ".stage.123456."}, "condition": "1 of selection*"}),
    r("Potential CVE-2021-41379 Exploitation Attempt", "critical", {**W, "category": "file_event"},
      {"sel": {"Image|endswith": "\\msiexec.exe",
               "TargetFilename|endswith": "\\elevation_service.exe"}, "condition": "sel"}),
    r("Atomic MacOS Stealer - Persistence Indicators", "high", {"product": "macos", "category": "file_event"},
      {"sel": {"TargetFilename": "/Library/LaunchDaemons/com.finder.helper.plist"}, "condition": "sel"}),
    r("Whoami Execution", "high", {**W, "category": "process_creation"},
      {"sel": {"Image|endswith": "\\whoami.exe"}, "condition": "sel"}),
]


def titles(row):
    return [h["title"] for h in S.evaluate(X.sigma_event(row), RULES)]


def cat(row):
    v = S.Event(row).edr()
    return (v["category"], v["os"]) if v else None


class DefenderXdr(unittest.TestCase):
    A = {"Timestamp": "2026-10-20T10:05:00Z", "DeviceName": "ws01",
         "InitiatingProcessFolderPath": "C:\\Windows\\System32\\reg.exe", "InitiatingProcessFileName": "reg.exe",
         "InitiatingProcessCommandLine": "reg add ..."}

    def test_registry_sticky_keys_backdoor(self):
        row = {**self.A, "ActionType": "RegistryValueSet",
               "RegistryKey": "HKEY_LOCAL_MACHINE" + IFEO + "sethc.exe", "RegistryValueName": "Debugger",
               "RegistryValueData": "C:\\Windows\\System32\\cmd.exe"}
        self.assertEqual(["Sticky Key Like Backdoor Usage - Registry"], titles(row))
        self.assertEqual("HKLM" + IFEO + "sethc.exe\\Debugger", S.Event(row).get("TargetObject"))

    def test_named_pipe_and_dns_from_device_events(self):
        pipe = {**self.A, "ActionType": "NamedPipeEvent",
                "AdditionalFields": json.dumps({"PipeName": "\\Device\\NamedPipe\\MsFteWds4f", "FileOperation": "File created"})}
        self.assertEqual(["CobaltStrike Named Pipe Pattern Regex"], titles(pipe))
        dns = {**self.A, "ActionType": "DnsQueryResponse",
               "AdditionalFields": json.dumps({"DnsQueryString": "aaa.stage.12345.evil.example"})}
        self.assertEqual(["Suspicious Cobalt Strike DNS Beaconing - Sysmon"], titles(dns))

    def test_file_event_and_its_writer(self):
        row = {**self.A, "ActionType": "FileCreated", "InitiatingProcessFolderPath": "C:\\Windows\\System32\\msiexec.exe",
               "FolderPath": "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\elevation_service.exe"}
        self.assertEqual(["Potential CVE-2021-41379 Exploitation Attempt"], titles(row))
        self.assertEqual(("file_delete", "windows"), cat({**row, "ActionType": "FileDeleted"}))

    def test_process_events_keep_folderpath_as_the_process(self):
        row = {**self.A, "ActionType": "ProcessCreated", "FolderPath": "C:\\Windows\\System32\\whoami.exe",
               "ProcessCommandLine": "whoami /all"}
        self.assertEqual(["Whoami Execution"], titles(row))
        self.assertEqual("C:\\Windows\\System32\\reg.exe", S.Event(row).get("ParentImage"))


class CarbonBlack(unittest.TestCase):
    BASE = {"device_name": "ws01", "device_os": "WINDOWS", "process_path": "c:\\windows\\explorer.exe",
            "process_cmdline": "explorer.exe", "backend_timestamp": "2026-10-20 10:05:00 +0000 UTC"}

    def test_procstart_child_is_the_new_process(self):
        row = {**self.BASE, "type": "endpoint.event.procstart", "action": "ACTION_CREATE_PROCESS",
               "childproc_name": "c:\\windows\\system32\\whoami.exe", "target_cmdline": "whoami /all"}
        self.assertEqual(["Whoami Execution"], titles(row))
        ev = S.Event(row)
        self.assertEqual(("c:\\windows\\explorer.exe", "whoami /all"), (ev.get("ParentImage"), ev.get("CommandLine")))

    def test_moduleload(self):
        row = {**self.BASE, "type": "endpoint.event.moduleload", "action": "ACTION_LOAD_MODULE",
               "process_path": "c:\\program files\\internet explorer\\iexplore.exe",
               "modload_name": "c:\\program files\\internet explorer\\iertutil.dll"}
        self.assertEqual(["Potential DCOM InternetExplorer.Application DLL Hijack - Image Load"], titles(row))

    def test_a_parent_running_is_not_a_process_creation_of_it(self):
        row = {**self.BASE, "type": "endpoint.event.netconn", "action": "ACTION_CONNECTION_CREATE",
               "process_path": "c:\\windows\\system32\\whoami.exe", "remote_ip": "203.0.113.9", "remote_port": "443"}
        self.assertEqual([], titles(row))
        self.assertEqual(("network_connection", "windows"), cat(row))


class SentinelOne(unittest.TestCase):
    def test_process_creation_target_is_the_new_process(self):
        row = {"event.type": "Process Creation", "src.process.image.path": "C:\\Windows\\explorer.exe",
               "src.process.cmdline": "explorer.exe", "tgt.process.image.path": "C:\\Windows\\System32\\whoami.exe",
               "tgt.process.cmdline": "whoami /priv", "endpoint.name": "ws01"}
        self.assertEqual(["Whoami Execution"], titles(row))

    def test_a_file_event_is_not_a_process_creation(self):
        row = {"event.type": "File Creation", "src.process.image.path": "C:\\Windows\\System32\\whoami.exe",
               "src.process.cmdline": "whoami", "tgt.file.path": "C:\\Users\\a\\x.txt"}
        self.assertEqual([], titles(row))
        self.assertNotIn(("windows", "process_creation", None), S.profiles(S.Event(row)))

    def test_macos_file_and_pipe(self):
        f = {"event.type": "File Creation", "tgt.file.path": "/Library/LaunchDaemons/com.finder.helper.plist",
             "src.process.image.path": "/bin/cp"}
        self.assertEqual(["Atomic MacOS Stealer - Persistence Indicators"], titles(f))
        p = {"event.type": "Named Pipe Creation", "namedPipe.name": "\\\\.\\pipe\\ntsvcs1a",
             "src.process.image.path": "C:\\Windows\\System32\\rundll32.exe"}
        self.assertEqual(["CobaltStrike Named Pipe Pattern Regex"], titles(p))


class CrowdStrikeAndElastic(unittest.TestCase):
    def test_crowdstrike_dns_and_file(self):
        self.assertEqual(["Suspicious Cobalt Strike DNS Beaconing - Sysmon"],
                         titles({"event_simpleName": "DnsRequest", "DomainName": "post.1a2b.evil.example", "aid": "x"}))
        self.assertEqual(("file_event", "windows"),
                         cat({"event_simpleName": "PeFileWritten", "TargetFileName": "\\Device\\HarddiskVolume3\\x.exe"}))

    def test_elastic_registry(self):
        row = {"event.category": ["registry"], "event.type": ["change"],
               "registry.path": "HKLM" + IFEO + "utilman.exe\\Debugger", "process.executable": "C:\\Windows\\reg.exe"}
        self.assertEqual(["Sticky Key Like Backdoor Usage - Registry"], titles(row))


if __name__ == "__main__":
    unittest.main()
