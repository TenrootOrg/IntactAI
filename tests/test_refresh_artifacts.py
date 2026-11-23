"""Every release ships the newest Velociraptor artifacts (scripts/ci/refresh_artifacts.py).

Newest by default, but a version that would hurt is held back: these run with full
privileges on customers' endpoints, and upstream can be wrong (on 2026-11-23
DetectRaptor's LolDrivers list went from 368 KB to its header line).
"""
import base64
import io
import os
import subprocess
import sys
import tempfile
import unittest
import zipfile
from unittest import mock

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
for _p in (_HERE, os.path.join(_ROOT, "modules/backend"), os.path.join(_ROOT, "scripts/ci")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

try:
    import yaml  # noqa: F401
    import refresh_artifacts as ra
except ImportError:
    raise unittest.SkipTest("pyyaml is not installed")

CSV = "Detection,KeywordRegex\n" + "".join(f"rule{i},x{i}\n" for i in range(200))


def _read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def art(query="SELECT Detection, OSPath FROM scope()", iocs=CSV, **kw):
    return {"name": "Windows.Test", "parameters": [{"name": "IOCs", "type": "csv", "default": iocs}],
            "sources": [{"query": query}], **kw}


class Gates(unittest.TestCase):
    def test_newest_is_taken_including_logic_changes(self):
        self.assertEqual(ra.gate("X.Y", art(), art(iocs=CSV + "new,rule\n"))[0], "updated")
        self.assertEqual(ra.gate("X.Y", art(), art("SELECT Detection, OSPath, Extra FROM scope()"))[0], "updated")
        self.assertEqual(ra.gate("X.Y", None, art())[0], "new")
        self.assertEqual(ra.gate("X.Y", art(), art())[0], "same")

    def test_a_gutted_indicator_list_is_held(self):
        kind, why = ra.gate("X.Y", art(), art(iocs="Detection,KeywordRegex\n"))
        self.assertEqual(kind, "held")
        self.assertIn("IOCs shrank", why)

    def test_a_gutted_rule_pack_is_held(self):
        q = 'SELECT yara(rules=gunzip(string=base64decode(string="%s"))) FROM scope()'
        kind, _ = ra.gate("X.Y", art(q % ("A" * 5000)), art(q % "AAAA"))
        self.assertEqual(kind, "held")

    def test_new_power_is_held_and_power_it_already_had_is_not(self):
        for call in ("execve(argv='x')", "http_client(url='x')", "upload(file='x')", "rm(filename='x')"):
            kind, why = ra.gate("X.Y", art(), art(f"SELECT {call} AS R, Detection, OSPath FROM scope()"))
            self.assertEqual(kind, "held", call)
            self.assertIn("gained", why)
        had = art("SELECT execve(argv='a') AS R, Detection, OSPath FROM scope()")
        self.assertEqual(ra.gate("X.Y", had, art("SELECT execve(argv='b') AS R, Detection, OSPath FROM scope()"))[0],
                         "updated")

    def test_a_tool_from_a_new_host_is_held(self):
        old = art(tools=[{"name": "T", "url": "https://github.com/a/T-1.exe"}])
        self.assertEqual(ra.gate("X.Y", old, art(tools=[{"name": "T", "url": "https://github.com/a/T-2.exe"}]))[0],
                         "updated")
        self.assertEqual(ra.gate("X.Y", old, art(tools=[{"name": "T", "url": "https://evil.example/T.exe"}]))[0],
                         "held")

    def test_a_column_case_analysis_reads_must_survive(self):
        new = art("SELECT Detection AS Renamed, Path FROM scope()")
        self.assertEqual(ra.gate("X.Y", art(), new, mapped=True)[0], "held")
        self.assertEqual(ra.gate("X.Y", art(), new, mapped=False)[0], "updated")

    def test_our_own_artifacts_are_never_replaced(self):
        for name in ("Custom.Anything", "tenRoot.IRIS.Timeline.Add", "IRIS.Sync.Asset",
                     "Server.Monitoring.ScheduleDeleteMonitoringData", "Windows.Applications.Disk2VHD"):
            self.assertEqual(ra.gate(name, art(), art(iocs=CSV + "z,z\n"))[0], "ours", name)

    def test_a_new_artifact_cannot_shadow_a_built_in(self):
        self.assertEqual(ra.gate("Windows.System.Pslist", None, art(), builtin=True)[0], "held")


class Archives(unittest.TestCase):
    def _zip(self, files):
        b = io.BytesIO()
        with zipfile.ZipFile(b, "w") as z:
            for n, body in files.items():
                z.writestr(n, body)
        return b.getvalue()

    def test_a_hostile_name_never_becomes_a_path(self):
        got = ra.read_zip(self._zip({
            "ok.yaml": "name: Windows.Good\nsources: []\n",
            "evil.yaml": "name: ../../etc/cron.d/x\nsources: []\n",
            "notes.txt": "name: Windows.NotYaml\n"}))
        self.assertEqual(list(got), ["Windows.Good"])
        self.assertEqual(ra.file_name("Windows.Good"), "Windows__Good.yaml")

    def test_a_hardcoded_webhook_is_scrubbed(self):
        raw, _ = ra._parse(b"name: Custom.A\nurl: https://hooks.slack.com/services/T0/B0/abc\n")
        self.assertNotIn(b"T0/B0/abc", raw)

    def test_rule_packs_are_shortened_only_for_the_verifier(self):
        raw = ('q: base64decode(string="%s")' % base64.b64encode(b"x" * 300000).decode()).encode()
        self.assertLess(len(ra._verifiable(raw)), 100)


class Refresh(unittest.TestCase):
    def test_writes_what_passed_and_keeps_what_did_not(self):
        with tempfile.TemporaryDirectory() as d:
            for name, doc in (("Windows.Up", art()), ("Windows.Gutted", art()), ("Windows.Bad", art())):
                with open(os.path.join(d, ra.file_name(name)), "w") as fh:
                    yaml.safe_dump({**doc, "name": name}, fh)
            def up(name, **kw):
                doc = {**art(**kw), "name": name}
                return yaml.safe_dump(doc).encode(), doc
            upstream = {"Windows.Up": up("Windows.Up", iocs=CSV + "new,r\n"),
                        "Windows.Gutted": up("Windows.Gutted", iocs="Detection,KeywordRegex\n"),
                        "Windows.Bad": up("Windows.Bad", iocs=CSV + "bad,r\n"),
                        "Windows.Fresh": up("Windows.Fresh")}

            def fake_verify(verifier, raw, tmp, definitions):
                return (b"bad,r" not in raw), "parse error"
            before = _read(os.path.join(d, "Windows__Bad.yaml"))
            with mock.patch.object(ra, "verify", side_effect=fake_verify):
                res = ra.refresh(d, upstream, "/v", builtin=set(), mapped=set())
            self.assertEqual({k: v[0] for k, v in res.items()},
                             {"Windows.Up": "updated", "Windows.Gutted": "held",
                              "Windows.Bad": "held", "Windows.Fresh": "new"})
            self.assertIn("new,r", _read(os.path.join(d, "Windows__Up.yaml")))
            self.assertTrue(os.path.exists(os.path.join(d, "Windows__Fresh.yaml")))
            self.assertEqual(_read(os.path.join(d, "Windows__Bad.yaml")), before)

    def test_a_source_that_cannot_be_fetched_fails_the_build(self):
        with mock.patch.object(sys, "argv", ["x", "--verifier", "/bin/true", "--bundle", "/nonexistent"]), \
             mock.patch.object(ra, "fetch_all", side_effect=ra.SourceFailed("down")):
            self.assertEqual(ra.main(), 1)


class TheRelease(unittest.TestCase):
    def test_the_workflow_refreshes_before_baking(self):
        with open(os.path.join(_ROOT, ".github/workflows/build-release-assets.yml"), encoding="utf-8") as fh:
            wf = fh.read()
        i = wf.index("python3 scripts/ci/refresh_artifacts.py")
        self.assertLess(i, wf.index("- name: Assert Velociraptor artifacts are present"))
        self.assertLess(i, wf.index("- name: Build the ${{ matrix.module }} asset"))
        step = wf[wf.rindex("- name:", 0, i):i]
        self.assertIn("if: matrix.module == 'velociraptor'", step)

    def test_the_script_that_wiped_the_bundle_refuses_to_run(self):
        r = subprocess.run([sys.executable, os.path.join(_ROOT, "modules/backend/scripts/regenerate_artifact_bundle.py")],
                           capture_output=True, text=True, timeout=20)
        self.assertEqual(r.returncode, 2)
        self.assertIn("RETIRED", r.stderr)


class TheNewRowsStillMap(unittest.TestCase):
    """The new MFT and Amcache output (2026-11-23) as Case Analysis reads it."""

    def _map(self, artifact, row):
        import _optional_deps  # noqa: F401
        from services.fusion.mappers.agentic import map_agentic
        ents, _ = map_agentic({artifact: [{"ClientId": "C.1", **row}]}, run_id="r1", hostnames={"C.1": "HOST1"})
        return [e for e in ents if e.type == "event"]

    def test_mft(self):
        ev = self._map("DetectRaptor.Windows.Detection.MFT", {
            "RuleID": "DR-1", "DetectionName": "Attacker Tool - Mimikatz", "FileName": "mimikatz.exe",
            "Detection": {"Name": "Attacker Tool - Mimikatz", "Criticality": "High", "RuleID": "DR-1"},
            "OSPath": "C:\\Temp\\mimikatz.exe", "Disposition": "Retained", "LocationContext": "Other",
            "SITimestamps": {"Created0x10": "2026-01-01T00:00:00Z"},
            "FNTimestamps": {"Created0x30": "2026-01-02T00:00:00Z"}})
        self.assertEqual(len(ev), 1)
        self.assertIn("Attacker Tool - Mimikatz", ev[0].label)
        self.assertEqual(ev[0].first_seen[:10], "2026-01-02")

    def test_amcache(self):
        ev = self._map("DetectRaptor.Windows.Detection.Amcache", {
            "RuleID": "DR-2", "DetectionName": "Credential Theft", "FileName": "x.exe", "OSPath": "c:\\temp\\x.exe",
            "Detection": {"Name": "Credential Theft", "Criticality": "High"},
            "KeyMTime": "2026-01-03T00:00:00Z", "EntryName": "x.exe", "EntryPath": "c:\\temp\\x.exe", "SHA1": "a" * 40})
        self.assertTrue(ev)
        self.assertTrue(any("Credential Theft" in e.label and "x.exe" in e.label for e in ev))


if __name__ == "__main__":
    unittest.main()
