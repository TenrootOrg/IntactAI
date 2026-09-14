"""What an analyst sees from a real Velociraptor collection must be right, not just
produced.

A QA collection (one Windows endpoint, 4,586 rows) fused without error on main,
and still read badly:

  - 135 links mapped, 4 kept: the severity floor removed every process a
    detection was about, and the links went with it;
  - 31 findings for what was 5 moments of activity (a single log clear fired four
    SIGMA rules), and one cmd.exe copied under five names was five findings;
  - 28% of Hayabusa rows were logged under the image's old computer name and
    were all attributed to the collecting host without a word;
  - the same local account appeared as `host\\administrator` and `administrator`;
  - 26 of 31 findings had no ATT&CK technique;
  - SAM/Parsed rows produced nothing;
  - merging two already-merged entities nested an observation list in itself.

Synthetic rows below have the shape of that collection. Each class pins one fix.
"""

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for p in ("/app", os.path.join(ROOT, "modules", "backend"), os.path.join(ROOT, "tests")):
    if p not in sys.path:
        sys.path.insert(0, p)
import _optional_deps  # noqa: F401,E402

from services.fusion import correlate, render, schema  # noqa: E402
from services.fusion.mappers.agentic import map_agentic  # noqa: E402

CID, HOST, OLD = "C.1", "DESKTOP-A", "WIN-OLD"
HOSTNAMES = {CID: HOST}


def _fuse(collected, min_severity="medium"):
    ents, rels = map_agentic(collected, run_id="r1", hostnames=HOSTNAMES)
    errors = []
    g = correlate.assemble("case", [(ents, rels)], ["r1"], min_severity=min_severity, errors=errors)
    assert not errors, errors
    return g


def _sigma(title, ts="2026-09-01T07:20:51Z", level="high", computer=HOST):
    return {"ClientId": CID, "Timestamp": ts, "Computer": computer, "Channel": "Security",
            "EID": 1102, "Level": level, "Title": title, "RecordID": 1, "Details": ""}


class LinkedContextSurvivesTheSeverityFloor(unittest.TestCase):

    def _graph(self, n_procs=3):
        g_ents = [schema.Entity(id="event:hi", type="event", label="SIGMA: bad", severity="high",
                                anomaly=50, first_seen="2026-09-01T07:00:00Z", flags=["sigma"],
                                attrs={"_assets": ["asset:a"], "title": "bad"})]
        rels = []
        for i in range(n_procs):
            g_ents.append(schema.Entity(id=f"process:{i}", type="process", label=f"p{i}",
                                        severity="informational", first_seen="2026-09-01T07:00:00Z",
                                        attrs={"_assets": ["asset:a"]}))
            rels.append(schema.Relationship(f"process:{i}", "event:hi", "event_about"))
        g_ents.append(schema.Entity(id="process:lonely", type="process", label="unlinked",
                                    severity="informational", first_seen="2026-09-01T07:00:00Z",
                                    attrs={"_assets": ["asset:a"]}))
        return correlate.assemble("c", [(g_ents, rels)], ["r"], min_severity="medium")

    def test_a_process_linked_to_a_kept_detection_is_kept_with_its_link(self):
        g = self._graph()
        self.assertIn("process:0", g.entities)
        self.assertIn("context", g.entities["process:0"].flags)
        self.assertEqual(3, sum(1 for r in g.relationships if r.dst == "event:hi"))

    def test_an_unlinked_below_floor_entity_is_still_dropped(self):
        self.assertNotIn("process:lonely", self._graph().entities)

    def test_context_is_capped_per_entity(self):
        g = self._graph(n_procs=correlate._CONTEXT_PER_ENTITY + 20)
        kept = sum(1 for e in g.entities.values() if "context" in e.flags)
        self.assertEqual(correlate._CONTEXT_PER_ENTITY, kept)

    def test_context_never_becomes_a_finding_on_its_own(self):
        g = self._graph()
        cited = {eid for f in g.findings for eid in f.entity_ids}
        self.assertFalse({"process:0", "process:1", "process:2"} & cited)


class OneMomentIsOneFinding(unittest.TestCase):

    def test_rules_firing_in_the_same_second_fold_into_one_corroborated_finding(self):
        g = _fuse({"Windows.Hayabusa.Rules": [
            _sigma("Security Eventlog Cleared"), _sigma("Important Log File Cleared"),
            _sigma("Log Cleared"), _sigma("Unrelated Rule", ts="2026-09-02T01:00:00Z")]})
        grouped = [f for f in g.findings if "(+2 related)" in f.title]
        self.assertEqual(1, len(grouped), [f.title for f in g.findings])
        f = grouped[0]
        self.assertEqual("high", f.confidence)
        for rule in ("Security Eventlog Cleared", "Important Log File Cleared", "Log Cleared"):
            self.assertIn(rule, f.summary)
        self.assertIn("T1070.001", f.mitre)
        self.assertEqual(2, len(g.findings), "the rule at another time stays its own finding")

    def test_the_group_is_named_after_its_most_specific_rule(self):
        """An AnyDesk drop was named "File Write to Suspicious Folder (+3 related)"."""
        g = _fuse({"Windows.Hayabusa.Rules": [
            _sigma("Windows Shell/Scripting Application File Write to Suspicious Folder"),
            _sigma("Suspicious Binaries and Scripts in Public Folder"),
            _sigma("Remote Access Tool - AnyDesk Silent Installation")]})
        self.assertEqual(1, len(g.findings), [f.title for f in g.findings])
        self.assertTrue(g.findings[0].title.startswith("SIGMA: Remote Access Tool - AnyDesk Silent Installation"),
                        g.findings[0].title)
        self.assertIn("T1219", g.findings[0].mitre)

    def test_one_file_under_several_names_is_one_renamed_binary_finding(self):
        rows = [{"ClientId": CID, "OSPath": f"C:\\\\Users\\\\Public\\\\{n}", "Name": n,
                 "Btime": "2026-09-01T07:2%d:00Z" % i,
                 "VersionInformation": {"OriginalFilename": "Cmd.Exe"},
                 "Hash": {"SHA256": "9" * 64, "SHA1": "a" * 40, "MD5": "c" * 32}}
                for i, n in enumerate(("w.exe", "AnyDesk.exe", "nxc.exe"))]
        g = _fuse({"DetectRaptor.Windows.Detection.BinaryRename": rows})
        renamed = [f for f in g.findings if f.title.startswith("Renamed binary")]
        self.assertEqual(1, len(renamed), [f.title for f in renamed])
        self.assertIn("Cmd.Exe copied as AnyDesk.exe, nxc.exe, w.exe", renamed[0].title)
        self.assertEqual(["T1036.003"], renamed[0].mitre)


class TheHostALogRecordedIsKept(unittest.TestCase):

    def test_rows_logged_under_another_computer_name_are_a_separate_labelled_finding(self):
        g = _fuse({"Windows.Hayabusa.Rules": [
            _sigma("Log Cleared", ts="2026-09-01T07:00:00Z"),
            _sigma("Log Cleared", ts="2025-12-05T03:26:42Z", computer=OLD)]})
        titles = sorted(f.title for f in g.findings)
        self.assertEqual([f"SIGMA: Log Cleared on {HOST}",
                          f"SIGMA: Log Cleared on {HOST} (logged as {OLD})"], titles)

    def test_the_report_says_how_many_findings_came_from_another_name(self):
        f = schema.Finding(id="f", title=f"SIGMA: Log Cleared on {HOST} (logged as {OLD})",
                           severity="high", confidence="medium", summary="", ts="2025-12-05T03:26:42Z")
        md = render._limitations_md(schema.FusionGraph(case_id="c"), [], [f])
        self.assertIn("1 finding(s) come from event logs recorded under another computer name", md)
        self.assertIn(OLD, md)


class ALocalAccountIsOneIdentity(unittest.TestCase):

    def test_host_qualified_and_bare_local_accounts_merge(self):
        g = _fuse({
            "Windows.EventLogs.CondensedAccountUsage": [
                {"ClientId": CID, "EventTime": "2026-09-01T07:00:00Z", "Computer": OLD,
                 "DomainName": OLD, "UserName": "Administrator", "EventID": 4624}],
            "Windows.Forensics.SAM/CreateTimes": [{"ClientId": CID, "Name": "Administrator"}]},
            min_severity="informational")
        accts = [e.id for e in g.entities.values() if e.type == "account"]
        self.assertEqual(1, len(accts), accts)
        self.assertNotIn("account:domain:", accts[0])

    def test_a_real_domain_account_stays_global(self):
        g = _fuse({"Windows.EventLogs.CondensedAccountUsage": [
            {"ClientId": CID, "EventTime": "2026-09-01T07:00:00Z", "Computer": HOST,
             "DomainName": "CORP", "UserName": "alice", "EventID": 4624}]},
            min_severity="informational")
        self.assertIn("account:domain:corp\\alice", g.entities)

    def test_sam_parsed_rows_fill_in_the_account(self):
        g = _fuse({"Windows.Forensics.SAM/Parsed": [
            {"ClientId": CID, "ParsedV": {"username": "vagrant", "AccountType": "Normal User"},
             "ParsedF": {"LastLoginDate": "2026-08-30T10:00:00Z", "PasswordResetDate": "2025-12-05T03:26:37Z"}}]},
            min_severity="informational")
        acct = next(e for e in g.entities.values() if e.type == "account")
        self.assertEqual("vagrant", acct.label)
        self.assertEqual("2026-08-30T10:00:00Z", acct.attrs.get("last_login"))
        self.assertEqual("Normal User", acct.attrs.get("account_type"))

    def test_the_windows_zero_date_means_never_logged_in(self):
        g = _fuse({"Windows.Forensics.SAM/Parsed": [
            {"ClientId": CID, "ParsedV": {"username": "guest", "AccountType": "Default Guest Acct"},
             "ParsedF": {"LastLoginDate": "1601-01-01T00:00:00Z", "PasswordResetDate": "1601-01-01T00:00:00Z"}}]},
            min_severity="informational")
        acct = next(e for e in g.entities.values() if e.type == "account")
        self.assertIsNone(acct.attrs.get("last_login"))
        self.assertIsNone(acct.attrs.get("password_reset"))


class MergedObservationsCombine(unittest.TestCase):

    def test_two_merged_entities_combine_their_observations(self):
        g = schema.FusionGraph(case_id="c")
        a = schema.Entity(id="ioc:h", type="ioc", label="h", sources=["x"],
                          attrs={"source_name": "w.exe",
                                 "source_name_observations": [{"value": "w.exe", "source": "prior"},
                                                              {"value": "a.exe", "source": "x"}]})
        b = schema.Entity(id="ioc:h", type="ioc", label="h", sources=["x"],
                          attrs={"source_name": "7zG.exe",
                                 "source_name_observations": [{"value": "7zG.exe", "source": "prior"},
                                                              {"value": "a.exe", "source": "x"}]})
        g.upsert(a)
        g.upsert(b)
        attrs = g.entities["ioc:h"].attrs
        self.assertNotIn("source_name_observations_observations", attrs)
        values = [o["value"] for o in attrs["source_name_observations"]]
        for name in ("w.exe", "a.exe", "7zG.exe"):
            self.assertIn(name, values)
        self.assertEqual(1, values.count("a.exe"))


class TechniquesFromRuleTitles(unittest.TestCase):

    def test_well_known_titles_map(self):
        cases = {"Security Eventlog Cleared": "T1070.001",
                 "Windows Defender Real-time Protection Disabled": "T1562.001",
                 "Credential Dumping Tools Accessing LSASS Memory": "T1003.001",
                 "Remote Access Tool - AnyDesk Silent Installation": "T1219"}
        for title, tid in cases.items():
            self.assertIn(tid, correlate._techniques_for_title(f"SIGMA: {title} on {HOST}"), title)

    def test_an_unknown_title_gets_nothing_and_the_host_is_ignored(self):
        self.assertEqual([], correlate._techniques_for_title("SIGMA: Something Unusual on POWERSHELL-HOST"))



class ExistingCasesRebuildOnce(unittest.TestCase):
    """These fixes change entity ids. A case fused before them must rebuild its
    graph on the next fuse, not add to it -- or the old and new entity for the
    same detection both survive and its finding shows twice."""

    def test_the_rebuild_signature_carries_the_engine_version(self):
        with open(os.path.join(ROOT, "modules/backend/services/fusion/store.py"), encoding="utf-8") as f:
            src = f.read()
        sig = src[src.index("def _graph_filter_signature"):src.index("def _stable_hash")]
        self.assertIn('"engine": _GRAPH_ENGINE_VERSION', sig)
        self.assertRegex(src, r"\n_GRAPH_ENGINE_VERSION = [2-9]\d*\n")


if __name__ == "__main__":
    unittest.main(verbosity=2)
