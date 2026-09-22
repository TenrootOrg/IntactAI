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


def _sigma(title, ts="2026-09-01T07:20:51Z", level="high", computer=HOST, record=1,
           channel="Security", eid=1102, event=None):
    r = {"ClientId": CID, "Timestamp": ts, "Computer": computer, "Channel": channel,
         "EID": eid, "Level": level, "Title": title, "RecordID": record, "Details": ""}
    if event:
        r["_Event"] = event
    return r


def _psblock(sbid, part=1):
    return {"EventData": {"ScriptBlockId": sbid, "MessageNumber": part, "MessageTotal": 2,
                          "ScriptBlockText": "…"}}


def _detectraptor(rule, ts, sbid=None, eid=4104, computer=HOST, part=1):
    r = {"ClientId": CID, "EventTime": ts, "Computer": computer,
         "Channel": "Microsoft-Windows-PowerShell/Operational", "EventID": eid,
         "Detection": {"Name": rule}, "Message": "Creating Scriptblock text"}
    if sbid:
        r["EventData"] = _psblock(sbid, part)["EventData"]
    return r


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
            _sigma("Log Cleared"), _sigma("Unrelated Rule", ts="2026-09-02T01:00:00Z", record=2)]})
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


class OneWindowsEventIsOneRow(unittest.TestCase):
    """"The same event" is what Windows wrote (script-block id, record id), never
    the second alone — one second at 03:02:24 on a QA case held ~20 different
    PowerShell script blocks, and the System and Security logs were cleared in the
    same second as two different events."""

    PS = "Microsoft-Windows-PowerShell/Operational"

    def test_two_logs_cleared_in_the_same_second_are_two_events(self):
        g = _fuse({"Windows.Hayabusa.Rules": [
            _sigma("Important Log File Cleared", channel="System", eid=104, record=973),
            _sigma("Important Windows Eventlog Cleared", channel="System", eid=104, record=973),
            _sigma("Log Cleared", record=18723), _sigma("Security Eventlog Cleared", record=18723)]})
        self.assertEqual(2, len(g.findings), [f.title for f in g.findings])
        self.assertTrue(all("(+1 related)" in f.title for f in g.findings))

    def test_two_detectors_on_one_script_block_are_one_row(self):
        g = _fuse({
            "Windows.Hayabusa.Rules": [_sigma("Suspicious PowerShell Invocations - Specific",
                                              ts="2026-09-01T07:42:33.295Z", channel=self.PS,
                                              eid=4104, record=934, event=_psblock("E1B4", 2))],
            "DetectRaptor.Windows.Detection.Evtx": [
                _detectraptor("T1059.001-Mimikatz Execution via PowerShell", "2026-09-01T07:42:33Z",
                              sbid="{e1b4}", part=2)]})
        rows = [f for f in g.findings if f.kind == "single"]
        self.assertEqual(1, len(rows), [f.title for f in rows])
        self.assertIn("(+1 related)", rows[0].title)

    def test_different_script_blocks_in_the_same_second_stay_apart(self):
        g = _fuse({"DetectRaptor.Windows.Detection.Evtx": [
            _detectraptor("T1059.001-PowerShell Web Request", "2026-09-01T07:42:33Z", sbid="aaaa"),
            _detectraptor("T1059.001-Use of Base64 Commands", "2026-09-01T07:42:33Z", sbid="bbbb")]})
        self.assertEqual(2, len(g.findings), [f.title for f in g.findings])

    def test_without_an_id_only_a_single_candidate_within_a_minute_joins(self):
        one = _fuse({
            "Windows.Hayabusa.Rules": [_sigma("Windows Defender Threat Detection Disabled",
                                              channel="Microsoft-Windows-Windows Defender/Operational",
                                              eid=5001, record=381)],
            "DetectRaptor.Windows.Detection.Evtx": [dict(
                _detectraptor("T1562.001-Win Defender Disabled", "2026-09-01T07:21:30Z", eid=5001),
                Channel="Microsoft-Windows-Windows Defender/Operational")]})
        self.assertEqual(1, len(one.findings), [f.title for f in one.findings])
        # Three rules, one second, no id: which of them saw the same event is
        # unknowable, so none are folded (live: three commands in one PSReadline
        # history file all carry the file's time).
        two = _fuse({"DetectRaptor.Windows.Detection.Evtx": [
            _detectraptor(n, "2026-06-18T12:41:34Z", eid=None)
            for n in ("T1059.001-Mimikatz Execution via PowerShell",
                      "T1059.001-Use of Base64 Commands", "C2-Powershell Socket Connection")]})
        self.assertEqual(3, len(two.findings), [f.title for f in two.findings])

    def test_an_event_already_on_its_own_row_is_not_repeated_in_a_burst(self):
        ents, rels = map_agentic({
            "Windows.Hayabusa.Rules": [
                _sigma("Usage Of Web Request Commands And Cmdlets - ScriptBlock", level="medium",
                       ts="2025-12-05T03:02:24.98Z", channel=self.PS, eid=4104, record=500,
                       event=_psblock("cccc")),
                _sigma("Uncommon PowerShell Hosts", level="medium", ts="2025-12-05T03:03:00Z",
                       channel=self.PS, eid=4104, record=501),
                _sigma("A Rule Has Been Deleted From The Windows Firewall Exception List",
                       level="medium", ts="2025-12-05T03:04:00Z", record=502),
                _sigma("WMI Persistence", level="medium", ts="2025-12-05T03:05:00Z", record=503)],
            "DetectRaptor.Windows.Detection.Evtx": [
                _detectraptor("T1059.001-PowerShell Web Request", "2025-12-05T03:02:24Z", sbid="cccc")]},
            run_id="r1", hostnames=HOSTNAMES)
        g = correlate.assemble("c", [(ents, rels)], ["r1"], min_severity="medium",
                               window={"start": "2025-12-01T00:00:00", "end": "2025-12-31T00:00:00"})
        burst = [f for f in g.findings if f.title.startswith("Coordinated")]
        members = {g.entities[i].attrs.get("title") for f in burst for i in f.entity_ids}
        self.assertNotIn("Usage Of Web Request Commands And Cmdlets - ScriptBlock", members,
                         "DetectRaptor's row already shows that script block")


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



class ActivityBeforeTheCurrentName(unittest.TestCase):
    """A QA machine was built from an image named WIN-UK1GV882OK6 in December and
    renamed DESKTOP-16OJFO6 in August. The report read the image build as a
    possible earlier compromise."""

    def _renamed(self, old_ts="2025-12-05T03:26:42Z"):
        return _fuse({"Windows.Hayabusa.Rules": [
            _sigma("Security Eventlog Cleared", ts=old_ts, computer=OLD),
            _sigma("Credential Dumping Tools Accessing LSASS Memory", ts="2026-09-01T08:01:17Z")]})

    def test_old_name_activity_that_ended_before_the_rename_is_marked(self):
        g = self._renamed()
        old = next(f for f in g.findings if "(logged as" in f.title)
        cur = next(f for f in g.findings if "(logged as" not in f.title)
        self.assertTrue(g.before_current_name(old))
        self.assertFalse(g.before_current_name(cur))
        hist = g.entities[f"asset:endpoint:{CID}"].attrs["name_history"]
        self.assertEqual([OLD, HOST], [h["name"] for h in hist])
        self.assertTrue(hist[0]["previous"])

    def test_current_activity_is_listed_first_and_nothing_is_downgraded(self):
        g = self._renamed()
        self.assertNotIn("(logged as", g.findings[0].title)
        self.assertEqual({"high"}, {f.severity for f in g.findings})

    def test_an_old_name_still_in_use_after_the_rename_is_not_marked(self):
        g = self._renamed(old_ts="2026-09-02T10:00:00Z")      # after the current name appeared
        self.assertFalse(any(g.before_current_name(f) for f in g.findings))
        hist = g.entities[f"asset:endpoint:{CID}"].attrs["name_history"]
        self.assertFalse(hist[0]["previous"])

    def test_the_report_writer_receives_the_marker_and_the_history(self):
        g = self._renamed()
        p = render.distilled(g)
        marked = [f for f in p["findings"] if f.get("before_current_name")]
        self.assertEqual(1, len(marked))
        self.assertIn("(logged as", marked[0]["title"])
        unmarked = [f for f in p["findings"] if "before_current_name" not in f]
        self.assertEqual(1, len(unmarked), "current findings keep exactly their old fields")
        self.assertTrue(any(r.get("name_history") for r in p["host_coverage"]))

    def test_a_row_with_no_machine_name_inside_an_earlier_name_period_is_marked(self):
        """MFT rows record no computer. An erasing tool dated during the image build
        belongs to it; one dated after the rename does not."""
        rows = {"Windows.Hayabusa.Rules": [
                    _sigma("Security Eventlog Cleared", ts="2025-12-05T02:40:00Z", computer=OLD),
                    _sigma("Important Log File Cleared", ts="2025-12-05T03:30:00Z", computer=OLD),
                    _sigma("Credential Dumping Tools Accessing LSASS Memory", ts="2026-09-01T08:01:17Z")],
                "DetectRaptor.Windows.Detection.MFT.Erasing.Tools": [
                    {"ClientId": CID, "EventTime": "2025-12-05T02:47:30Z", "OSPath": "C:\\Tools\\sdelete.exe",
                     "Detection": {"Name": "Erasing Tools", "Criticality": "Medium"}},
                    {"ClientId": CID, "EventTime": "2026-09-02T10:00:00Z", "OSPath": "C:\\Tools\\eraser.exe",
                     "Detection": {"Name": "Erasing Tools", "Criticality": "Medium"}}]}
        g = _fuse(rows, min_severity="informational")
        mft = {e.attrs.get("path") or e.label: "previous_name" in e.flags
               for e in g.entities.values() if e.type == "event" and "erasing" in str(e.attrs.get("artifact", "")).lower()}
        inside = [v for k, v in mft.items() if "sdelete" in str(k).lower()]
        outside = [v for k, v in mft.items() if "eraser" in str(k).lower()]
        self.assertEqual([True], inside, mft)
        self.assertEqual([False], outside, mft)

    def test_every_report_prompt_carries_the_rule(self):
        with open(os.path.join(ROOT, "modules/backend/services/fusion/llm_sim.py"), encoding="utf-8") as f:
            self.assertEqual(3, f.read().count("before_current_name=true"))

    def test_limitations_names_the_earlier_names(self):
        g = self._renamed()
        assets = [e for e in g.entities.values() if e.type == "asset"]
        md = render._limitations_md(g, assets, g.findings)
        self.assertIn(f"was previously recorded as {OLD}", md)
        self.assertIn("1 finding(s) predate its current name", md)

    def test_a_failure_in_the_pass_costs_nothing_else(self):
        """Hostile attrs on one entity must not stop the fuse or lose findings."""
        ents, rels = map_agentic({"Windows.Hayabusa.Rules": [
            _sigma("Security Eventlog Cleared", ts="2025-12-05T03:26:42Z", computer=OLD),
            _sigma("Credential Dumping Tools Accessing LSASS Memory", ts="2026-09-01T08:01:17Z")]},
            run_id="r1", hostnames=HOSTNAMES)
        ents.append(schema.Entity(id="event:odd", type="event", label="odd", severity="high",
                                  first_seen="not-a-date", attrs={"recorded_host": ["x"], "_assets": [f"asset:endpoint:{CID}"]}))
        errors = []
        g = correlate.assemble("c", [(ents, rels)], ["r1"], min_severity="medium", errors=errors)
        self.assertEqual(2, len([f for f in g.findings if f.title.startswith("SIGMA:")]), errors)


class CoordinatedActivityIsOneBurst(unittest.TestCase):
    """69 detections over nine months were called one coordinated burst, and the row
    was named "Coordinated suspicious activity" — which says nothing about what
    fired, for how long, or why it is one row (QA TASK-12667)."""

    WINDOW = {"start": "2016-01-01T00:00:00Z", "end": None}

    def _rows(self, day, titles, computer=HOST):
        return [_sigma(t, ts=f"{day}T07:{10 + i:02d}:00Z", level="medium", computer=computer,
                       record=hash((day, t)) % 100000)
                for i, t in enumerate(titles)]

    def _fuse_window(self, rows):
        ents, rels = map_agentic({"Windows.Hayabusa.Rules": rows}, run_id="r1", hostnames=HOSTNAMES)
        g = correlate.assemble("c", [(ents, rels)], ["r1"], min_severity="medium", window=self.WINDOW)
        return [f for f in g.findings if f.kind == "derived" and f.title.startswith("Burst of")]

    def test_the_row_says_what_fired_and_for_how_long(self):
        coord = self._fuse_window(self._rows(
            "2026-09-01", ["Suspicious PowerShell Invocation", "Security Eventlog Cleared",
                           "LSASS Access"]))
        self.assertEqual(1, len(coord))
        self.assertEqual("Burst of 3 detections in 2 min — LSASS Access, Security Eventlog "
                         f"Cleared, Suspicious PowerShell Invocation on {HOST}", coord[0].title)
        self.assertIn("too low-severity to reach the timeline on its own", coord[0].summary)
        self.assertIn("T1003", coord[0].mitre, "the techniques it spans, for filters")

    def test_hours_of_quiet_end_a_burst(self):
        """At a WEEK, one row covered six days and 32 detections on a live case."""
        coord = self._fuse_window(
            self._rows("2026-09-01", ["Suspicious PowerShell Invocation", "Security Eventlog Cleared",
                                      "LSASS Access"])
            + self._rows("2026-09-04", ["Encoded Command Seen", "Defender Disable Attempt",
                                        "Mimikatz Detected"]))
        self.assertEqual(2, len(coord), [f.title for f in coord])

    def test_diversity_is_measured_in_attack_techniques_not_words(self):
        """The old gate was a keyword list of Windows PowerShell/LSASS words —
        nothing from another source could ever match it."""
        one_technique = self._fuse_window(self._rows(
            "2026-09-01", ["Suspicious PowerShell Invocation", "Powershell Encoded Command",
                           "Malicious PowerShell Commandlets"]))
        self.assertEqual([], one_technique, "three names, one technique, is not a pattern")
        named = self._fuse_window(self._rows(
            "2026-09-01", ["Suspicious PowerShell Invocation", "LSASS Access",
                           "Security Eventlog Cleared"]))
        self.assertEqual(1, len(named))

    def test_a_source_with_no_techniques_needs_more_detections(self):
        few = self._fuse_window(self._rows("2026-09-01", ["Odd Thing A", "Odd Thing B", "Odd Thing C"]))
        self.assertEqual([], few, "nothing maps to a technique — three names prove nothing")
        many = self._fuse_window(self._rows(
            "2026-09-01", [f"Odd Thing {c}" for c in "ABCDE"]))
        self.assertEqual(1, len(many))

    def test_a_burst_under_an_old_name_is_labelled_and_kept_apart(self):
        coord = self._fuse_window(
            self._rows("2025-12-05", ["Suspicious PowerShell Invocation", "Security Eventlog Cleared",
                                      "LSASS Access"], computer=OLD)
            + self._rows("2026-09-01", ["Encoded Command Seen", "Defender Disable Attempt",
                                        "Mimikatz Detected"]))
        self.assertEqual(2, len(coord), [f.title for f in coord])
        self.assertTrue(any(f"(logged as {OLD})" in f.title for f in coord), [f.title for f in coord])


if __name__ == "__main__":
    unittest.main(verbosity=2)
