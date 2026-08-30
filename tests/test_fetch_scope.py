"""Every Velociraptor path retrieves only the artifacts we can map.

Half the evidence store was rows nothing could read: measured across this
appliance's payloads, 581 MB of 1,158 MB was artifacts SUPPORTED_ARTIFACTS
excludes and always will — including a 403 MB Windows.NTFS.MFT dump of 354,831
rows that produces exactly zero entities. Retrieving them cost collection time,
disk, and the json.load that OOM-killed the backend.

THE COLLECTION IS UNTOUCHED. Every blueprint artifact still runs on the endpoint
and still lands in Velociraptor; blueprints are not trimmed. Only the retrieval
INTO the appliance is scoped, so an artifact that later gains a mapper is one
Fetch away.

That holds for the offline collector too, which is not obvious: its ZIP is
deleted after import (importer.py os.remove), so raw_results.json looks like the
only copy. It is not — the import runs Velociraptor's own import and gets a
HuntId back, so the collector's contents live in Velociraptor exactly like a
collection. Verified on this appliance: the hunt an upload created,
H.DA9TC7LTQRN9S, was adopted into a fresh case afterwards and returned all
188,790 rows.

An earlier attempt filtered at WRITE time instead — fetch everything, discard on
save. That was reverted: it wasted the fetch, and it broke the case-bundle
contract, which requires the payload to travel so a future release with a wider
allowlist can re-fuse an imported case (case_bundle.py). Scoping the fetch has
neither problem, because Velociraptor keeps the original.
"""

import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND = os.path.join(ROOT, "modules/backend")

# every path that pulls rows out of Velociraptor -> how many call sites
PATHS = {
    "services/agentic/pipeline/_runners.py": ("live collection / hunt", 1),
    "routes/dashboard_routes.py": ("the Fetch button (hunt + flow branches)", 2),
    "routes/velociraptor_routes.py": ("adopt by flow/hunt id", 2),
    "routes/upload_routes.py": ("offline-collector import read-back", 2),
}


def read(rel):
    with open(os.path.join(BACKEND, rel), encoding="utf-8") as fh:
        return fh.read()


class TestEveryPathIsScoped(unittest.TestCase):

    def test_each_velociraptor_path_asks_only_for_mappable_artifacts(self):
        for rel, (what, n) in PATHS.items():
            with self.subTest(path=what):
                src = read(rel)
                self.assertEqual(src.count("only_artifacts=SUPPORTED_ARTIFACTS"), n,
                                 f"{what} must scope every retrieval")

    def test_no_path_was_missed(self):
        """A new retrieval that forgets to scope is the bug coming back."""
        for rel, (what, _) in PATHS.items():
            with self.subTest(path=what):
                src = read(rel)
                for call in re.findall(r"get_existing_collection_results\((?:[^()]|\([^()]*\))*\)", src):
                    self.assertIn("only_artifacts", call,
                                  f"unscoped retrieval in {rel}: {call[:90]}")


class TestTheCollectionItselfIsUntouched(unittest.TestCase):
    """Scoping the READ must never become scoping what the endpoint gathers —
    the operator chose those artifacts and an analyst pivots them in
    Velociraptor."""

    def test_blueprints_are_not_filtered(self):
        """The launch must pass the blueprint's own `artifacts`, unfiltered.
        (Slicing at the first 'stream_collect_and_analyze' would hit the import
        at the top of the file and search an empty string — use the CALL.)"""
        src = read("services/agentic/pipeline/_runners.py")
        launch = src[:src.index("all_results, timed_out = stream_collect_and_analyze")]
        self.assertIn("create_collections(run_id, artifacts", launch,
                      "the collection must still be created with the FULL "
                      "blueprint artifact list")

    def test_every_retrieval_site_in_the_stream_collector_is_scoped(self):
        """There are TWO retrieval loops — the poll and the closing 'Final:'
        pass that picks up whatever landed after the last poll. Scoping only the
        poll left the second one pulling everything: a live BestPractice
        collection still landed 25 unmappable sources. Count the query calls and
        require a scope check for each."""
        src = read("services/agentic/collectors/_stream.py")
        queries = src.count("rows = query_artifact_results(")
        guards = src.count("_keep_source(source_name, only_artifacts)")
        self.assertEqual(guards, queries,
                         f"{queries} retrieval site(s) but only {guards} scoped — "
                         f"an unscoped one pulls artifacts we cannot map")

    def test_the_stream_collector_defaults_to_taking_everything(self):
        """A caller that does not scope must still get everything — the filter
        is something you ask for, never something you inherit."""
        src = read("services/agentic/collectors/_stream.py")
        sig = re.search(r"def stream_collect_and_analyze\(([\s\S]*?)\):", src).group(1)
        self.assertIn("only_artifacts=None", sig.replace(" ", "").replace("\n", ""))


class TestTheBaseNameRuleIsRight(unittest.TestCase):
    """Sub-sources and export prefixes must resolve to their base artifact, or
    'Windows.Forensics.SAM/Parsed' would never match 'windows.forensics.sam'."""

    def setUp(self):
        import ast
        src = read("services/agentic/collectors/_stream.py")
        node = next(n for n in ast.parse(src).body
                    if isinstance(n, ast.FunctionDef) and n.name == "_keep_source")
        ns = {}
        exec(compile(ast.Module(body=[node], type_ignores=[]), "_stream.py", "exec"), ns)
        self.keep = ns["_keep_source"]
        self.allow = {"windows.forensics.sam", "windows.hayabusa.rules"}

    def test_a_sub_source_matches_its_base_artifact(self):
        self.assertTrue(self.keep("Windows.Forensics.SAM/Parsed", self.allow))
        self.assertTrue(self.keep("Windows.Forensics.SAM/CreateTimes", self.allow))

    def test_an_export_prefix_is_stripped(self):
        self.assertTrue(self.keep("All Windows.Hayabusa.Rules", self.allow))

    def test_an_unmapped_artifact_is_rejected(self):
        for name in ("Windows.NTFS.MFT", "Windows.Forensics.Usn",
                     "Generic.Forensic.SQLiteHunter/Chromium Browser History_Visits"):
            with self.subTest(artifact=name):
                self.assertFalse(self.keep(name, self.allow))

    def test_matching_is_case_insensitive(self):
        self.assertTrue(self.keep("WINDOWS.HAYABUSA.RULES", self.allow))


class TestYaraWebshellIsUsable(unittest.TestCase):
    """A webshell on disk must reach the analyst, and say which file it is.

    Admitting DetectRaptor.Generic.Detection.YaraWebshell to the allowlist was
    not enough on its own — two things in the yara branch made it useless:

      * the id was (asset, rule, pid). A FILE scan has no pid, so it degenerated
        to (asset, rule) and every file matching one signature collapsed into a
        single node. Verified on a live endpoint: three distinct webshells under
        C:\\AtomicRedTeam\\atomics\\T1505.003 — b.jsp, tests.jsp, cmd.aspx — and
        the path was never stored, so nothing said WHICH file matched.
      * a yarahit only became a finding through the CROSS-HOST path
        (correlate.py: type in ("ioc","account","yarahit") and >= 2 assets), so a
        signature hit on ONE host produced no timeline row at all.

    Its sibling Generic.Detection.YaraFile stays OUT: measured on the same flow,
    all 1,654 of its hits were on C:\\pagefile.sys — string coincidences in
    swapped-out memory, matching rules like GODMODERULES_IDDQD_God_Mode_Rule
    (311) and Coinminer_Strings (97). Admitting it would add five times the
    whole graph in noise from one file.
    """

    def setUp(self):
        self.src = read("services/fusion/mappers/agentic.py")
        i = self.src.index('elif "yara" in an:')
        # to the next sibling branch (12-space `elif`), not a fixed char window —
        # the branch grew when memory scans were added and a window truncated it.
        j = self.src.index("\n            elif ", i + 1)
        self.branch = self.src[i:j]
        self.code = "\n".join(l for l in self.branch.splitlines()
                              if not l.lstrip().startswith("#"))

    def test_the_webshell_artifact_is_admitted(self):
        self.assertIn("detectraptor.generic.detection.yarawebshell", self.src)

    def test_its_noisy_sibling_is_not(self):
        self.assertNotIn("detectraptor.generic.detection.yarafile", self.src,
                         "YaraFile matched 1,654 times on pagefile.sys alone")

    def test_the_file_is_part_of_the_identity(self):
        """Without the path, three webshells matching one rule are one node."""
        self.assertIn("ypath", self.code)
        self.assertIn("yarahit_id(asset, rule, pid if pid is not None else (ypath",
                      self.code)

    def test_the_path_is_stored_so_the_analyst_can_see_the_file(self):
        self.assertIn("path=str(ypath)", self.code)

    def test_a_single_host_hit_still_reaches_the_timeline(self):
        """The timeline renders findings, and a finding needs this flag."""
        self.assertIn('flags=["detection"]', self.code)
        self.assertIn('YARA:', self.code)


class TestSimulatedDetectionsAreAdmittedAndUsable(unittest.TestCase):
    """Five empty DetectRaptor artifacts were triggered on a live Windows host
    (DESKTOP-566AT85) and mapped; three needed wiring beyond an allowlist line.

    Live results, min_severity=informational:
        MFT.Erasing.Tools  6 rows -> 6 dated MEDIUM findings (Criticality)
        NamedPipes         4 rows -> 4 dated HIGH  findings (already wired)
        ISEAutoSave        2 rows -> 2 dated HIGH  findings (ATT&CK T1059.001)

    Two fired but were left OUT:
        YaraProcessWin    18 rows -> mapped, but undated (a memory match has no
                                     event time) and the default FireEye/
                                     SIGNATURE_BASE ruleset is a known FP source
                                     against benign process memory — the YaraFile
                                     failure mode. A rigged plant proved only the
                                     plumbing; real signal-to-noise was unmeasured.
        LolRMM             1 row  -> weak LOW node; dual-use, noisy, and the
                                     mapper drops its RMM context.
    """

    def setUp(self):
        self.src = read("services/fusion/mappers/agentic.py")

    def test_the_two_new_artifacts_are_admitted(self):
        for base in ("detectraptor.windows.detection.powershell.iseautosave",
                     "detectraptor.windows.detection.mft.erasing.tools"):
            self.assertIn(base, self.src)

    def test_the_rejected_artifacts_are_not_admitted(self):
        """YaraProcessWin (undated + noisy, the YaraFile failure mode) and LolRMM
        (weak, dual-use) both fired in the simulation but stay out of fusion."""
        self.assertNotIn("detectraptor.windows.detection.yaraprocesswin", self.src)
        self.assertNotIn("detectraptor.windows.detection.lolrmm", self.src)

    def _branch(self, head):
        i = self.src.index(head)
        j = self.src.index("\n            elif ", i + 1)
        return "\n".join(l for l in self.src[i:j].splitlines()
                         if not l.lstrip().startswith("#"))

    def test_iseautosave_takes_its_timestamp_from_fileinfo(self):
        """The date is nested in FileInfo.Mtime; first_ts()'s top-level spec
        misses it, so the branch must read it explicitly or land undated."""
        code = self._branch('elif "iseautosave" in an')
        self.assertIn('r.get("FileInfo")', code)
        self.assertIn("Mtime", code)
        self.assertIn("keys.norm_ts", code)
        self.assertIn('flags=["detection"]', code)

    def test_erasing_tools_promote_to_the_timeline(self):
        """Anti-forensic tooling is the deliberate exception to the MFT branch's
        BAU rule: it gets the 'detection' flag; the general MFT artifact does
        not (its rules fire on routine files like OneDrive uploads)."""
        code = self._branch('elif "mft" in an and ("detection" in an or "erasing" in an)')
        self.assertIn('erasing = "erasing" in an', code)
        self.assertIn('flags=["detection"] if erasing else ["mft_detection"]', code)
