"""Two different files must not be the same event.

`keys.event_id(asset, ts, msg)` runs its SECOND argument through `norm_ts`, which
ends in `if "T" in s: return s[:19]`. Twenty mapper call sites were passing
`f"{asset}:{path}"` there to make the id unique. Every such string contains a "T"
(in "asset:endpoinT"), so norm_ts took the ISO branch and truncated it to a
19-character constant — the asset prefix — deleting the path from the identity.

Measured on a real 9-host case before the fix:

    DetectRaptor.Windows.Detection.MFT           516 rows ->  69 nodes  (86.6% lost)
    DetectRaptor.Windows.Detection.BinaryRename   38 rows ->  14 nodes
    DetectRaptor.Windows.Detection.Evtx        2,960 rows -> 2,080 nodes

One MFT node fused AdFind.exe, PingCastle.exe, ADRecon.ps1 and Everything.exe
across twelve months into a single dated point; BinaryRename merged a
$Recycle.Bin copy of AdFind — deleted-evidence — into a benign one.

`keys.event_key` takes its discriminating parts explicitly and variadically, so
nothing can be smuggled into a timestamp slot.
"""

import os
import types
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KEYS = os.path.join(ROOT, "modules/backend/services/fusion/keys.py")


def _load_keys():
    """Exec keys.py standalone. It is stdlib-only and deliberately has no
    intra-fusion imports (see its docstring), so it loads without dragging in
    the backend — importing services.fusion would need yaml, grpc and the rest."""
    mod = types.ModuleType("keys_under_test")
    mod.__file__ = KEYS
    with open(KEYS, encoding="utf-8") as fh:
        exec(compile(fh.read(), KEYS, "exec"), mod.__dict__)
    return mod


keys = _load_keys()

ASSET = "asset:endpoint:C.c646d74ad4a35aad"


class TestTheOldTrapIsStillThere(unittest.TestCase):
    """Document the behaviour that made the bug, so nobody 'simplifies' it back."""

    def test_norm_ts_truncates_any_string_containing_a_T(self):
        got = keys.norm_ts(f"{ASSET}:C:\\Tenroot\\AD-Assess\\Bin\\AdFind.exe")
        self.assertEqual(got, "asset:endpoint:C.c6")
        self.assertEqual(len(got), 19)

    def test_event_id_still_collapses_when_misused(self):
        """event_id is not being changed — it is a timestamp API and behaves
        correctly for one. This is why the CALL SITES had to move."""
        a = keys.event_id(ASSET, f"{ASSET}:C:\\a\\AdFind.exe", "binrename:AdFind.exe")
        b = keys.event_id(ASSET, f"{ASSET}:C:\\$Recycle.Bin\\AdFind.exe",
                          "binrename:AdFind.exe")
        self.assertEqual(a, b, "unchanged: misusing the ts slot still collapses")


class TestEventKeySeparatesWhatIsActuallyDifferent(unittest.TestCase):

    def test_two_paths_are_two_events(self):
        a = keys.event_key(ASSET, "binrename:AdFind.exe", "C:\\a\\AdFind.exe")
        b = keys.event_key(ASSET, "binrename:AdFind.exe", "C:\\$Recycle.Bin\\AdFind.exe")
        self.assertNotEqual(a, b,
                            "the $Recycle.Bin copy is deleted-evidence, not the same file")

    def test_the_same_file_is_one_event(self):
        """Re-collecting the same host must still collapse to one node."""
        p = "C:\\Windows\\Temp\\evil.exe"
        self.assertEqual(keys.event_key(ASSET, "mft:Suspicious Location", p),
                         keys.event_key(ASSET, "mft:Suspicious Location", p))

    def test_the_same_file_on_another_host_is_a_separate_event(self):
        other = "asset:endpoint:C.0000000000000000"
        p = "C:\\Windows\\Temp\\evil.exe"
        self.assertNotEqual(keys.event_key(ASSET, "mft:x", p),
                            keys.event_key(other, "mft:x", p))

    def test_different_rules_on_one_file_stay_separate(self):
        """A file can trip several DetectRaptor rules; each is its own finding.
        Measured: one Evtx node carried six different rule names."""
        p = "C:\\tmp\\a.ps1"
        self.assertNotEqual(keys.event_key(ASSET, "evtx:msg", "ts", "T1059.001-Base64"),
                            keys.event_key(ASSET, "evtx:msg", "ts", "T1003-Mimikatz"))

    def test_empty_and_none_parts_are_skipped_not_stringified(self):
        """PSReadline's FullPath is None on every row; a literal 'None' in the key
        would be silent noise that still collides."""
        self.assertEqual(keys.event_key(ASSET, "ps:whoami", None, ""),
                         keys.event_key(ASSET, "ps:whoami"))

    def test_the_id_is_shaped_like_every_other_event_id(self):
        k = keys.event_key(ASSET, "mft:x", "C:\\a")
        self.assertTrue(k.startswith(f"event:{ASSET}:"))
        self.assertEqual(len(k.rsplit(":", 1)[1]), 16)


class TestNoCallSiteStillMisusesTheTimestampSlot(unittest.TestCase):
    """The fix is only complete if none of the twenty sites came back."""

    def test_the_agentic_mapper_passes_no_asset_into_a_timestamp(self):
        src = open(os.path.join(ROOT, "modules/backend/services/fusion/mappers/agentic.py"),
                   encoding="utf-8").read()
        self.assertNotIn('event_id(asset, f"{asset}', src,
                         "a call site is smuggling the asset into the ts slot again")


class TestSigmaFoldsInsteadOfCopying(unittest.TestCase):
    """Fusion reduces. The Hayabusa branch was not reducing at all.

    Its event id carried RecordID — unique per event-log record — so it emitted
    ONE ENTITY PER ROW. Measured on a 9-host import: 183,436 sigma rows became
    183,738 graph nodes for 534 distinct (host, rule) pairs. A 344:1
    over-production, in the component whose entire job is to shrink evidence
    into a case graph.

    156,017 of those rows are Level "informational", which is why lowering a
    case's severity filter to informational built 71,375 relationships and
    exhausted a 15 GB appliance until the kernel killed the backend.

    Folding by id ALONE would not have worked: upsert preserves forensic
    integrity by parking conflicting attr values in `<k>_observations` lists, so
    183k merges would have grown 183k-element lists instead of collapsing. The
    rows are folded in the mapper, keeping an occurrence count, the true first
    and last times, and the loudest row as the exemplar.

    After: 188,790 rows -> 7,813 entities (24:1), 3,247 relationships,
    534 sigma nodes, peak RSS 1.70 GB.
    """

    @staticmethod
    def _sigma_branch_code():
        """The sigma branch with comments stripped — the comment BLOCK there
        explains the bug and names RecordID, so a raw substring check matches
        the explanation rather than the code."""
        src = open(os.path.join(ROOT,
                   "modules/backend/services/fusion/mappers/agentic.py"),
                   encoding="utf-8").read()
        i = src.index('elif "hayabusa" in an or "sigma" in an:')
        branch = src[i:i + 3000]
        return "\n".join(l for l in branch.splitlines()
                          if not l.lstrip().startswith("#"))

    def test_the_id_no_longer_carries_a_per_record_discriminator(self):
        """RecordID in the id is what made it one-node-per-row."""
        self.assertNotIn("RecordID", self._sigma_branch_code(),
                         "RecordID back in the sigma id means one node per row again")

    def test_the_branch_folds_rather_than_appending_per_row(self):
        branch = self._sigma_branch_code()
        self.assertIn("sigma_agg", branch, "the sigma branch must fold, not append")
        self.assertNotIn("ents.append(ev)", branch,
                         "a per-row append in this branch is the bug returning")

    def test_every_folded_row_is_still_counted(self):
        """Folding must not lose evidence — the count is how 183,436 rows stay
        accounted for behind 534 nodes."""
        src = open(os.path.join(ROOT,
                   "modules/backend/services/fusion/mappers/agentic.py"),
                   encoding="utf-8").read()
        self.assertIn("occurrences=n", src,
                      "folded sigma entities must carry their occurrence count")
