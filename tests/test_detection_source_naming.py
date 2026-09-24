"""One source, one name in the timeline.

The timeline showed these side by side on the same host:

    Evtx: T1059.001-Mimikatz Execution via PowerShell on DESKTOP-16OJFO6
    SIGMA: Important Log File Cleared (+1 related) on DESKTOP-16OJFO6

Both are Sigma rules matching Windows event logs — Hayabusa on one side,
DetectRaptor's Sigma-to-VQL pack on the other — so an analyst reading the
timeline saw one source presented as two detectors (TASK-12662).

The mapper prefixed every DetectRaptor detection with its ARTIFACT name
("Evtx:", "MFT:", "Lnk:"), while Hayabusa's own path prefixed "SIGMA:". The
artifact is an implementation detail; what the analyst needs is what kind of
evidence fired.

So the prefix now follows the EVIDENCE, not the artifact: a row carrying a
Windows channel and an event id is an event-log rule and says SIGMA, and
everything else keeps its artifact name — MFT and LNK really are different
sources and should still say so.
"""

import ast
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MAPPER = os.path.join(ROOT, "modules/backend/services/fusion/mappers/agentic.py")


def _load(path, name):
    with open(path, encoding="utf-8") as fh:
        src = fh.read()
    fn = next(n for n in ast.parse(src).body
              if isinstance(n, ast.FunctionDef) and n.name == name)
    ns = {}
    exec(compile(ast.get_source_segment(src, fn), path, "exec"), ns)
    return ns[name]


def _read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
        return fh.read()


prefix = _load(MAPPER, "_detection_prefix")

EVTX = "DetectRaptor.Windows.Detection.Evtx"


class TestAnEventLogRuleIsCalledSigma(unittest.TestCase):
    """Row shapes are copied from the qa-test case: 243 Evtx detections, all
    carrying Channel + EventID."""

    def test_channel_and_event_id_means_sigma(self):
        self.assertEqual(
            prefix({"Channel": "Microsoft-Windows-PowerShell/Operational",
                    "EventID": 4104}, EVTX),
            "SIGMA: ")

    def test_the_older_EID_spelling_counts_too(self):
        """Hayabusa rows use EID, DetectRaptor uses EventID; both appear."""
        self.assertEqual(prefix({"Channel": "Security", "EID": 1102}, EVTX), "SIGMA: ")

    def test_a_different_source_keeps_its_own_name(self):
        """MFT is the filesystem, not the event log — collapsing it into SIGMA
        would hide a real distinction."""
        self.assertEqual(prefix({}, "DetectRaptor.Windows.Detection.MFT"), "MFT: ")
        self.assertEqual(prefix(None, "DetectRaptor.Windows.Detection.Lnk"), "Lnk: ")

    def test_half_the_evidence_is_not_enough(self):
        """A channel with no event id, or an id with no channel, is not a
        confirmed event-log rule — don't claim it is."""
        self.assertEqual(prefix({"Channel": "Security"}, EVTX), "Evtx: ")
        self.assertEqual(prefix({"EventID": 4104}, EVTX), "Evtx: ")

    def test_it_cannot_raise_whatever_it_is_handed(self):
        """It runs once per detection row while the graph is built. A mapper
        that throws on one malformed row costs the whole RUN: the fuse's
        per-run guard catches it, logs "skipped", and that collection
        contributes nothing to the case. So this must not throw — for any
        input, including the non-dict rows that reach it from malformed JSON
        (a bare string raised AttributeError before this was hardened)."""
        rows = [None, {}, "a string row", ["list"], 42, 0, True, b"bytes",
                {"Channel": ["odd"], "EventID": {"x": 1}},
                {"Channel": None, "EventID": None}, {"Channel": "", "EID": 0}]
        artifacts = [EVTX, None, "", 123, "NoDots", "A.B.MFT"]
        for row in rows:
            for art in artifacts:
                got = prefix(row, art)          # must not raise
                self.assertIsInstance(got, str)

    def test_an_unusable_artifact_yields_no_prefix_rather_than_the_word_None(self):
        self.assertEqual(prefix({}, None), "")
        self.assertEqual(prefix({}, ""), "")

    def test_the_real_cases_still_work_after_hardening(self):
        self.assertEqual(prefix({"Channel": "Security", "EventID": 1102}, EVTX), "SIGMA: ")
        self.assertEqual(prefix({}, "DetectRaptor.Windows.Detection.MFT"), "MFT: ")

    def test_the_fuse_survives_a_mapper_that_throws_anyway(self):
        """Belt and braces: even if some future edit reintroduces a raise, one
        run's failure must not lose the case."""
        src = _read("modules/backend/services/fusion/store.py")
        self.assertIn("except Exception as e:  # never let one run break the fuse", src)


class TestTheMapperAndTheFindingAgree(unittest.TestCase):

    def test_the_mapper_uses_the_helper(self):
        src = _read("modules/backend/services/fusion/mappers/agentic.py")
        self.assertIn("title=(f\"{_detection_prefix(r, artifact)}\"", src)

    def test_the_artifact_name_is_no_longer_hardcoded_into_the_title(self):
        src = _read("modules/backend/services/fusion/mappers/agentic.py")
        self.assertNotIn("title=(f\"{artifact.split('.')[-1]}: {str(dname)[:60]}\"", src)

    def test_the_summary_does_not_wrap_a_source_in_a_source(self):
        """With the prefix in the title, "Detection 'SIGMA: X' fired" reads as
        a source inside a source."""
        src = _read("modules/backend/services/fusion/correlate.py")
        self.assertNotIn("summary=f\"Detection '{title}' fired", src)
        self.assertIn('summary=f"{title} fired', src)

    def test_hayabusas_own_prefix_is_unchanged(self):
        """Both paths must land on the same word, or the fix moves the
        inconsistency instead of removing it."""
        src = _read("modules/backend/services/fusion/correlate.py")
        self.assertIn('title=f"SIGMA: {title} on {host}"', src)


if __name__ == "__main__":
    unittest.main(verbosity=2)
