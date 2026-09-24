"""Jev's grounding check: flag report statements the evidence does not support,
beside the report — never cut them, and never cry wolf.

Two ways it could mislead: truncating an evidence payload too big for one call
would make every claim about the cut part look unsupported, so it skips (and
says so in the case log) instead; and it must send the masked evidence and
masked statements, since the report path is exactly where masking matters.
"""
import os
import sys
import unittest
from unittest import mock

_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (_HERE, os.path.join(os.path.dirname(_HERE), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import jev, llm_sim  # noqa: E402

NARR = """## Summary
**Host HOST1** ran mimikatz at 02:14 and dumped credentials from lsass memory.
| a | table | row that is long enough to be a claim if it were one, but it is a table |
- The attacker then moved laterally to HOST2 using PsExec with the stolen admin hash.
> quoted text that is not a claim of the report even though it is long enough
Short one.
"""


class Claims(unittest.TestCase):
    def test_prose_sentences_only(self):
        c = jev._claims(NARR)
        self.assertEqual(c, ["Host HOST1 ran mimikatz at 02:14 and dumped credentials from lsass memory.",
                             "The attacker then moved laterally to HOST2 using PsExec with the stolen admin hash."])


class Unsupported(unittest.TestCase):
    def check(self, answers, payload='{"e":1}', enabled=True, mask=None):
        events, sent = [], {}

        def fake_ask_each(items, render, question, context=None, **kw):
            sent["items"] = [render(i) for i in items]
            sent["context"] = context
            return answers
        with mock.patch.object(jev, "enabled", return_value=enabled), \
             mock.patch.object(jev, "ask_each", side_effect=fake_ask_each) as ae:
            bad = jev.unsupported_claims(NARR, payload, mask,
                                         log_event=lambda *a: events.append(a))
        return bad, events, sent, ae

    def test_only_low_scores_are_flagged(self):
        bad, events, sent, _ = self.check([{"noul": 0.9}, {"noul": 0.1}])
        self.assertEqual(bad, ["The attacker then moved laterally to HOST2 using PsExec with the stolen admin hash."])
        self.assertEqual(sent["context"], '{"e":1}')
        self.assertIn("1 of 2", events[-1][2])

    def test_failed_answers_flag_nothing(self):
        self.assertEqual(self.check([None, None])[0], [])

    def test_off_sends_nothing(self):
        bad, events, _, ae = self.check([], enabled=False)
        self.assertEqual((bad, events), ([], []))
        ae.assert_not_called()

    def test_oversized_evidence_is_skipped_not_truncated(self):
        bad, events, _, ae = self.check([], payload="x" * (jev.MAX_TOKENS * 4))
        self.assertEqual(bad, [])
        ae.assert_not_called()
        self.assertIn("skipped", events[0][0])

    def test_statements_are_masked_before_sending(self):
        mask = mock.Mock(mapping={"HOST1": "HOST_A", "HOST2": "HOST_B"})
        _, _, sent, _ = self.check([{"noul": 1}, {"noul": 1}], mask=mask)
        self.assertTrue(all("HOST1" not in s and "HOST2" not in s for s in sent["items"]))
        self.assertIn("HOST_A", sent["items"][0])


class InTheReport(unittest.TestCase):
    """The real generate_report path: the flag lands beside the narrative, which is kept."""

    def test_note_is_added_and_prose_kept(self):
        import test_report_phase_failures as rpf
        claim = "The attacker exfiltrated 40 GB to a Tor exit node."
        narrative = f"## Summary\n{claim}\n"
        seen = {}

        def fake_unsupported(narr, payload, mask, **kw):
            seen["payload"] = payload
            return [claim]
        with mock.patch.object(llm_sim, "_real_llm", lambda *a, **k: narrative), \
             mock.patch.object(llm_sim, "_use_real", lambda: True), \
             mock.patch.object(llm_sim, "_agentic_cfg", lambda: {}), \
             mock.patch.object(llm_sim, "_case_event", lambda *a, **k: None), \
             mock.patch.object(jev, "unsupported_claims", side_effect=fake_unsupported):
            md = llm_sim.generate_report(rpf._graph(), prefer_llm=True,
                                         altitude_mode="focused", run_id="c")
        self.assertIn("**Grounding check (Jev):**", md)
        self.assertIn(f"> - {claim}", md)
        self.assertEqual(md.count(claim), 2)          # in the prose AND in the note
        self.assertTrue(seen["payload"].startswith("{"))


if __name__ == "__main__":
    unittest.main()
