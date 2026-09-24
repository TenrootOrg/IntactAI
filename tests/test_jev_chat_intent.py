"""Jev reads whether a chat message states a verdict — and changes nothing else.

The keyword matcher cannot read Hebrew, and reads "the backup server was
compromised" as benign. When enabled, Jev's confident reading replaces that
guess. What must NOT change: a question is never a verdict (and costs no call),
the verdict must still ground to a real finding, and applying it still needs
the literal "confirm" — the chat promises that anything else, including "yes",
leaves the finding alone.
"""
import os
import sys
import types
import unittest
from unittest import mock

_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (_HERE, os.path.join(os.path.dirname(_HERE), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import jev, llm_sim  # noqa: E402
from services.fusion.schema import Finding  # noqa: E402

G = types.SimpleNamespace(
    findings=[Finding(id="f1", title="Mimikatz credential dumping on HOST1",
                      severity="high", confidence="high", summary="")],
    entities={})


class DetectWithHint(unittest.TestCase):
    def test_hint_replaces_keywords_but_not_grounding(self):
        msg = "the mimikatz run was a red team exercise"       # no keyword hit
        self.assertIsNone(llm_sim.detect_disposition(G, msg))
        p = llm_sim.detect_disposition(G, msg, verdict_hint="benign")
        self.assertEqual((p["target"], p["verdict"]), ("f1", "benign"))
        # a keyword false positive is overruled by a confident "none"
        self.assertIsNotNone(llm_sim.detect_disposition(G, "mimikatz is benign"))
        self.assertIsNone(llm_sim.detect_disposition(G, "mimikatz is benign", verdict_hint="none"))
        # still must ground to a finding or entity
        self.assertIsNone(llm_sim.detect_disposition(G, "this is fine", verdict_hint="benign"))

    def test_questions_are_never_verdicts(self):
        self.assertIsNone(llm_sim.detect_disposition(G, "is mimikatz benign?",
                                                     verdict_hint="benign"))


class ChatVerdict(unittest.TestCase):
    def verdict(self, msg, answer, enabled=True, conf_floor=0.8):
        with mock.patch.object(jev, "enabled", return_value=enabled), \
             mock.patch.object(jev, "min_confidence", return_value=conf_floor), \
             mock.patch.object(jev, "ask", return_value=answer) as ask:
            return jev.chat_verdict(msg, {}, G), ask

    def test_confident_answer_is_used(self):
        v, ask = self.verdict("המימיקץ הוא של צוות האדום", {"v": {"choice": "benign", "confidence": 0.93}})
        self.assertEqual(v, "benign")
        self.assertEqual(ask.call_args.args[0], {"message": "המימיקץ הוא של צוות האדום"})

    def test_unsure_failed_or_off_falls_back_to_keywords(self):
        self.assertIsNone(self.verdict("x", {"v": {"choice": "benign", "confidence": 0.5}})[0])
        self.assertIsNone(self.verdict("x", None)[0])
        self.assertIsNone(self.verdict("x", {"v": {"choice": "maybe", "confidence": 0.99}})[0])
        v, ask = self.verdict("x", {}, enabled=False)
        self.assertIsNone(v)
        ask.assert_not_called()

    def test_a_question_costs_no_call(self):
        v, ask = self.verdict("who ran mimikatz?", {"v": {"choice": "benign", "confidence": 1}})
        self.assertIsNone(v)
        ask.assert_not_called()


class Grounding(unittest.TestCase):
    """Found live: every title ends "on <host>", so a message naming the host
    grounded to whichever finding came first."""

    def test_host_suffix_does_not_ground_and_the_best_match_wins(self):
        g = types.SimpleNamespace(entities={}, findings=[
            Finding(id="ps", title="SIGMA: PowerShell Web Request (+1 related) on DESKTOP-16OJFO6",
                    severity="high", confidence="high", summary=""),
            Finding(id="log", title="SIGMA: Security Eventlog Cleared (+1 related) on DESKTOP-16OJFO6",
                    severity="high", confidence="high", summary="")])
        p = llm_sim.detect_disposition(g, "the eventlog cleared on desktop-16ojfo6 was our IT",
                                       verdict_hint="benign")
        self.assertEqual(p["target"], "log")
        self.assertIsNone(llm_sim.detect_disposition(g, "desktop-16ojfo6 related work was fine",
                                                     verdict_hint="benign"))


class EntityEstimate(unittest.TestCase):
    """"How likely is kobi malicious?" gets Jev's number for the account it names —
    and nothing at all when Jev is off, the question is not about risk, the name
    resolves to nothing, or nothing involves it."""

    def graph(self):
        from services.fusion.schema import Entity
        acct = Entity(id="acct:kobia", type="account", label="kobia")
        host = Entity(id="asset:h1", type="asset", label="ALClient022")
        f = Finding(id="f9", title="Rubeus on ALClient022", severity="high",
                    confidence="high", summary="", entity_ids=["acct:kobia"], asset_ids=["asset:h1"])
        return types.SimpleNamespace(findings=[f], entities={e.id: e for e in (acct, host)})

    def estimate(self, q, answer=({"noul": 0.34},), resolved=None, enabled=True):
        g = self.graph()
        res = {"resolved": [g.entities["acct:kobia"]] if resolved is None else resolved}
        with mock.patch.object(jev, "enabled", return_value=enabled), \
             mock.patch("services.fusion.resolve.resolve", return_value=res), \
             mock.patch.object(jev, "_entity_state", lambda g, e, fs: {"entity": e.label}), \
             mock.patch.object(jev, "ask_each", return_value=list(answer)) as ae:
            return jev.entity_estimates(q, {}, g), ae

    def test_names_the_account_its_basis_and_that_it_is_not_a_verdict(self):
        out, _ = self.estimate("How confident are you that kobi is malicious user?")
        self.assertIn("**kobia** (account): **34%** likely involved in malicious activity", out)
        self.assertIn("from 1 finding on 1 host", out)
        self.assertIn("not a verdict", out)

    def test_silent_when_it_should_be(self):
        q = "How confident are you that kobi is malicious user?"
        self.assertEqual(self.estimate(q, enabled=False)[0], "")
        out, ae = self.estimate("what did kobi run?")                       # not a risk question
        self.assertEqual(out, "")
        ae.assert_not_called()
        self.assertEqual(self.estimate("kobi is malicious")[0], "")          # a statement, not a question
        self.assertEqual(self.estimate(q, resolved=[])[0], "")               # names nothing
        self.assertEqual(self.estimate(q, answer=(None,))[0], "")            # Jev did not answer


class ConfirmStaysLiteral(unittest.TestCase):
    """Jev is never consulted on the reply to an offer."""

    def test_casual_yes_does_not_confirm(self):
        self.assertFalse(llm_sim.is_affirmative("yes"))
        self.assertFalse(llm_sim.is_affirmative("yep go ahead"))
        self.assertTrue(llm_sim.is_affirmative("confirm"))
        src = open(os.path.join(os.path.dirname(_HERE),
                                "modules/backend/services/fusion/store.py"), encoding="utf-8").read()
        start = src.index("def chat_case(")
        pending_block = src[start:src.index("# anything else: the offer simply lapses", start)]
        self.assertNotIn("jev", pending_block)


if __name__ == "__main__":
    unittest.main()
