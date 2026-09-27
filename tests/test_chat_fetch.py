"""Chat: the question reaches the model as typed, and the MODEL decides whether it
needs the explicit data behind the case summary — it fetches it itself.

Asked 2026-09-27: "keep the questions as they are; if the LLM is connected let
it choose if explicit data is needed afterwards". The chat used to be one call
over a summary the backend pre-selected by keyword-matching the question.
"""
import os
import sys
import unittest
from unittest import mock

for _p in (os.path.dirname(os.path.abspath(__file__)),
           os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import investigate, llm_sim, schema  # noqa: E402

Q = "Who are the 3 most dangerous users and why do you think they are compromised?"


def _graph():
    g = schema.FusionGraph(case_id="c")
    g.upsert(schema.Entity(id="asset:WS1", type="asset", label="WS1"))
    g.findings = [schema.Finding(id="f1", title="SIGMA: Mimikatz on WS1", severity="critical",
                                 confidence="h", summary="", asset_ids=["asset:WS1"], ts="2026-01-01T10:00:00Z")]
    return g


class Fetch(unittest.TestCase):
    def run_chat(self, replies, tool_case="case_1", mask=None):
        sent, tools = [], []
        it = iter(replies)

        def fake_llm(system, user, **kw):
            sent.append((system, user))
            return next(it)

        def fake_tool(case_id, name, args):
            tools.append((case_id, name, args))
            return {"findings": [{"id": "f1", "title": "SIGMA: Mimikatz on WS1"}]}
        with mock.patch.object(llm_sim, "_real_llm", fake_llm), \
             mock.patch.object(llm_sim, "_llm_available", return_value=True), \
             mock.patch.object(llm_sim, "_case_event"), \
             mock.patch.object(investigate, "_safe_tool", fake_tool):
            ans = llm_sim.chat(_graph(), Q, full_context=True, require_llm=True, tool_case=tool_case, mask=mask)
        return ans, sent, tools

    def test_the_question_goes_as_typed_and_a_direct_answer_is_one_call(self):
        ans, sent, tools = self.run_chat(["kobia, srv and nofl — here is why…"])
        self.assertEqual(len(sent), 1)
        self.assertTrue(sent[0][1].rstrip().endswith("Q: " + Q))      # verbatim, last
        self.assertIn("FETCHING MORE", sent[0][0])                      # it was told it may fetch
        self.assertEqual(tools, [])
        self.assertEqual(ans, "kobia, srv and nofl — here is why…")    # no footer when nothing fetched

    def test_the_model_fetches_then_answers(self):
        ans, sent, tools = self.run_chat(['{"tool":"search","args":{"query":"mimikatz"}}',
                                          "srv ran Mimikatz on WS1."])
        self.assertEqual(tools, [("case_1", "search", {"query": "mimikatz"})])
        self.assertEqual(len(sent), 2)
        self.assertIn("RESULT of search", sent[1][1])
        self.assertIn("SIGMA: Mimikatz on WS1", sent[1][1])           # the result reached the model
        self.assertTrue(ans.startswith("srv ran Mimikatz on WS1."))
        self.assertIn("_Looked up: search_", ans)                        # the analyst sees what it fetched

    def test_a_fenced_fetch_request_is_understood(self):
        _, _, tools = self.run_chat(['```json\n{"tool":"evidence","args":{"finding_id":"f1"}}\n```', "done"])
        self.assertEqual([t[1] for t in tools], ["evidence"])

    def test_the_fetch_budget_ends_in_an_answer(self):
        loop = ['{"tool":"list_findings","args":{"limit":5}}'] * (llm_sim.MAX_CHAT_FETCHES + 1)
        ans, sent, tools = self.run_chat(loop + ["final answer from what I have"])
        self.assertEqual(len(tools), llm_sim.MAX_CHAT_FETCHES)
        self.assertIn("No more fetches are available", sent[-1][1])
        self.assertTrue(ans.startswith("final answer from what I have"))

    def test_without_a_case_there_are_no_tools(self):
        ans, sent, tools = self.run_chat(['{"tool":"search","args":{"query":"x"}}'], tool_case=None)
        self.assertNotIn("FETCHING MORE", sent[0][0])
        self.assertEqual(tools, [])

    def test_fetched_data_is_masked_and_args_come_back_real(self):
        class M:          # minimal DataAnonymizer: WS1 <-> Hostname1
            mapping = {"WS1": "Hostname1"}

        with mock.patch.object(llm_sim, "_build_mask_mapping"), mock.patch.object(llm_sim, "_log_mask_audit"), \
             mock.patch.object(llm_sim, "_apply_mask", side_effect=lambda t, m: t.replace("WS1", "Hostname1")), \
             mock.patch.object(llm_sim, "_revert_mask", side_effect=lambda t, m: t.replace("Hostname1", "WS1")):
            ans, sent, tools = self.run_chat(['{"tool":"pivot","args":{"value":"Hostname1"}}', "On Hostname1: …"],
                                             mask=M())
        self.assertEqual(tools[0][2], {"value": "WS1"})                 # the tool ran on the real name
        self.assertNotIn("WS1", sent[1][1])                              # the model never saw it
        self.assertTrue(ans.startswith("On WS1"))                        # the analyst reads real names


if __name__ == "__main__":
    unittest.main()
