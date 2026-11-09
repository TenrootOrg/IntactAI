"""Case-row state machines (QA C3, C6, C7, C8), on an in-memory case row.

C3: _merge_case_details merges details and never rewrites the case's status.
C6: declining a checklist item after accepting it un-suppresses the finding, and
    clearing that disposition puts an accepted item back to pending.
C7: the chat's pending verdict is taken once; a busy fuse answers "saved, queued"
    and a scope switch mid-turn files the exchange under the scope it was asked in.
C8: a change the report is written from marks every saved scope's report behind.
"""
import copy
import os
import sys
import threading
import unittest
from unittest import mock

for _p in (os.path.dirname(os.path.abspath(__file__)),
           os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import store, llm_sim  # noqa: E402

CASE = "case_1700000000000"


class _FakeWS:
    """The two workflow_service writers store.py uses, with the same contract:
    update_run_status sets the status and merges details; mutate_run_details
    touches details only, under a lock."""

    def __init__(self, details, status="completed"):
        self.row = {"automation_type": store.CASE_TYPE, "status": status, "details": details}
        self.lock = threading.Lock()
        self.status_writes = []

    def get_automation_run(self, rid):
        return copy.deepcopy(self.row)

    def mutate_run_details(self, rid, fn):
        with self.lock:
            fn(self.row["details"])
            return True

    def update_run_status(self, rid, status, details=None, **kw):
        with self.lock:
            self.status_writes.append(status)
            self.row["status"] = status
            if details:
                self.row["details"].update(details)
            return True


class _Base(unittest.TestCase):
    def setUp(self):
        self.ws = _FakeWS(self.details())
        for p in (mock.patch.object(store, "_ws", return_value=self.ws),
                  mock.patch.object(store, "log_case_event"),
                  mock.patch.object(store, "fuse_case"),
                  mock.patch.object(store, "_ask_scope_estimates")):
            p.start()
            self.addCleanup(p.stop)

    def details(self):
        return {}

    @property
    def d(self):
        return self.ws.row["details"]


class MergeKeepsStatus(_Base):
    def test_merge_never_writes_the_status(self):
        # A concurrent writer moved the status after the merge would have read it.
        self.ws.row["status"] = "pending"
        store._merge_case_details(CASE, {"x": 1})
        self.assertEqual(self.ws.row["status"], "pending")
        self.assertEqual(self.d["x"], 1)
        self.assertEqual(self.ws.status_writes, [])

    def test_a_write_that_did_not_land_still_raises(self):
        self.ws.mutate_run_details = lambda rid, fn: False
        with self.assertRaises(RuntimeError):
            store._merge_case_details(CASE, {"x": 1})


class ChecklistDecisions(_Base):
    def details(self):
        return {"disposition_checklist": [{"id": "q1", "finding_id": "f1", "status": "pending",
                                           "question": "is it IT?"}]}

    def _item(self):
        return self.d["disposition_checklist"][0]["status"]

    def test_decline_after_accept_unsuppresses_the_finding(self):
        store.decide_checklist_item(CASE, "q1", "accept")
        self.assertEqual([x["target"] for x in self.d["dispositions"]], ["f1"])
        store.decide_checklist_item(CASE, "q1", "decline")
        self.assertEqual(self.d["dispositions"], [])
        self.assertEqual(self._item(), "declined")

    def test_decline_leaves_an_operator_verdict_alone(self):
        self.d["dispositions"] = [{"target": "f1", "verdict": "benign", "attribution": "operator"}]
        store.decide_checklist_item(CASE, "q1", "decline")
        self.assertEqual(len(self.d["dispositions"]), 1)

    def test_clearing_the_disposition_reopens_the_accepted_item(self):
        store.decide_checklist_item(CASE, "q1", "accept")
        self.assertEqual(self._item(), "accepted")
        store.clear_disposition(CASE, "f1")
        self.assertEqual(self._item(), "pending")


class ChatPendingOffer(_Base):
    def details(self):
        return {"pending_disposition": {"target": "f1", "label": "PsExec", "verdict": "benign",
                                        "attribution": "it_admin", "scope": "case"}}

    def test_a_busy_fuse_is_saved_queued_and_not_reapplied(self):
        with mock.patch.object(store, "view_graph"), \
             mock.patch.object(store, "fuse_case", side_effect=store.FusionBusy("busy")):
            ans = store.chat_case(CASE, "confirm")
        self.assertIn("saved", ans)
        self.assertIn("queued", ans)
        self.assertNotIn("pending_disposition", self.d)
        self.assertEqual([x["target"] for x in self.d["dispositions"]], ["f1"])
        self.assertIn(CASE, store._FUSE_OWED)                       # the "queued" is true
        store._FUSE_OWED.discard(CASE)

    def test_two_turns_cannot_both_take_the_offer(self):
        self.assertIsNotNone(store._take_pending_disposition(CASE))
        self.assertIsNone(store._take_pending_disposition(CASE))


class ChatScopeSwitchMidTurn(_Base):
    def details(self):
        return {"active_scope": "full", "chat_messages": [{"role": "user", "content": "old"}],
                "scopes": [{"id": "full", "chat_messages": []},
                           {"id": "w1", "chat_messages": []}]}

    def test_the_answer_lands_in_the_scope_it_was_asked_in(self):
        def _answer(*a, **k):
            store.switch_scope(CASE, "w1")          # the operator switches while the model answers
            return "the answer"
        from services.fusion import injection, decision_model as dm
        with mock.patch.object(store, "view_graph"), \
             mock.patch.object(injection, "take_hits", return_value=[]), \
             mock.patch.object(injection, "note", return_value=""), \
             mock.patch.object(llm_sim, "detect_disposition", return_value=None), \
             mock.patch.object(dm, "chat_verdict", return_value=None), \
             mock.patch.object(dm, "entity_estimates", return_value=""), \
             mock.patch.object(store, "_configured_fusion_model", return_value=(None, None, None)), \
             mock.patch.object(store, "_case_mask", return_value=None), \
             mock.patch.object(store, "_effective_output_cap", return_value=None), \
             mock.patch.object(store, "_llm_identity_budget", return_value=None), \
             mock.patch.object(store, "_reported", return_value=None), \
             mock.patch.object(llm_sim, "chat", side_effect=_answer):
            store.chat_case(CASE, "what happened?")
        self.assertEqual(self.d["active_scope"], "w1")
        self.assertEqual(self.d["chat_messages"], [])               # w1's own chat, untouched
        full = next(s for s in self.d["scopes"] if s["id"] == "full")
        self.assertEqual([m["content"] for m in full["chat_messages"]],
                         ["old", "what happened?", "the answer"])


class ReportBehindEveryScope(_Base):
    def details(self):
        return {"active_scope": "full", "report_md": "# whole case", "report_dirty": False,
                "scopes": [{"id": "full"},
                           {"id": "w1", "report_md": "# phase", "report_dirty": False},
                           {"id": "w2"}]}

    def test_a_verdict_marks_the_other_scopes_report_behind(self):
        store._report_behind(CASE)
        store.switch_scope(CASE, "w1")
        self.assertTrue(self.d["report_dirty"])
        self.assertNotIn("report_dirty", next(s for s in self.d["scopes"] if s["id"] == "w2"))

    def test_a_report_setting_marks_them_too(self):
        with mock.patch.object(store, "_log_config_changes"):
            store.set_analysis_config(CASE, {"language": "he"})
        self.assertTrue(next(s for s in self.d["scopes"] if s["id"] == "w1")["report_dirty"])


if __name__ == "__main__":
    unittest.main()
