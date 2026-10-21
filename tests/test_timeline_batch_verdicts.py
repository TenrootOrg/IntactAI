"""A batch of Timeline verdicts: every row saved and logged, ONE re-fuse for all.

2026-10-21: one click, one re-fuse -- three fast clicks were three re-fuses. The page
now holds a burst and sends it once (validate_timeline_batch).
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
from services.fusion import store  # noqa: E402
from services.fusion.schema import Finding  # noqa: E402


def _f(fid):
    return Finding(id=fid, title=f"T on {fid}", severity="high", confidence="medium",
                   summary="", occ_count=1, occ_latest="2026-06-01T10:00:00Z")


class Batch(unittest.TestCase):
    def run_it(self, items, fuse_side=None, dispositions=()):
        state = {"timeline_validations": [], "dispositions": list(dispositions)}
        ws = mock.Mock()
        ws.mutate_run_details.side_effect = lambda cid, fn: fn(state)

        def mut(cid, field, fn):
            state[field] = fn(list(state.get(field) or []))
        logs = []
        g = types.SimpleNamespace(findings=[_f(x) for x in "abcde"])
        dm = types.SimpleNamespace(after_fuse=lambda cid: None)
        with mock.patch.object(store, "get_case", side_effect=lambda cid: dict(state)), \
             mock.patch.object(store, "load_graph", return_value=g), \
             mock.patch.object(store, "_mutate_list_field", side_effect=mut), \
             mock.patch.object(store, "_ws", return_value=ws), \
             mock.patch.object(store, "_report_behind"), \
             mock.patch.object(store, "ack_rows"), \
             mock.patch.dict(sys.modules, {"services.fusion.decision_model": dm}), \
             mock.patch.object(store, "log_case_event", side_effect=lambda cid, a, s, d, **k: logs.append((a, s, d))), \
             mock.patch.object(store, "fuse_case", side_effect=fuse_side) as fuse:
            try:
                res = store.validate_timeline_batch("c1", items)
            except store.FusionBusy as e:
                res = e
        return res, logs, state, fuse

    def test_three_verdicts_one_refuse(self):
        res, logs, state, fuse = self.run_it([{"finding_id": "a", "status": "true_positive"},
                                              {"finding_id": "b", "status": "false_positive"},
                                              {"finding_id": "c", "status": "known"}])
        self.assertEqual(1, fuse.call_count, "one re-fuse for the whole batch")
        self.assertEqual(store.TRIGGER_DISPOSITION, fuse.call_args.kwargs["trigger"])
        self.assertEqual({"a": "true_positive", "b": "false_positive", "c": "known"},
                         {v["finding_id"]: v["status"] for v in state["timeline_validations"]})
        self.assertEqual(sorted(d["target"] for d in state["dispositions"]), ["b", "c"])
        marked = [d for a, s, d in logs if a == "Timeline · validation"]
        self.assertEqual(["a marked true_positive", "b marked false_positive", "c marked known"], marked)
        self.assertEqual({"saved": 3, "statuses": {"true_positive": 1, "false_positive": 1, "known": 1}}, res)

    def test_the_last_verdict_on_a_row_wins(self):
        _, _, state, _ = self.run_it([{"finding_id": "a", "status": "known"},
                                      {"finding_id": "a", "status": "false_positive"}])
        self.assertEqual([("a", "false_positive")], [(v["finding_id"], v["status"]) for v in state["timeline_validations"]])

    def test_nothing_to_suppress_is_no_refuse(self):
        _, _, _, fuse = self.run_it([{"finding_id": "a", "status": "true_positive"},
                                     {"finding_id": "d", "status": "true_positive"}])
        self.assertEqual(0, fuse.call_count)

    def test_a_running_fuse_is_said_busy_and_the_verdicts_are_kept(self):
        res, _, state, _ = self.run_it([{"finding_id": "b", "status": "known"}],
                                       fuse_side=store.FusionBusy("case c1 is already fusing"))
        self.assertIsInstance(res, store.FusionBusy, "the route answers 409 'deferred'")
        self.assertEqual(1, len(state["timeline_validations"]))

    def test_a_failed_refuse_keeps_the_verdicts_and_says_so(self):
        res, logs, state, _ = self.run_it([{"finding_id": "b", "status": "known"}, {"finding_id": "e", "status": "known"}],
                                          fuse_side=RuntimeError("graph write failed"))
        self.assertEqual(2, len(state["timeline_validations"]))
        self.assertIn("re-fuse the case", res["warning"])
        self.assertTrue(any(s == "error" and "2 verdict(s) saved, but the re-fuse failed" in d for _a, s, d in logs), logs)


if __name__ == "__main__":
    unittest.main()
