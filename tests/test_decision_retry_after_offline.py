"""Fused offline, refused online: the decision model must answer the refusion.

One failed call pauses every decision-model call for ten minutes (so an offline
box does not time out on each feature after every fuse). That pause also covered
the Refusion an operator clicked once the internet was back: nothing was asked,
the case got no suggestions, and the Log only said "asked again on the next fuse".
A fuse a person asked for now clears the pause first, as Settings' Test always did.
"""
import os
import re
import sys
import types
import unittest
from unittest import mock

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_BACKEND = os.path.join(_ROOT, "modules/backend")
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)
for _pkg, _rel in (("services", "services"), ("services.fusion", "services/fusion")):
    if _pkg not in sys.modules:
        _m = types.ModuleType(_pkg)
        _m.__path__ = [os.path.join(_BACKEND, _rel)]
        sys.modules[_pkg] = _m
if "requests" not in sys.modules:
    sys.modules["requests"] = types.ModuleType("requests")
    sys.modules["requests"].post = None

from services.fusion import decision_model as dm  # noqa: E402

ON = {"online_llm": {"provider": "openrouter", "api_key": "sk-or-x"},
      "decision_model": {"enabled": True}}
Q = {"q": {"type": "noul", "instructions": "x"}}


class _Ok:
    status_code, text = 200, ""

    @staticmethod
    def json():
        return {"answers": {"q": {"type": "noul", "noul": 0.9}}}


class RetryAfterOffline(unittest.TestCase):
    def setUp(self):
        dm.retry_now()

    def test_the_pause_holds_until_an_operator_asks(self):
        with mock.patch.object(dm.requests, "post", side_effect=ConnectionError("offline")) as post:
            self.assertIsNone(dm.ask({}, Q, cfg=ON))           # offline: fails, pauses
            self.assertEqual(1, post.call_count)
        with mock.patch.object(dm.requests, "post", return_value=_Ok()) as post:
            self.assertIsNone(dm.ask({}, Q, cfg=ON))           # online again, still paused
            self.assertEqual(0, post.call_count)
            dm.retry_now()                                     # an operator asked
            self.assertEqual({"q": {"type": "noul", "noul": 0.9}}, dm.ask({}, Q, cfg=ON))
            self.assertEqual(1, post.call_count)

    def test_only_a_fuse_a_person_asked_for_clears_it(self):
        src = open(os.path.join(_BACKEND, "services/fusion/store.py")).read()
        ops = re.search(r"_OPERATOR_TRIGGERS = \(([^)]*)\)", src).group(1)
        self.assertEqual({"TRIGGER_MANUAL_REFUSION", "TRIGGER_MANUAL_RESCAN", "TRIGGER_API_FUSE"},
                         {t.strip() for t in ops.split(",") if t.strip()})
        body = src[src.index("def fuse_case("):src.index("def _track_rows(")]
        self.assertRegex(body, r"if trig in _OPERATOR_TRIGGERS:\s*(#[^\n]*\n\s*)*from \. import decision_model as _dm\s*_dm\.retry_now\(\)")


if __name__ == "__main__":
    unittest.main()
