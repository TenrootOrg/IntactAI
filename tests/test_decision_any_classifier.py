"""Any decision model OpenRouter lists can be used, and a refusal says why.

A conformance pass on 2026-10-19 sent one real-shaped request to all 21 OpenRouter
classifiers. 15 answered as-is. ScaleDown refused every structured state ("state
must be a string or an object with only text, document ...") and answered the
same JSON once it came as text, so every fuse of a box set to it got nothing while
Settings' Test, which sent plain text, said it worked. Five more were refused by
OpenRouter itself (the account's data policy, or not served), and the case Log
said only "returned an error".
"""
import json
import os
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

TEXT_ONLY = {"provider": "openrouter", "model": "vendor/text-only-classifier"}
CFG = {"online_llm": {"provider": "openrouter", "api_key": "sk-or-x"},
       "decision_model": {"enabled": True, "model": TEXT_ONLY["model"]}}
STATE = {"finding": {"title": "Credential dumping", "host": "WS1"}}
Q = {"q": {"type": "noul", "instructions": "x"}}


class _R:
    def __init__(self, status, body):
        self.status_code, self._b, self.text = status, body, json.dumps(body)

    def json(self):
        return self._b


OK = _R(200, {"answers": {"q": {"type": "noul", "noul": 0.8}}})
TEXT_ERR = _R(400, {"error": {"message": "X state must be a string or an object with only text, "
                                         "document, and document_mime_type", "code": 400}})


class AnyClassifier(unittest.TestCase):
    def setUp(self):
        dm.retry_now()
        dm._TEXT_STATE.discard(TEXT_ONLY["model"])

    def test_a_text_only_model_gets_the_same_state_as_text_and_keeps_it(self):
        sent = []

        def post(url, json=None, **kw):
            sent.append(json["state"])
            return TEXT_ERR if not ("text" in json["state"] and len(json["state"]) == 1) else OK
        with mock.patch.object(dm.requests, "post", side_effect=post):
            self.assertEqual({"q": {"type": "noul", "noul": 0.8}}, dm.ask(STATE, Q, cfg=CFG))
            self.assertEqual([STATE, {"text": json.dumps(STATE)}], sent)
            self.assertEqual("", dm.unavailable(CFG))               # not an outage
            sent.clear()
            dm.ask(STATE, Q, cfg=CFG)                               # remembered: text at once
            self.assertEqual([{"text": json.dumps(STATE)}], sent)

    def test_a_refusal_carries_the_providers_own_words(self):
        policy = _R(404, {"error": {"message": "0 endpoints out of 1 requested are available matching "
                                               "your guardrail restrictions and data policy.\nZDR violation "
                                               "(account settings): configurable at https://openrouter.ai/settings/privacy"}})
        with mock.patch.object(dm.requests, "post", return_value=policy):
            self.assertIsNone(dm.ask(STATE, Q, cfg=CFG))
        why = dm.unavailable(CFG)
        self.assertIn("HTTP 404", why)
        self.assertIn("data policy", why)
        self.assertIn("openrouter.ai/settings/privacy", why)

    def test_other_400s_are_not_mistaken_for_text_only(self):
        bad = _R(400, {"error": {"message": "unknown question type"}})
        with mock.patch.object(dm.requests, "post", return_value=bad) as post:
            self.assertIsNone(dm.ask(STATE, Q, cfg=CFG))
            self.assertEqual(1, post.call_count)
        self.assertNotIn(TEXT_ONLY["model"], dm._TEXT_STATE)


class ReadTimeout(Exception):
    """Named like requests' own: _call recognises it by name."""


class SlowModel(unittest.TestCase):
    """A slower classifier timed out on a full batch of a 1,059-finding case: that
    stopped every suggestion and paused the decision model for the next Refusion."""

    def setUp(self):
        dm.retry_now()

    def test_a_slow_batch_is_split_and_every_item_answered(self):
        def post(url, json=None, **kw):
            qs = json["questions"]
            if len(qs) > 2:
                raise ReadTimeout("read timed out")
            return _R(200, {"answers": {k: {"type": "noul", "noul": 0.7} for k in qs}})
        q = lambda k: {"type": "noul", "instructions": "x"}   # noqa: E731
        with mock.patch.object(dm.requests, "post", side_effect=post):
            ans = dm.ask_each(list(range(8)), str, q, cfg=CFG)
        self.assertEqual(8, sum(1 for a in ans if a))
        self.assertEqual("", dm.unavailable(CFG))

    def test_an_unexplained_400_on_a_batch_is_split_like_a_too_big_one(self):
        # Kev 4B: 30 findings fine, 50 refused with "The parameter is invalid".
        invalid = _R(400, {"error": {"message": 'HTTP 400: {"code":20015,"message":"The parameter is invalid."}'}})

        def post(url, json=None, **kw):
            qs = json["questions"]
            return invalid if len(qs) > 3 else _R(200, {"answers": {k: {"type": "noul", "noul": 0.6} for k in qs}})
        q = lambda k: {"type": "noul", "instructions": "x"}   # noqa: E731
        with mock.patch.object(dm.requests, "post", side_effect=post):
            ans = dm.ask_each(list(range(10)), str, q, cfg=CFG)
        self.assertEqual(10, sum(1 for a in ans if a))
        self.assertEqual("", dm.unavailable(CFG))

    def test_one_slow_item_is_an_outage(self):
        with mock.patch.object(dm.requests, "post", side_effect=ReadTimeout("read timed out")):
            self.assertIsNone(dm.ask(STATE, Q, cfg=CFG))
        self.assertIn("ReadTimeout", dm.unavailable(CFG))

    def test_a_clicked_fuse_clears_the_pause_for_its_own_pass_too(self):
        src = open(os.path.join(_BACKEND, "services/fusion/store.py")).read()
        self.assertIn("dm.after_fuse(case_id, retry=trig in _OPERATOR_TRIGGERS)", src)


if __name__ == "__main__":
    unittest.main()
