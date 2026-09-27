"""Jev client: off unless every condition holds, and silent on failure.

Jev is reached through OpenRouter's Decisions endpoint with the operator's
OpenRouter key. So it must stay inert when the feature is off, when the one use
is unticked, when the provider is anything but OpenRouter, or when there is no
key — and any failed call must come back None, which every caller treats as
"no suggestion". These pin those rules, the request shape, and the chunking
that lets one call answer many items without crossing the context limit.
"""
import os
import sys
import types
import unittest
from unittest import mock

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_BACKEND = os.path.join(_ROOT, "modules/backend")
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)
# Bare packages, so services/__init__.py (grpc, storage init) never runs.
for _pkg, _rel in (("services", "services"), ("services.fusion", "services/fusion")):
    if _pkg not in sys.modules:
        _m = types.ModuleType(_pkg)
        _m.__path__ = [os.path.join(_BACKEND, _rel)]
        sys.modules[_pkg] = _m
# Stdlib-only runner: requests is a container dependency. Every call is mocked.
if "requests" not in sys.modules:
    sys.modules["requests"] = types.ModuleType("requests")
    sys.modules["requests"].post = None

from services.fusion import jev  # noqa: E402

ON = {"online_llm": {"provider": "openrouter", "api_key": "sk-or-x"},
      "jev": {"enabled": True}}


class _Resp:
    def __init__(self, status=200, body=None):
        self.status_code, self._body, self.text = status, body or {}, "err"

    def json(self):
        return self._body


class Enabled(unittest.TestCase):
    def test_every_condition_is_required(self):
        self.assertTrue(jev.enabled("disposition", ON))
        self.assertFalse(jev.enabled("disposition", {**ON, "jev": {}}))
        self.assertFalse(jev.enabled("disposition",
                                     {**ON, "jev": {"enabled": True, "uses": {"disposition": False}}}))
        self.assertTrue(jev.enabled("identity",
                                    {**ON, "jev": {"enabled": True, "uses": {"disposition": False}}}))
        self.assertFalse(jev.enabled("disposition",
                                     {**ON, "online_llm": {"provider": "claude", "api_key": "k"}}))
        self.assertFalse(jev.enabled("disposition",
                                     {**ON, "online_llm": {"provider": "openrouter", "api_key": ""}}))
        # offline mode means nothing leaves the box, key or no key
        self.assertFalse(jev.enabled("disposition", {**ON, "llm_mode": "offline"}))

    def test_own_key_works_under_any_chat_provider(self):
        codex = {"online_llm": {"provider": "codex-subscription", "api_key": "sk-or-old"},
                 "jev": {"enabled": True, "api_key": "sk-or-jev"}}
        self.assertTrue(jev.enabled("disposition", codex))
        self.assertEqual(jev._key(codex), "sk-or-jev")
        # without its own key, a non-OpenRouter provider's leftover key is NOT used
        self.assertFalse(jev.enabled("disposition", {**codex, "jev": {"enabled": True}}))
        # and its own key wins over the main one
        self.assertEqual(jev._key({**ON, "jev": {"enabled": True, "api_key": "sk-or-jev"}}), "sk-or-jev")
        self.assertIsNone(jev._key({**codex, "llm_mode": "offline"}))

    def test_defaults_are_not_mutated_by_settings(self):
        jev.settings({"jev": {"uses": {"grounding": False}}})
        self.assertTrue(jev.DEFAULTS["uses"]["grounding"])


class Ask(unittest.TestCase):
    def test_request_shape_and_answers(self):
        body = {"model": "jev-1.13.0", "answers": {"q0": {"noul": 0.9}},
                "usage": {"input_tokens": 10, "output_tokens": 1, "cost": 0.001}}
        with mock.patch.object(jev.requests, "post", return_value=_Resp(200, body)) as post:
            out = jev.ask({"x": 1}, {"q0": {"type": "noul", "instructions": "?"}}, cfg=ON)
        self.assertEqual(out, {"q0": {"noul": 0.9}})
        args, kw = post.call_args
        self.assertEqual(args[0], "https://openrouter.ai/api/v1/systemone")
        self.assertEqual(kw["headers"]["Authorization"], "Bearer sk-or-x")
        self.assertEqual(kw["json"]["model"], "jev-latest")
        self.assertEqual(set(kw["json"]), {"model", "state", "questions"})

    def test_failures_return_none(self):
        q = {"q0": {"type": "noul", "instructions": "?"}}
        with mock.patch.object(jev.requests, "post", return_value=_Resp(429)):
            self.assertIsNone(jev.ask({}, q, cfg=ON))
        with mock.patch.object(jev.requests, "post", side_effect=OSError("no route")):
            self.assertIsNone(jev.ask({}, q, cfg=ON))
        with mock.patch.object(jev.requests, "post") as post:
            self.assertIsNone(jev.ask({}, q, cfg={**ON, "online_llm": {"provider": "claude"}}))
            post.assert_not_called()

    def test_usage_lands_on_the_run(self):
        body = {"answers": {"q0": {}}, "usage": {"input_tokens": 7, "cost": 0.5}}
        rec = mock.Mock()
        ws = types.ModuleType("services.workflow_service")
        ws.record_llm_metrics = rec
        with mock.patch.dict(sys.modules, {"services.workflow_service": ws}), \
             mock.patch.object(jev.requests, "post", return_value=_Resp(200, body)):
            jev.ask({}, {"q0": {}}, run_id="R1", cfg=ON)
        rec.assert_called_once()
        self.assertEqual(rec.call_args.kwargs["input_tokens"], 7)
        self.assertEqual(rec.call_args.kwargs["cost_usd"], 0.5)


class Pack(unittest.TestCase):
    def test_limits(self):
        chunks = list(jev.pack(range(120), lambda i: "x" * 40, max_tokens=10**6, max_items=50))
        self.assertEqual([len(c) for c in chunks], [50, 50, 20])
        chunks = list(jev.pack(range(10), lambda i: "x" * 400, max_tokens=250))  # 100 tokens each
        self.assertEqual([len(c) for c in chunks], [2, 2, 2, 2, 2])
        # an item bigger than the budget still goes out, alone
        self.assertEqual([len(c) for c in jev.pack([1, 2], lambda i: "x" * 4000, max_tokens=10)], [1, 1])

    def test_ask_each_keys_and_stops_on_failure(self):
        replies = iter([{"q0": "a", "q1": "b"}, None])

        def fake_ask(state, questions, **kw):
            self.assertEqual(set(state["items"]), set(questions))
            return next(replies)
        with mock.patch.object(jev, "pack", lambda items, r, max_tokens, **kw: iter([items[:2], items[2:]])), \
             mock.patch.object(jev, "ask", fake_ask):
            out = jev.ask_each(["i", "j", "k"], str, lambda k: {"type": "noul"})
        self.assertEqual(out, ["a", "b", None])


class TooBig(unittest.TestCase):
    """Found live: Jev refused batches our estimate thought fit
    (max_tokens_exceeded) and 108 of 323 rows went unanswered."""

    def test_a_too_big_batch_is_split_and_retried(self):
        calls = []

        def fake_ask(state, questions, **kw):
            calls.append(len(questions))
            if len(questions) > 2:                          # Jev: too large
                jev._last["too_big"] = True
                return None
            jev._last["too_big"] = False
            return {k: {"noul": 0.5} for k in questions}
        with mock.patch.object(jev, "ask", fake_ask):
            out = jev.ask_each(list("abcdefgh"), str, lambda k: {"type": "noul"})
        self.assertEqual(out, [{"noul": 0.5}] * 8)
        self.assertEqual(calls[0], 8)
        self.assertTrue(all(n <= 8 for n in calls))

    def test_an_outage_is_not_retried(self):
        calls = []

        def fake_ask(state, questions, **kw):
            calls.append(len(questions))
            jev._last["too_big"] = False
            return None
        with mock.patch.object(jev, "ask", fake_ask):
            out = jev.ask_each(list("abcdefgh"), str, lambda k: {"type": "noul"})
        self.assertEqual(out, [None] * 8)
        self.assertEqual(calls, [8])                        # one call, not a dozen

    def test_ask_records_why_it_failed(self):
        body = '{"error":{"message":"HTTP 400: {\\"detail\\":{\\"error_type\\":\\"max_tokens_exceeded\\"}}"}}'
        r = _Resp(400); r.text = body
        with mock.patch.object(jev.requests, "post", return_value=r):
            self.assertIsNone(jev.ask({}, {"q0": {}}, cfg=ON))
        self.assertTrue(jev._last["too_big"])
        with mock.patch.object(jev.requests, "post", return_value=_Resp(429)):
            jev.ask({}, {"q0": {}}, cfg=ON)
        self.assertFalse(jev._last["too_big"])

    def test_questions_count_toward_the_batch_size(self):
        chunks = list(jev.pack(range(50), lambda i: "x" * 40, max_tokens=1000, per_item=100))
        self.assertTrue(all(len(c) <= 10 for c in chunks))


class Masking(unittest.TestCase):
    def test_off_is_none_and_broken_refuses_to_send(self):
        self.assertIsNone(jev.mask_for({}, None))
        with self.assertRaises(RuntimeError):
            jev.masked("host-1", False)
        self.assertEqual(jev.masked("host-1", None), "host-1")


if __name__ == "__main__":
    unittest.main()
