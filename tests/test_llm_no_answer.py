"""A reply with no answer in it says so, in the provider's words -- and Gemini fails fast.

A fault-injection pass on 2026-10-20 sent every provider's client the replies a real
provider sends when something goes wrong. Each one raised, so nothing crashed, but a
200 carrying no answer -- OpenRouter's {"error": ..., "choices": null}, a captive
portal page, an Anthropic reply holding only a thinking block -- reached the case Log
as "'NoneType' object is not subscriptable". And a Gemini 503 ("model overloaded")
was retried by the SDK for up to 600 s, every attempt inside our timeout, so a
report sat silent for ten minutes.
"""
import os
import sys
import types
import unittest
from unittest import mock

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_BACKEND = os.path.join(_ROOT, "modules/backend")
for _p in ("/app", _BACKEND, _ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)
for _pkg, _rel in (("services", "services"),
                   ("services.agentic", "services/agentic"),
                   ("services.agentic.analyzers", "services/agentic/analyzers")):
    if _pkg not in sys.modules:
        _m = types.ModuleType(_pkg)
        _m.__path__ = [os.path.join(_BACKEND, _rel)]
        sys.modules[_pkg] = _m

from services.agentic.analyzers import _llm  # noqa: E402

NS = types.SimpleNamespace


def _openai(reply):
    mod = types.ModuleType("openai")
    client = NS(chat=NS(completions=NS(create=lambda **kw: reply)))
    mod.OpenAI = lambda **kw: client
    return mod


def _compat(reply):
    with mock.patch.dict(sys.modules, {"openai": _openai(reply)}), \
         mock.patch.object(_llm, "_record_llm_usage", lambda *a, **k: None):
        return _llm._call_openai_compatible("openrouter", "hi", "sys", "key", "m", 8,
                                            base_url="https://openrouter.ai/api/v1")


def _online(provider, modules):
    with mock.patch.dict(sys.modules, modules), \
         mock.patch.object(_llm, "_record_llm_usage", lambda *a, **k: None), \
         mock.patch.object(_llm, "resolve_model_alias", lambda m, p: m):
        return _llm._call_llm_online("hi", "sys", {"provider": provider, "api_key": "k",
                                                   "model": "m"}, 8)


class OpenAICompatible(unittest.TestCase):
    def test_an_upstream_error_in_a_200_is_named(self):
        with self.assertRaisesRegex(RuntimeError, "Openrouter returned no answer: upstream provider overloaded"):
            _compat(NS(choices=None, error={"message": "upstream provider overloaded"}))

    def test_no_choices_and_a_page_say_what_came_back(self):
        for reply in (NS(choices=[]), "<html>captive portal</html>"):
            with self.assertRaisesRegex(RuntimeError, "returned no answer: got"):
                _compat(reply)

    def test_an_empty_answer_is_still_an_empty_answer(self):
        self.assertEqual("", _compat(NS(choices=[NS(message=NS(content=None))])))


class Claude(unittest.TestCase):
    def _mods(self, reply):
        mod = types.ModuleType("anthropic")
        mod.Anthropic = lambda **kw: NS(messages=NS(create=lambda **kw: reply))
        return {"anthropic": mod}

    def test_the_text_block_is_read_past_a_thinking_block(self):
        reply = NS(content=[NS(type="thinking", thinking="..."), NS(type="text", text="OK")])
        self.assertEqual("OK", _online("claude", self._mods(reply)))

    def test_thinking_only_is_an_empty_answer_not_an_attribute_error(self):
        self.assertEqual("", _online("claude", self._mods(NS(content=[NS(type="thinking", thinking="...")]))))

    def test_no_content_is_named(self):
        with self.assertRaisesRegex(RuntimeError, "Claude returned no answer"):
            _online("claude", self._mods(NS(content=None, error={"message": "overloaded"})))


class Gemini(unittest.TestCase):
    def _mods(self, sent, text_error=None):
        genai = types.ModuleType("google.generativeai")
        genai.configure = lambda **kw: None
        genai.types = NS(GenerationConfig=lambda **kw: kw)

        class Reply:
            prompt_feedback = "block_reason: SAFETY"

            @property
            def text(self):
                if text_error:
                    raise ValueError(text_error)
                return "OK"

        class Model:
            def __init__(self, name):
                pass

            def generate_content(self, prompt, **kw):
                sent.update(kw)
                return Reply()
        genai.GenerativeModel = Model
        google = types.ModuleType("google")
        google.generativeai = genai
        return {"google": google, "google.generativeai": genai}

    def test_no_sdk_retry_so_a_503_fails_at_once(self):
        sent = {}
        self.assertEqual("OK", _online("gemini", self._mods(sent)))
        self.assertIn("retry", sent["request_options"])
        self.assertIsNone(sent["request_options"]["retry"])

    def test_a_blocked_reply_is_named(self):
        with self.assertRaisesRegex(RuntimeError, "Gemini returned no answer: block_reason: SAFETY"):
            _online("gemini", self._mods({}, text_error="requires a single candidate"))


class Ollama(unittest.TestCase):
    def _call(self, body):
        resp = NS(raise_for_status=lambda: None, json=lambda: body)
        with mock.patch.object(_llm.requests, "post", lambda *a, **k: resp), \
             mock.patch.object(_llm, "_record_llm_usage", lambda *a, **k: None):
            return _llm._call_llm_offline("hi", "sys", {"provider": "ollama", "url": "http://x"}, 2048, 5)

    def test_an_error_body_is_named_not_returned_as_blank(self):
        with self.assertRaisesRegex(RuntimeError, "Ollama returned no answer: model 'm' not found"):
            self._call({"error": "model 'm' not found"})

    def test_a_non_object_is_named(self):
        with self.assertRaisesRegex(RuntimeError, "Ollama returned no answer: got"):
            self._call([])

    def test_an_answer_is_returned(self):
        self.assertEqual("OK", self._call({"response": "OK", "done": True}))


if __name__ == "__main__":
    unittest.main()
