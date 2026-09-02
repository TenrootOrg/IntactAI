"""A model must not be reported as broken because of a parameter WE chose.

temperature=0.1 is deliberate -- a DFIR narrative should be as reproducible as
the model can manage -- but a growing set of reasoning models reject the
parameter outright with a 400 instead of ignoring it. Through a catalog of
hundreds of routed models that presented as "this model doesn't work" when the
model was fine and our request was not.

The retry is deliberately NARROW: retrying every 400 without temperature would
silently re-send prompts that failed for real reasons (context too long, bad
model id) and double the bill for each one.

    docker exec intact_backend sh -lc \
      'PYTHONPATH=/app python3 -m pytest /app/tests/test_llm_temperature_fallback.py -q'
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


class _Reply:
    def __init__(self, text="OK"):
        self.choices = [types.SimpleNamespace(message=types.SimpleNamespace(content=text))]
        self.usage = None


class _FakeCompletions:
    """Records every request; optionally 400s the ones carrying temperature."""

    def __init__(self, reject_temperature=False, error=None):
        self.calls = []
        self.reject_temperature = reject_temperature
        self.error = error

    def create(self, **kw):
        self.calls.append(kw)
        if self.error is not None and not self.reject_temperature:
            raise self.error
        if self.reject_temperature and "temperature" in kw:
            raise ValueError(
                "Error code: 400 - unsupported_value: 'temperature' is not "
                "supported with this model. Only the default (1) is supported.")
        return _Reply()


def _fake_openai(completions):
    mod = types.ModuleType("openai")
    client = types.SimpleNamespace(chat=types.SimpleNamespace(completions=completions))
    mod.OpenAI = lambda **kw: client
    return mod


def _call(completions):
    with mock.patch.dict(sys.modules, {"openai": _fake_openai(completions)}), \
         mock.patch.object(_llm, "_record_llm_usage", lambda *a, **k: None):
        return _llm._call_openai_compatible(
            "openrouter", "hi", "sys", "key", "some/model", 8,
            base_url="https://openrouter.ai/api/v1")


class TemperatureIsNotAllowedToFailAModel(unittest.TestCase):

    def test_a_model_that_rejects_temperature_still_answers(self):
        c = _FakeCompletions(reject_temperature=True)
        self.assertEqual(_call(c), "OK")
        self.assertEqual(len(c.calls), 2, "expected one retry")
        self.assertIn("temperature", c.calls[0], "the first attempt must still send it")
        self.assertNotIn("temperature", c.calls[1], "the retry must drop it")

    def test_a_normal_model_is_called_once_with_temperature(self):
        """The retry must not cost a second call on the overwhelming majority."""
        c = _FakeCompletions()
        self.assertEqual(_call(c), "OK")
        self.assertEqual(len(c.calls), 1)
        self.assertEqual(c.calls[0]["temperature"], 0.1)

    def test_an_unrelated_failure_is_not_retried(self):
        """Retrying every 400 would re-send prompts that failed for real reasons
        and bill twice for each."""
        c = _FakeCompletions(error=ValueError("Error code: 400 - context_length_exceeded"))
        with self.assertRaises(Exception):
            _call(c)
        self.assertEqual(len(c.calls), 1)


class TheRetryTriggerIsNarrow(unittest.TestCase):

    def test_recognised_rejections(self):
        for msg in (
            "unsupported_value: 'temperature' is not supported with this model",
            "temperature does not support 0.1",
            "Unrecognized request argument supplied: temperature",
            "Only the default temperature of 1 is permitted",
            "invalid value for 'temperature'",
        ):
            self.assertTrue(_llm._rejects_temperature(ValueError(msg)), msg)

    def test_everything_else_is_left_alone(self):
        for msg in (
            "context_length_exceeded",
            "model not found",
            "Insufficient credits",
            "rate limit exceeded",
            "temperature",                      # names it, but claims nothing
        ):
            self.assertFalse(_llm._rejects_temperature(ValueError(msg)), msg)


class RetriesAreBounded(unittest.TestCase):
    """The SDK default of 2 turns one 600s timeout into ~30 minutes of a report
    that looks hung with nothing in the activity log."""

    def test_max_retries_is_pinned(self):
        seen = {}
        mod = types.ModuleType("openai")

        def _client(**kw):
            seen.update(kw)
            return types.SimpleNamespace(
                chat=types.SimpleNamespace(completions=_FakeCompletions()))
        mod.OpenAI = _client
        with mock.patch.dict(sys.modules, {"openai": mod}), \
             mock.patch.object(_llm, "_record_llm_usage", lambda *a, **k: None):
            _llm._call_openai_compatible("openrouter", "hi", "s", "k", "m", 8)
        self.assertEqual(seen.get("max_retries"), 1)


if __name__ == "__main__":
    unittest.main()
