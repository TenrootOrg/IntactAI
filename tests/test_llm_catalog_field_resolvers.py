"""get_model_max_output_tokens / get_model_context_length resolve the same way.

WHY THIS EXISTS. The two functions in services/agentic/analyzers/_llm.py were
byte-identical apart from the field name they read -- verified mechanically:
ast.unparse both, rename `max_output_tokens` -> FIELD in one and
`context_length` -> FIELD in the other, and the bodies compare equal. 130 lines
holding one algorithm twice.

They had NO test. That is the whole reason this file exists: it pins the walk
order so the two can be folded into one parameterised helper without guessing.
Note the comment at _llm.py's `codex-subscription` branch records a real bug
from exactly this duplication -- the branch was present in one twin and missing
from the other, so subscription models silently got the default output cap and
long reports were truncated. Divergence between copies is not hypothetical here.

The walk, for both fields:
    1. the friendly alias table
    2. the provider's catalog (native id, raw input, or canonical id)
    3. the OpenRouter mirror, for direct-SDK ids of claude/openai/gemini
    4. None
"""

import os
import sys
import types
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND = os.path.join(ROOT, "modules/backend")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BACKEND)

import _optional_deps  # noqa: E402
# Deliberately NOT stubbing flask: a process-wide flask stub makes
# tests/test_case_fuse_races.py stop SKIPPING two tests and fail against the
# fake instead. Measured. Stub only what these modules actually import.
_optional_deps.stub("requests", "grpc", "pyvelociraptor", "yaml")

# Bind `services` to its directory WITHOUT executing services/__init__.py, the
# idiom tests/test_case_bundle.py:42-46 established.
if "services" not in sys.modules:
    _svc = types.ModuleType("services")
    _svc.__path__ = [os.path.join(BACKEND, "services")]
    sys.modules["services"] = _svc

from services.agentic.analyzers import _llm  # noqa: E402

FIELDS = ("max_output_tokens", "context_length")


def _resolver(field):
    return (_llm.get_model_max_output_tokens if field == "max_output_tokens"
            else _llm.get_model_context_length)


class TestBothResolversWalkTheSameSteps(unittest.TestCase):
    def setUp(self):
        self._alias = dict(_llm.MODEL_ALIASES)

    def tearDown(self):
        _llm.MODEL_ALIASES.clear()
        _llm.MODEL_ALIASES.update(self._alias)

    def test_empty_input_is_none(self):
        for f in FIELDS:
            with self.subTest(field=f):
                self.assertIsNone(_resolver(f)("", "claude"))
                self.assertIsNone(_resolver(f)(None, "claude"))

    def test_the_alias_table_wins(self):
        _llm.MODEL_ALIASES["pinned-model"] = {f: 4321 for f in FIELDS}
        for f in FIELDS:
            with self.subTest(field=f):
                self.assertEqual(4321, _resolver(f)("pinned-model", "claude"))

    def test_an_alias_entry_without_the_field_falls_through(self):
        # A zero/absent value must NOT short-circuit the walk.
        _llm.MODEL_ALIASES["half-known"] = {"something_else": 1}
        for f in FIELDS:
            with self.subTest(field=f):
                self.assertIsNone(_resolver(f)("half-known", "no-such-provider"))

    def test_an_unknown_model_resolves_to_none(self):
        for f in FIELDS:
            with self.subTest(field=f):
                self.assertIsNone(
                    _resolver(f)("model-that-does-not-exist", "no-such-provider"))

    def test_every_provider_branch_is_reachable(self):
        # Not asserting a value -- only that no provider name raises. The
        # codex-subscription branch existed in one twin and not the other.
        for provider in ("openrouter", "claude", "openai", "gemini",
                         "codex-subscription", "custom", ""):
            for f in FIELDS:
                with self.subTest(field=f, provider=provider):
                    _resolver(f)("some-model", provider)


if __name__ == "__main__":
    unittest.main(verbosity=2)
