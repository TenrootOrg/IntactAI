"""The AI-call ledger and the per-case AI budget (services/llm_usage.py).

Before 2026-11-22 a call's cost was only added to a running total on the run: no
case had a cost of its own, nobody could see which call cost what, and no case
could be held to a budget. Now every model call is one row; a case's cost and
its budget check are sums over its rows. Runs against a throwaway SQLite DB.
"""
import json
import os
import shutil
import sys
import tempfile
import types
import unittest
from unittest import mock

_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (_HERE, os.path.join(os.path.dirname(_HERE), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

_BASE = tempfile.mkdtemp(prefix="intact-llmusage-")
os.environ["INTACT_STORAGE_BASE"] = _BASE
import atexit  # noqa: E402
atexit.register(shutil.rmtree, _BASE, True)

import _optional_deps  # noqa: F401,E402
from services.storage import base  # noqa: E402
from services import llm_usage  # noqa: E402
from services.agentic.analyzers import _llm  # noqa: E402

base.create_tables()


def _rows(case_id=None):
    q = "SELECT source, provider, model, input_tokens, output_tokens, cost_usd, cost_kind, case_id FROM llm_usage"
    args = ()
    if case_id:
        q += " WHERE case_id = ?"
        args = (case_id,)
    return [tuple(r) for r in base.get_connection().execute(q + " ORDER BY id", args)]


def _clear():
    c = base.get_connection()
    c.execute("DELETE FROM llm_usage")
    c.execute("DELETE FROM workflows")
    c.commit()


class Ledger(unittest.TestCase):
    def setUp(self):
        _clear()

    def test_a_case_id_is_its_own_case_and_a_run_carries_its_case(self):
        base.get_connection().execute(
            "INSERT INTO workflows (run_id, automation_type, case_id) VALUES ('run-1','memory','case_9')")
        base.get_connection().commit()
        self.assertEqual(llm_usage.case_of("case_9"), "case_9")
        self.assertEqual(llm_usage.case_of("run-1"), "case_9")
        self.assertIsNone(llm_usage.case_of("run-unknown"))
        self.assertIsNone(llm_usage.case_of(None))

    def test_rows_add_up_per_case_by_source_and_by_model(self):
        llm_usage.record("case_1", provider="openrouter", model="m/a", input_tokens=100,
                         output_tokens=10, cost_usd=0.5, cost_kind="exact", source="report")
        llm_usage.record("case_1", provider="openrouter", model="m/a", input_tokens=50,
                         output_tokens=5, cost_usd=0.25, cost_kind="exact", source="chat")
        llm_usage.record("case_1", provider="claude", model="m/b", cost_usd=1.0,
                         cost_kind="estimated", source="chat")
        llm_usage.record("case_2", provider="claude", model="m/b", cost_usd=9.0)
        s = llm_usage.case_summary("case_1")
        self.assertEqual((s["calls"], s["cost_usd"], s["estimated_usd"]), (3, 1.75, 1.0))
        self.assertEqual((s["input_tokens"], s["output_tokens"]), (150, 15))
        self.assertEqual({r["name"]: r["cost_usd"] for r in s["by_source"]}, {"chat": 1.25, "report": 0.5})
        self.assertEqual({r["name"]: r["calls"] for r in s["by_model"]}, {"m/a": 2, "m/b": 1})
        self.assertTrue(s["since"])
        self.assertEqual(llm_usage.case_spent("case_2"), 9.0)

    def test_the_default_source_says_case_analysis_or_agentic_run(self):
        llm_usage.record("case_3", provider="x", model="y")
        llm_usage.record("run-x", provider="x", model="y")
        self.assertEqual([r[0] for r in _rows()], ["case analysis", "agentic run"])
        self.assertEqual(_rows()[1][7], None, "a run outside any case has no case")

    def test_recording_never_raises(self):
        with mock.patch.object(llm_usage, "get_connection", side_effect=RuntimeError("db gone")):
            llm_usage.record("case_1", provider="x", model="y", cost_usd=1)   # no exception


class Budget(unittest.TestCase):
    def setUp(self):
        _clear()

    def test_the_budget_is_the_cases_own_and_nothing_else(self):
        for own, want in ((5, 5.0), ("7.5", 7.5), (None, None), (0, None), ("x", None)):
            with mock.patch("services.fusion.store.get_case", return_value={"ai_budget_usd": own}):
                self.assertEqual(llm_usage.case_budget("case_1"), want, own)
        self.assertFalse(hasattr(llm_usage, "default_budget"), "no platform-wide default (2026-11-22)")

    def test_costs_by_case_in_one_query(self):
        llm_usage.record("case_1", provider="x", model="y", cost_usd=0.25)
        llm_usage.record("case_1", provider="x", model="y", cost_usd=0.5)
        llm_usage.record("case_2", provider="x", model="y", cost_usd=2.0)
        llm_usage.record("run-orphan", provider="x", model="y", cost_usd=9.0)
        self.assertEqual(llm_usage.costs_by_case(), {"case_1": 0.75, "case_2": 2.0})

    def test_a_used_up_budget_refuses_and_a_case_without_one_passes(self):
        llm_usage.record("case_1", provider="x", model="y", cost_usd=2.0)
        with mock.patch.object(llm_usage, "case_budget", return_value=2.0):
            with self.assertRaises(llm_usage.AIBudgetExceeded) as cm:
                llm_usage.check_budget("case_1")
            self.assertEqual(cm.exception.reason, "case_budget")
            self.assertIn("$2.00", str(cm.exception))
        with mock.patch.object(llm_usage, "case_budget", return_value=5.0):
            llm_usage.check_budget("case_1")                 # 2 of 5: passes
        with mock.patch.object(llm_usage, "case_budget", return_value=None):
            llm_usage.check_budget("case_1")                 # no budget: passes
        llm_usage.check_budget("run-not-in-a-case")          # no case: passes


class Recorder(unittest.TestCase):
    """_llm._record_llm_usage: the exact charge when the provider gives one."""

    def setUp(self):
        _clear()

    def _resp(self, **usage):
        return types.SimpleNamespace(usage=types.SimpleNamespace(**usage))

    def test_openrouter_charge_is_exact_and_labelled(self):
        tok = _llm._LLM_PURPOSE.set("report")
        try:
            _llm._record_llm_usage("case_1", "openrouter", "anthropic/claude-x",
                                   self._resp(prompt_tokens=1000, completion_tokens=200, cost=0.0123))
        finally:
            _llm._LLM_PURPOSE.reset(tok)
        self.assertEqual(_rows(), [("report", "openrouter", "anthropic/claude-x", 1000, 200, 0.0123, "exact", "case_1")])

    def test_charge_in_model_extra_is_read_too(self):
        u = types.SimpleNamespace(prompt_tokens=1, completion_tokens=1, model_extra={"cost": 0.5})
        _llm._record_llm_usage("case_1", "openrouter", "m", types.SimpleNamespace(usage=u))
        self.assertEqual(_rows()[0][5:7], (0.5, "exact"))

    def test_without_a_charge_it_is_estimated_local_or_subscription(self):
        with mock.patch.object(_llm, "_estimate_llm_cost", return_value=0.02):
            _llm._record_llm_usage("case_1", "claude", "claude-x",
                                   self._resp(input_tokens=10, output_tokens=2))
        _llm._record_llm_usage("case_1", "ollama", "llama", {"prompt_eval_count": 5, "eval_count": 1})
        _llm._record_llm_usage("case_1", "claude-cli", "", {"in_tokens": 7, "out_tokens": 3, "text": "x"})
        self.assertEqual([r[5:7] for r in _rows()], [(0.02, "estimated"), (0.0, "local"), (0.0, "subscription")])


class CallLlmGate(unittest.TestCase):
    def setUp(self):
        _clear()

    def test_the_budget_is_checked_before_the_call_and_the_purpose_reaches_the_recorder(self):
        seen = []
        with mock.patch.object(_llm, "_call_llm", side_effect=lambda *a, **k: seen.append(_llm._LLM_PURPOSE.get()) or "ok"):
            with mock.patch.object(llm_usage, "check_budget",
                                   side_effect=llm_usage.AIBudgetExceeded("case_1", 1.0, 1.5)):
                with self.assertRaises(llm_usage.AIBudgetExceeded):
                    _llm.call_llm("p", "s", {}, run_id="case_1", purpose="chat")
            self.assertEqual(seen, [], "no model call once the budget is used up")
            with mock.patch.object(llm_usage, "check_budget", return_value=None):
                self.assertEqual(_llm.call_llm("p", "s", {}, run_id="case_1", purpose="chat"), "ok")
            self.assertEqual(seen, ["chat"])
            self.assertIsNone(_llm._LLM_PURPOSE.get(), "the label does not leak to the next call")


class OpenRouterAsksForItsCharge(unittest.TestCase):
    def _capture(self, provider, reasoning_effort=None, reject_reasoning=False):
        sent = []

        class _Comp:
            @staticmethod
            def create(**kw):
                sent.append(kw)
                if reject_reasoning and "reasoning" in (kw.get("extra_body") or {}):
                    raise RuntimeError("unrecognized parameter: reasoning")
                msg = types.SimpleNamespace(content="ok")
                return types.SimpleNamespace(choices=[types.SimpleNamespace(message=msg)], usage=None)

        client = types.SimpleNamespace(chat=types.SimpleNamespace(completions=_Comp()))
        fake = types.SimpleNamespace(OpenAI=lambda **kw: client)
        with mock.patch.dict(sys.modules, {"openai": fake}), \
             mock.patch.object(_llm, "_rejects_temperature", return_value=False), \
             mock.patch.object(_llm, "_rejects_reasoning", side_effect=lambda e: "reasoning" in str(e)):
            _llm._call_openai_compatible(provider, "p", "s", "k", "m", 10,
                                         reasoning_effort=reasoning_effort)
        return sent

    def test_openrouter_requests_usage_and_keeps_it_when_reasoning_is_refused(self):
        sent = self._capture("openrouter")
        self.assertEqual(sent[0]["extra_body"], {"usage": {"include": True}})
        sent = self._capture("openrouter", reasoning_effort="low", reject_reasoning=True)
        self.assertEqual(sent[0]["extra_body"], {"reasoning": {"effort": "low"}, "usage": {"include": True}})
        self.assertEqual(sent[1]["extra_body"], {"usage": {"include": True}}, "retry drops only reasoning")

    def test_other_providers_send_no_extra_body(self):
        self.assertNotIn("extra_body", self._capture("openai")[0])


class CaseAnalysisSaysWhy(unittest.TestCase):
    def test_a_refused_call_reads_as_the_case_budget(self):
        from services.fusion import llm_sim
        r = llm_sim.classify_llm_failure(llm_usage.AIBudgetExceeded("case_1", 2.0, 2.5))
        self.assertEqual(r["code"], "case_budget")
        self.assertIn("AI budget", r["reason"])
        self.assertIn("Configuration", r["fix"])


if __name__ == "__main__":
    unittest.main()
