"""Report-generation edge cases found by the H-series run against a live appliance.

Each was reproduced with a fake model server on the container loopback before it
was fixed, and each is pinned here offline:

H14/H15/H16  A model that ANSWERS badly — empty, not JSON, HTTP 500 — was reported
             as "check the API key and the internet connection". The provider was
             reached and the key worked; the operator was sent to fix what worked.
H17          A slow but valid answer was written off as stuck. The stuck limit was
             applied as given, so a local model with a long ollama_timeout (the
             normal air-gapped setup) lost a good answer before its own timeout.
H23          A deterministic regeneration ("no LLM tokens spent") still called the
             model for the checklist when the case had none, inside the HTTP
             request, blocking it for the model's whole timeout.
H21          A settings save whose body is not JSON answered HTTP 500, not 400.
"""

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (os.path.dirname(os.path.abspath(__file__)), os.path.join(ROOT, "modules", "backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import llm_sim  # noqa: E402


class AModelThatAnswersBadlyIsNotAKeyOrNetworkProblem(unittest.TestCase):

    def _says(self, exc):
        code = llm_sim._classify_llm_error(exc)
        return code, llm_sim.llm_error_message(code).lower()

    def _not_key_or_network(self, msg):
        self.assertNotIn("api key", msg)
        self.assertNotIn("internet", msg)

    def test_an_empty_answer(self):
        code, msg = self._says(llm_sim.LLMUnavailable("empty_reply"))
        self.assertEqual("empty_reply", code)
        self._not_key_or_network(msg)

    def test_a_reply_that_is_not_json(self):
        # requests' own wording for an HTML error page served with HTTP 200
        code, msg = self._says(Exception("JSONDecodeError: Expecting value: line 1 column 1 (char 0)"))
        self.assertEqual("bad_response", code)
        self._not_key_or_network(msg)

    def test_a_provider_500(self):
        code, msg = self._says(Exception("500 Server Error: Internal Server Error for url: http://x/api/generate"))
        self.assertEqual("provider_error", code)
        self._not_key_or_network(msg)

    def test_a_gateway_timeout_is_still_a_timeout(self):
        code, _ = self._says(Exception("504 Server Error: Gateway Timeout"))
        self.assertEqual("timeout", code)

    def test_none_of_them_counts_as_no_route(self):
        # the checklist must still be attempted: the provider IS reachable
        for code in ("empty_reply", "bad_response", "provider_error"):
            reason, _ = llm_sim._llm_reason_text(code)
            self.assertFalse(llm_sim.provider_unreachable(reason), code)


class ASlowValidAnswerIsNotWrittenOff(unittest.TestCase):

    def setUp(self):
        from services.fusion import store
        self.store = store
        self._cfg = llm_sim._agentic_cfg

    def tearDown(self):
        llm_sim._agentic_cfg = self._cfg

    def _limits(self, **ag):
        llm_sim._agentic_cfg = lambda: ag
        return self.store._watchdog_limits()

    def test_the_stuck_limit_never_undercuts_an_offline_call_timeout(self):
        hb, stuck = self._limits(llm_mode="offline", ollama_timeout=1800, report_stuck_seconds=900)
        self.assertGreaterEqual(stuck, 1800 + self.store.REPORT_STUCK_MARGIN_SECONDS)

    def test_the_stuck_limit_never_undercuts_an_online_call_timeout(self):
        from services.agentic.constants import ONLINE_LLM_TIMEOUT_SECONDS
        hb, stuck = self._limits(llm_mode="online", report_stuck_seconds=30)
        self.assertGreaterEqual(stuck, ONLINE_LLM_TIMEOUT_SECONDS + self.store.REPORT_STUCK_MARGIN_SECONDS)

    def test_a_longer_configured_limit_is_kept(self):
        hb, stuck = self._limits(llm_mode="offline", ollama_timeout=60, report_stuck_seconds=3600)
        self.assertEqual(3600, stuck)


class ADeterministicRegenerationMakesNoModelCall(unittest.TestCase):

    def test_the_checklist_honours_allow_llm_false(self):
        called = []
        real_use, real_llm = llm_sim._use_real, llm_sim._real_llm
        llm_sim._use_real = lambda: True
        llm_sim._real_llm = lambda *a, **k: called.append(1) or '{"checklist": []}'
        try:
            from services.fusion import schema
            oc = {}
            llm_sim.generate_disposition_checklist(schema.FusionGraph(case_id="c"), outcome=oc, allow_llm=False)
        finally:
            llm_sim._use_real, llm_sim._real_llm = real_use, real_llm
        self.assertEqual([], called, "a deterministic regeneration must not call the model")
        self.assertFalse(oc.get("used_llm"))

    def test_regenerate_passes_use_llm_through(self):
        src = open(os.path.join(ROOT, "modules/backend/services/fusion/store.py"), encoding="utf-8").read()
        regen = src[src.index("def regenerate_report("):src.index("def engagement_markdown(")]
        self.assertIn("allow_llm=bool(use_llm and not offline)", regen)
        self.assertIn("_cl_llm = bool(use_llm and not offline and llm_sim._use_real())", regen)


class AnEmptyChecklistReplyIsAFailure(unittest.TestCase):

    def test_empty_is_reported_as_failed_not_as_nothing_to_confirm(self):
        real_use, real_llm = llm_sim._use_real, llm_sim._real_llm
        llm_sim._use_real = lambda: True
        llm_sim._real_llm = lambda *a, **k: "   "
        try:
            from services.fusion import schema
            oc = {}
            llm_sim.generate_disposition_checklist(schema.FusionGraph(case_id="c"), outcome=oc)
        finally:
            llm_sim._use_real, llm_sim._real_llm = real_use, real_llm
        self.assertEqual("empty_reply", oc.get("error"))
        self.assertFalse(oc.get("empty"), "an empty reply must not read as a successful, empty checklist")


class ABadSettingsBodyIsA400(unittest.TestCase):

    def test_save_config_does_not_500_on_non_json(self):
        src = open(os.path.join(ROOT, "modules/backend/routes/config_routes.py"), encoding="utf-8").read()
        save = src[src.index("def save_config():"):src.index("\n@config_bp.route", src.index("def save_config():"))]
        self.assertIn("request.get_json(silent=True)", save)
        self.assertIn(", 400", save)


if __name__ == "__main__":
    unittest.main(verbosity=2)
