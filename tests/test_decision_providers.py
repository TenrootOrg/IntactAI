"""The decision model runs on the provider the operator picks -- and only there.

Settings → Agentic → Decision model: Online via OpenRouter (Jev, Clef…) or OpenAI's
Decisions API; Offline via a Jev-compatible server on the local network. These pin what each choice sends where, and the four ways it could go
wrong: a box saved before the choice existed starting to call a cloud, a key
following a provider switch to another vendor, a "local" model that is really a
public one, and a provider that silently cuts the request and answers anyway.
Responses below are the ones observed live on 2026-10-11 (OpenRouter, Clef);
OpenAI's are from its documentation -- no key was available to call it.
"""
import os
import sys
import unittest
from unittest import mock

_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (_HERE, os.path.join(os.path.dirname(_HERE), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import decision_model as dm  # noqa: E402

NOUL = {"type": "noul", "instructions": "Is items.a malicious?",
        "criteria": {"true": "Attacker activity.", "false": "Benign."}}
CHOICE = {"type": "choice", "instructions": "Classify items.b.",
          "criteria": {"true_positive": "Real.", "false_positive": "Misfire.", "known": "Expected."}}


def cfg(**dm_cfg):
    return {"llm_mode": "online", "online_llm": {"provider": "claude", "api_key": "sk-ant"},
            "decision_model": {"enabled": True, **dm_cfg}}


class _Resp:
    def __init__(self, body, status=200, text=""):
        self.status_code, self._body, self.text = status, body, text

    def json(self):
        return self._body


class Choice(unittest.TestCase):
    def setUp(self):
        dm._down.update(until=0.0, fp=None, why="")

    def test_saved_before_the_choice_existed_follows_the_ai_model_mode(self):
        old = {"llm_mode": "offline", "online_llm": {"provider": "openrouter", "api_key": "sk-or"},
               "decision_model": {"enabled": True, "api_key": "sk-or-own"}}
        self.assertEqual(dm.provider(old), "local")             # never a cloud call
        self.assertFalse(dm.enabled("disposition", old))
        self.assertIn("Offline mode needs", dm.why_inactive(old))
        self.assertEqual(dm.provider({**old, "llm_mode": "online"}), "openrouter")

    def test_own_mode_wins_once_saved(self):
        c = {**cfg(mode="online", provider="openai", api_key="sk-oa"), "llm_mode": "offline"}
        self.assertEqual(dm.provider(c), "openai")
        self.assertEqual(dm.provider(cfg(mode="offline", provider="openai")), "local")

    def test_keys(self):
        self.assertIsNone(dm._key(cfg(provider="openai")))                     # chat is Claude
        shared = {**cfg(provider="openai"), "online_llm": {"provider": "openai", "api_key": "sk-oa"}}
        self.assertEqual(dm._key(shared), "sk-oa")
        sub = {**cfg(provider="openai"), "online_llm": {"provider": "codex-subscription", "api_key": "x"}}
        self.assertIsNone(dm._key(sub))                         # a subscription is not an API key
        self.assertIsNone(dm._key(cfg(mode="offline")))                       # local: no URL
        self.assertEqual(dm._key(cfg(mode="offline", url="http://10.0.0.5/v1")), "")    # key optional

    def test_a_model_saved_for_another_provider_is_not_sent(self):
        self.assertEqual(dm.model_name(cfg(provider="openai", model="jev-latest")), "gpt-6-luna")
        self.assertEqual(dm.model_name(cfg(provider="openrouter", model="cloudflare/clef")), "cloudflare/clef")
        self.assertEqual(dm.model_name(cfg(provider="openrouter", model="some/new-model")), "some/new-model")

    def test_context_follows_the_model(self):
        self.assertEqual(dm.context_tokens(cfg(api_key="k")), 24000)
        self.assertEqual(dm.context_tokens(cfg(api_key="k", model="cloudflare/clef")), 12000)
        self.assertEqual(dm.context_tokens(cfg(mode="offline", url="http://10.0.0.5/v1")), dm.UNKNOWN_BUDGET)
        self.assertEqual(dm.context_tokens(cfg(mode="offline", url="http://10.0.0.5/v1", context_tokens=30000)), 30000)


class Wire(unittest.TestCase):
    def setUp(self):
        dm._down.update(until=0.0, fp=None, why="")

    def test_openrouter_jev_wire_and_no_redirects(self):
        body = {"model": "typesafe/jev-1.13-20260917", "answers": {"q1": {"type": "noul", "noul": 0.93}},
                "usage": {"input_tokens": 424, "output_tokens": 21, "cost": 1.78e-05}}
        with mock.patch.object(dm.requests, "post", return_value=_Resp(body)) as post:
            self.assertEqual(dm.ask({"items": {}}, {"q1": NOUL}, cfg=cfg(api_key="sk-or")), body["answers"])
        url, kw = post.call_args[0][0], post.call_args[1]
        self.assertEqual(url, "https://openrouter.ai/api/v1/systemone")
        self.assertEqual(kw["json"], {"model": "jev-latest", "state": {"items": {}}, "questions": {"q1": NOUL}})
        self.assertIs(kw["allow_redirects"], False)
        self.assertEqual(kw["headers"], {"Authorization": "Bearer sk-or"})

    def test_openai_translation_both_ways(self):
        c = cfg(mode="online", provider="openai", api_key="sk-oa")
        reply = {"model": "gpt-6-luna", "usage": {"input_tokens": 300, "output_tokens": 0},
                 "answers": [{"type": "predicate", "name": "n", "probability": 0.81},
                             {"type": "choice", "name": "c", "choice": "known", "confidence": 0.7,
                              "probabilities": [{"value": "true_positive", "probability": 0.1},
                                                {"value": "false_positive", "probability": 0.1},
                                                {"value": "known", "probability": 0.8}]}]}
        with mock.patch.object(dm.requests, "post", return_value=_Resp(reply)) as post:
            ans = dm.ask({"items": {"a": 1}}, {"n": NOUL, "c": CHOICE}, cfg=c)
        sent = post.call_args[1]["json"]
        self.assertEqual(post.call_args[0][0], "https://api.openai.com/v1/decisions")
        self.assertEqual(sent["model"], "gpt-6-luna")
        self.assertEqual(sent["input"], '{"items": {"a": 1}}')
        n, ch = sent["questions"]
        self.assertEqual((n["type"], n["name"]), ("predicate", "n"))
        self.assertIn("True means: Attacker activity.", n["instructions"])
        self.assertEqual(ch["choices"][2], {"value": "known", "description": "Expected."})
        self.assertEqual(ans["n"], {"type": "noul", "noul": 0.81})
        self.assertEqual(ans["c"]["probabilities"]["known"], 0.8)
        self.assertEqual(ans["c"]["choice"], "known")

    def test_the_removed_custom_provider_reads_as_openrouter(self):
        # "custom" (any URL) existed for one day; a box that saved it must not keep
        # sending case data to that URL.
        c = cfg(mode="online", provider="custom", url="https://dec.example/v1/systemone", api_key="sk-or")
        self.assertEqual(dm.provider(c), "openrouter")
        with mock.patch.object(dm.requests, "post", return_value=_Resp({"answers": {"q1": {"noul": 0.5}}})) as post:
            dm.ask({}, {"q1": NOUL}, cfg=c)
        self.assertEqual(post.call_args[0][0], "https://openrouter.ai/api/v1/systemone")


class Local(unittest.TestCase):
    def setUp(self):
        dm._down.update(until=0.0, fp=None, why="")

    def _ask(self, addr):
        c = cfg(mode="offline", url="http://decide.lan:8080/v1/systemone", model="kev-4b")
        with mock.patch("socket.getaddrinfo", return_value=[(2, 1, 6, "", (addr, 0))]), \
             mock.patch.object(dm.requests, "post", return_value=_Resp({"answers": {"q1": {"noul": 0.4}}})) as post:
            ans = dm.ask({}, {"q1": NOUL}, cfg=c)
        return ans, post, c

    def test_a_private_server_is_used(self):
        ans, post, _ = self._ask("192.168.1.40")
        self.assertEqual(ans, {"q1": {"noul": 0.4}})
        self.assertEqual(post.call_args[1]["timeout"], 60)

    def test_a_public_address_is_refused_and_nothing_is_sent(self):
        ans, post, c = self._ask("8.8.8.8")
        self.assertIsNone(ans)
        post.assert_not_called()
        self.assertIn("public address", dm.unavailable(c))

    def test_offline_never_falls_back_to_the_cloud(self):
        c = {**cfg(mode="offline"), "online_llm": {"provider": "openrouter", "api_key": "sk-or"}}
        with mock.patch.object(dm.requests, "post") as post:
            self.assertIsNone(dm.ask({}, {"q1": NOUL}, cfg=c))
        post.assert_not_called()


class SilentCut(unittest.TestCase):
    """Clef on OpenRouter read 16,384 tokens of a 50k request and answered anyway."""

    def setUp(self):
        dm._down.update(until=0.0, fp=None, why="")

    def test_an_answer_from_a_cut_request_is_split_not_trusted(self):
        c = cfg(api_key="k", model="cloudflare/clef")
        seen = []

        def post(url, **kw):
            n = len(kw["json"]["questions"])
            seen.append(n)
            used = 16384 if n > 2 else 300
            return _Resp({"answers": {k: {"noul": 0.3} for k in kw["json"]["questions"]},
                          "usage": {"input_tokens": used}})
        with mock.patch.object(dm.requests, "post", side_effect=post):
            out = dm.ask_each(list("abcdefgh"), str, lambda k: NOUL, cfg=c)
        self.assertEqual(out, [{"noul": 0.3}] * 8)
        self.assertEqual(seen[0], 8)
        self.assertEqual(dm.unavailable(c), "")                 # not an outage


class Conformance(unittest.TestCase):
    """Conformance pass over every catalog model (2026-10-11): Tev1 refuses more than
    32 questions a call; both Upstage models got obvious cases wrong."""

    def setUp(self):
        dm._down.update(until=0.0, fp=None, why="")

    def test_batches_respect_the_models_question_limit(self):
        c = cfg(api_key="k", model="togethercomputer/tev1-4b-experimental")
        self.assertEqual(dm.max_questions(c), 32)
        self.assertEqual(dm.max_questions(cfg(api_key="k")), dm.MAX_QUESTIONS)
        sizes = []

        def post(url, **kw):
            sizes.append(len(kw["json"]["questions"]))
            return _Resp({"answers": {k: {"noul": 0.2} for k in kw["json"]["questions"]}})
        with mock.patch.object(dm.requests, "post", side_effect=post):
            out = dm.ask_each(["x"] * 70, str, lambda k: NOUL, cfg=c)
        self.assertEqual(sizes, [32, 32, 6])
        self.assertEqual(len(out), 70)

    def test_an_unknown_models_question_limit_is_split_not_an_outage(self):
        c = cfg(api_key="k", model="some/new-model")
        refused = 'Tev1 accepts at most 32 questions per request; this request has 40'

        def post(url, **kw):
            n = len(kw["json"]["questions"])
            if n > 20:
                return _Resp({"error": {"message": refused}}, status=400, text=refused)
            return _Resp({"answers": {k: {"noul": 0.2} for k in kw["json"]["questions"]}})
        with mock.patch.object(dm.requests, "post", side_effect=post):
            out = dm.ask_each(["x"] * 40, str, lambda k: NOUL, cfg=c)
        self.assertEqual(out, [{"noul": 0.2}] * 40)
        self.assertEqual(dm.unavailable(c), "")

    def test_models_that_failed_are_not_suggested(self):
        avoid = {m["model"] for m in dm.catalog() if m.get("avoid")}
        self.assertEqual(avoid, {"upstage/solar-decide", "upstage/solar-decide-flash"})
        try:
            import flask
            from routes import config_routes as cr
        except ImportError as e:
            self.skipTest(f"no flask here: {e}")
        app = flask.Flask(__name__)
        app.register_blueprint(cr.config_bp)
        got = {m["model"] for m in app.test_client().get("/api/config/decision_model/models").get_json()["models"]}
        self.assertFalse(got & avoid)
        self.assertIn("togethercomputer/tev1-4b-experimental", got)


class CachesFollowTheModel(unittest.TestCase):
    def test_another_models_answers_are_not_shown(self):
        d = {"decision_suggestions": {"f1": {"label": "known"}}}       # unstamped = Jev on OpenRouter
        jev, clef = cfg(api_key="k"), cfg(api_key="k", model="cloudflare/clef")
        self.assertEqual(dm.cached(d, "suggestions", jev), {"f1": {"label": "known"}})
        self.assertEqual(dm.cached(d, "suggestions", clef), {})
        d["decision_by"] = {"suggestions": "openrouter/cloudflare/clef"}
        self.assertEqual(dm.cached(d, "suggestions", clef), {"f1": {"label": "known"}})
        self.assertEqual(dm.cached(d, "suggestions", jev), {})

    def test_save_stamps_only_what_it_wrote(self):
        from services.fusion import store
        written = {}
        with mock.patch.object(store, "get_case", return_value={"decision_by": {"identity": "x/y"}}), \
             mock.patch.object(store, "_merge_case_details", side_effect=lambda cid, p: written.update(p)), \
             mock.patch.object(dm, "_cfg", return_value=cfg(api_key="k", model="cloudflare/clef-flash")):
            dm._save("c1", scopes={"s": 0.5})
        self.assertEqual(written["decision_scopes"], {"s": 0.5})
        self.assertEqual(written["decision_by"], {"identity": "x/y", "scopes": "openrouter/cloudflare/clef-flash"})


class Catalog(unittest.TestCase):
    """Update catalog stores OpenRouter's decision-model list; the hand-checked
    entries win where both name a model (Clef's listed 64k is a silent 16k cut)."""

    def test_listed_models_join_the_hand_checked_ones(self):
        listed = [{"provider": "openrouter", "model": "cloudflare/clef", "name": "Clef", "context": 65536},
                  {"provider": "openrouter", "model": "inception/mercury-decide", "name": "Mercury Decide",
                   "context": 65536, "price_per_m": 0.02},
                  {"provider": "openrouter", "model": "jaredpalmer/kev-4b", "name": "Kev 4B", "context": 8192},
                  {"provider": "openrouter", "model": "respan/span-01", "name": "Span", "context": 0}]
        store = mock.Mock(load=mock.Mock(return_value=listed))
        with mock.patch.object(dm, "_catalog_store", return_value=store):
            by = {(m["provider"], m["model"]): m for m in dm.catalog()}
            c = cfg(api_key="k", model="jaredpalmer/kev-4b")
            self.assertEqual(dm.context_tokens(c), 3072)                       # 3/8 of a small window
        self.assertEqual(by[("openrouter", "cloudflare/clef")]["cut_at"], 16384)   # hand entry kept
        self.assertEqual(by[("openrouter", "inception/mercury-decide")]["budget"], 24000)
        self.assertEqual(by[("openrouter", "respan/span-01")]["budget"], dm.UNKNOWN_BUDGET)
        self.assertEqual(sum(k == ("openrouter", "cloudflare/clef") for k in by), 1)

    def test_refresh_skips_aliases_and_reads_the_price(self):
        body = {"data": [{"id": "~typesafe/jev-latest", "name": "Jev Latest", "context_length": 64000},
                         {"id": "liquid/d1", "name": "LiquidAI: d1", "context_length": 65536,
                          "pricing": {"prompt": "0.00000004"}}]}
        store = mock.Mock(write=mock.Mock(side_effect=lambda rows: {"success": True, "rows": rows}))
        resp = mock.Mock(json=lambda: body, raise_for_status=lambda: None)
        with mock.patch.object(dm, "_catalog_store", return_value=store), \
             mock.patch.object(dm.requests, "get", return_value=resp, create=True) as get:
            rows = dm.refresh_catalog(cfg(api_key="sk-or"))["rows"]
        self.assertIn("output_modalities=decisions", get.call_args[0][0])
        self.assertEqual(rows, [{"provider": "openrouter", "model": "liquid/d1", "name": "LiquidAI: d1",
                                 "context": 65536, "price_per_m": 0.04}])


class KeyGuard(unittest.TestCase):
    """A masked key on screen means "keep the saved one" -- only while it still goes
    to the same place. Needs Flask (the backend image has it; a bare dev box skips)."""

    def put(self, body, stored_dm):
        try:
            import flask
            from routes import config_routes as cr
        except ImportError as e:
            self.skipTest(f"no flask here: {e}")
        saved = {}
        app = flask.Flask(__name__)
        app.register_blueprint(cr.config_bp)
        with mock.patch.object(cr, "load_frontend_config", return_value={"agentic": {"decision_model": stored_dm}}), \
             mock.patch.object(cr, "save_frontend_config", side_effect=lambda c: saved.update(c)):
            self.assertEqual(app.test_client().put("/api/config", json=body).status_code, 200)
        return saved["agentic"]["decision_model"]

    def test_switching_provider_does_not_carry_the_key(self):
        stored = {"enabled": True, "provider": "openrouter", "mode": "online", "api_key": "sk-or-real"}
        out = self.put({"agentic": {"decision_model": {**stored, "provider": "openai", "api_key": "••••••••real"}}}, stored)
        self.assertEqual(out["api_key"], "")
        out = self.put({"agentic": {"decision_model": {**stored, "mode": "offline", "url": "http://10.0.0.5/v1",
                                                       "api_key": "••••••••real"}}}, stored)
        self.assertEqual(out["api_key"], "")

    def test_same_provider_keeps_it(self):
        stored = {"enabled": True, "api_key": "sk-or-real"}               # saved before provider existed
        out = self.put({"agentic": {"decision_model": {"enabled": True, "mode": "online", "provider": "openrouter",
                                                       "model": "cloudflare/clef", "api_key": "••••••••real"}}}, stored)
        self.assertEqual(out["api_key"], "sk-or-real")


if __name__ == "__main__":
    unittest.main()
