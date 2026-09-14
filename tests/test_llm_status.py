"""Why a report came out deterministic — said plainly, and said correctly.

Reported from the box: "Air-gap analysis ... doesn't work, even if it's unchecked
it still shows the air-gap report". It was not broken. The appliance had no model
configured, so every report was written by the deterministic narrator whether the
tick was on or off — and nothing anywhere said so. The only hint was a line at the
very bottom of the report reading "Set agentic.fusion_llm_mode='real' to use a
live model", which had stopped being true when configuring a model became the
opt-in. So the operator was told to flip a flag that would not have helped.

Four different situations produced one identical, silent template:

    air-gap ticked        a deliberate choice — nothing is wrong
    no model configured   Settings ▸ Agentic
    no API key            Settings ▸ Agentic
    provider unreachable  the appliance has no route out

Each needs a different action, so each must be named. These pin the mapping and
the error classifier that separates "no route" from "key rejected" — the two that
are easiest to confuse and most expensive to confuse.

llm_sim cannot be imported (it pulls the backend), so the real functions are
lifted out and executed against a stubbed config, exactly as elsewhere here.
"""

import ast
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LLM_SIM = os.path.join(ROOT, "modules/backend/services/fusion/llm_sim.py")

WANTED = ("llm_status", "_classify_llm_error", "_sim_tag", "_llm_reason_text",
          "_subscription_gap", "llm_status_known", "_reach_fingerprint")
CONSTS = ("LLM_OK", "LLM_PINNED", "LLM_NO_MODEL", "LLM_MISSING_KEY",
          "_LLM_CONFIG_REASONS", "_LLM_ERR_MESSAGES", "_SIM_TAG_PREFIX", "_REACH_LAST")


def _load():
    with open(LLM_SIM, encoding="utf-8") as f:
        src = f.read()
    tree = ast.parse(src)
    ns = {"_state": {"cfg": {}, "subscription": False}}
    ns["_agentic_cfg"] = lambda: ns["_state"]["cfg"]
    ns["_subscription_ready"] = lambda p: ns["_state"]["subscription"]

    for node in tree.body:
        if isinstance(node, ast.Assign):
            names = [t.id for t in node.targets if isinstance(t, ast.Name)]
            if any(n in CONSTS for n in names):
                exec(compile(ast.Module(body=[node], type_ignores=[]), LLM_SIM, "exec"), ns)
    picked = {n.name: n for n in tree.body
              if isinstance(n, ast.FunctionDef) and n.name in WANTED}
    missing = [w for w in WANTED if w not in picked]
    if missing:
        raise AssertionError("not found in llm_sim.py: %s" % ", ".join(missing))
    for w in WANTED:
        exec(compile(ast.Module(body=[picked[w]], type_ignores=[]), LLM_SIM, "exec"), ns)
    for c in CONSTS:
        if c not in ns:
            raise AssertionError("constant %s missing from llm_sim.py" % c)
    return ns


NS = _load()
STATE = NS["_state"]
status = NS["llm_status"]
classify = NS["_classify_llm_error"]
sim_tag = NS["_sim_tag"]
reason_text = NS["_llm_reason_text"]


class _Base(unittest.TestCase):
    def setUp(self):
        STATE["cfg"] = {"llm_mode": "online",
                        "online_llm": {"provider": "openai", "model": "gpt-4o",
                                       "api_key": "sk-test"}}
        STATE["subscription"] = False


class TestAvailable(_Base):

    def test_a_configured_online_model_is_available(self):
        st = status()
        self.assertTrue(st["available"])
        self.assertEqual(st["reason"], "", "nothing to explain when it works")

    def test_a_subscription_needs_no_api_key(self):
        STATE["cfg"]["online_llm"] = {"provider": "claude", "model": "opus"}
        STATE["subscription"] = True
        self.assertTrue(status()["available"])

    def test_a_subscription_with_the_model_left_blank_is_available(self):
        """Reported live: a connected Codex subscription with the Model field
        blank (the plan's default, which Settings allows) was shown as "No AI
        model is selected", and the banner never offered Regenerate. The report
        path itself worked; only this status check demanded a model name."""
        STATE["cfg"]["online_llm"] = {"provider": "codex-subscription", "model": "",
                                      "api_key": "leftover"}
        STATE["subscription"] = True
        st = status()
        self.assertTrue(st["available"], st)
        self.assertEqual("", st["reason"])

    def test_a_blank_model_is_still_missing_for_a_key_based_provider(self):
        STATE["cfg"]["online_llm"] = {"provider": "openai", "model": "", "api_key": "sk-test"}
        self.assertEqual(NS["LLM_NO_MODEL"], status()["code"])

    def test_a_self_hosted_model_needs_neither_key_nor_route(self):
        STATE["cfg"] = {"llm_mode": "offline"}
        self.assertTrue(status()["available"])


class TestEachReasonIsNamed(_Base):

    def test_there_is_no_air_gap_setting_left(self):
        """It was removed: on a box with no model the report came out
        deterministic whether it was ticked or not, so the tick read as broken.
        An appliance with no route now simply gets the deterministic report and
        is told why — which is all the tick ever did."""
        import inspect
        self.assertEqual(list(inspect.signature(status).parameters), [],
                         "llm_status must not take an air_gap argument any more")
        self.assertNotIn("air_gap", NS["_LLM_CONFIG_REASONS"])

    def test_no_model_is_reported(self):
        STATE["cfg"]["online_llm"] = {"provider": "openai", "api_key": "sk-test"}
        st = status()
        self.assertEqual(st["code"], NS["LLM_NO_MODEL"])
        self.assertIn("Settings", st["fix"])

    def test_no_api_key_is_reported(self):
        STATE["cfg"]["online_llm"] = {"provider": "openai", "model": "gpt-4o"}
        st = status()
        self.assertEqual(st["code"], NS["LLM_MISSING_KEY"])
        self.assertIn("API key", st["reason"])

    def test_it_uses_the_same_code_chat_uses(self):
        """One vocabulary across the product: the same condition must not be
        called `no_api_key` here and `missing_key` in chat."""
        self.assertIn(NS["LLM_MISSING_KEY"], NS["_LLM_ERR_MESSAGES"])

    def test_no_api_key_explains_what_happens_meanwhile(self):
        """The operator should not be left wondering what they are looking at."""
        STATE["cfg"]["online_llm"] = {"provider": "openai", "model": "gpt-4o"}
        self.assertIn("no network", status()["fix"])

    def test_a_pinned_deterministic_box_is_reported(self):
        STATE["cfg"]["fusion_llm_mode"] = "simulated"
        st = status()
        self.assertEqual(st["code"], NS["LLM_PINNED"])

    def test_every_config_reason_carries_a_fix(self):
        """A reason with no action is just a complaint."""
        for code, (reason, fix) in NS["_LLM_CONFIG_REASONS"].items():
            self.assertTrue(reason.strip(), "%s has no reason text" % code)
            self.assertTrue(fix.strip(), "%s tells the operator nothing to do" % code)


class TestTheLastLiveAnswer(_Base):
    """The case payload's status: config, corrected by the last live probe of
    that exact config, with no call made. It lets the Analysis tab act at once
    instead of waiting ~10s for its own probe."""

    def setUp(self):
        super().setUp()
        NS["_REACH_LAST"].clear()

    def _remember(self, result):
        NS["_REACH_LAST"][NS["_reach_fingerprint"](STATE["cfg"])] = result

    def test_no_probe_yet_reads_as_config(self):
        self.assertTrue(NS["llm_status_known"]()["available"])

    def test_a_rejected_key_is_remembered(self):
        self._remember({"available": False, "code": "invalid_key",
                        "reason": "The AI provider rejected the API key.", "fix": "x"})
        st = NS["llm_status_known"]()
        self.assertFalse(st["available"])
        self.assertEqual("invalid_key", st["code"])
        self.assertFalse(st["checked_live"], "remembered, not probed just now")

    def test_a_new_key_is_not_judged_by_the_old_ones_failure(self):
        """The fingerprint used bool(api_key): replacing a rejected key with a
        working one kept the same fingerprint, so the old "rejected" stuck."""
        self._remember({"available": False, "code": "invalid_key", "reason": "r", "fix": "f"})
        STATE["cfg"]["online_llm"]["api_key"] = "sk-a-different-key"
        self.assertTrue(NS["llm_status_known"]()["available"])

    def test_the_fingerprint_never_contains_the_key(self):
        fp = NS["_reach_fingerprint"](STATE["cfg"])
        self.assertNotIn("sk-test", fp)

    def test_a_config_problem_still_wins(self):
        STATE["cfg"]["online_llm"] = {"provider": "openai", "model": "gpt-4o"}
        self.assertEqual(NS["LLM_MISSING_KEY"], NS["llm_status_known"]()["code"])


class TestErrorClassification(_Base):
    """A call that failed: no route, a rejected key, or an empty account? The
    operator's next action is completely different for each.

    These pin the EXISTING classifier rather than a new one. A duplicate was
    briefly added here and Python silently shadowed it with the real definition
    further down the file, so the codes it produced never matched the ones it was
    compared against — which is how the duplication was noticed at all."""

    def test_a_connection_error_is_a_route_problem(self):
        self.assertEqual(classify(ConnectionError("connection refused")),
                         "no_internet")

    def test_a_timeout_is_reported_as_a_timeout(self):
        """Distinct from no-route: retrying a timeout can work, a dead route cannot."""
        self.assertEqual(classify(TimeoutError("timed out")), "timeout")

    def test_dns_failure_is_a_route_problem(self):
        self.assertEqual(classify(OSError("Name or service not known")),
                         "no_internet")

    def test_a_rejected_key_is_not_reported_as_a_network_problem(self):
        self.assertEqual(classify(RuntimeError("401 Unauthorized")), "invalid_key")
        self.assertEqual(classify(RuntimeError("invalid api key")), "invalid_key")

    def test_an_unrecognised_failure_falls_back_to_a_generic_code(self):
        self.assertEqual(classify(RuntimeError("something odd")), "llm_error")

    def test_billing_is_not_mistaken_for_a_key_or_rate_problem(self):
        """A funded-out account still authenticates, and OpenAI returns it as a
        429 — so both the auth and rate-limit branches would give wrong advice."""
        self.assertEqual(classify(RuntimeError("credit balance is too low")), "no_credit")
        self.assertEqual(classify(RuntimeError("429 insufficient_quota")), "no_credit")

    def test_classification_never_raises(self):
        class Odd(Exception):
            def __str__(self):
                raise ValueError("cannot render")
        try:
            classify(ValueError("x"))
        except Exception as e:  # noqa: BLE001
            self.fail("classifier raised: %s" % e)


class TestTheReportTag(_Base):

    def test_the_tag_names_the_reason(self):
        STATE["cfg"]["online_llm"] = {"provider": "openai", "model": "gpt-4o"}
        tag = sim_tag()
        self.assertIn("API key", tag)
        self.assertIn("Deterministic report", tag)

    def test_no_reason_gives_the_stale_advice(self):
        """fusion_llm_mode='real' stopped being the opt-in when configuring a model
        became it, so telling an operator to set it wastes their time. Checked on
        the TEXT SHOWN, not the file — a comment explaining the old advice is
        exactly what this file should contain."""
        shown = [t for pair in NS["_LLM_CONFIG_REASONS"].values() for t in pair]
        shown.append(NS["_SIM_TAG_PREFIX"])
        for text in shown:
            self.assertNotIn("fusion_llm_mode='real'", text,
                             "this is the advice that stopped being true")
        # `pinned` is the one reason whose fix genuinely IS a config key: somebody
        # deliberately set it, there is no UI for it, and the person clearing it is
        # support. Every other reason must point at the UI, not at internals.
        for code, (reason, fix) in NS["_LLM_CONFIG_REASONS"].items():
            if code == NS["LLM_PINNED"]:
                continue
            self.assertNotIn("fusion_llm_mode", reason + fix,
                             "%s names an internal key at the operator" % code)

    def test_an_available_model_still_tags_the_deterministic_path(self):
        """Explains a report written deterministically while a model WAS available
        (a background fuse), rather than implying something is misconfigured."""
        tag = sim_tag()
        self.assertIn("Deterministic report", tag)
        self.assertNotIn("API key", tag)



class TestEveryMessageIsPlain(_Base):
    """Every reason an AI report could not be written, held to one standard.

    Reported from QA: the Analysis banner was confusing. One message said "no
    model call made", the next "a model is reachable now", the last "add a model
    and API key". So every message is now a (problem, fix) pair: the problem in
    one plain sentence, then what to do and where. These rules keep it that way
    for every code, including ones added later."""

    def _all(self):
        out = dict(NS["_LLM_ERR_MESSAGES"])
        out.update({"config:" + k: v for k, v in NS["_LLM_CONFIG_REASONS"].items()})
        return out

    def test_every_message_is_a_problem_and_a_fix(self):
        for code, pair in self._all().items():
            self.assertIsInstance(pair, tuple, code)
            self.assertEqual(2, len(pair), code)
            problem, fix = pair
            self.assertTrue(problem.strip(), "%s has no problem text" % code)
            self.assertTrue(fix.strip(), "%s tells the operator nothing to do" % code)

    def test_every_sentence_is_finished_and_short(self):
        for code, (problem, fix) in self._all().items():
            for part, text, cap in (("problem", problem, 160), ("fix", fix, 170)):
                self.assertRegex(text, r"[.)]$", "%s %s is not a finished sentence: %r" % (code, part, text))
                self.assertNotIn("..", text, "%s %s has a doubled period" % (code, part))
                self.assertLessEqual(len(text), cap, "%s %s is too long to read at a glance" % (code, part))

    def test_no_internal_jargon_reaches_the_operator(self):
        for code, (problem, fix) in self._all().items():
            text = problem + " " + fix
            for word in ("LLM", "deterministic", "narrat", "graph", "⚠", "→", "pinned"):
                self.assertNotIn(word, text, "%s says %r: %r" % (code, word, text))

    def test_every_fix_says_where_or_how(self):
        """A fix must be something to DO: a place in Settings, a retry, or (for
        the one config-only switch) who changes it."""
        for code, (_problem, fix) in self._all().items():
            self.assertTrue(
                "Settings ▸ Agentic" in fix or "try again" in fix.lower() or "Support" in fix,
                "%s gives no place or action: %r" % (code, fix))

    def test_every_fix_ends_by_retrying(self):
        """One reading order everywhere: what to do, THEN retry. The banner turns
        "then try again." into "then click Regenerate report."; a fix that ends on
        anything else gets a retry sentence bolted on after it, which reads badly."""
        for code, (_problem, fix) in self._all().items():
            self.assertTrue(fix.endswith("then try again.") or fix.startswith("Try again."),
                            "%s does not end by retrying: %r" % (code, fix))

    def test_the_billing_and_routing_messages_say_the_key_is_fine(self):
        """Both arrive looking like auth failures; an operator told nothing
        replaces a key that works."""
        for code in ("no_credit", "model_not_routable"):
            self.assertIn("The API key itself is fine.", NS["_LLM_ERR_MESSAGES"][code][0], code)

    def test_every_error_code_the_classifier_returns_has_a_message(self):
        samples = ("credit balance is too low", "no endpoints available", "401",
                   "timed out", "429", "connection refused", "something odd")
        for text in samples:
            code = classify(RuntimeError(text))
            self.assertIn(code, NS["_LLM_ERR_MESSAGES"], "%r -> %s has no message" % (text, code))

    def test_reason_text_returns_the_pair_unchanged(self):
        self.assertEqual(NS["_LLM_ERR_MESSAGES"]["invalid_key"], reason_text("invalid_key"))
        self.assertEqual(NS["_LLM_CONFIG_REASONS"]["no_model"], reason_text("no_model"))
        self.assertEqual(NS["_LLM_ERR_MESSAGES"]["llm_error"], reason_text("never-heard-of-it"))

    def test_the_report_tag_reads_as_one_clean_sentence_pair(self):
        STATE["cfg"]["online_llm"] = {"provider": "openai", "model": "gpt-4o"}
        tag = sim_tag()
        self.assertNotIn("..", tag)
        self.assertIn("No API key is set for the AI model. Until then, reports use", tag)
        self.assertTrue(tag.rstrip().endswith("then try again._"), tag)


if __name__ == "__main__":
    unittest.main(verbosity=2)
