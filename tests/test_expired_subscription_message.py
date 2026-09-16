"""A spent subscription token must say what happened, not "did not answer".

A Codex subscription login works for days and then every report fails with

    LLM · OpenAI (Subscription) connection failed — llm_error: OpenAI
    (Subscription): Your access token could not be refreshed because your
    refresh token was already used. Please log out and sign in again.
    Report · LLM call failed — The AI model did not answer. Check the API key
    and the internet connection in Settings ▸ Agentic, then try again.

Every sentence there is wrong for the operator. There is no API key (it is
subscription auth), the internet is fine, nothing was misconfigured, and the
vendor's "log out and sign in again" names a screen the appliance does not
have -- signing in happens on the HOST, in a shell.

What actually happened: OAuth refresh tokens are single-use. The CLI spent the
stored one, the vendor issued a replacement, and the replacement was written
into the scratch CODEX_HOME that gets shredded after the call -- because the
credential is the operator's own ~/.codex, mounted READ-ONLY. It only bites at
the FIRST refresh, which is the access token's whole lifetime after signing in,
so it looks random and unrelated to the login.

These pin the message: the failure is classified as its own reason, and the text
names the cause, the host, and both sign-in commands.
"""

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (os.path.dirname(os.path.abspath(__file__)),
           os.path.join(ROOT, "modules", "backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402  -- stubs grpc et al for a stdlib-only run

VENDOR = ("OpenAI (Subscription): Your access token could not be refreshed because "
          "your refresh token was already used. Please log out and sign in again.")


class TheFailureIsRecognised(unittest.TestCase):

    def setUp(self):
        from services.agentic import subscription_cli as sub
        self.sub = sub

    def test_the_vendors_sentence_is_classified_as_an_expired_credential(self):
        self.assertEqual("cli_credential_expired", self.sub._classify(VENDOR))

    def test_it_is_not_confused_with_never_having_signed_in(self):
        self.assertEqual("cli_not_authenticated", self.sub._classify("not logged in"))

    def test_a_read_only_host_credential_says_so_and_how_to_fix_it(self):
        P = "codex-subscription"
        home = "/tmp/intact-cli-home-test"
        self.sub._HOME_SOURCE[home] = "host"
        try:
            note = self.sub._credential_note(P, home)
        finally:
            self.sub._HOME_SOURCE.pop(home, None)
        self.assertIn("READ-ONLY", note)
        self.assertIn("codex login", note)
        self.assertIn("--device-auth", note)
        self.assertIn("HOST", note)

    def test_a_stored_credential_gets_the_same_commands_without_the_mount_story(self):
        P = "codex-subscription"
        note = self.sub._credential_note(P, "/tmp/nothing-registered")
        self.assertIn("codex login", note)
        self.assertIn("--device-auth", note)
        self.assertNotIn("READ-ONLY", note)

    def test_the_explanation_is_attached_to_the_exception_the_case_log_prints(self):
        P = "codex-subscription"
        home = "/tmp/intact-cli-home-test2"
        self.sub._HOME_SOURCE[home] = "host"
        try:
            with self.assertRaises(self.sub.SubscriptionCLIError) as cm:
                self.sub._fail(P, home, "OpenAI (Subscription): " + VENDOR, VENDOR)
        finally:
            self.sub._HOME_SOURCE.pop(home, None)
        self.assertEqual("cli_credential_expired", cm.exception.reason)
        self.assertIn("codex login", str(cm.exception))


class TheOperatorFacingMessage(unittest.TestCase):

    def setUp(self):
        from services.fusion import llm_sim
        self.msg = llm_sim.llm_error_message("cli_credential_expired")

    def test_it_names_both_sign_in_commands(self):
        self.assertIn("codex login", self.msg)
        self.assertIn("codex login --device-auth", self.msg)

    def test_it_sends_the_operator_to_the_host_not_to_a_settings_screen(self):
        self.assertIn("HOST", self.msg)
        self.assertNotIn("Settings ▸ Agentic", self.msg)

    def test_it_does_not_blame_an_api_key_or_the_network(self):
        low = self.msg.lower()
        self.assertNotIn("api key", low)
        self.assertNotIn("internet connection", low)

    def test_it_is_not_the_generic_did_not_answer_message(self):
        from services.fusion import llm_sim
        self.assertNotEqual(llm_sim.llm_error_message("llm_error"), self.msg)


if __name__ == "__main__":
    unittest.main(verbosity=2)
