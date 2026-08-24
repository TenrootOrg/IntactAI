"""One account must not become two entities because of how it was spelled.

Windows hands the same account back in two shapes depending on the artifact:
a parsed pair (domain="adatumlab", user="noda"), or one qualified string
(user="adatumlab\\noda", no domain). The account key branches on whether a
domain is present, so the second shape never reached the domain branch and
minted a SECOND, host-scoped entity for an account that already existed:

    account:domain:adatumlab\\noda
    account:asset:endpoint:C.d1a336242178d27f:adatumlab\\noda

Same person, same host, two rows in the Identities tab. Reported from the
field, then reproduced on a real case here for every user in it.

keys.py is a deliberate leaf module — "no intra-fusion imports, avoids a
cycle" — so it loads standalone and the real function is exercised here rather
than a copy of its logic. The mapper itself cannot be imported without pulling
in the whole backend, so its wiring is checked statically instead.
"""

import ast
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FUSION = os.path.join(ROOT, "modules/backend/services/fusion")
sys.path.insert(0, FUSION)

import keys  # noqa: E402  — leaf module, no package init runs


class TestSplitDomainUser(unittest.TestCase):

    def test_a_qualified_user_is_split(self):
        self.assertEqual(keys.split_domain_user("adatumlab\\noda"),
                         ("adatumlab", "noda"))

    def test_an_explicit_domain_is_left_alone(self):
        """The caller already knew; re-deriving could only disagree with it."""
        self.assertEqual(keys.split_domain_user("noda", "adatumlab"),
                         ("adatumlab", "noda"))

    def test_an_explicit_domain_wins_even_over_a_qualified_user(self):
        self.assertEqual(keys.split_domain_user("other\\noda", "adatumlab"),
                         ("adatumlab", "other\\noda"))

    def test_a_bare_user_is_unchanged(self):
        self.assertEqual(keys.split_domain_user("noda"), ("", "noda"))

    def test_case_and_whitespace_are_normalised(self):
        self.assertEqual(keys.split_domain_user("  ADATUMLAB\\Noda  "),
                         ("adatumlab", "noda"))

    def test_the_windows_local_form_is_not_a_domain(self):
        r""".\user means "this machine" — splitting it would invent a domain
        called "." and scatter local accounts into a global node."""
        self.assertEqual(keys.split_domain_user(".\\vagrant"), ("", ".\\vagrant"))

    def test_malformed_strings_are_left_alone(self):
        """A half-written name must stay on the local path rather than key a
        node on an empty domain or an empty user."""
        for bad in ("\\noda", "adatumlab\\", "\\", "\\\\"):
            self.assertEqual(keys.split_domain_user(bad), ("", bad.strip()),
                             f"{bad!r} should not have been split")

    def test_the_last_separator_wins(self):
        self.assertEqual(keys.split_domain_user("a\\b\\c"), ("a\\b", "c"))

    def test_upn_is_deliberately_not_split(self):
        """`@` also appears in ordinary local account names, and cloud.py has
        its own UPN handling that knows a provider context this does not."""
        self.assertEqual(keys.split_domain_user("noda@adatumlab.local"),
                         ("", "noda@adatumlab.local"))

    def test_empty_and_none(self):
        self.assertEqual(keys.split_domain_user(None), ("", ""))
        self.assertEqual(keys.split_domain_user(""), ("", ""))
        self.assertEqual(keys.split_domain_user(None, None), ("", ""))

    def test_it_never_raises(self):
        """The fusion module's own rule: a failure here must never break a
        fuse. Anything unexpected falls back rather than propagating."""
        class Hostile:
            def __str__(self):
                raise RuntimeError("nope")

        for bad in (Hostile(), 12345, ["a", "b"], {"a": 1}, object()):
            try:
                d, u = keys.split_domain_user(bad)
            except Exception as exc:                      # noqa: BLE001
                self.fail(f"raised on {type(bad).__name__}: {exc}")
            self.assertIsInstance(d, str)
            self.assertIsInstance(u, str)


class TestTheDuplicateActuallyCollapses(unittest.TestCase):
    """The point of the change, stated as the ids it produces."""

    def test_both_spellings_now_key_the_same_account(self):
        parsed_d, parsed_u = keys.split_domain_user("noda", "adatumlab")
        qual_d, qual_u = keys.split_domain_user("adatumlab\\noda")
        self.assertEqual((parsed_d, parsed_u), (qual_d, qual_u),
                         "the two shapes still disagree, so they would still "
                         "mint two entities")

    def test_a_local_account_stays_host_scoped(self):
        """The other half of the contract: without a domain there is nothing to
        globalise, and two machines' `vagrant` are NOT the same account."""
        d, u = keys.split_domain_user("vagrant")
        self.assertEqual(d, "")
        self.assertNotEqual(keys.account_id("asset:endpoint:C.aaa", None, u),
                            keys.account_id("asset:endpoint:C.bbb", None, u))


class TestTheMapperUsesIt(unittest.TestCase):
    """agentic.py drags in the whole backend on import, so check the wiring by
    reading it — the risk is the call being dropped, not it misbehaving."""

    def setUp(self):
        with open(os.path.join(FUSION, "mappers/agentic.py"), encoding="utf-8") as fh:
            self.src = fh.read()
        self.fn = self._func("_account_eid")

    def _func(self, name):
        tree = ast.parse(self.src)
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == name:
                return ast.get_source_segment(self.src, node) or ""
        self.fail(f"{name} is gone from agentic.py")

    def test_it_splits_before_choosing_a_key(self):
        self.assertIn("keys.split_domain_user", self.fn,
                      "_account_eid no longer splits a qualified user, so the "
                      "duplicate-entity bug is back")

    def test_the_split_happens_only_when_no_domain_was_given(self):
        self.assertIn("if not d:", self.fn,
                      "the split must not override a domain the caller supplied")

    def test_the_global_branch_still_exists(self):
        self.assertIn("account:domain:", self.fn,
                      "domain accounts must still key to one cross-host node")


if __name__ == "__main__":
    unittest.main(verbosity=2)
