"""qa/lib/probe.py — the two helpers that keep a failing phase from making a
mess.

Both exist because of failure modes observed while writing the phases that use
them, and both are easy to "simplify" into uselessness:

  * `attempt` must convert an exception into a FAILED CHECK. If someone changes
    it to swallow and return the default silently, a broken endpoint becomes a
    green run — the exact opposite of the point.
  * `cleanup` must never raise. It is called from `finally` blocks, so a
    teardown that throws would replace the phase's real diagnosis with a
    misleading one, and would skip the remaining teardowns.
"""

import os
import sys
import unittest

QA = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "qa")
if QA not in sys.path:
    sys.path.insert(0, QA)

from lib import probe                                          # noqa: E402


class _Ctx:
    def __init__(self):
        self.checks = []

    def check(self, name, ok, expected=None, actual=None, note=None):
        self.checks.append((name, ok, actual))
        return bool(ok)


class _Client:
    """Records DELETEs; raises for any path containing 'boom'."""

    def __init__(self):
        self.calls = []

    def request(self, method, path, expect=None):
        self.calls.append((method, path))
        if "boom" in path:
            raise RuntimeError("the server hung up")
        return {}


class Attempt(unittest.TestCase):
    def test_a_successful_call_is_passed_straight_through(self):
        ctx = _Ctx()
        self.assertEqual(probe.attempt(ctx, "x", lambda: 42), 42)
        self.assertEqual(ctx.checks, [], "a success must not record a check")

    def test_a_raising_call_becomes_a_failed_check_not_an_exception(self):
        ctx = _Ctx()
        def _boom():
            raise ValueError("nope")
        out = probe.attempt(ctx, "the thing works", _boom, default="fallback")
        self.assertEqual(out, "fallback")
        self.assertEqual(len(ctx.checks), 1)
        name, ok, actual = ctx.checks[0]
        self.assertEqual(name, "the thing works")
        self.assertFalse(ok, "the whole point is that this FAILS, loudly")
        self.assertIn("ValueError", actual, "the report has to say what broke")
        self.assertIn("nope", actual)

    def test_the_phase_can_keep_going_after_one_call_fails(self):
        """The reason this exists: a blip on one of twenty assertions must not
        cost the other nineteen."""
        ctx = _Ctx()
        probe.attempt(ctx, "first", lambda: (_ for _ in ()).throw(OSError("x")))
        self.assertEqual(probe.attempt(ctx, "second", lambda: "ok"), "ok")
        self.assertEqual([c[1] for c in ctx.checks], [False])


class Cleanup(unittest.TestCase):
    def test_it_deletes_everything_it_is_given(self):
        c = _Client()
        done = probe.cleanup(c, ["/api/a", "/api/b"])
        self.assertEqual(done, ["/api/a", "/api/b"])
        self.assertEqual(c.calls, [("DELETE", "/api/a"), ("DELETE", "/api/b")])

    def test_none_entries_are_skipped_so_callers_need_no_guards(self):
        """Callers write `cleanup(c, [job and f"/jobs/{job}", ...])` on a path
        where the id may never have been assigned."""
        c = _Client()
        self.assertEqual(probe.cleanup(c, [None, "/api/a", None]), ["/api/a"])

    def test_a_failing_delete_never_raises_and_never_stops_the_rest(self):
        """THE PROPERTY THAT MATTERS. This runs inside `finally`; raising here
        would mask the real failure and strand every later teardown."""
        c = _Client()
        done = probe.cleanup(c, ["/api/boom", "/api/after"])
        self.assertEqual(done, ["/api/after"],
                         "the surviving delete must still have been attempted")
        self.assertEqual(len(c.calls), 2)

    def test_an_empty_or_none_list_is_harmless(self):
        c = _Client()
        self.assertEqual(probe.cleanup(c, None), [])
        self.assertEqual(probe.cleanup(c, []), [])


class Contract(unittest.TestCase):
    def test_gone_accepts_the_codes_a_missing_thing_answers(self):
        """Teardown of something already removed is not a failure."""
        for code in (200, 204, 404):
            self.assertIn(code, probe.GONE)

    def test_soft_includes_404_so_an_empty_list_is_not_a_phase_failure(self):
        self.assertIn(404, probe.SOFT)
        self.assertIn(200, probe.SOFT)


if __name__ == "__main__":
    unittest.main(verbosity=2)
