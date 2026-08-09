#!/usr/bin/env python3
"""Fix 3 regression test: the refresh/sign-in warning must be logged as its
own line, immediately before the "Phase 1 complete" line, at both places an
upgrade hits the awaiting_restart handoff -- see commit b9bec9f. A real
captured run showed everything logged deeper in the workflow (services/
upgrade/__init__.py) gets lost the moment the backend restart kills the
connection delivering it to the browser; this route-layer line, at this
exact moment, is what actually survives.

Two things are exercised, both against the ACTUAL shipped module (no
reimplementation of its logic here):

  1. _log_session_note_before_restart() -- called for real, with both
     needs_swap values -- picks the right wording, logs at "warning" level,
     and actually calls add_log_to_run (not just builds a string nobody
     sends).
  2. Both real call sites (offline upgrade + online upgrade) still call it
     BEFORE their "Phase 1 complete" line, not after and not at all -- a
     structural check on the source file itself, so a future edit that
     reorders or drops either call site fails this test without needing to
     execute either surrounding route handler (each does far more: creates
     automation runs, spawns background workflow threads, etc).

flask and the `services` package aren't installed/importable in a bare dev
checkout (`import services` pulls in grpc + touches sqlite storage at import
time) -- both are stubbed in sys.modules below, just enough for
`import upgrade_routes` to succeed. Nothing under test ever calls into the
stubs' own logic, only into the recording add_log_to_run.
"""
import os
import re
import sys
import types
import unittest

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_BACKEND_DIR = os.path.join(_THIS_DIR, '..', 'modules', 'backend')
_ROUTE_FILE = os.path.join(_BACKEND_DIR, 'routes', 'upgrade_routes.py')

_log_calls = []


def _install_stub_modules():
    if 'flask' not in sys.modules:
        flask_stub = types.ModuleType('flask')
        flask_stub.Blueprint = lambda *a, **k: types.SimpleNamespace(
            route=lambda *a, **k: (lambda f: f))
        flask_stub.jsonify = lambda *a, **k: None
        flask_stub.request = None
        flask_stub.send_file = lambda *a, **k: None
        sys.modules['flask'] = flask_stub

    if 'services' not in sys.modules:
        services_stub = types.ModuleType('services')
        services_stub.create_automation_run = lambda *a, **k: None

        def _add_log_to_run(run_id, message, level='info'):
            _log_calls.append((run_id, message, level))

        services_stub.add_log_to_run = _add_log_to_run
        services_stub.update_run_status = lambda *a, **k: None
        sys.modules['services'] = services_stub


_install_stub_modules()
sys.path.insert(0, _BACKEND_DIR)
sys.path.insert(0, os.path.join(_BACKEND_DIR, 'routes'))
import upgrade_routes as ur  # noqa: E402  (must follow the stub install above)


class SessionNoteMessageTests(unittest.TestCase):
    """_log_session_note_before_restart() itself, exercised for real."""

    def setUp(self):
        _log_calls.clear()

    def test_image_swap_wording_and_level(self):
        ur._log_session_note_before_restart('run-1', {'needs_swap': True})
        self.assertEqual(len(_log_calls), 1)
        run_id, message, level = _log_calls[0]
        self.assertEqual(run_id, 'run-1')
        self.assertEqual(level, 'warning')
        self.assertIn('recreated from a new image', message)

    def test_plain_restart_wording_and_level(self):
        ur._log_session_note_before_restart('run-2', {'needs_swap': False})
        self.assertEqual(len(_log_calls), 1)
        _, message, level = _log_calls[0]
        self.assertEqual(level, 'warning')
        self.assertIn('backend restarts', message)
        self.assertNotIn('recreated from a new image', message)

    def test_missing_needs_swap_defaults_to_plain_restart(self):
        ur._log_session_note_before_restart('run-3', {})
        _, message, _ = _log_calls[0]
        self.assertIn('backend restarts', message)


class CallSiteOrderingTests(unittest.TestCase):
    """Structural check on the real source: both awaiting_restart handlers
    must call the session note BEFORE the Phase 1 complete line. Reads the
    actual file on disk each run, so it fails the moment someone reorders,
    duplicates, or removes either call site."""

    def setUp(self):
        with open(_ROUTE_FILE, encoding='utf-8') as fh:
            self.source = fh.read()

    def test_two_awaiting_restart_call_sites_exist(self):
        occurrences = self.source.count(
            "if result.get('phase') == 'awaiting_restart':")
        self.assertEqual(
            occurrences, 2,
            "expected exactly 2 awaiting_restart handlers (offline + online) "
            f"-- found {occurrences}. If a third was added, add a test for it too.")

    def test_session_note_precedes_phase1_complete_at_every_call_site(self):
        blocks = re.split(
            r"if result\.get\('phase'\) == 'awaiting_restart':", self.source)[1:]
        self.assertEqual(len(blocks), 2)
        for i, block in enumerate(blocks):
            # Only the handful of lines making up this branch, not the rest
            # of the (much longer) enclosing function.
            snippet = block[:400]
            note_pos = snippet.find('_log_session_note_before_restart(')
            complete_pos = snippet.find('Phase 1 complete')
            self.assertNotEqual(
                note_pos, -1,
                f"call site #{i + 1} is missing the session-note call")
            self.assertNotEqual(
                complete_pos, -1,
                f"call site #{i + 1} is missing its Phase 1 complete message")
            self.assertLess(
                note_pos, complete_pos,
                f"call site #{i + 1}: session note must be logged BEFORE "
                "Phase 1 complete, not after")


if __name__ == '__main__':
    unittest.main()
