"""The running-hunt reconcile does not ask Velociraptor on every poll.

_reconcile_velociraptor_hunt ran is_hunt_registered() -- a docker exec plus a
gRPC query -- for every running hunt on every poll of the Workflows list and of
each open log window. A "yes" never changes (a hunt Velociraptor holds stays
registered), so it is kept; a "no" is re-asked after 30 s.

The route file is loaded on its own with a stand-in `flask` (the backend's
dependencies are not installed here); is_hunt_registered is mocked.
"""

import importlib.util
import os
import sys
import tempfile
import types
import unittest
from unittest import mock

os.environ.setdefault("INTACT_STORAGE_BASE", tempfile.mkdtemp(prefix="intact-huntcache-"))
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [os.path.join(ROOT, "modules", "backend"), os.path.join(ROOT, "tests")]

try:
    import flask  # noqa: F401
except ImportError:
    _flask = types.ModuleType("flask")

    class _Blueprint:
        def __init__(self, *a, **k):
            pass

        def route(self, *a, **k):
            return lambda f: f
    _flask.Blueprint = _Blueprint
    _flask.jsonify = lambda *a, **k: a[0] if a else k
    sys.modules["flask"] = _flask

import _optional_deps  # noqa: F401,E402
import services.velociraptor_service as vs  # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "dashboard_routes_under_test", os.path.join(ROOT, "modules/backend/routes/dashboard_routes.py"))
dr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dr)


class Cache(unittest.TestCase):

    def setUp(self):
        dr._hunts_registered.clear()
        dr._hunts_not_yet.clear()

    def test_no_is_reasked_after_30s_and_yes_is_kept(self):
        clock = [1000.0]
        answers = [False, False, True]
        with mock.patch("time.monotonic", side_effect=lambda: clock[0]), \
                mock.patch.object(vs, "is_hunt_registered", side_effect=answers) as ask:
            self.assertFalse(dr._hunt_registered_cached("H.1"))
            clock[0] += 10
            self.assertFalse(dr._hunt_registered_cached("H.1"))       # cached "no"
            self.assertEqual(ask.call_count, 1)
            clock[0] += 25
            self.assertFalse(dr._hunt_registered_cached("H.1"))       # 35 s: asked again
            clock[0] += 31
            self.assertTrue(dr._hunt_registered_cached("H.1"))
            clock[0] += 10_000
            self.assertTrue(dr._hunt_registered_cached("H.1"))        # kept for good
            self.assertEqual(ask.call_count, 3)

    def test_hunts_are_cached_separately(self):
        with mock.patch.object(vs, "is_hunt_registered", side_effect=lambda h: h == "H.yes") as ask:
            self.assertTrue(dr._hunt_registered_cached("H.yes"))
            self.assertFalse(dr._hunt_registered_cached("H.no"))
            self.assertFalse(dr._hunt_registered_cached("H.no"))
            self.assertEqual(ask.call_count, 2)


if __name__ == "__main__":
    unittest.main()
