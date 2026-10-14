"""Settings → Velociraptor pilot box: the fleet is read once per 10 s, not per keystroke.

client_versions() is two full-fleet VQL queries plus classification. The pilot
autocomplete called it on every keystroke, so typing a host name on a 1,000-client
fleet ran it once per letter. Executes the real helper (lifted out of the route
module by AST: flask is a container dependency, not a test one).
"""
import ast
import os
import sys
import threading
import unittest
from unittest import mock

_HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(_HERE)
for _p in (_HERE, os.path.join(ROOT, "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
import services.velociraptor_clients as vc  # noqa: E402

VELO = os.path.join(ROOT, "modules/backend/routes/velociraptor_routes.py")
NAMES = {"_PILOT_FLEET_TTL", "_pilot_fleet", "_pilot_fleet_lock", "_pilot_fleet_status"}


class _Clock:
    now = 1000.0

    def time(self):
        return self.now


def _src():
    with open(VELO, encoding="utf-8") as fh:
        return fh.read()


def _load(clock):
    src = _src()
    ns = {"threading": threading, "time": clock}
    for n in ast.parse(src).body:
        names = {t.id for t in getattr(n, "targets", []) if isinstance(t, ast.Name)}
        if getattr(n, "name", None) in NAMES or names & NAMES:
            exec(compile(ast.get_source_segment(src, n), VELO, "exec"), ns)
    return ns["_pilot_fleet_status"]


class PilotFleetCache(unittest.TestCase):
    def test_keystrokes_share_one_fleet_read_until_ttl(self):
        clock = _Clock()
        status = _load(clock)
        fleet = {"server_version": "0.77.2", "clients": []}
        with mock.patch.object(vc, "client_versions", return_value=fleet) as cv:
            for _ in range(5):                 # five keystrokes inside the window
                self.assertIs(status(), fleet)
            self.assertEqual(cv.call_count, 1)
            clock.now += 10                    # TTL over: the next keystroke re-reads
            status()
            self.assertEqual(cv.call_count, 2)

    def test_concurrent_keystrokes_do_not_stampede(self):
        status = _load(_Clock())
        gate = threading.Event()

        def slow():
            gate.wait(2)
            return {"clients": []}

        with mock.patch.object(vc, "client_versions", side_effect=slow) as cv:
            ts = [threading.Thread(target=status) for _ in range(8)]
            for t in ts:
                t.start()
            gate.set()
            for t in ts:
                t.join(5)
            self.assertEqual(cv.call_count, 1)

    def test_route_uses_the_cache(self):
        body = _src().split("def velociraptor_pilot_candidates", 1)[1].split("\n@", 1)[0]
        self.assertIn("_pilot_fleet_status()", body)
        self.assertNotIn("client_versions()", body)


if __name__ == "__main__":
    unittest.main()
