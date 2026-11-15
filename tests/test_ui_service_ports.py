"""The dashboard tiles must open the port the operator set in config.yaml.

Each tool's public port is a per-module key (modules.elk.kibana_port,
modules.iris.port, ...). A box upgraded from before those keys existed has none
of them, and nginx then publishes the compose defaults -- so the route must
report exactly those defaults, or every tile on every old box opens a dead port.
"""

import ast
import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "modules", "backend", "routes", "system_routes.py")
APP_JS = os.path.join(ROOT, "modules", "nginx", "html", "js", "stores", "app.js")

DEFAULTS = {"kibana": 5602, "portainer": 9444, "iris": 8444,
            "timesketch": 5443, "volweb": 8002, "velociraptor_agent": 8000}


def _payload():
    """routes/system_routes.py imports flask at module scope and the offline
    suite has stdlib python only, so compile just the table and the function."""
    tree = ast.parse(open(SRC, encoding="utf-8").read())
    keep = [n for n in tree.body
            if (isinstance(n, ast.FunctionDef) and n.name == "service_ports_payload")
            or (isinstance(n, ast.Assign) and any(getattr(t, "id", "") == "SERVICE_PORT_KEYS"
                                                  for t in n.targets))]
    assert len(keep) == 2, "service_ports_payload / SERVICE_PORT_KEYS gone from system_routes.py"
    ns = {}
    exec(compile(ast.Module(body=keep, type_ignores=[]), SRC, "exec"), ns)
    return ns["service_ports_payload"]


class ServicePorts(unittest.TestCase):
    def test_no_keys_means_the_compose_defaults(self):
        for cfg in (None, {}, {"modules": None}, {"modules": {"elk": {"enabled": True}}}):
            self.assertEqual(_payload()(cfg), DEFAULTS)

    def test_custom_values_win(self):
        cfg = {"modules": {"elk": {"kibana_port": 15602}, "portainer": {"port": "19444"},
                           "iris": {"port": 18444}, "timesketch": {"port": 15443},
                           "volweb": {"port": 18002}, "velociraptor": {"agent_port": 18000}}}
        self.assertEqual(_payload()(cfg), {"kibana": 15602, "portainer": 19444, "iris": 18444,
                                           "timesketch": 15443, "volweb": 18002,
                                           "velociraptor_agent": 18000})

    def test_garbage_falls_back_to_default(self):
        cfg = {"modules": {"iris": {"port": "abc"}, "volweb": {"port": 70000},
                           "timesketch": {"port": 0}, "portainer": {"port": None}}}
        got = _payload()(cfg)
        for k in ("iris", "volweb", "timesketch", "portainer"):
            self.assertEqual(got[k], DEFAULTS[k])

    def test_frontend_defaults_match_backend(self):
        js = open(APP_JS, encoding="utf-8").read()
        for k in ("kibana", "portainer", "iris", "timesketch", "volweb"):
            m = re.search(r"\b%s: \{ port: (\d+)" % k, js)
            self.assertTrue(m, "window.services.%s has no default port" % k)
            self.assertEqual(int(m.group(1)), DEFAULTS[k], k)
        self.assertIn("velociraptor: { path: '/velociraptor/'", js)
        self.assertIn("/api/system/service-ports", js)


if __name__ == "__main__":
    unittest.main()
