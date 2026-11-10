"""The QA helpers that changed when every web UI moved behind the main nginx.

Offline and zero-dependency like test_qa_harness.py: the phase modules import
requests, so the two pure helpers are lifted out of the source by AST and run
on their own.
"""

import ast
import os
import re
import tempfile
import unittest

QA = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                  "qa", "phases")


def _load(fn, *names):
    """{name: object} for top-level functions/assignments `names` in qa/phases/fn."""
    with open(os.path.join(QA, fn), encoding="utf-8") as fh:
        tree = ast.parse(fh.read())
    keep = [n for n in tree.body
            if (isinstance(n, ast.FunctionDef) and n.name in names)
            or (isinstance(n, ast.Assign)
                and any(getattr(t, "id", None) in names for t in n.targets))]
    ns = {"os": os, "re": re}
    exec(compile(ast.Module(body=keep, type_ignores=[]), fn, "exec"), ns)
    return {n: ns[n] for n in names}


class TestFirstPublishedPort(unittest.TestCase):
    """The rollback scenario holds this port; None means it tests nothing."""

    port = staticmethod(_load("upgrade.py", "_first_published_port")
                        ["_first_published_port"])

    def _with(self, ports_line):
        root = tempfile.mkdtemp()
        os.makedirs(os.path.join(root, "modules", "portainer"))
        with open(os.path.join(root, "modules", "portainer",
                               "docker-compose.yaml"), "w") as fh:
            fh.write("services:\n  portainer:\n    ports:\n"
                     f"      {ports_line}\n")
        return self.port(root, "portainer")

    def test_loopback_bound_form(self):
        self.assertEqual(self._with('- "127.0.0.1:9443:9443"'), 9443)

    def test_legacy_lan_form(self):
        self.assertEqual(self._with('- "9443:9443"'), 9443)

    def test_trailing_comment_and_tcp_suffix(self):
        self.assertEqual(self._with("- 127.0.0.1:9443:9443/tcp  # why"), 9443)

    def test_missing_compose(self):
        self.assertIsNone(self.port(tempfile.mkdtemp(), "portainer"))


class TestLoginRedirect(unittest.TestCase):
    ok = staticmethod(_load("platform.py", "_is_login_redirect")
                      ["_is_login_redirect"])

    def test_relative_redirect_on_443(self):
        self.assertTrue(self.ok(302, "https://h:443/kibana/",
                                "/login.html?reason=expired"))

    def test_extra_port_must_go_to_443(self):
        self.assertTrue(self.ok(302, "https://h:8444/", "https://h/login.html"))
        # a relative Location from :8444 lands on :8444, where no login lives
        self.assertFalse(self.ok(302, "https://h:8444/", "/login.html"))
        self.assertFalse(self.ok(302, "https://h:5443/",
                                 "https://h:5443/login.html"))

    def test_not_a_gate(self):
        self.assertFalse(self.ok(200, "https://h:443/portainer/", ""))
        self.assertFalse(self.ok(404, "https://h:443/kibana/", "/login.html"))
        self.assertFalse(self.ok(302, "https://h:8444/", "/login"))  # IRIS' own
        self.assertFalse(self.ok("error: refused", "https://h:5443/", ""))


class TestPortLists(unittest.TestCase):
    def test_moved_ports_are_loopback_only_and_gated(self):
        got = _load("platform.py", "LOOPBACK_ONLY", "NGINX_GATED")
        loopback = {p for p, _ in got["LOOPBACK_ONLY"]}
        self.assertLessEqual({9200, 5601, 8443, 9443, 5000}, loopback)
        gated = {(p, path) for p, path, _ in got["NGINX_GATED"]}
        self.assertLessEqual({(443, "/kibana/"), (443, "/portainer/"),
                              (8444, "/"), (5443, "/"), (8002, "/")}, gated)
        self.assertFalse(loopback & {p for p, _ in gated},
                         "a port cannot be both loopback-only and an entry point")


if __name__ == "__main__":
    unittest.main()
