"""A blueprint naming an artifact the Velociraptor server never loaded no longer
fails the whole bulk hunt.

hunt() refused all 20 artifacts of "Agentic QuickWins Windows" over one newer
bundled artifact (Custom.Windows.Detection.DefenderExclusions) on a server still
running the previous image. The unknown one is now left out and named in the Log.
The routes module needs Flask, so the function is taken from the source and run.
"""
import ast
import json
import os
import types
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "modules/backend/routes/velociraptor_routes.py")


def _load():
    tree = ast.parse(open(SRC).read())
    fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_drop_unknown_artifacts")
    pb2 = types.SimpleNamespace(VQLCollectorArgs=lambda **k: k, VQLRequest=lambda **k: k)
    ns = {"json": json, "api_pb2": pb2}
    exec(compile(ast.Module(body=[fn], type_ignores=[]), SRC, "exec"), ns)
    return ns["_drop_unknown_artifacts"]


class _Stub:
    def __init__(self, names=None, fail=False):
        self.names, self.fail = names, fail

    def Query(self, req, timeout):
        if self.fail:
            raise RuntimeError("unavailable")
        return [types.SimpleNamespace(Response=json.dumps([{"name": n} for n in self.names]))]


class DropUnknown(unittest.TestCase):
    def setUp(self):
        self.drop, self.logs = _load(), []
        self.log = lambda m, lvl="info": self.logs.append((lvl, m))

    def test_unknown_is_left_out_and_named(self):
        got = self.drop(_Stub(["A.One", "A.Two"]), ["A.One", "New.Thing", "A.Two"], self.log)
        self.assertEqual(["A.One", "A.Two"], got)
        self.assertEqual("warning", self.logs[0][0])
        self.assertIn("New.Thing", self.logs[0][1])

    def test_all_known_logs_nothing(self):
        self.assertEqual(["A.One"], self.drop(_Stub(["A.One"]), ["A.One"], self.log))
        self.assertEqual([], self.logs)

    def test_failed_lookup_keeps_the_list(self):
        self.assertEqual(["A.One", "X"], self.drop(_Stub(fail=True), ["A.One", "X"], self.log))
        self.assertEqual([], self.drop(_Stub([]), [], self.log))

    def test_bulk_path_uses_it(self):
        self.assertIn("artifacts = _drop_unknown_artifacts(stub, artifacts", open(SRC).read())


if __name__ == "__main__":
    unittest.main()
