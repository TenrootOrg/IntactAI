"""Memory defaults are read-only through /api/memory/blueprints too (QA D9).

blueprint_routes.py refuses edits to shipped defaults, but memory_routes.py
writes the same table through its own CRUD: PUT and DELETE on a default, and a
POST reusing a default's id (the store is INSERT OR REPLACE), all went through.
The real route functions are executed with flask and the store faked, and the
refusal helper is the real one from blueprint_routes.py, so the message cannot
drift between the two doors.
"""
import ast
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MEM = os.path.join(ROOT, "modules/backend/routes/memory_routes.py")
BPR = os.path.join(ROOT, "modules/backend/routes/blueprint_routes.py")


def _segments(path, names):
    with open(path, encoding="utf-8") as fh:
        src = fh.read()
    out = []
    for n in ast.parse(src).body:
        if isinstance(n, ast.FunctionDef) and n.name in names:
            out.append(ast.get_source_segment(src, n))   # decorators excluded
        elif isinstance(n, ast.Assign) and any(
                getattr(t, "id", None) in names for t in n.targets):
            out.append(ast.get_source_segment(src, n))
    return "\n\n".join(out)


class _Req:
    body = None

    def get_json(self, *a, **k):
        return self.body


def _load():
    store = {"mem_default": {"id": "mem_default", "name": "Shipped", "is_default": True},
             "custom_1": {"id": "custom_1", "name": "Mine", "is_default": False}}
    req = _Req()
    ns = {"jsonify": lambda d: d, "request": req, "_BLUEPRINT_TYPE": "memory",
          "get_blueprint": lambda t, i: dict(store[i]) if i in store else None,
          "save_blueprint": lambda t, d: store.__setitem__(d["id"], dict(d)) or dict(d),
          "delete_blueprint": lambda t, i: store.pop(i, None) is not None}
    exec(_segments(BPR, {"DEFAULT_READONLY_ERROR", "_refuse_default_write"}), ns)
    exec(_segments(MEM, {"create_memory_blueprint", "update_memory_blueprint",
                         "delete_memory_blueprint"}), ns)
    return ns, store, req


def _status(resp):
    return resp[1] if isinstance(resp, tuple) else 200


class MemoryDefaultsLocked(unittest.TestCase):
    def setUp(self):
        self.ns, self.store, self.req = _load()

    def call(self, name, body, *args):
        self.req.body = body
        return self.ns[name](*args)

    def test_put_on_default_is_403_and_row_unchanged(self):
        resp = self.call("update_memory_blueprint", {"name": "hacked"}, "mem_default")
        self.assertEqual(403, _status(resp))
        self.assertEqual(self.ns["DEFAULT_READONLY_ERROR"], resp[0]["error"])
        self.assertEqual("Shipped", self.store["mem_default"]["name"])

    def test_post_reusing_default_id_is_403(self):
        resp = self.call("create_memory_blueprint", {"id": "mem_default", "name": "hacked"})
        self.assertEqual(403, _status(resp))
        self.assertEqual("Shipped", self.store["mem_default"]["name"])

    def test_delete_of_default_is_refused_like_blueprint_routes(self):
        resp = self.ns["delete_memory_blueprint"]("mem_default")
        self.assertEqual((400, "Cannot delete default blueprints"), (resp[1], resp[0]["error"]))
        self.assertIn("mem_default", self.store)

    def test_custom_still_editable_and_cannot_be_promoted(self):
        resp = self.call("update_memory_blueprint",
                         {"name": "Renamed", "is_default": True}, "custom_1")
        self.assertEqual(200, _status(resp))
        self.assertEqual(("Renamed", False), (self.store["custom_1"]["name"],
                                              self.store["custom_1"]["is_default"]))
        resp = self.call("create_memory_blueprint", {"name": "New", "is_default": True})
        self.assertEqual(201, _status(resp))
        self.assertFalse(self.store[resp[0]["blueprint"]["id"]]["is_default"])
        self.assertEqual({"ok": True}, self.ns["delete_memory_blueprint"]("custom_1"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
