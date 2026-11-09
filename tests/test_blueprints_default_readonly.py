"""Default blueprints are read-only (QA D9).

seed_default_blueprints() re-syncs every is_default row from the YAML on each
backend start. The PUT routes used to accept an edit to a default and keep the
flag, so the edit "saved" and then silently reverted on the next restart. Now
PUT (and a POST reusing a default's id, since the store is INSERT OR REPLACE)
is refused for every type, and a custom copy survives the re-seed.

The real routes module is loaded with flask and the storage layer stubbed by an
in-memory dict (flask is a container dependency, not a test one).
"""

import importlib.util
import os
import sys
import types
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROUTES = os.path.join(ROOT, "modules/backend/routes/blueprint_routes.py")

YAML = {
    "velociraptor": [{"id": "velo_default", "name": "Velo", "description": "d",
                      "is_default": True, "artifacts": ["A"], "settings": {"cpu_limit": 50}}],
    "agentic": [],
    "timesketch": [{"id": "ts_default", "name": "TS", "description": "d",
                    "is_default": True, "settings": {"collection_timeout": 100000,
                                                     "timesketch_processing_timeout": 259200}}],
    "memory": [{"id": "mem_default", "name": "Mem", "description": "d",
                "is_default": True, "settings": {"plugin_set": ["x"]}}],
}


class _Req:
    body = None

    def get_json(self, *a, **k):
        return self.body


def _load():
    store = {"velociraptor": {}, "timesketch": {}, "memory": {}}

    def fns(t):
        return (lambda bp: store[t].__setitem__(bp["id"], dict(bp)) or True,
                lambda: [dict(v) for v in store[t].values()],
                lambda i: dict(store[t][i]) if i in store[t] else None,
                lambda i: store[t].pop(i, None) is not None)

    fss = types.ModuleType("services.file_storage_service")
    for t in store:
        save, load, get, delete = fns(t)
        setattr(fss, f"save_{t}_blueprint", save)
        setattr(fss, f"load_{t}_blueprints", load)
        setattr(fss, f"get_{t}_blueprint", get)
        setattr(fss, f"delete_{t}_blueprint", delete)
    fss.save_agentic_blueprint = fss.save_velociraptor_blueprint
    fss.load_agentic_blueprints = fss.load_velociraptor_blueprints
    bs = types.ModuleType("services.storage.blueprint_store")
    bs.load_memory_blueprints, bs.save_memory_blueprint, bs.delete_memory_blueprint = (
        fss.load_memory_blueprints, fss.save_memory_blueprint, fss.delete_memory_blueprint)
    loader = types.ModuleType("services.blueprint_loader_service")
    loader.get_all_blueprints = lambda: {k: [dict(b) for b in v] for k, v in YAML.items()}
    loader.get_artifact_lists = lambda: {}

    flask = types.ModuleType("flask")
    req = _Req()

    class Blueprint:
        def __init__(self, *a, **k):
            pass

        def route(self, *a, **k):
            return lambda f: f

    flask.Blueprint, flask.jsonify, flask.request = Blueprint, (lambda obj: obj), req

    for name, mod in {"flask": flask, "services": types.ModuleType("services"),
                      "services.storage": types.ModuleType("services.storage"),
                      "services.file_storage_service": fss,
                      "services.storage.blueprint_store": bs,
                      "services.blueprint_loader_service": loader}.items():
        sys.modules[name] = mod
    spec = importlib.util.spec_from_file_location("blueprint_routes_under_test", ROUTES)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)   # runs the real seed into the empty store
    return mod, store, req


def _status(resp):
    return resp[1] if isinstance(resp, tuple) else 200


class DefaultBlueprintsReadOnly(unittest.TestCase):
    def setUp(self):
        self.m, self.store, self.req = _load()

    def call(self, fn, body, *args):
        self.req.body = body
        return fn(*args)

    def test_put_on_every_default_is_refused_and_row_unchanged(self):
        for fn, t, bid in ((self.m.update_velociraptor_blueprint_route, "velociraptor", "velo_default"),
                           (self.m.update_agentic_blueprint_route, "velociraptor", "velo_default"),
                           (self.m.update_timesketch_blueprint_route, "timesketch", "ts_default"),
                           (self.m.update_memory_blueprint_route, "memory", "mem_default")):
            resp = self.call(fn, {"name": "hacked", "artifacts": ["B"], "settings": {}}, bid)
            self.assertEqual(403, _status(resp), fn.__name__)
            self.assertIn("duplicate", resp[0]["error"].lower())
            self.assertEqual(True, self.store[t][bid]["is_default"])
            self.assertNotEqual("hacked", self.store[t][bid]["name"])

    def test_post_reusing_a_default_id_is_refused(self):
        for fn, t, bid in ((self.m.create_velociraptor_blueprint, "velociraptor", "velo_default"),
                           (self.m.create_timesketch_blueprint, "timesketch", "ts_default"),
                           (self.m.create_memory_blueprint, "memory", "mem_default")):
            resp = self.call(fn, {"id": bid, "name": "hacked", "artifacts": ["B"]})
            self.assertEqual(403, _status(resp), fn.__name__)
            self.assertTrue(self.store[t][bid]["is_default"])

    def test_duplicate_is_editable_and_survives_reseed(self):
        resp = self.call(self.m.create_velociraptor_blueprint,
                         {"name": "Velo (copy)", "artifacts": ["A"], "settings": {"cpu_limit": 50}})
        self.assertEqual(201, _status(resp))
        cid = resp[0]["blueprint"]["id"]
        resp = self.call(self.m.update_velociraptor_blueprint_route,
                         {"name": "Mine", "artifacts": ["B"], "settings": {"cpu_limit": 10},
                          "is_default": True}, cid)
        self.assertEqual(200, _status(resp))
        self.m.seed_default_blueprints()
        row = self.store["velociraptor"][cid]
        self.assertEqual(("Mine", ["B"], False), (row["name"], row["artifacts"], row["is_default"]),
                         "a PUT body cannot promote a custom row to default")
        self.assertIn("velo_default", self.store["velociraptor"])

    def test_delete_of_default_still_refused(self):
        resp = self.m.delete_memory_blueprint_route("mem_default")
        self.assertEqual(400, _status(resp))


if __name__ == "__main__":
    unittest.main(verbosity=2)
