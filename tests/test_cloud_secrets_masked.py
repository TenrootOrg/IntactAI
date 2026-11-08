"""Cloud secrets are masked by every config GET and kept on a masked PUT.

QA 2026-11-08: GET /api/config returned cloud.aws.secret_access_key in clear
(the whole AWS secret) while GET /api/config/cloud masked it. Both now use one
rule (_mask_cloud / _keep_masked_cloud). _load_cloud_config also deep-copies
its defaults: a shallow copy let the saved secrets, then the GET's mask, be
written into the module-level DEFAULT_CLOUD_CONFIG.
"""
import copy
import importlib.util
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

_HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(_HERE)
for _p in (_HERE, os.path.join(ROOT, "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)
if "INTACT_STORAGE_BASE" not in os.environ:
    os.environ["INTACT_STORAGE_BASE"] = tempfile.mkdtemp(prefix="intact-cloudmask-")
    import atexit
    atexit.register(shutil.rmtree, os.environ["INTACT_STORAGE_BASE"], True)

import _optional_deps  # noqa: F401,E402

try:
    import flask  # noqa: F401
except ImportError:
    _optional_deps.stub("flask")        # route modules import it at the top


def _routes():
    spec = importlib.util.spec_from_file_location(
        "_route_config_routes_mask", os.path.join(ROOT, "modules/backend/routes/config_routes.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


cr = _routes()
STORED = {"provider": "aws",
          "aws": {"access_key_id": "AKIAEXAMPLE000000001", "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                  "session_token": "FwoGZXIvYXdzEXAMPLETOKEN", "region": "us-east-1"},
          "azure": {"tenant_id": "t", "client_id": "c", "client_secret": "azure-secret-value"}}


class Mask(unittest.TestCase):
    def test_every_secret_is_masked_and_ids_are_not(self):
        m = cr._mask_cloud(STORED)
        self.assertEqual("••••••••EKEY", m["aws"]["secret_access_key"])
        self.assertEqual("••••••••", m["aws"]["session_token"])
        self.assertEqual("••••••••", m["azure"]["client_secret"])
        self.assertEqual(STORED["aws"]["access_key_id"], m["aws"]["access_key_id"])   # an id, not a secret
        for v in ("wJalrXUtnFEMI", "FwoGZXIv", "azure-secret-value"):
            self.assertNotIn(v, repr(m))

    def test_the_stored_config_is_never_changed_by_masking(self):
        before = copy.deepcopy(STORED)
        cr._mask_cloud(STORED)
        self.assertEqual(before, STORED)

    def test_empty_or_odd_configs(self):
        self.assertEqual({}, cr._mask_cloud(None))
        self.assertEqual({"aws": {}}, cr._mask_cloud({"aws": {}}))
        self.assertEqual({"aws": "x"}, cr._mask_cloud({"aws": "x"}))


class KeepOnSave(unittest.TestCase):
    def test_a_masked_value_sent_back_keeps_the_stored_secret(self):
        back = cr._keep_masked_cloud(cr._mask_cloud(STORED), STORED)
        self.assertEqual(STORED["aws"]["secret_access_key"], back["aws"]["secret_access_key"])
        self.assertEqual(STORED["aws"]["session_token"], back["aws"]["session_token"])
        self.assertEqual(STORED["azure"]["client_secret"], back["azure"]["client_secret"])

    def test_a_new_value_replaces_it(self):
        incoming = cr._mask_cloud(STORED)
        incoming["aws"]["secret_access_key"] = "NEW-SECRET"
        self.assertEqual("NEW-SECRET", cr._keep_masked_cloud(incoming, STORED)["aws"]["secret_access_key"])


class Endpoints(unittest.TestCase):
    """Both GET handlers mask and both PUT handlers keep: source checks, since the
    handlers need a Flask request (the image has Flask; this test run may not)."""
    SRC = open(os.path.join(ROOT, "modules/backend/routes/config_routes.py"), encoding="utf-8").read()

    def body(self, fn):
        i = self.SRC.index(f"def {fn}(")
        return self.SRC[i:self.SRC.index("\n@config_bp.route", i)]

    def test_wiring(self):
        self.assertIn("config['cloud'] = _mask_cloud(config['cloud'])", self.body("get_config"))
        self.assertIn("_keep_masked_cloud(config['cloud'], _load_cloud_config())", self.body("save_config"))
        get_cloud = self.body("get_cloud_config")
        self.assertIn("cfg = _load_cloud_config()", get_cloud)
        self.assertIn("out = _mask_cloud(cfg)", get_cloud)
        self.assertIn("return jsonify(out)", get_cloud)
        self.assertIn("_keep_masked_cloud(config, existing)", self.body("save_cloud_config_endpoint"))


class DefaultsStayClean(unittest.TestCase):
    def test_loading_and_masking_never_write_into_the_defaults(self):
        before = copy.deepcopy(cr.DEFAULT_CLOUD_CONFIG)
        import services.storage.config_store as cs
        with mock.patch.object(cs, "load_cloud_config", lambda: copy.deepcopy(STORED)):
            for _ in range(2):
                cr._mask_cloud(cr._load_cloud_config())
        self.assertEqual(before, cr.DEFAULT_CLOUD_CONFIG)


if __name__ == "__main__":
    unittest.main()
