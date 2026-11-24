"""What the intact asset's source/intact/ tree carries from the source checkout.

* Untracked operator spoil a box's tree holds must not ship, even when a caller
  hands the packager a working tree rather than a clean checkout:
  config.yaml.pre-upgrade-backup (GitHub token, module passwords), logs, and
  the Velociraptor binaries in modules/nginx/html/downloads and
  modules/velociraptor/clients.
* data/ stays out, except the two TRACKED paths the box reads from its own
  data/: tools_inventory.yaml and custom_artifacts/*.yaml. They never reached
  an upgraded box before.

Drives the real prepare_upgrade_package for the intact module with the backend
image bake and the GitHub config fetch stubbed. No docker, no network.
"""
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_TMP = tempfile.mkdtemp(prefix="packager-source-copy-")
os.environ["INTACT_PATH"] = os.path.join(_TMP, "workdir")
os.environ.pop("INTACT_HOST_PATH", None)
os.environ["INTACT_STORAGE_BASE"] = os.path.join(_TMP, "storage")
sys.path[:0] = [os.path.join(ROOT, "tests"), os.path.join(ROOT, "scripts", "ci"),
                os.path.join(ROOT, "modules", "backend")]

import _optional_deps  # noqa: F401,E402
from packager import package as P  # noqa: E402
from packager import resolver as R  # noqa: E402


def _w(path, text="x"):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(text)


class SourceCopy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        src = cls.src = os.path.join(_TMP, "src")
        _w(f"{src}/install.sh")
        _w(f"{src}/lib/common.sh")
        _w(f"{src}/config.yaml", "versions: {}\n")
        _w(f"{src}/data/tools_inventory.yaml", "tools: []\n")
        _w(f"{src}/data/custom_artifacts/Custom.A.yaml", "name: Custom.A\n")
        _w(f"{src}/data/custom_artifacts/notes.txt")
        _w(f"{src}/data/state/ca.key")
        _w(f"{src}/data/intact.db")
        _w(f"{src}/config.yaml.pre-upgrade-backup", "token: LIVE")
        _w(f"{src}/install_20261117.log")
        _w(f"{src}/modules/nginx/html/index.html")
        _w(f"{src}/modules/nginx/html/downloads/velociraptor")
        _w(f"{src}/modules/velociraptor/clients/linux/velociraptor")
        cls.pkg = os.path.join(_TMP, "pkg")

        def _no_fetch(*a, **k):
            raise RuntimeError("no network in tests")

        with mock.patch.object(P, "_prepare_backend_images", lambda *a, **k: {"success": True}), \
             mock.patch.object(R, "fetch_upstream_config", _no_fetch):
            cls.result = P.prepare_upgrade_package(
                {"intact": "intact-20990101"}, run_id="t", compress=False,
                work_dir=cls.pkg, source_dir=src, logger=lambda m, l="info": None)
        cls.out = os.path.join(cls.pkg, "source", "intact")

    def test_package_built(self):
        self.assertTrue(self.result.get("success"), self.result.get("error"))
        self.assertTrue(os.path.isfile(os.path.join(self.out, "lib", "common.sh")))

    def test_untracked_spoil_is_not_shipped(self):
        for rel in ("config.yaml", "config.yaml.pre-upgrade-backup", "install_20261117.log",
                    "modules/nginx/html/downloads", "modules/velociraptor/clients"):
            self.assertFalse(os.path.exists(os.path.join(self.out, rel)), rel)

    def test_tracked_data_files_ship_and_nothing_else_from_data(self):
        data = os.path.join(self.out, "data")
        found = sorted(os.path.relpath(os.path.join(r, f), data)
                       for r, _, fs in os.walk(data) for f in fs)
        self.assertEqual(found, ["custom_artifacts/Custom.A.yaml", "tools_inventory.yaml"])


def tearDownModule():
    shutil.rmtree(_TMP, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
