"""A module whose images did not make it into the package must FAIL packaging.

Three paths in scripts/ci/packager/package.py used to log and carry on, so the
build still wrote an asset that cannot deploy offline (installs and upgrades
run compose with --no-build --pull never):

* velociraptor: no Linux server binary -> `continue` (module skipped, asset built);
* velociraptor: image bake or save failed -> "Target will rebuild locally from
  the staged binaries (still offline-safe)", which is false: the Dockerfile
  runs apt-get;
* any image module: 0/N images -> MODULE_FAILED_PREPARE then `continue`, and a
  partial N-1/N bundle only warned.

Drives the real prepare_upgrade_package with docker, curl and the image saves
stubbed. Nothing is pulled, built or downloaded.
"""
import os
import re
import shutil
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_TMP = tempfile.mkdtemp(prefix="packager-fail-closed-")
# proc.WORKDIR is read at import: point it at a throwaway tree, never the box.
os.environ["INTACT_PATH"] = os.path.join(_TMP, "workdir")
os.environ.pop("INTACT_HOST_PATH", None)
# Importing services opens a SQLite db; keep it in the throwaway tree too.
os.environ["INTACT_STORAGE_BASE"] = os.path.join(_TMP, "storage")
sys.path[:0] = [os.path.join(ROOT, "tests"), os.path.join(ROOT, "scripts", "ci"),
                os.path.join(ROOT, "modules", "backend")]

import _optional_deps  # noqa: F401,E402
from packager import package as P  # noqa: E402
from packager import velociraptor_release as V  # noqa: E402


def _fake_run(fail_on):
    """run_command stand-in: `-o <dest>` writes a 2 MB file; any command
    matching `fail_on` fails; everything else succeeds."""
    def run(cmd, *a, **k):
        if fail_on and re.search(fail_on, cmd):
            return {"success": False, "error": "stubbed failure", "output": ""}
        m = re.search(r"-o (\S+)", cmd)
        if m:
            dest = m.group(1).strip("'")
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            with open(dest, "wb") as f:
                f.write(b"\0" * (2 * 1024 * 1024))
        return {"success": True, "output": "", "stdout": ""}
    return run


class FailClosed(unittest.TestCase):
    def setUp(self):
        self.pkg = tempfile.mkdtemp(dir=_TMP)
        self.logs = []

    def _prepare(self, modules):
        return P.prepare_upgrade_package(
            modules, run_id="t", compress=False, work_dir=self.pkg,
            logger=lambda m, l="info": self.logs.append(m))

    def _velo(self, fail_on):
        with mock.patch.object(P, "run_command", _fake_run(fail_on)), \
             mock.patch.object(V, "resolve_velociraptor_release_tag", lambda *a, **k: "v0.77.3"), \
             mock.patch.object(V, "refresh_velociraptor_build_files", lambda *a, **k: None):
            return self._prepare({"velociraptor": "0.77.3"})

    def test_velociraptor_without_its_linux_binary_fails(self):
        r = self._velo(r"curl")
        self.assertFalse(r["success"])
        self.assertIn("Linux server binary", r["error"])

    def test_velociraptor_image_build_failure_fails(self):
        r = self._velo(r"compose .* build")
        self.assertFalse(r["success"])
        self.assertIn("image build failed", r["error"])

    def test_velociraptor_image_save_failure_fails(self):
        r = self._velo(r"docker save")
        self.assertFalse(r["success"])
        self.assertIn("could not save", r["error"])

    def test_velociraptor_without_compose_fails(self):
        r = self._velo(r"docker compose version")
        self.assertFalse(r["success"])
        self.assertIn("compose", r["error"])

    def test_no_offline_safe_claim_is_logged(self):
        self._velo(r"compose .* build")
        self.assertFalse([m for m in self.logs if "offline-safe)" in m])

    def _images(self, saved):
        with mock.patch.object(P, "get_docker_images_for", lambda *a, **k: ["a:1", "b:1"]), \
             mock.patch.object(P, "get_transitive_versions_for", lambda *a, **k: {}), \
             mock.patch.object(P, "_pull_and_save_images", lambda *a, **k: (saved, False)):
            return self._prepare({"portainer": "2.0.0"})

    def test_zero_of_n_images_fails(self):
        r = self._images([])
        self.assertFalse(r["success"])
        self.assertIn("bundled 0/2", r["error"])

    def test_partial_bundle_fails(self):
        r = self._images(["a-1.tar"])
        self.assertFalse(r["success"])
        self.assertIn("bundled 1/2", r["error"])

    def test_complete_bundle_still_succeeds(self):
        r = self._images(["a-1.tar", "b-1.tar"])
        self.assertTrue(r["success"], r.get("error"))


def tearDownModule():
    shutil.rmtree(_TMP, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
