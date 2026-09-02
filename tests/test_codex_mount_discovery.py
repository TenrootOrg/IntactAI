"""The backend must find the operator's codex wherever they installed it.

Two live-verified defects sat behind "codex is not installed" on a box where
`codex --version` worked perfectly in the operator's own shell:

  * lib/config.sh deliberately climbs OUT of the version component so that a
    `codex upgrade` needs no re-stamp, which leaves INTACT_HOST_CODEX_PKG at
    ~/.codex/packages/standalone/releases -- but the container only globbed
    <mount>/releases/*/bin/codex, i.e. .../releases/releases/*/bin/codex.
    Nothing could ever match, so for the DOCUMENTED standalone install the whole
    codex-pkg mount was dead weight.

  * the pkg mount is also how an operator-declared `agentic.codex_path` reaches
    the container, and that can name a directory of any shape at all.

Run in-container against the shipped package (PYTHONPATH=/app), or from a repo
checkout:

    docker exec intact_backend sh -lc \
      'PYTHONPATH=/app python3 -m pytest /app/tests/test_codex_mount_discovery.py -q'
"""
import os
import sys
import tempfile
import unittest
from unittest import mock

import types

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_BACKEND = os.path.join(_ROOT, "modules/backend")
for _p in ("/app", _BACKEND, _ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)

# services/__init__.py imports the whole backend (grpc, elasticsearch, the
# Velociraptor client), none of which a dev box or CI has. Bind the package to
# its directory WITHOUT executing that __init__ -- the same convention
# test_case_bundle.py uses -- so the module under test imports for real.
# services.agentic.__init__ then pulls in the whole agentic pipeline the same
# way, so it gets the same treatment -- subscription_cli itself depends on
# nothing heavier than the stdlib plus the secret store.
for _pkg, _rel in (("services", "services"),
                   ("services.agentic", "services/agentic")):
    if _pkg not in sys.modules:
        _m = types.ModuleType(_pkg)
        _m.__path__ = [os.path.join(_BACKEND, _rel)]
        sys.modules[_pkg] = _m

from services.agentic import subscription_cli as sub  # noqa: E402

PROVIDER = "codex-subscription"


def _touch_exec(path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        fh.write("#!/bin/sh\nexit 0\n")
    os.chmod(path, 0o755)
    return path


class StampedPackageRootResolves(unittest.TestCase):
    """What lib/config.sh actually stamps must be what the container searches."""

    def _candidates_with_pkg_mount(self, mount):
        with mock.patch.object(sub, "_HOST_PKG_DIR", mount):
            return sub._candidate_paths(PROVIDER)

    def test_standalone_releases_dir_is_found(self):
        """The exact shape lib/config.sh produces for the documented install:
        the mount root IS releases/, holding one versioned release directory."""
        with tempfile.TemporaryDirectory() as tmp:
            # <mount>/0.152.1-x86_64-unknown-linux-musl/bin/codex
            binary = _touch_exec(os.path.join(
                tmp, "0.152.1-x86_64-unknown-linux-musl", "bin", "codex"))
            self.assertIn(binary, self._candidates_with_pkg_mount(tmp))

    def test_an_upgrade_beside_it_is_found_too(self):
        """The version is stripped precisely so `codex upgrade` needs no
        re-stamp -- which only holds if BOTH releases resolve through the glob."""
        with tempfile.TemporaryDirectory() as tmp:
            old = _touch_exec(os.path.join(tmp, "0.152.1-x86_64-unknown-linux-musl",
                                           "bin", "codex"))
            new = _touch_exec(os.path.join(tmp, "0.153.0-x86_64-unknown-linux-musl",
                                           "bin", "codex"))
            found = self._candidates_with_pkg_mount(tmp)
            self.assertIn(old, found)
            self.assertIn(new, found)

    def test_a_root_stamped_one_level_up_still_resolves(self):
        """The older shape (<mount>/releases/<version>/bin) must not regress."""
        with tempfile.TemporaryDirectory() as tmp:
            binary = _touch_exec(os.path.join(tmp, "releases", "0.152.1-x86_64",
                                              "bin", "codex"))
            self.assertIn(binary, self._candidates_with_pkg_mount(tmp))

    def test_a_bare_directory_of_any_shape_resolves(self):
        """agentic.codex_path can name a prefix with no layout around it at all
        -- /opt/codex/bin, a shared tree, another account's install."""
        with tempfile.TemporaryDirectory() as tmp:
            binary = _touch_exec(os.path.join(tmp, "codex"))
            self.assertIn(binary, self._candidates_with_pkg_mount(tmp))

    def test_the_package_root_shape_still_resolves(self):
        with tempfile.TemporaryDirectory() as tmp:
            binary = _touch_exec(os.path.join(tmp, "bin", "codex"))
            self.assertIn(binary, self._candidates_with_pkg_mount(tmp))


class EmptyMountsAreReported(unittest.TestCase):
    """An empty mount is the signature of both failure modes, and is invisible
    from the host -- out there the paths in .env look perfectly correct."""

    def test_an_empty_mount_is_named_as_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(sub, "_HOST_PKG_DIR", tmp):
                self.assertEqual(sub._mount_report().get(tmp), "mounted but EMPTY")

    def test_an_absent_mount_is_named_as_absent(self):
        missing = "/nonexistent-mount-for-this-test"
        with mock.patch.object(sub, "_HOST_PKG_DIR", missing):
            self.assertEqual(sub._mount_report().get(missing), "not mounted")

    def test_a_populated_mount_is_counted(self):
        with tempfile.TemporaryDirectory() as tmp:
            _touch_exec(os.path.join(tmp, "codex"))
            with mock.patch.object(sub, "_HOST_PKG_DIR", tmp):
                self.assertEqual(sub._mount_report().get(tmp), "1 entry")


if __name__ == "__main__":
    unittest.main()
