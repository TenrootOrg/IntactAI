"""Installers for a Velociraptor org other than root (velociraptor_clients.build_org_installer).

A host enrols into the org whose client config (Client.nonce) its installer
carries. The installer is repacked with the org's config and read back: one that
does not carry the org's nonce is refused, never served -- it would enrol hosts
into another org, unnoticed until they are missing.
"""
import os
import sys
import tempfile
import types
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (os.path.join(ROOT, "tests"), os.path.join(ROOT, "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services import velociraptor_clients as vc  # noqa: E402

ORG_CFG = "Client:\n  server_urls:\n  - https://x:8000/\n  nonce: ORGNONCE=\n"


class OrgInstaller(unittest.TestCase):
    def setUp(self):
        self.calls = []
        self.embedded = "ORGNONCE="
        self.saved = (vc.org_client_config, vc._velo_exec, vc.msi_config_text)
        vc.org_client_config = lambda org: (ORG_CFG, "intact test")

        def velo_exec(*args, **kw):
            self.calls.append(args)
            if args[0] == "cat":
                return types.SimpleNamespace(returncode=0, stdout=b"BINARY", stderr=b"")
            if "--embedded_config" in args:
                return types.SimpleNamespace(returncode=0, stdout=f"  nonce: {self.embedded}\n", stderr="")
            return types.SimpleNamespace(returncode=0, stdout="", stderr="")
        vc._velo_exec = velo_exec
        vc.msi_config_text = lambda blob: f"Client:\n  nonce: {self.embedded}\n"
        import subprocess
        self.saved_run = subprocess.run
        subprocess.run = lambda *a, **k: types.SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
        self.out = tempfile.mkdtemp()

    def tearDown(self):
        vc.org_client_config, vc._velo_exec, vc.msi_config_text = self.saved
        import subprocess
        subprocess.run = self.saved_run

    def test_builds_from_the_plain_upstream_binary_and_names_the_org(self):
        path, name, mime = vc.build_org_installer("windows-msi", "OFM5G", self.out)
        self.assertEqual("velociraptor-client-windows-intact-test.msi", name)
        self.assertEqual(b"BINARY", open(path, "rb").read())
        repack = next(c for c in self.calls if "repack" in c)
        self.assertIn("--msi", repack)
        self.assertIn("/opt/velociraptor/windows/velociraptor_client.msi", repack)

    def test_a_wrong_nonce_is_refused(self):
        self.embedded = "ROOTNONCE="
        for platform in ("windows-msi", "linux"):
            with self.assertRaises(RuntimeError, msg=platform):
                vc.build_org_installer(platform, "OFM5G", self.out)
        self.assertEqual([], os.listdir(self.out))

    def test_temp_files_are_removed_from_the_container(self):
        vc.build_org_installer("linux", "OFM5G", self.out)
        self.assertTrue(any(c[:2] == ("rm", "-f") for c in self.calls))


if __name__ == "__main__":
    unittest.main()
