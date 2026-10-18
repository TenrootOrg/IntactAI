"""Velociraptor 0.77.3 publishes its binaries gzipped (`<name>.gz`); 0.77.2, the
MSIs and the legacy 0.7.1 are plain. The release-tag probe and the downloads
must accept both, or a 0.77.3 install/package resolves the wrong tag and 404s.

Executed against the real code with a fake curl and a fake GitHub: the shell
helper lib/docker.sh:_velo_fetch and the packager's download_cmd /
resolve_velociraptor_release_tag.
"""
import gzip
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts", "ci"))

from packager import velociraptor_release as V  # noqa: E402

# A curl that serves files from $FAKE_GH (URL basename -> file) and 404s otherwise.
FAKE_CURL = r"""#!/bin/bash
out=""; url=""
while (( $# )); do
  case "$1" in -o) out="$2"; shift 2 ;; -w|--retry|--retry-delay|--retry-max-time|--connect-timeout) shift 2 ;;
    -*) shift ;; *) url="$1"; shift ;; esac
done
src="$FAKE_GH/$(basename "$url")"
[[ -f "$src" ]] || exit 22
cp "$src" "$out"; echo "1 0.1 10"
"""


class Downloads(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.gh = os.path.join(self.d, "gh"); os.mkdir(self.gh)
        self.bin = os.path.join(self.d, "bin"); os.mkdir(self.bin)
        with open(os.path.join(self.bin, "curl"), "w") as f:
            f.write(FAKE_CURL)
        os.chmod(os.path.join(self.bin, "curl"), 0o755)
        with gzip.open(os.path.join(self.gh, "velociraptor-v0.77.3-linux-amd64.gz"), "wb") as f:
            f.write(b"\x7fELF new")
        with open(os.path.join(self.gh, "velociraptor-v0.77.2-linux-amd64"), "wb") as f:
            f.write(b"\x7fELF old")
        self.env = dict(os.environ, PATH=self.bin + ":" + os.environ["PATH"], FAKE_GH=self.gh)

    def _sh(self, script):
        return subprocess.run(["bash", "-c", f"source {ROOT}/lib/common.sh >/dev/null 2>&1; "
                               f"source {ROOT}/lib/docker.sh >/dev/null 2>&1; LOG_FILE=/dev/null; "
                               f"log_info() {{ :; }}; {script}"], env=self.env, capture_output=True, text=True)

    def _read(self, name):
        with open(os.path.join(self.d, name), "rb") as f:
            return f.read()

    def test_installer_unpacks_a_gzipped_binary_to_the_plain_name(self):
        r = self._sh(f"_velo_fetch x https://gh/velociraptor-v0.77.3-linux-amd64 {self.d}/out")
        self.assertEqual(0, r.returncode, r.stderr)
        self.assertEqual(b"\x7fELF new", self._read("out"))
        self.assertFalse(os.path.exists(os.path.join(self.d, "out.gz")))

    def test_installer_still_takes_a_plain_binary(self):
        self.assertEqual(0, self._sh(f"_velo_fetch x https://gh/velociraptor-v0.77.2-linux-amd64 {self.d}/old").returncode)
        self.assertEqual(b"\x7fELF old", self._read("old"))

    def test_installer_fails_when_neither_exists(self):
        self.assertNotEqual(0, self._sh(f"_velo_fetch x https://gh/nothing {self.d}/n").returncode)
        self.assertFalse(os.path.exists(os.path.join(self.d, "n")))

    def test_packager_command_does_the_same(self):
        dest = os.path.join(self.d, "pkg bin")                   # a space survives the quoting
        r = subprocess.run(V.download_cmd("https://gh/velociraptor-v0.77.3-linux-amd64", dest),
                           shell=True, env=self.env, capture_output=True)
        self.assertEqual(0, r.returncode)
        self.assertEqual(b"\x7fELF new", self._read("pkg bin"))


class TagProbe(unittest.TestCase):
    def test_a_release_with_only_gzipped_binaries_gets_its_own_tag(self):
        def head(url, **kw):
            ok = url.endswith("/v0.77.3/velociraptor-v0.77.3-linux-amd64.gz")
            return mock.Mock(status_code=302 if ok else 404)
        with mock.patch.object(V.requests, "head", head):
            self.assertEqual("v0.77.3", V.resolve_velociraptor_release_tag("0.77.3", logger=lambda *a: None))


if __name__ == "__main__":
    unittest.main()
