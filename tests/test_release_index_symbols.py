"""The release index records the symbol pack carried by the volweb asset.

2026-10-05: VolWeb moves every few months, the Volatility symbol pack should
reach every box every release. A filtered upgrade decides whether to fetch the
volweb asset for its pack alone (lib/release.sh) -- from the index, the only
thing it has read by then. This runs the REAL "Build and validate the index"
step of build-release-assets.yml on two fake module sidecars.
"""
import json
import os
import shutil
import subprocess
import tempfile
import textwrap
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WF = os.path.join(ROOT, ".github/workflows/build-release-assets.yml")


def index_step() -> str:
    lines = open(WF, encoding="utf-8").read().split("\n")
    start = next(i for i, l in enumerate(lines) if "- name: Build and validate the index" in l)
    py = next(i for i in range(start, len(lines)) if lines[i].strip() == "python3 - <<'PY'")
    end = next(i for i in range(py + 1, len(lines)) if lines[i].strip() == "PY")
    return textwrap.dedent("\n".join(lines[py + 1:end]))


class TheIndexCarriesThePack(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        for mod, contents in (("volweb", {"volweb_symbols": {"file": "volweb_symbols/windows.zip",
                                                             "sha256": "231d6973", "size": 839727133,
                                                             "tables": 3014, "source_url": "u"},
                                          "volweb_symbols_files": {
                                              "windows.zip": {"sha256": "231d6973", "size": 1, "tables": 3014},
                                              "intact-windows-kernels.zip": {"sha256": "k3rn", "size": 2,
                                                                             "tables": 1065}}}),
                              ("intact", {})):
            asset = f"t-{mod}.tar.gz"
            os.makedirs(os.path.join(self.d, "meta", mod))
            json.dump({"module": mod, "asset": asset, "source_commit": "c0ffee", "release_tag": "t",
                       "modules": {mod: "1"}, "size": 1, "sha256": mod, "parts": []},
                      open(os.path.join(self.d, "meta", mod, asset + ".meta.json"), "w"))
            json.dump({"contents": contents},
                      open(os.path.join(self.d, "meta", mod, asset + ".manifest.json"), "w"))
        os.makedirs(os.path.join(self.d, "out"))               # the step's own `mkdir -p out`
        env = dict(os.environ, TAG="t", COMMIT="c0ffee", EXPECTED_MODULES='["volweb", "intact"]')
        env.pop("GITHUB_STEP_SUMMARY", None)
        r = subprocess.run(["python3", "-c", index_step()], cwd=self.d, env=env,
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.index = json.load(open(os.path.join(self.d, "out", "t.index.json")))

    def test_the_volweb_entry_names_its_pack(self):
        vs = dict(self.index["assets"]["volweb"]["volweb_symbols"])
        vs.pop("files", None)
        self.assertEqual(vs, {"sha256": "231d6973", "size": 839727133, "tables": 3014})

    def test_every_pack_file_is_named_with_its_checksum(self):
        # windows.zip AND the kernel pack: an upgrade fetches the asset when either moves
        self.assertEqual(self.index["assets"]["volweb"]["volweb_symbols"]["files"],
                         {"windows.zip": "231d6973", "intact-windows-kernels.zip": "k3rn"})

    def test_a_module_without_a_pack_has_no_such_field(self):
        self.assertNotIn("volweb_symbols", self.index["assets"]["intact"])


if __name__ == "__main__":
    unittest.main()
