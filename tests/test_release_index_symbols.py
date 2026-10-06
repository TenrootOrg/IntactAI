"""The release index lists the VolWeb symbols asset -- outside the modules.

2026-10-06: the Volatility symbol packs ride in their own <tag>-volweb_symbols.tar
("pack it out of the volweb ... so we wont pass the limit"). The index must:
name it under index["volweb_symbols"] (never index["assets"], where --only, the
version plan and the completeness check would treat it as a module), carry each
pack's sha256 so an upgrade can tell a changed pack, add the packs to the merged
manifest's sha256 map (or the upgrade's scoped verifier rejects them), and stop
the release when the asset is missing. Runs the REAL "Build and validate the
index" step of build-release-assets.yml on fake sidecars.
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
SYM = {"asset": "t-volweb_symbols.tar", "sha256": "5ym", "size": 3, "parts": [],
       "files": {"windows.zip": "231d6973", "intact-windows-kernels.zip": "k3rn"},
       "tables": {"windows.zip": 3014, "intact-windows-kernels.zip": 1470}}


def index_step() -> str:
    lines = open(WF, encoding="utf-8").read().split("\n")
    start = next(i for i, l in enumerate(lines) if "- name: Build and validate the index" in l)
    py = next(i for i in range(start, len(lines)) if lines[i].strip() == "python3 - <<'PY'")
    end = next(i for i in range(py + 1, len(lines)) if lines[i].strip() == "PY")
    return textwrap.dedent("\n".join(lines[py + 1:end]))


def run(d, with_symbols=True):
    for mod in ("volweb", "intact"):
        asset = f"t-{mod}.tar"
        os.makedirs(os.path.join(d, "meta", mod))
        json.dump({"module": mod, "asset": asset, "source_commit": "c0ffee", "release_tag": "t",
                   "modules": {mod: "1"}, "size": 1, "sha256": mod, "parts": []},
                  open(os.path.join(d, "meta", mod, asset + ".meta.json"), "w"))
        json.dump({"contents": {"sha256": {f"images/{mod}.tar": mod}}},
                  open(os.path.join(d, "meta", mod, asset + ".manifest.json"), "w"))
    if with_symbols:
        os.makedirs(os.path.join(d, "symmeta"))
        json.dump(SYM, open(os.path.join(d, "symmeta", "t-volweb_symbols.tar.meta.json"), "w"))
    os.makedirs(os.path.join(d, "out"))                      # the step's own `mkdir -p out`
    env = dict(os.environ, TAG="t", COMMIT="c0ffee", EXPECTED_MODULES='["volweb", "intact"]')
    env.pop("GITHUB_STEP_SUMMARY", None)
    return subprocess.run(["python3", "-c", index_step()], cwd=d, env=env,
                          capture_output=True, text=True, timeout=60)


class TheIndexCarriesTheSymbols(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)

    def test_the_symbols_asset_is_listed_outside_the_modules(self):
        r = run(self.d)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        index = json.load(open(os.path.join(self.d, "out", "t.index.json")))
        self.assertEqual(index["volweb_symbols"]["asset"], "t-volweb_symbols.tar")
        self.assertEqual(index["volweb_symbols"]["files"],
                         {"windows.zip": "231d6973", "intact-windows-kernels.zip": "k3rn"})
        self.assertEqual(sorted(index["assets"]), ["intact", "volweb"])     # not a module

    def test_the_packs_are_in_the_merged_sha256_map(self):
        run(self.d)
        shas = json.load(open(os.path.join(self.d, "out", "t.manifest.json")))["contents"]["sha256"]
        self.assertEqual(shas["volweb_symbols/windows.zip"], "231d6973")
        self.assertEqual(shas["volweb_symbols/intact-windows-kernels.zip"], "k3rn")
        self.assertEqual(shas["images/volweb.tar"], "volweb")                # modules untouched

    def test_a_release_without_the_symbols_asset_stops(self):
        r = run(self.d, with_symbols=False)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("no symbols asset", r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main()
