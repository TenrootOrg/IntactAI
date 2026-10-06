"""The upgrade dropdown and development pre-releases (2026-10-06: "our system
need to be able to upgrade to pre-release [it will be out development
releases]"). Runs the REAL settings store (js/stores/settings.js) in node:
pre-releases (intact-<date>-devN) stay hidden until "Show development
pre-releases" is ticked, the one hop is always to the next STABLE release, and
dev builds order before the stable release of their date.
"""
import json
import os
import shutil
import subprocess
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STORE = os.path.join(ROOT, "modules/nginx/html/js/stores/settings.js")

DRIVER = r"""
const fs = require('fs');
let init; const stores = {};
global.document = { addEventListener: (ev, fn) => { if (ev === 'alpine:init') init = fn; } };
global.window = global; global.localStorage = { getItem: () => null, setItem: () => {} };
global.Alpine = { store: (n, o) => (o === undefined ? stores[n] : (stores[n] = o)) };
eval(fs.readFileSync(process.argv[1], 'utf8'));
init();
const s = stores.settings;
const ref = (name, prerelease) => ({ kind: 'tag', name, prerelease, label: name });
s.upgradeRefs = [ref('intact-20261005', false), ref('intact-20261006-dev1', true),
                 ref('intact-20261006-dev2', true), ref('intact-20261006', false), ref('intact-20261007', false)];
s.prepareModalMode = 'online';
const out = {};
s.currentIntactVersion = 'intact-20261005';
s.showPrereleases = false; out.off = s.filteredUpgradeRefs().map(r => r.name);
s.showPrereleases = true;  out.on = s.filteredUpgradeRefs().map(r => r.name);
s.currentIntactVersion = 'intact-20261006-dev1';
out.fromDev = s.filteredUpgradeRefs().map(r => r.name);
out.classify = ['intact-20261005', 'intact-20261006-dev2', 'intact-20261006']
    .map(n => s.classifyUpgradeRef(ref(n, false)));
console.log(JSON.stringify(out));
"""


@unittest.skipIf(shutil.which("node") is None, "node is not installed")
class PreReleasesInTheDropdown(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        r = subprocess.run(["node", "-e", DRIVER, STORE], capture_output=True, text=True, timeout=60)
        assert r.returncode == 0, r.stderr
        cls.out = json.loads(r.stdout.strip().splitlines()[-1])

    def test_hidden_unless_asked_for(self):
        self.assertEqual(self.out["off"], ["intact-20261006", "intact-20261005"])

    def test_offered_when_asked_for_with_the_stable_hop_first(self):
        self.assertEqual(self.out["on"], ["intact-20261006", "intact-20261006-dev1",
                                          "intact-20261006-dev2", "intact-20261005"])

    def test_a_dev_box_moves_on_to_a_newer_dev_build_or_the_stable_release(self):
        self.assertEqual(self.out["fromDev"], ["intact-20261006", "intact-20261006-dev2",
                                               "intact-20261006-dev1"])
        self.assertEqual(self.out["classify"], ["older", "newer", "newer"])


if __name__ == "__main__":
    unittest.main()
