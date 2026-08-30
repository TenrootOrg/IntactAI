"""The blueprint editor's artifact list needs a way to see what is SELECTED.

580 artifacts, ~30 of them ticked. Reviewing what a blueprint actually contains
meant scrolling the whole list hunting for checkmarks, and the search box does
not help — you cannot search for "the ones I picked".

The filter is real logic with three interacting inputs (search term, the
selected-only toggle, and each row's checkbox), so it is EXECUTED here rather
than asserted about: the function is lifted out of blueprints.js and run under
node against a DOM stub. Skipped where node is unavailable.
"""

import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
JS = os.path.join(ROOT, "modules/nginx/html/js/blueprints.js")
HTML = os.path.join(ROOT, "modules/nginx/html/partials/blueprints.html")

HARNESS = r"""
const fs = require('fs');
const src = fs.readFileSync(process.argv[2], 'utf8');
const m = src.match(/function filterBlueprintArtifacts\(\)[\s\S]*?\n}/);
if (!m) { console.error('filterBlueprintArtifacts not found'); process.exit(2); }
const spec = JSON.parse(process.argv[3]);

const labels = spec.rows.map(([name, checked]) => {
  const cb = { checked };
  const cls = new Set();
  return {
    textContent: name,
    classList: { add: c => cls.add(c), remove: c => cls.delete(c),
                 contains: c => cls.has(c) },
    querySelector: s => (s === '.blueprint-artifact-cb' ? cb : null),
    _hidden: () => cls.has('hidden'),
  };
});
const appended = [];
const container = {
  querySelectorAll: () => labels,
  querySelector: () => appended[0] || null,
  appendChild: el => appended.push(el),
};
global.document = {
  getElementById: id =>
      id === 'blueprint-artifact-search' ? { value: spec.search }
    : id === 'blueprint-artifact-selected-only' ? { checked: spec.selectedOnly }
    : id === 'blueprint-artifacts-list' ? container : null,
  createElement: () => ({ className: '', textContent: '',
                          remove() { appended.length = 0; } }),
};
eval(m[0]);
filterBlueprintArtifacts();
console.log(JSON.stringify({
  visible: labels.filter(l => !l._hidden()).map(l => l.textContent),
  message: appended.length ? appended[0].textContent : null,
}));
"""

ROWS = [
    ["Windows.Hayabusa.Rules", True],
    ["DetectRaptor.Windows.Detection.Amcache", True],
    ["Windows.NTFS.MFT", False],
    ["Custom.Windows.DensityScout", False],
]


@unittest.skipUnless(shutil.which("node"), "node not available")
class TestSelectedOnlyFilter(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.harness = os.path.join(cls.tmp, "h.js")
        with open(cls.harness, "w", encoding="utf-8") as fh:
            fh.write(HARNESS)

    def run_filter(self, search="", selected_only=False, rows=None):
        spec = {"rows": rows if rows is not None else ROWS,
                "search": search, "selectedOnly": selected_only}
        out = subprocess.run(["node", self.harness, JS, json.dumps(spec)],
                             capture_output=True, text=True, timeout=30)
        self.assertEqual(out.returncode, 0, out.stderr)
        return json.loads(out.stdout)

    def test_with_no_filters_everything_shows(self):
        self.assertEqual(len(self.run_filter()["visible"]), 4)

    def test_selected_only_shows_just_the_ticked_rows(self):
        """The reported need: see what this blueprint actually collects."""
        self.assertEqual(self.run_filter(selected_only=True)["visible"],
                         ["Windows.Hayabusa.Rules",
                          "DetectRaptor.Windows.Detection.Amcache"])

    def test_search_and_selected_only_combine(self):
        r = self.run_filter(search="detectraptor", selected_only=True)
        self.assertEqual(r["visible"], ["DetectRaptor.Windows.Detection.Amcache"])

    def test_a_search_hitting_only_unticked_rows_is_empty(self):
        r = self.run_filter(search="ntfs", selected_only=True)
        self.assertEqual(r["visible"], [])
        self.assertIn("No selected artifacts", r["message"] or "")

    def test_nothing_selected_says_so_rather_than_looking_broken(self):
        rows = [[n, False] for n, _ in ROWS]
        r = self.run_filter(selected_only=True, rows=rows)
        self.assertEqual(r["visible"], [])
        self.assertEqual(r["message"], "Nothing selected yet.")

    def test_turning_the_toggle_off_restores_the_full_list(self):
        self.assertEqual(len(self.run_filter(selected_only=False)["visible"]), 4)

    def test_an_unticked_row_leaves_the_selected_view(self):
        """Untick while the toggle is on and the row must go — which is why the
        checkbox's onchange re-runs the filter, not just the counter."""
        rows = [["Windows.Hayabusa.Rules", False],
                ["DetectRaptor.Windows.Detection.Amcache", True]]
        self.assertEqual(self.run_filter(selected_only=True, rows=rows)["visible"],
                         ["DetectRaptor.Windows.Detection.Amcache"])


class TestTheToggleIsWiredUp(unittest.TestCase):
    """The filter is only correct if the events that change selection re-run it."""

    def setUp(self):
        with open(JS, encoding="utf-8") as fh:
            self.js = fh.read()
        with open(HTML, encoding="utf-8") as fh:
            self.html = fh.read()

    def test_the_checkbox_exists_in_the_editor(self):
        self.assertIn("blueprint-artifact-selected-only", self.html)

    def test_ticking_an_artifact_refreshes_the_view(self):
        row = re.search(r'class="blueprint-artifact-cb"[\s\S]{0,200}?onchange="([^"]+)"',
                        self.js)
        self.assertIsNotNone(row, "artifact checkbox onchange not found")
        self.assertIn("filterBlueprintArtifacts", row.group(1))

    def test_check_all_refreshes_the_view(self):
        fn = re.search(r"function toggleAllBlueprintArtifacts[\s\S]*?\n}", self.js).group(0)
        self.assertIn("filterBlueprintArtifacts", fn)

    def test_the_toggle_resets_when_a_modal_opens(self):
        """A modal opened with the toggle left on from the previous blueprint
        looks like an empty artifact list."""
        self.assertEqual(self.js.count("if (selOnly) selOnly.checked = false;"), 2,
                         "both modal-open paths must reset the toggle")
