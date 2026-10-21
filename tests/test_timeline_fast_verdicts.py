"""Fast verdict clicks on several Timeline rows land on the rows clicked, and the
timeline is refetched ONCE, 4 s after the clicking stops and every verdict is saved.

2026-10-21: Known on row 1, True Positive on row 6, False Positive on row 8 in
quick succession -- every saved verdict refetched and repainted 1,068 rows while
the next clicks landed, so rows flipped back and forth and a click could hit the
row a repaint had just moved under the pointer. Runs the real functions from
cases.html in node, with fetch and the paint faked.
"""
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CASES = os.path.join(ROOT, "modules/nginx/html/cases.html")

HARNESS = r"""
const sc = JSON.parse(process.argv[2]);
const rows = Array.from({length: 10}, (_, i) => ({finding_id: 'f' + (i + 1), validation: 'pending'}));
global.window = {_tlCase: 'case_1'};
global.TL_STATES = [['pending','Pending'],['true_positive','True Positive'],['false_positive','False Positive'],['known','Known']];
let paints = 0, refetches = 0, posts = [], toasts = [];
global.tlPaint = () => { paints++; };
global._tlEachRow = fn => rows.forEach(fn);
global.toast = m => toasts.push(m);
global.renderTimeline = () => { refetches++; };
let i = 0;
global.fetch = (url, opt) => {
  const body = JSON.parse(opt.body), n = i++;
  posts.push(body);
  return new Promise(res => setTimeout(() => res({
    ok: !(sc.fail || []).includes(n),
    json: async () => ((sc.fail || []).includes(n) ? {error: 'locked'} : {status: body.status})}),
    (sc.delays || [])[n] || 50));
};
CODE
for (const [fid, st] of sc.clicks) tlValidate(fid, st);
setTimeout(() => {
  console.log(JSON.stringify({refetchesWhileBusy: refetches}));
}, 300);
setTimeout(() => {
  console.log(JSON.stringify({rows: Object.fromEntries(rows.map(r => [r.finding_id, r.validation])),
                              refetches, posts, toasts, saving: window._tlSaving}));
}, 5200);
"""


class FastVerdicts(unittest.TestCase):
    def run_page(self, **sc):
        node = shutil.which("node")
        if not node:
            self.skipTest("no node on this host")
        with open(CASES, encoding="utf-8") as fh:
            src = fh.read()
        code = re.search(r"window\._tlSaving=0;\n.*?\nfunction tlValidateMany\(.*?\n\}", src, re.S).group(0)
        js = HARNESS.replace("CODE", code)
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as t:
            t.write(js)
        try:
            out = subprocess.run([node, t.name, json.dumps(sc)], capture_output=True, text=True, timeout=30)
        finally:
            os.unlink(t.name)
        self.assertEqual(0, out.returncode, out.stderr)
        lines = [json.loads(x) for x in out.stdout.strip().splitlines()]
        return lines[0], lines[-1]

    def test_three_fast_clicks_land_on_their_rows_and_refetch_once(self):
        early, got = self.run_page(clicks=[["f1", "known"], ["f6", "true_positive"], ["f8", "false_positive"]],
                                   delays=[400, 100, 250])      # saves finish out of order
        self.assertEqual(0, early["refetchesWhileBusy"], "no refetch while clicks are still being saved")
        self.assertEqual(("known", "true_positive", "false_positive"), (got["rows"]["f1"], got["rows"]["f6"], got["rows"]["f8"]))
        self.assertEqual("pending", got["rows"]["f2"], "no other row changes")
        self.assertEqual([("f1", "known"), ("f6", "true_positive"), ("f8", "false_positive")],
                         [(p["finding_id"], p["status"]) for p in got["posts"]])
        self.assertEqual(1, got["refetches"])
        self.assertEqual(0, got["saving"])

    def test_a_failed_save_is_said_and_refetched(self):
        _, got = self.run_page(clicks=[["f3", "known"]], fail=[0])
        self.assertTrue(any(t.startswith("Not saved: locked") for t in got["toasts"]), got["toasts"])
        self.assertEqual(1, got["refetches"], "the refetch puts back what is saved")


if __name__ == "__main__":
    unittest.main()
