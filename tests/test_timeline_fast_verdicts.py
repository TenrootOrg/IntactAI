"""Timeline verdicts are held and sent together: one request, one re-fuse, one refetch.

2026-10-21: Known on row 1, True Positive on row 6, False Positive on row 8 in quick
succession -- each click saved and re-fused the case at once (three clicks, three
re-fuses), and the refetches repainted 1,068 rows while the next clicks landed, so
rows flipped and a click could hit the row moved under the pointer. Now a click
paints at once and joins a batch; 4 s after the last click the batch is ONE request.
Runs the real functions from cases.html in node, with fetch and the paint faked.
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
const rows = Array.from({length: 10}, (_, i) => ({finding_id: 'f' + (i + 1), title: 'Row ' + (i + 1), validation: 'pending'}));
global.window = {_tlCase: 'case_1', addEventListener: () => {}};
global.tab = 'timeline';
let paints = 0, refetches = 0, posts = [], toasts = [];
global.tlPaint = () => { paints++; };
global._tlEachRow = fn => rows.forEach(fn);
global.toast = m => toasts.push(m);
global.renderTimeline = () => { refetches++; };
global.fetch = (url, opt) => {
  posts.push({at: Date.now() - t0, body: JSON.parse(opt.body), keepalive: !!opt.keepalive});
  return new Promise(res => setTimeout(() => res({ok: !sc.fail, status: sc.fail ? 500 : 200,
    json: async () => (sc.fail ? {error: 'not saved: OSError: database is locked'} : {saved: 1})}), 50));
};
CODE
const t0 = Date.now();
let k = 0;
for (const [fid, st, gapMs] of sc.clicks) setTimeout(() => sc.many ? tlValidateMany(fid, st) : tlValidate(fid, st), gapMs);
setTimeout(() => console.log(JSON.stringify({postsBefore4s: posts.length, paintsSoon: paints})), 3500);
setTimeout(() => console.log(JSON.stringify({rows: Object.fromEntries(rows.map(r => [r.finding_id, r.validation])),
                                             refetches, posts, toasts, held: Object.keys(window._tlQueue).length})), 5600);
"""


class HeldVerdicts(unittest.TestCase):
    def run_page(self, **sc):
        node = shutil.which("node")
        if not node:
            self.skipTest("no node on this host")
        with open(CASES, encoding="utf-8") as fh:
            src = fh.read()
        code = re.search(r"window\._tlQueue=\{\}; window\._tlSaving=0;\n.*?\nfunction tlValidateMany\(.*?\n\}", src, re.S).group(0)
        js = HARNESS.replace("CODE", code.replace("window.addEventListener('pagehide',()=>_tlFlush());", ""))
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as t:
            t.write(js)
        try:
            out = subprocess.run([node, t.name, json.dumps(sc)], capture_output=True, text=True, timeout=30)
        finally:
            os.unlink(t.name)
        self.assertEqual(0, out.returncode, out.stderr)
        early, got = [json.loads(x) for x in out.stdout.strip().splitlines()]
        return early, got

    def test_three_fast_clicks_are_one_request_after_the_clicking_stops(self):
        early, got = self.run_page(clicks=[["f1", "known", 0], ["f6", "true_positive", 300], ["f8", "false_positive", 600],
                                           ["f6", "false_positive", 900]])   # row 6 changed its mind
        self.assertEqual(0, early["postsBefore4s"], "nothing is sent while the clicking goes on")
        self.assertEqual(4, early["paintsSoon"], "every click shows at once")
        self.assertEqual(1, len(got["posts"]), "one request for the whole burst")
        sent = {i["finding_id"]: i["status"] for i in got["posts"][0]["body"]["items"]}
        self.assertEqual({"f1": "known", "f6": "false_positive", "f8": "false_positive"}, sent, "the last verdict on a row wins")
        self.assertGreaterEqual(got["posts"][0]["at"], 4800, "sent 4 s after the LAST click (at 0.9 s)")
        self.assertTrue(got["posts"][0]["keepalive"])
        self.assertEqual(("known", "false_positive", "false_positive", "pending"),
                         (got["rows"]["f1"], got["rows"]["f6"], got["rows"]["f8"], got["rows"]["f2"]))
        self.assertEqual(1, got["refetches"])
        self.assertEqual(["Saved 3 verdicts."], got["toasts"])
        self.assertEqual(0, got["held"])

    def test_a_group_header_joins_the_batch_with_its_titles(self):
        _, got = self.run_page(many=True, clicks=[[["f2", "f3"], "known", 0]])
        self.assertEqual([("f2", "known", "Row 2"), ("f3", "known", "Row 3")],
                         [(i["finding_id"], i["status"], i["title"]) for i in got["posts"][0]["body"]["items"]])

    def test_a_failed_batch_is_said_and_refetched(self):
        _, got = self.run_page(fail=True, clicks=[["f3", "known", 0]])
        self.assertTrue(any(t.startswith("Not saved: not saved: OSError") for t in got["toasts"]), got["toasts"])
        self.assertEqual(1, got["refetches"], "the refetch puts back what is saved")


REFRESH = r"""
const rows = [{finding_id: 'f1', title: 'Row 1', validation: 'pending'}];
global.window = {_tlCase: 'case_1', _tlData: rows, addEventListener: () => {}};
global.tab = 'timeline';
let reads = 0, posts = 0;
global.tlPaint = () => {}; global.toast = () => {};
global._tlEachRow = fn => rows.forEach(fn);
global.api = () => { reads++; return new Promise(() => {}); };   // a timeline read
global.$ = () => ({});
global.tabIsStill = () => true;
global.fetch = () => { posts++; return new Promise(() => {}); };  // the batch, still in flight
CODE
tlValidate('f1', 'known');               // held
renderTimeline('case_1');                // the section is re-entered within 4 s
const afterHeld = {reads, posts, held: Object.keys(window._tlQueue).length};
renderTimeline('case_1');                // again, while that batch is still saving
console.log(JSON.stringify({afterHeld, readsWhileSaving: reads, posts}));
"""


class ReturningToTheSection(unittest.TestCase):
    def test_a_refresh_sends_held_verdicts_instead_of_reading_stale_rows(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("no node on this host")
        with open(CASES, encoding="utf-8") as fh:
            src = fh.read()
        code = re.search(r"window\._tlQueue=\{\}; window\._tlSaving=0;\n.*?\nfunction tlValidateMany\(.*?\n\}", src, re.S).group(0)
        code = code.replace("window.addEventListener('pagehide',()=>_tlFlush());", "")
        code += "\n" + re.search(r"function renderTimeline\(id\)\{.*?\n\}\n", src, re.S).group(0)
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as t:
            t.write(REFRESH.replace("CODE", code))
        try:
            out = subprocess.run([node, t.name], capture_output=True, text=True, timeout=30)
        finally:
            os.unlink(t.name)
        self.assertEqual(0, out.returncode, out.stderr)
        got = json.loads(out.stdout.strip().splitlines()[-1])
        self.assertEqual({"reads": 0, "posts": 1, "held": 0}, got["afterHeld"], "sent now, no stale read")
        self.assertEqual(0, got["readsWhileSaving"], "a save in flight: its own refetch paints")
        self.assertEqual(1, got["posts"])


if __name__ == "__main__":
    unittest.main()
