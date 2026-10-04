"""Switching to Analysis paused for seconds: clampEvidence wrote a class and read a
height for each evidence line in turn, so the browser laid out the whole report
once PER LINE (179 on a real case). It now writes all, reads all, writes again.
Runs the real clampEvidence from cases.html on fake lines that record every
access, so a read landing between writes (a forced layout) fails the test.
"""
import json
import os
import re
import shutil
import subprocess
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = open(os.path.join(ROOT, "modules/nginx/html/cases.html"), encoding="utf-8").read()


@unittest.skipIf(shutil.which("node") is None, "node is not installed")
class OneLayout(unittest.TestCase):
    def test_writes_then_reads_then_writes_and_the_same_result(self):
        fn = re.search(r"function clampEvidence\(root\)\{.*?\n\}", SRC, re.S).group(0)
        js = fn + r"""
const log = [];
const li = (tall) => { const c = new Set(['open']);
  return { classList: { add: x => { log.push('w'); c.add(x); }, remove: (...x) => { log.push('w'); x.forEach(y => c.delete(y)); } },
           get scrollHeight() { log.push('r'); return tall ? 200 : 20; },
           get clientHeight() { log.push('r'); return c.has('clip') ? 40 : 200; }, c }; };
const L = [li(true), li(false), li(true), li(false)];
clampEvidence({ querySelectorAll: () => L });
const order = log.join('').replace(/w+/g, 'W').replace(/r+/g, 'R');
console.log(JSON.stringify({ order, clipped: L.map(x => x.c.has('clip')), open: L.map(x => x.c.has('open')) }));"""
        out = json.loads(subprocess.run(["node", "-e", js], capture_output=True, text=True, check=True).stdout)
        self.assertEqual(out["order"], "WRW")                         # one batch of reads: one layout
        self.assertEqual(out["clipped"], [True, False, True, False])  # tall lines clipped, short ones not
        self.assertEqual(out["open"], [False] * 4)                    # a redraw closes any opened line


if __name__ == "__main__":
    unittest.main()
