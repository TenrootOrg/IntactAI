"""A model's chat answer renders as a document, not as raw markdown with gaps.

2026-10-21, case chat: '#### Explicitly Dispositioned Hosts', '---', '*(logged
historically as …)*' and 'chrome.exe $\\rightarrow$ cmd.exe' printed as typed, and the
answer gaped -- the bubble was pre-wrap, so every newline between the rendered
elements was a blank line, and each blank line of the model's padding was a <br/>.
Runs the real mdToHtml from cases.html in node.
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

ANSWER = """Based on the case records, the following are **Known / Expected (Benign)**:



---



### 1. IT Admin Confirmed / Known Events

#### Explicitly Dispositioned Hosts

* **ALClient022** *(logged historically as ALClient02.adatumlab.local)*
    * Event / Rule: `SIGMA: Uncommon Service Installation Image Path`
* **ALClient09**: phishing spawn chain (chrome.exe $\\rightarrow$ cmd.exe)
"""


class ChatAnswer(unittest.TestCase):
    def render(self, md):
        node = shutil.which("node")
        if not node:
            self.skipTest("no node on this host")
        with open(CASES, encoding="utf-8") as fh:
            src = fh.read()
        fns = [re.search(r"function %s\(.*?\n\}" % n, src, re.S) or re.search(r"function %s\(.*\n" % n, src)
               for n in ("escape", "inline", "mdToHtml")]
        js = "\n".join(m.group(0) for m in fns) + "\nconsole.log(JSON.stringify(mdToHtml(%s)));" % json.dumps(md)
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as t:
            t.write(js)
        try:
            return json.loads(subprocess.run([node, t.name], capture_output=True, text=True, check=True).stdout)
        finally:
            os.unlink(t.name)

    def test_nothing_prints_as_typed(self):
        html = self.render(ANSWER)
        for raw in ("####", "---", "$\\rightarrow$", "*(logged"):
            self.assertNotIn(raw, html, raw)
        self.assertIn("<hr/>", html)
        self.assertIn("<h4>Explicitly Dispositioned Hosts</h4>", html)
        self.assertIn("<em>(logged historically as ALClient02.adatumlab.local)</em>", html)
        self.assertIn("chrome.exe → cmd.exe", html)

    def test_padding_is_one_break_and_none_after_a_rule(self):
        html = self.render(ANSWER)
        self.assertNotIn("<br/>\n<br/>", html, "a run of blank lines is one break")
        self.assertNotIn("<hr/>\n<br/>", html, "no break right after a rule")

    def test_stars_that_are_not_italics_stay(self):
        html = self.render("a * b * c and 2*3*4 and **bold**")
        self.assertIn("a * b * c and 2*3*4 and <strong>bold</strong>", html)

    def test_the_bubble_is_not_pre_wrapped(self):
        with open(CASES, encoding="utf-8") as fh:
            src = fh.read()
        rule = re.search(r"\.msg\.a\{[^}]*\}", src).group(0)
        self.assertNotIn("pre-wrap", rule)
        self.assertIn("'a md'", src, "the answer bubble takes the report's markdown styles")


if __name__ == "__main__":
    unittest.main()
