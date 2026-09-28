"""Fenced code in the report and chat renders as a code box (QA screenshot).

The model quotes command lines in ```text … ``` fences; the page's renderer had no
fence support, so the report showed literal ``` lines around a plain paragraph.
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


class Fence(unittest.TestCase):
    def render(self, md):
        node = shutil.which("node")
        if not node:
            self.skipTest("no node on this host")
        with open(os.path.join(ROOT, "modules/nginx/html/cases.html"), encoding="utf-8") as fh:
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

    def test_a_fenced_command_is_one_code_box(self):
        html = self.render('Step 5:\n\n```text\n"C:\\\\AnyDesk.exe" /d /c echo <x> --silent\n```\n\nThen:')
        self.assertNotIn("```", html)
        self.assertIn('<pre><code>"C:\\\\AnyDesk.exe" /d /c echo &lt;x&gt; --silent</code></pre>', html)
        self.assertIn("<p>Then:</p>", html)

    def test_inside_a_fence_nothing_is_markdown(self):
        html = self.render("```\n- not a bullet\n# not a heading\n```")
        self.assertIn("<pre><code>- not a bullet\n# not a heading</code></pre>", html)
        self.assertNotIn("<li>", html)

    def test_an_unclosed_fence_still_shows_its_text(self):
        self.assertIn("<pre><code>nxc.exe smb</code></pre>", self.render("```text\nnxc.exe smb"))


if __name__ == "__main__":
    unittest.main()
