"""The report's Markdown on the Analysis tab: an underscore inside a word is a
character, and a picture survives whatever text sits beside it.

QA screenshot: the evidence "Cobalt Strike: trick_ryuk.profile — screenshot" showed
a broken image whose alt read "trick</em>ryuk.profile". The italic rule ran over the
finished <img> tag and paired the "_" in its URL (case_1790…) with the one in the
name; the title beside it lost its underscore too ("trickryuk.profile").
Runs the real escape()/inline() from cases.html in node.
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
class Inline(unittest.TestCase):
    def run_inline(self, lines):
        fns = (re.search(r"function escape\(s\)\{.*?\}\n", SRC).group(0)
               + re.search(r"function inline\(s\)\{.*?\n\}", SRC, re.S).group(0))
        js = fns + "\nconsole.log(JSON.stringify(%s.map(inline)));" % json.dumps(lines)
        return json.loads(subprocess.run(["node", "-e", js], capture_output=True, text=True, check=True).stdout)

    def test_a_picture_named_with_an_underscore_stays_whole(self):
        url = "/api/cases/case_1790842125282/files/5b54d5fc33ff?inline=1"
        out, = self.run_inline(["![Cobalt Strike: trick_ryuk.profile — screenshot](%s)" % url])
        self.assertIn('<img src="%s" alt="Cobalt Strike: trick_ryuk.profile — screenshot"' % url, out)
        self.assertNotIn("<em>", out)

    def test_an_underscore_inside_a_word_is_a_character(self):
        bold, svc = self.run_inline(["**Cobalt Strike: trick_ryuk.profile — screenshot** · supports: trick_ryuk on ALClient022",
                                     "accounts sccm_sql and adim_std"])
        self.assertIn("<strong>Cobalt Strike: trick_ryuk.profile — screenshot</strong>", bold)
        self.assertIn("supports: trick_ryuk on", bold)
        self.assertEqual(svc, "accounts sccm_sql and adim_std")

    def test_italics_still_work_at_word_edges(self):
        a, b = self.run_inline(["_(picture removed: x)_", "an _important_ word"])
        self.assertEqual(a, "<em>(picture removed: x)</em>")
        self.assertEqual(b, "an <em>important</em> word")

    def test_a_quote_in_the_name_cannot_break_the_tag(self):
        out, = self.run_inline(['![say "hi"](/api/cases/c1/files/0123456789ab?inline=1)'])
        self.assertIn('alt="say &quot;hi&quot;"', out)


if __name__ == "__main__":
    unittest.main()
