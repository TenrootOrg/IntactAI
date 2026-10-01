"""The HTML export's screen design (services/engagement/pdf.py: _screen_layout).

"The html export is very ugly": the export was the PDF's print layout with a thin
screen stylesheet on top. It is now re-shaped for reading -- a contents rail, a
reading column, severity chips, a risk banner -- while staying one self-contained
file that opens offline, and without touching the PDF.

pdf.py needs `markdown`, which the host has not got, so the layout code is lifted
out of the module and run on a document shaped like the real one.
"""
import os
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = open(os.path.join(ROOT, "modules/backend/services/engagement/pdf.py"), encoding="utf-8").read()
BLOCK = SRC[SRC.index("_TOC_BLOCK = re.compile"):SRC.index("def render_engagement_pdf(")]
NS = {"re": re}
exec(BLOCK, NS)
layout, CSS, JS = NS["_screen_layout"], NS["_SCREEN_CSS"], NS["_SCREEN_JS"]

DOC = """<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>t</title><style>h2{color:red}</style></head>
<body>
  <section class="cover"><h1>Engagement Report<br><span class="accent">asd</span></h1></section>

  <h3 class="toc-heading" id="table-of-contents">Table of Contents</h3>
<div class="toc">
<ul>
<li><a href="#table-of-contents">Table of Contents</a></li>
<li><a href="#incident-case-report-asd">Incident Case Report — asd</a><ul>
<li><a href="#executive-summary">Executive Summary</a></li>
</ul></li>
</ul>
</div>
<h2 id="incident-case-report-asd">Incident Case Report — asd</h2>
<h3 id="executive-summary">Executive Summary</h3>
<p><strong>Risk: CRITICAL</strong> — ticket abuse reached the domain controller.</p>
<ul><li><code>2026-04-07T13:24:58Z</code> · <strong>[high]</strong> Known tool on disk</li>
<li><code>2026-04-08T19:44:55Z</code> · <strong>[critical]</strong> Mimikatz</li></ul>
<table><thead><tr><th>Host</th></tr></thead><tbody><tr><td>ALDC02</td></tr></tbody></table>
<hr />
<p><em>Narrative by live LLM; fact tables deterministic.</em></p>
</body>
</html>"""


class ScreenLayout(unittest.TestCase):
    def test_the_contents_become_a_rail_and_the_rest_a_reading_column(self):
        out = layout(DOC)
        nav = re.search(r'<nav class="rp-nav".*?</nav>', out, re.S).group(0)
        main = re.search(r'<main class="rp-main">.*?</main>', out, re.S).group(0)
        self.assertIn('<div class="toc">', nav)
        self.assertNotIn("#table-of-contents", out)                 # the list no longer links to itself
        self.assertNotIn("toc-heading", out.split("</style>")[-1])  # nor keeps its print heading
        self.assertIn('href="#executive-summary"', nav)
        self.assertIn('<h3 id="executive-summary">', main)          # every link still has its target
        self.assertNotIn("<nav", main)
        self.assertLess(out.index('class="cover"'), out.index('class="rp-shell"'))   # the cover stays on top
        self.assertEqual(out.count("<main"), 1)

    def test_severity_reads_as_chips_and_the_risk_as_a_banner(self):
        out = layout(DOC)
        self.assertIn('<span class="rp-sev rp-high">high</span>', out)
        self.assertIn('<span class="rp-sev rp-critical">critical</span>', out)
        self.assertNotIn("<strong>[high]</strong>", out)
        self.assertIn('<p class="rp-risk rp-critical"><strong>Risk: CRITICAL</strong> — ticket abuse', out)
        self.assertIn('<div class="rp-tw"><table>', out)             # a wide table scrolls by itself
        self.assertEqual(out.count('<div class="rp-tw">'), out.count("</table></div>"))

    def test_a_document_it_does_not_recognise_is_left_readable(self):
        no_cover = DOC.replace('<section class="cover">', "<div>").replace("</section>", "</div>")
        out = layout(no_cover)
        self.assertNotIn("rp-shell", out.split("</style>")[-1])      # untouched, styles only
        self.assertIn("Executive Summary", out)
        no_toc = re.sub(r'<h3 class="toc-heading".*?</div>', "", DOC, flags=re.S)
        out = layout(no_toc)
        self.assertIn('class="rp-shell rp-solo"', out)               # no rail, one centred column
        self.assertNotIn("<nav", out)

    def test_it_is_one_offline_file(self):
        for blob in (CSS, JS):
            for bad in ("http://", "https://", "@import", "url(", "<link"):
                self.assertNotIn(bad, blob)                           # no web font, no request of any kind
        out = layout(DOC)
        self.assertEqual(out.count(CSS), 1)
        self.assertEqual(out.count(JS), 1)

    def test_the_design_is_for_the_screen_only_and_the_page_still_scrolls(self):
        before, screen = CSS.split("@media screen {", 1)
        self.assertNotIn("font-family", before)                      # only chips + print rules apply to print
        self.assertIn("@media print", before)
        body_rule = re.search(r"\n  body \{.*?\}", screen, re.S).group(0)
        self.assertNotIn("overflow", body_rule)                      # overflow on body stopped the page scrolling
        self.assertIn("prefers-color-scheme: dark", screen)
        self.assertIn("prefers-reduced-motion", screen)
        self.assertEqual(CSS.count("{"), CSS.count("}"))

    def test_the_pdf_is_not_touched(self):
        pdf = SRC[SRC.index("def render_engagement_pdf("):]
        pdf = pdf[:pdf.index("\ndef ", 10)] if "\ndef " in pdf[10:] else pdf
        self.assertNotIn("_screen_layout", pdf)
        self.assertNotIn("_SCREEN_CSS", pdf)
        html_fn = SRC[SRC.index("def render_engagement_html("):SRC.index("_TOC_BLOCK = re.compile")]
        self.assertIn("return _screen_layout(html)", html_fn)

    @unittest.skipIf(shutil.which("node") is None, "node is not installed")
    def test_the_inline_script_parses(self):
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as t:
            t.write(re.search(r"<script>(.*?)</script>", JS, re.S).group(1))
        try:
            r = subprocess.run(["node", "--check", t.name], capture_output=True, text=True)
        finally:
            os.unlink(t.name)
        self.assertEqual(r.returncode, 0, r.stderr)


if __name__ == "__main__":
    unittest.main()
