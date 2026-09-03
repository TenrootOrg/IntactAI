"""The branded PDF is the deliverable a customer actually receives.

Everything here was found by RENDERING it and looking at the pages, not by reading
the CSS. The web view was fine throughout; these are PDF-only defects.

  1. The cover logo was a BLACK RECTANGLE. tenroot-logo.png is 594x174 and 100%
     opaque with a solid black background -- invisible against white app chrome,
     a hard black box on the cover's navy gradient.
  2. The cover did not fill the sheet. `height:100vh` with content-box sizing and
     62mm of vertical padding overflowed, so the gradient stopped short leaving a
     white band, and the last metadata row ran into the footer rule.
  3. Wrapped bullets had NO HANGING INDENT. `h3 + ul` set
     `list-style-position:inside`, which puts the marker in the text flow, so every
     continuation line ran back to the container edge -- the Key Judgements block
     read as five bullet-prefixed paragraphs.
  4. An EMPTY BLACK BAR sat above the scope table: it is a key/value grid written
     with `| | |` headings, markdown emits a <thead> of empty <th>, and the dark
     header style rendered it as a solid black band.
  5. Everything was set tight -- 1.55 leading, 2.5mm paragraph gaps, 0.8mm between
     list items, 1.6mm table cells.
"""

import io
import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "modules/backend/services/engagement/pdf.py")


def _src():
    return io.open(SRC, encoding="utf-8").read()


def _mm(value: str) -> float:
    return float(re.match(r"([\d.]+)", value).group(1))


class TheCoverMustNotShowABlackBox(unittest.TestCase):
    def test_the_logo_background_is_keyed_out(self):
        s = _src()
        self.assertIn("def _transparent_bg", s)
        self.assertIn("_transparent_bg(blob)", s,
                      "the logo is embedded raw again -- black box is back")

    def test_only_background_connected_to_the_edge_is_removed(self):
        """A black glyph INSIDE the mark must survive; a blanket colour swap
        would punch holes through the artwork."""
        body = _src().split("def _transparent_bg")[1].split("\ndef ")[0]
        self.assertIn("stack", body, "must flood fill from the border, not swap all")

    def test_a_logo_failure_never_breaks_the_report(self):
        body = _src().split("def _transparent_bg")[1].split("\ndef ")[0]
        self.assertIn("return png_bytes", body,
                      "must fall back to the original bytes")


class TheCoverMustFillTheSheet(unittest.TestCase):
    def _cover(self):
        return _src().split(".cover {{")[1].split("}}")[0]

    def test_border_box_sizing(self):
        self.assertIn("box-sizing: border-box", self._cover(),
                      "content-box + padding overflowed the page and left a white band")

    def test_bottom_padding_clears_the_absolute_footer(self):
        """The footer rule is positioned at bottom:18mm; content must stop above it
        or the last metadata row collides with it, as PREPARED BY did."""
        pad = re.search(r"padding:\s*([\d.]+mm)\s+([\d.]+mm)\s+([\d.]+mm)", self._cover())
        self.assertIsNotNone(pad)
        self.assertGreater(_mm(pad.group(3)), 18.0)


class BulletsMustHangProperly(unittest.TestCase):
    def test_the_callout_list_is_not_inside_positioned(self):
        block = _src().split("h3 + ul {{")[1].split("}}")[0]
        self.assertNotIn("list-style-position: inside", block,
                         "inside kills the hanging indent on every wrapped line")
        self.assertIn("list-style-position: outside", block)

    def test_list_items_are_separated(self):
        block = _src().split("    li {{")[1].split("}}")[0]
        gap = _mm(re.search(r"margin-bottom:\s*([\d.]+mm)", block).group(1))
        self.assertGreaterEqual(gap, 2.0, "0.8mm ran the bullets together")


class AnEmptyHeaderRowMustNotRenderAsABlackBar(unittest.TestCase):
    def test_empty_theads_are_tagged_and_hidden(self):
        s = _src()
        self.assertIn("def _mark_empty_theads", s)
        self.assertIn("_mark_empty_theads(body_html)", s)
        self.assertIn("thead.is-empty", s)

    def _fn(self):
        """Exec ONLY the regex and the function. Importing the module pulls in
        markdown/weasyprint, which are backend-image dependencies, not test ones."""
        src = _src()
        ns = {"re": re}
        start = src.index("_EMPTY_THEAD_RE = ")
        end = src.index("def _build_html(")
        exec(compile(src[start:end], SRC, "exec"), ns)
        return ns["_mark_empty_theads"]

    def test_a_header_with_content_is_left_alone(self):
        """Document History has real headings and must keep its dark bar."""
        fn = self._fn()
        self.assertNotIn(
            "is-empty",
            fn("<thead><tr><th>VERSION</th><th>DATE</th></tr></thead>"))

    def test_an_all_empty_header_is_tagged(self):
        fn = self._fn()
        self.assertIn("is-empty", fn("<thead><tr><th></th><th></th></tr></thead>"))

    def test_a_partly_filled_header_is_kept(self):
        """One labelled column still means the row carries information."""
        fn = self._fn()
        self.assertNotIn(
            "is-empty", fn("<thead><tr><th></th><th>VALUE</th></tr></thead>"))


class TheDocumentMustNotBeSetTight(unittest.TestCase):
    def test_body_leading_was_opened_up(self):
        block = _src().split("html, body {{")[1].split("}}")[0]
        self.assertGreaterEqual(
            float(re.search(r"line-height:\s*([\d.]+)", block).group(1)), 1.6)

    def test_paragraphs_and_cells_have_room(self):
        s = _src()
        p_gap = _mm(re.search(r"p {{ margin: 0 0 ([\d.]+mm) 0; }}", s).group(1))
        self.assertGreaterEqual(p_gap, 3.0)
        td = s.split("    td {{")[1].split("}}")[0]
        self.assertGreaterEqual(_mm(re.search(r"padding:\s*([\d.]+mm)", td).group(1)), 2.0)
