"""Engagement Report PDF renderer.

Markdown → styled HTML → PDF (via WeasyPrint). The markdown coming in
is the same document the /download endpoint serves; this layer adds:

  - Cover page with the Tenroot logo + classification + version
  - Page header (engagement name + TLP marker) and footer (page N
    of M, "Prepared by Intact.AI")
  - Severity colour coding for Critical / High / Medium / Low badges
  - Table of Contents linking to numbered sections
  - Typography tuned for print (Inter / DejaVu fallback, line height,
    page-break rules)

The PDF is generated fresh on every download — markdown is the
source of truth, PDF is a derived view.
"""
from __future__ import annotations

import base64
import io
import os
import re
from datetime import datetime
from typing import Optional

import markdown as _markdown


# Logo lives under the nginx static dir on the host; the backend
# container mounts the host path 1:1 so this absolute path resolves
# inside the container too (see docker-compose.yaml volumes).
_LOGO_PATH = '/home/tenroot/intact/modules/nginx/html/img/tenroot-logo.png'


# The wordmark ships as a 594x174 PNG that is 100% OPAQUE with a solid BLACK
# background -- fine on the white app chrome, a visible black rectangle on the
# cover's navy gradient, which is the first thing anyone sees on the deliverable.
# Keying it out here rather than editing the asset: the same file is used all over
# the UI, where the black background is doing no harm.
_LOGO_BG_CUTOFF = 40          # a pixel this dark on every channel is background


def _transparent_bg(png_bytes: bytes) -> bytes:
    """Make a near-black logo background transparent. Returns the ORIGINAL bytes
    unchanged if anything goes wrong -- a slightly ugly cover beats no logo."""
    try:
        from PIL import Image
        import io as _io
        im = Image.open(_io.BytesIO(png_bytes)).convert("RGBA")
        px = im.load()
        w, h = im.size
        # Only key out pixels connected to the border, so a genuinely black glyph
        # in the middle of the mark survives. Flood fill inward from the edges.
        seen = set()
        stack = [(x, y) for x in range(w) for y in (0, h - 1)]
        stack += [(x, y) for y in range(h) for x in (0, w - 1)]
        while stack:
            x, y = stack.pop()
            if (x, y) in seen or not (0 <= x < w and 0 <= y < h):
                continue
            seen.add((x, y))
            r, g, b, a = px[x, y]
            if a == 0 or max(r, g, b) > _LOGO_BG_CUTOFF:
                continue
            px[x, y] = (r, g, b, 0)
            stack += [(x + 1, y), (x - 1, y), (x, y + 1), (x, y - 1)]
        out = _io.BytesIO()
        im.save(out, format="PNG")
        return out.getvalue()
    except Exception as e:  # noqa: BLE001 — never fail a report over the logo
        print(f"[PDF] logo background not keyed out: {e}", flush=True)
        return png_bytes


def _logo_data_url() -> str:
    """Return the logo as a base64 data URL so WeasyPrint embeds it
    in the PDF without needing a file fetch. Falls back to an empty
    string if the file is missing (PDF still renders, just without
    branding)."""
    try:
        with open(_LOGO_PATH, 'rb') as f:
            blob = f.read()
        blob = _transparent_bg(blob)
        b64 = base64.b64encode(blob).decode('ascii')
        # All logo files in the project are PNG today; if that ever
        # changes, sniff the magic bytes.
        return f"data:image/png;base64,{b64}"
    except Exception as e:
        print(f"[PDF] Could not embed logo: {e}", flush=True)
        return ''


# Extract the cover-block metadata from the markdown so we can hoist
# it into a styled PDF cover page rather than letting it render as
# inline content. The engagement assembler emits a specific structure
# we can parse:
#
#   # Engagement Report — <name>
#   **Classification:** `TLP:AMBER` 🟧 · **Version:** v1 · **Generated:** <ts>
#   **Prepared by:** ...
#   ---
#   ## Workflows included
#   ...
#   ## Document History
#   ...
#
_TITLE_RE = re.compile(r'^#\s+Engagement Report\s+—\s+(?P<name>.+?)\s*$', re.MULTILINE)
_META_RE = re.compile(
    r"\*\*Classification:\*\*\s+`TLP:(?P<tlp>[A-Z+]+)`\s*\S*\s*·\s*"
    r"\*\*Version:\*\*\s+v(?P<version>\d+)\s*·\s*"
    r"\*\*Generated:\*\*\s+(?P<generated>[^\n]+)",
)
_CUSTOMER_RE = re.compile(r'^\*\*Prepared for:\*\*\s+(?P<customer>.+?)\s*$', re.MULTILINE)
_SEVERITY_RE = re.compile(r'^\*\*Severity Summary:\*\*\s+(?P<severity>.+?)\s*$', re.MULTILINE)


def _extract_cover_meta(md: str) -> dict:
    """Pull title + TLP + version + generated-at + customer + severity
    summary from the markdown cover so the PDF cover page can render
    them in styled HTML instead of plain markdown."""
    out = {
        'name': 'Engagement Report',
        'tlp': 'AMBER',
        'version': 1,
        'generated': datetime.now().strftime('%Y-%m-%d %H:%M UTC'),
        'customer': '',
        'severity': '',
    }
    m = _TITLE_RE.search(md)
    if m:
        out['name'] = m.group('name').strip()
    m = _META_RE.search(md)
    if m:
        out['tlp'] = m.group('tlp')
        out['version'] = int(m.group('version'))
        out['generated'] = m.group('generated').strip()
    m = _CUSTOMER_RE.search(md)
    if m:
        out['customer'] = m.group('customer').strip()
    m = _SEVERITY_RE.search(md)
    if m:
        out['severity'] = m.group('severity').strip()
    return out


def _tlp_color(tlp: str) -> str:
    """CSS background colour for the classification badge. Matches
    common DFIR-firm conventions (red is strict, amber sensitive,
    green community, white public)."""
    return {
        'RED': '#dc2626',
        'AMBER+STRICT': '#ea580c',
        'AMBER': '#f59e0b',
        'GREEN': '#16a34a',
        'WHITE': '#94a3b8',
        'CLEAR': '#94a3b8',
    }.get((tlp or '').upper(), '#f59e0b')


def _strip_cover_from_md(md: str) -> str:
    """The original markdown has a textual cover (title + metadata +
    Workflows table + Document History). The PDF renders those as
    its own first-page HTML, so strip them from the body to avoid
    duplication. We cut everything before the first `## 1. Executive
    Summary` heading (or the first numbered H2 if that exact text
    isn't present)."""
    cut = re.search(r'(?m)^##\s+1\.\s+', md)
    if not cut:
        # Fall back to the first H2 we find — keeps the renderer
        # robust if numbering changes later.
        cut = re.search(r'(?m)^##\s+', md)
    if cut:
        return md[cut.start():]
    return md


def _wrap_findings_severity(html: str) -> str:
    """Inject CSS class hints onto severity lines inside Finding
    blocks so the printed PDF can colour-code them. The assembler's
    output looks like `- **Severity:** Critical`; we wrap that with
    `<span class="sev sev-critical">Critical</span>`."""
    pattern = re.compile(
        r'<strong>Severity:</strong>\s*(Critical|High|Medium|Low)\b',
        re.IGNORECASE,
    )

    def repl(m):
        level = m.group(1).lower()
        return f'<strong>Severity:</strong> <span class="sev sev-{level}">{m.group(1).title()}</span>'

    return pattern.sub(repl, html)


_EMPTY_THEAD_RE = re.compile(r"<thead>\s*<tr>(?:\s*<th[^>]*>\s*</th>)+\s*</tr>\s*</thead>",
                             re.IGNORECASE)


def _mark_empty_theads(html: str) -> str:
    """Flag header rows whose every cell is empty, so the CSS can drop them.

    The report writes its scope block as a two-column key/value grid, which in
    markdown needs a header row -- and writes it as `| | |`. Markdown dutifully
    emits <thead> with two empty <th>, and the PDF's dark header styling turned
    that into a SOLID BLACK BAR across the page above the first row."""
    return _EMPTY_THEAD_RE.sub(
        lambda m: m.group(0).replace("<thead>", '<thead class="is-empty">', 1), html)


def _build_html(md_body: str, meta: dict, source_run_id: str, customer_logo: str = '') -> str:
    """Compose the full HTML document the PDF renderer will see.

    The Tenroot logo always renders on the cover (this is OUR
    engagement-builder deliverable; customer-facing or not, the tool's
    brand stays). When `customer_logo` is provided (a `data:image/...;
    base64,...` URL), it joins the Tenroot logo side-by-side on the
    cover with a thin separator — the classic co-branded look
    professional IR firms use ("Customer × Tenroot")."""
    body_html = _markdown.markdown(
        md_body,
        extensions=[
            'markdown.extensions.tables',
            'markdown.extensions.fenced_code',
            'markdown.extensions.toc',
            'markdown.extensions.attr_list',
            'pymdownx.tilde',
            'pymdownx.caret',
        ],
        extension_configs={
            'markdown.extensions.toc': {'permalink': False, 'baselevel': 2},
        },
    )
    body_html = _wrap_findings_severity(body_html)
    body_html = _mark_empty_theads(body_html)

    tenroot_logo = _logo_data_url()
    cust_logo = (customer_logo or '').strip()
    tlp_color = _tlp_color(meta['tlp'])
    css = f"""
    @page {{
        size: A4;
        margin: 22mm 18mm 22mm 18mm;
        @top-left {{
            content: "{_html_escape(meta['name'])[:80]}";
            font-size: 8pt;
            color: #6b7280;
        }}
        @top-right {{
            content: "TLP:{_html_escape(meta['tlp'])} · v{meta['version']}";
            font-size: 8pt;
            font-weight: 600;
            color: {tlp_color};
        }}
        @bottom-center {{
            content: "Page " counter(page) " of " counter(pages);
            font-size: 8pt;
            color: #6b7280;
        }}
        @bottom-left {{
            content: "Prepared by Intact.AI";
            font-size: 8pt;
            color: #9ca3af;
        }}
    }}
    @page :first {{
        margin: 0;
        @top-left {{ content: ""; }}
        @top-right {{ content: ""; }}
        @bottom-center {{ content: ""; }}
        @bottom-left {{ content: ""; }}
    }}

    html, body {{
        font-family: "Inter", "DejaVu Sans", "Helvetica", sans-serif;
        font-size: 9.5pt;
        /* The whole document was set tight: 1.55 leading with 2.5mm paragraph
           gaps and 0.8mm between list items, so sections ran together and a page
           of findings read as one grey slab. Everything below is loosened as a
           set -- leading, paragraph rhythm, list spacing and cell padding move
           together or the page just looks unevenly airy. */
        line-height: 1.62;
        color: #1f2937;
    }}

    /* Cover page */
    .cover {{
        page-break-after: always;
        /* box-sizing MATTERS here: with the default content-box, 100vh plus 62mm
           of vertical padding is taller than the sheet, the last metadata row
           ("PREPARED BY") collided with the footer rule, and the gradient stopped
           short leaving a white band across the bottom of an otherwise dark cover. */
        box-sizing: border-box;
        /* bottom padding clears the absolutely-positioned footer rule (bottom:18mm
           plus its own height), so the metadata grid can never run into it again. */
        padding: 34mm 22mm 36mm 22mm;
        height: 297mm;
        background: linear-gradient(160deg, #0f172a 0%, #1e293b 60%, #0f172a 100%);
        color: #f8fafc;
        position: relative;
    }}
    .cover .logo-wrap {{
        margin-bottom: 22mm;
        display: flex;
        align-items: center;
        gap: 10mm;
    }}
    /* Both logos render into the SAME bounding box (60×22 mm) with
       object-fit:contain so each is scaled to fit, preserving its
       aspect ratio with whitespace padding the rest of the box. This
       keeps a wide Tenroot wordmark and a square customer mark visually
       balanced — neither dwarfs the other. */
    .cover .logo-wrap img {{
        height: 22mm;
        width: 60mm;
        object-fit: contain;
        object-position: center;
    }}
    /* Thin vertical separator between Tenroot and the customer logo —
       classic "co-branded engagement deliverable" look. Only rendered
       when both logos are present. */
    .cover .logo-wrap .sep {{
        width: 1px;
        height: 18mm;
        background: rgba(248, 250, 252, 0.25);
    }}
    .cover h1 {{
        font-size: 28pt;
        font-weight: 800;
        line-height: 1.15;
        margin: 0 0 8mm 0;
        color: #f8fafc;
        letter-spacing: -0.01em;
    }}
    .cover h1 .accent {{ color: #38bdf8; }}
    .cover .subtitle {{
        font-size: 11pt;
        line-height: 1.6;
        color: #cbd5e1;
        margin-bottom: 26mm;
        max-width: 130mm;
    }}
    .cover .tlp-badge {{
        display: inline-block;
        padding: 6px 14px;
        font-size: 10pt;
        font-weight: 700;
        letter-spacing: 0.08em;
        background: {tlp_color};
        color: #ffffff;
        border-radius: 4px;
        margin-bottom: 14mm;
    }}
    .cover .meta-grid {{
        display: table;
        width: 100%;
        font-size: 10pt;
        color: #e2e8f0;
    }}
    .cover .meta-row {{ display: table-row; }}
    .cover .meta-label {{
        display: table-cell;
        padding: 3.6mm 8mm 3.6mm 0;
        font-weight: 600;
        color: #94a3b8;
        text-transform: uppercase;
        font-size: 8pt;
        letter-spacing: 0.06em;
        width: 32mm;
    }}
    /* The engagement id is rendered as <code>, which inherits the BODY chip style
       -- a pale grey block with dark text, dropped onto the navy cover. Invert it
       there so it reads as part of the cover instead of a stray light rectangle. */
    .cover code {{
        background: rgba(148, 163, 184, 0.16);
        color: #e2e8f0;
        border-radius: 3px;
        padding: 0.8mm 2mm;
    }}
    .cover .meta-value {{
        display: table-cell;
        padding: 3mm 0;
        color: #f8fafc;
    }}
    .cover .footer-line {{
        position: absolute;
        bottom: 18mm;
        left: 22mm;
        right: 22mm;
        font-size: 8pt;
        color: #64748b;
        border-top: 1px solid #334155;
        padding-top: 4mm;
        display: flex;
        justify-content: space-between;
    }}

    /* Body */
    /* markdown baselevel=2 shifts everything down one: the report's `#` title is
       h2, its `##` sections are h3, and `###` findings/phases are h4. The spacing
       below follows THAT hierarchy, not the tag names. */
    h2 {{
        font-size: 15pt;
        font-weight: 700;
        color: #0f172a;
        margin: 11mm 0 4.5mm 0;
        padding-bottom: 2mm;
        border-bottom: 1px solid #cbd5e1;
        page-break-after: avoid;
    }}
    h3 {{
        font-size: 11.5pt;
        font-weight: 700;
        color: #1e3a8a;
        margin: 9mm 0 3mm 0;
        letter-spacing: -0.005em;
        page-break-after: avoid;
    }}
    h4 {{
        font-size: 10pt;
        font-weight: 700;
        color: #334155;
        margin: 6mm 0 2.5mm 0;
        page-break-after: avoid;
    }}
    /* A heading immediately after another must not inherit the full gap -- the
       stacked "## Section" + "### Phase" pair otherwise opens a hole. */
    h2 + h3, h3 + h4 {{ margin-top: 3.5mm; }}
    p {{ margin: 0 0 3.4mm 0; }}
    strong {{ color: #0f172a; }}
    code {{
        font-family: "DejaVu Sans Mono", "Consolas", monospace;
        font-size: 8.3pt;
        /* Reports are dense with hostnames and account names, so most paragraphs
           carry several of these. A heavy chip turned every such line into a row
           of grey blocks; the tint is now barely there and the colour carries it. */
        background: #f3f6f9;
        padding: 0.6px 3px;
        border-radius: 2px;
        color: #1e3a5f;
    }}
    pre code {{
        display: block;
        padding: 3mm;
        font-size: 8pt;
        line-height: 1.4;
        page-break-inside: avoid;
    }}
    ul, ol {{
        margin: 0 0 3.4mm 0;
        padding-left: 7mm;
    }}
    li {{
        margin-bottom: 2.2mm;
        padding-left: 0.5mm;
    }}
    li:last-child {{ margin-bottom: 0; }}
    /* A list item holding paragraphs (the ranked "Where to start" entries) needs
       its inner paragraphs tightened, or each item reads as its own section. */
    li > p {{ margin-bottom: 1.6mm; }}
    li > p:last-child {{ margin-bottom: 0; }}
    li > ul, li > ol {{ margin-top: 1.8mm; }}
    blockquote {{
        margin: 4mm 0 4mm 2mm;
        padding: 1mm 0 1mm 5mm;
        border-left: 3px solid #cbd5e1;
        color: #475569;
        font-style: italic;
    }}
    blockquote p:last-child {{ margin-bottom: 0; }}
    hr {{
        border: none;
        border-top: 1px dashed #cbd5e1;
        margin: 6mm 0;
    }}

    /* Tables */
    table {{
        width: 100%;
        border-collapse: collapse;
        font-size: 8.5pt;
        margin: 3.5mm 0 6mm 0;
        page-break-inside: avoid;
    }}
    th {{
        background: #0f172a;
        color: #f8fafc;
        font-weight: 600;
        text-align: left;
        padding: 2.6mm 3mm;
        font-size: 8pt;
        letter-spacing: 0.04em;
        text-transform: uppercase;
    }}
    td {{
        padding: 2.4mm 3mm;
        border-bottom: 1px solid #e2e8f0;
        vertical-align: top;
        line-height: 1.5;
    }}
    /* A HEADER ROW WITH NOTHING IN IT is not a header. The report's scope table
       is written as a two-column key/value grid with empty `| | |` headings, and
       markdown still emits a <thead> -- which rendered as a solid black bar
       across the page above the first real row. */
    thead.is-empty {{ display: none; }}
    tr:nth-child(even) td {{ background: #f8fafc; }}

    /* Severity badges */
    .sev {{
        display: inline-block;
        padding: 0.5mm 2.5mm;
        font-size: 8pt;
        font-weight: 700;
        letter-spacing: 0.05em;
        border-radius: 3px;
        text-transform: uppercase;
        color: #ffffff;
    }}
    .sev-critical {{ background: #b91c1c; }}
    .sev-high     {{ background: #c2410c; }}
    .sev-medium   {{ background: #b45309; }}
    .sev-low      {{ background: #15803d; }}

    /* Finding block container — applied via h3 + following content */
    h3 + ul {{
        background: #f8fafc;
        border-left: 3px solid #1e3a8a;
        /* was 2mm 4mm: the text sat hard against the accent rule */
        padding: 4mm 5mm 4mm 9mm;
        margin: 0 0 4mm 0;
        /* NOT list-style-position:inside. Inside puts the marker in the text flow,
           so every wrapped line runs back to the container edge and the bullet
           stops meaning anything -- measured on a real report, the Key Judgements
           block was five paragraphs of hanging-indent-less text. */
        list-style-position: outside;
        page-break-inside: avoid;
    }}
    h3 + ul > li {{ margin-bottom: 3mm; }}
    h3 + ul > li:last-child {{ margin-bottom: 0; }}

    /* Page-break rules */
    h2 {{ page-break-before: auto; }}
    h2 + p, h2 + ul, h2 + table {{ page-break-before: avoid; }}
    table {{ page-break-inside: avoid; }}
    h3, h4 {{ page-break-after: avoid; }}

    /* Table of Contents — rendered by markdown.extensions.toc from
       the [TOC] marker prepended in render_engagement_pdf. Sits on
       its own page right after the cover so the reader can navigate
       a long IR deliverable. */
    h2.toc-heading {{
        page-break-before: always;
        border-bottom: none;
        margin-top: 0;
        color: #1d4ed8;
    }}
    .toc {{
        page-break-after: always;
        font-size: 9.5pt;
        line-height: 1.5;
    }}
    .toc ul {{ list-style: none; padding-left: 1rem; margin: 0.25rem 0; }}
    .toc > ul {{ padding-left: 0; }}
    .toc li {{ padding: 0.1rem 0; }}
    .toc a {{ color: #1f2937; text-decoration: none; }}
    .toc a:hover {{ color: #1d4ed8; text-decoration: underline; }}
    """

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>{_html_escape('Incident Response Report — ' + (meta.get('customer') or meta['name']))}</title>
  <style>{css}</style>
</head>
<body>
  <section class="cover">
    <div class="logo-wrap">
      {f'<img src="{tenroot_logo}" alt="Tenroot">' if tenroot_logo else '<div style="font-weight:800;font-size:18pt;color:#38bdf8;">TENROOT</div>'}
      {f'<div class="sep"></div><img src="{_html_escape(cust_logo)}" alt="Customer">' if cust_logo else ''}
    </div>
    <div class="tlp-badge">TLP:{_html_escape(meta['tlp'])}</div>
    <h1>Engagement Report<br><span class="accent">{_html_escape(meta['name'])}</span></h1>
    <p class="subtitle">Incident Response Engagement Deliverable — multi-environment forensic write-up prepared by the Intact.AI engagement builder, reviewed by the operator who ran the source workflows.</p>
    <div class="meta-grid">
      <div class="meta-row"><div class="meta-label">Classification</div><div class="meta-value">TLP:{_html_escape(meta['tlp'])}</div></div>
      {f'<div class="meta-row"><div class="meta-label">Prepared for</div><div class="meta-value">{_html_escape(meta["customer"])}</div></div>' if meta.get('customer') else ''}
      {f'<div class="meta-row"><div class="meta-label">Severity Summary</div><div class="meta-value">{_html_escape(meta["severity"])}</div></div>' if meta.get('severity') else ''}
      <div class="meta-row"><div class="meta-label">Version</div><div class="meta-value">v{meta['version']}</div></div>
      <div class="meta-row"><div class="meta-label">Generated</div><div class="meta-value">{_html_escape(meta['generated'])}</div></div>
      <div class="meta-row"><div class="meta-label">Engagement ID</div><div class="meta-value"><code>{_html_escape(source_run_id)}</code></div></div>
      <div class="meta-row"><div class="meta-label">Prepared by</div><div class="meta-value">Tenroot · Intact.AI Engagement Builder</div></div>
    </div>
    <div class="footer-line">
      <span>Confidential — handle per TLP marking above.</span>
      <span>tenroot.io</span>
    </div>
  </section>

  {body_html}
</body>
</html>"""


class BlockedResourceError(Exception):
    """A report referenced a resource the renderer refuses to fetch."""


def _data_only_url_fetcher(url, *args, **kwargs):
    """Let the report embed data: URLs and fetch nothing else.

    The renderer previously ran with ``base_url='/'``, so every relative or
    absolute URL in the document resolved against the FILESYSTEM ROOT. Combined
    with the markdown pipeline passing raw HTML through untouched, an
    ``<img src="/etc/hostname">`` or an external ``src`` in report content would
    be fetched and embedded — local file inclusion into a customer deliverable,
    and an outbound request from the render host.

    Escaping the content would have been the weaker fix: it has to be right
    everywhere, forever, against LLM-generated narrative built over attacker-
    influenced forensic artifacts. Refusing to fetch is one rule, and it holds
    whatever the markdown contains.

    Nothing legitimate is lost. The only resources these reports reference are
    the Tenroot logo (``_logo_data_url()``) and the customer logo, both data
    URLs. WeasyPrint runs no JavaScript, so with fetching locked the residual
    risk of raw-HTML passthrough is layout and content spoofing — not
    execution, exfiltration or SSRF.

    On what a refusal looks like: for an ``<img>``, WeasyPrint catches the
    error, logs it and renders the document WITHOUT that image — verified, the
    file contents do not reach the PDF. So the usual outcome is a report that
    renders fine and is simply missing a resource it should never have had.
    The caller still translates the exception for the paths WeasyPrint does
    propagate (stylesheets, and anything raised before layout).
    """
    if not str(url).lower().startswith('data:'):
        raise BlockedResourceError(
            f"report referenced a non-embedded resource, which the renderer "
            f"does not fetch: {str(url)[:120]}")
    from weasyprint import default_url_fetcher
    return default_url_fetcher(url, *args, **kwargs)


def _html_escape(s) -> str:
    """Minimal HTML escape for text inserted into CSS / attributes /
    inline strings."""
    if s is None:
        return ''
    return (
        str(s)
        .replace('&', '&amp;')
        .replace('<', '&lt;')
        .replace('>', '&gt;')
        .replace('"', '&quot;')
    )


def render_engagement_pdf(markdown_text: str, run_id: str, logo_b64: str = '') -> bytes:
    """Public entry point. Takes the engagement-report markdown and
    returns the PDF as bytes ready to ship in an HTTP response.

    `logo_b64`, when set, is a `data:image/...;base64,...` URL for the
    operator-uploaded CUSTOMER logo. It's rendered alongside (not in
    place of) the embedded Tenroot logo on the cover page — co-branded
    look. Empty string = Tenroot logo only."""
    from weasyprint import HTML  # heavy import — defer
    meta = _extract_cover_meta(markdown_text)
    body = _strip_cover_from_md(markdown_text)
    # Inject a clickable Table of Contents right after the cover page.
    # The markdown.extensions.toc extension expands the `[TOC]` marker
    # in-place at render time, producing an HTML <div class="toc">…</div>
    # with anchor links to every H2/H3 in the document. Wrap it in a
    # heading + CSS class so the cover stylesheet can lay it out as a
    # distinct page rather than running into the first section.
    body = "## Table of Contents {.toc-heading}\n\n[TOC]\n\n" + body
    html = _build_html(body, meta, run_id, customer_logo=logo_b64)
    buf = io.BytesIO()
    try:
        HTML(string=html, base_url=None,
             url_fetcher=_data_only_url_fetcher).write_pdf(buf)
    except BlockedResourceError as e:
        # Surface it as something an operator can act on rather than a 500.
        raise ValueError(
            f"Report render blocked: {e}. Report images must be embedded "
            f"(data: URLs); the renderer does not fetch local or remote "
            f"resources. Check the case's customer logo and any image in the "
            f"report body.") from e
    return buf.getvalue()
