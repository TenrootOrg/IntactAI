"""The engagement PDF must embed its images, never fetch them.

Two holes, one persisted and one at render time.

`render_engagement_pdf` ran WeasyPrint with `base_url='/'`, so every relative or
absolute URL in the document resolved against the FILESYSTEM ROOT. The markdown
pipeline passes raw HTML through untouched, and the report body is
LLM-generated narrative written over collected forensic artifacts — so an
`<img src="/etc/hostname">` or an external `src` reaching that renderer meant
local file inclusion into a customer deliverable and an outbound request from
the render host.

Separately, `POST /api/cases/<id>/branding` stored `customer_logo_b64` with no
validation at all, and that value is interpolated straight into an `<img src>`
on the report cover.

Sanitising the content would have been the weaker fix — it has to be right
everywhere, forever, against text nobody on this side authored. Refusing to
fetch anything that is not a `data:` URL is one rule that holds regardless of
what the markdown contains, and it costs nothing: the only resources these
reports reference are the two logos, both already data URLs.

Both halves are pure functions, so this needs no WeasyPrint render and no case.

Run: docker exec intact_backend python3 /app/workdir/tests/test_report_render_resources.py
"""

import sys

if "/app" not in sys.path:
    sys.path.insert(0, "/app")

from services.engagement import pdf as P            # noqa: E402
import routes.case_routes as C                      # noqa: E402

PNG = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUg=="


# --- the renderer's fetch policy -------------------------------------------


def test_data_urls_are_the_only_thing_fetched():
    """A data: URL must still work — the logos depend on it."""
    calls = {}

    def _fake_default(url, *a, **k):
        calls["url"] = url
        return {"string": b"", "mime_type": "image/png"}

    import weasyprint
    saved = weasyprint.default_url_fetcher
    weasyprint.default_url_fetcher = _fake_default
    try:
        P._data_only_url_fetcher(PNG)
    finally:
        weasyprint.default_url_fetcher = saved
    assert calls.get("url") == PNG, calls


def test_local_and_remote_resources_are_refused():
    """The finding itself: base_url='/' made every one of these resolvable."""
    for url in ("file:///etc/passwd",
                "/etc/hostname",
                "../../etc/shadow",
                "http://169.254.169.254/latest/meta-data/",
                "https://evil.example/pixel.png",
                "HTTP://EVIL.EXAMPLE/x.png"):
        try:
            P._data_only_url_fetcher(url)
        except P.BlockedResourceError:
            continue
        raise AssertionError(f"renderer would have fetched {url!r}")


def test_a_real_report_still_renders():
    """The lock is worthless if it breaks ordinary reports. Renders the shape a
    real engagement produces — cover metadata, a table, inline formatting."""
    md = ("# Engagement Report\n\n**Case:** Render Check\n**Customer:** Acme\n"
          "**TLP:** AMBER\n\n## Findings\n\n| Host | Finding |\n|---|---|\n"
          "| WS01 | Suspicious process |\n\nNarrative with `code`.\n")
    out = P.render_engagement_pdf(md, "case_render_check")
    assert out[:5] == b"%PDF-", out[:20]
    assert len(out) > 5000, f"suspiciously small PDF: {len(out)} bytes"


def test_a_local_file_never_reaches_the_pdf():
    """The property that actually matters. WeasyPrint catches an image fetch
    error, logs it and renders on — so the report SUCCEEDS. What must hold is
    that the file's bytes are not in the output."""
    import os
    probe = "/etc/hostname"
    if not os.path.exists(probe):
        return
    with open(probe, "rb") as fh:
        secret = fh.read().strip()
    if not secret:
        return

    seen = []
    orig = P._data_only_url_fetcher

    def _spy(url, *a, **k):
        seen.append(str(url))
        return orig(url, *a, **k)

    P._data_only_url_fetcher = _spy
    try:
        out = P.render_engagement_pdf(f'# R\n\n<img src="file://{probe}">\n',
                                      "case_lfi_check")
    finally:
        P._data_only_url_fetcher = orig

    assert any(probe in u for u in seen), \
        f"the fetcher was never consulted for the file URL: {seen}"
    assert secret not in out, \
        f"{probe} contents were embedded in the rendered PDF"


def test_the_renderer_is_wired_to_the_fetcher():
    """Guards the wiring, not just the helper — the helper is inert if the
    HTML() call still uses the default fetcher or a filesystem base_url."""
    import inspect
    src = inspect.getsource(P.render_engagement_pdf)
    assert "url_fetcher=_data_only_url_fetcher" in src, \
        "render_engagement_pdf is not using the restricted fetcher"
    assert "base_url='/'" not in src, \
        "base_url='/' resolves relative URLs at the filesystem root"


# --- the branding boundary --------------------------------------------------


def _bad(value):
    return C._validate_logo_data_url(value)


def test_a_real_png_data_url_is_accepted():
    assert _bad(PNG) is None, _bad(PNG)
    assert _bad("data:image/jpeg;base64,/9j/4AAQSkZJRg==") is None
    assert _bad("data:image/webp;base64,UklGRh4AAABXRUJQ") is None


def test_file_and_http_logos_are_rejected():
    for v in ("file:///etc/passwd",
              "http://internal.example/logo.png",
              "https://evil.example/logo.png",
              "/var/lib/secret.png",
              "javascript:alert(1)"):
        assert _bad(v), f"{v!r} was accepted as a logo"


def test_svg_is_rejected_even_though_it_is_an_image():
    """SVG can carry script and external references. Inert under the data-only
    fetcher, but a customer deliverable is no place to store it."""
    err = _bad("data:image/svg+xml;base64,PHN2Zz48L3N2Zz4=")
    assert err and "SVG" in err, err


def test_an_oversized_logo_is_rejected():
    huge = "data:image/png;base64," + ("A" * (3 * 1024 * 1024))
    err = _bad(huge)
    assert err and "limit" in err.lower(), err


def test_a_data_url_with_a_smuggled_quote_is_rejected():
    """The value lands in a double-quoted <img src="...">. It is escaped there
    now as well, but the character set should never have allowed it."""
    assert _bad('data:image/png;base64,AAA" onerror=alert(1) x="')


if __name__ == "__main__":
    import traceback
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn(); print(f"PASS {fn.__name__}")
        except Exception:
            failed += 1; print(f"FAIL {fn.__name__}"); traceback.print_exc()
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    sys.exit(1 if failed else 0)
