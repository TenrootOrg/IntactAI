"""The web UI — the surface every operator actually touches, with zero coverage.

WHY THIS EXISTS. The suite drives `/api/*` exclusively. Nothing has ever fetched
a page. So the entire class of failure where the API is perfect and the
dashboard is blank has been invisible: a green board with 100% of the API sweep
passing is exactly what a broken UI looks like from here.

No browser is needed, and that is the point. The dashboard is static Alpine.js
served by nginx from `modules/nginx/html/`, assembled at load time by
`js/bootstrap/partial-loader.js`, which fetches `partials/<name>.html` for a
hard-coded list of names and swaps each into a matching
`<div data-partial="NAME">` placeholder in `index.html`. Both halves are
hand-maintained, in two different files, and the loader does this:

    const ph = document.querySelector(`[data-partial="${name}"]`);
    if (!ph) return;                    // <- silently

A partial listed in `PARTIALS` with no placeholder in `index.html` therefore
renders NOTHING, with no error anywhere. The reverse — a placeholder whose name
is not in `PARTIALS` — leaves an empty div in the page for ever. Both are one
careless edit away, both survive every test this suite has, and both are caught
by comparing the two lists. That is the headline check here.

EVERYTHING IS PARSED OUT OF WHAT THE BOX SERVES, not out of the repo. A test
that reads the checkout proves the source is consistent; this has to prove the
DEPLOYED page is, because the two diverge exactly when it matters (a stale
image, a bind mount pointing at the wrong tree, an asset that did not ship).

WHAT THIS DELIBERATELY DOES NOT CLAIM. It cannot detect a stale `?v=` — an asset
edited without bumping its cache-buster still serves 200, and only a browser
holding the old copy would know. What it does catch is the neighbouring and more
common failure: an asset renamed, moved or deleted while `index.html` still
references it, which is a 404 and a dead page.
"""

import re

from lib import api as api_lib

# The one non-/api/ path nginx gates with auth_request; the dashboard's
# Velociraptor tab is an iframe onto it.
VELO_PATH = "/velociraptor/"

# Case Analysis is an iframe three hand-versioned cache layers deep
# (index -> partial-loader -> partials/* -> cases.html?embed=1). The innermost
# one is reached by nothing else in this suite.
EMBED_PATH = "/cases.html?embed=1&view=analysis"

# Unauthenticated entry points. These MUST serve without a session or nobody
# can ever log in to a fresh box.
PUBLIC_PAGES = ("/login.html", "/setup.html")


def _fetch(c, path):
    """(status, content-type, body). Status codes alone are useless here — see
    the SPA-fallback note in the phase — so every check needs the type and the
    first bytes as well."""
    r = c.s.get(c.base + path, timeout=60)
    return r.status_code, (r.headers.get("Content-Type") or "").lower(), r.text


def _is_spa_fallback(body):
    """Did nginx hand back index.html instead of the file that was asked for?"""
    head = (body or "").lstrip()[:200].lower()
    return head.startswith("<!doctype html") or head.startswith("<html")


def _text(c, path, expect=(200,)):
    """A page as text. `raw` returns bytes and does not try to JSON-decode,
    which `request` would do to an HTML body before handing back a str."""
    return (c.raw(path, expect=expect) or b"").decode("utf-8", "replace")


def register(runner, cfg):

    @runner.phase("frontend_smoke",
                  "Fetch the dashboard and prove it can actually assemble",
                  needs=("auth",))
    def frontend_smoke(ctx):
        c = ctx.get("client")
        detail = {}

        # ---------------------------------------------------------- 1 ----
        index = _text(c, "/")
        detail["index_bytes"] = len(index)
        ctx.check("the dashboard root serves an HTML document",
                  "<!DOCTYPE html>" in index and "<title>" in index,
                  expected="an HTML shell",
                  actual=index[:80].replace("\n", " ") if index else "empty",
                  note="nginx serving its own error page here is a 200 with the "
                       "wrong body, which no status-code check would catch")
        if len(index) < 500:
            return detail

        # ---------------------------------------------------------- 2 ----
        # THE HEADLINE CHECK. Both lists come off the wire.
        loader = _text(c, "/js/bootstrap/partial-loader.js?v=15", expect=(200, 404))
        m = re.search(r"const\s+PARTIALS\s*=\s*\[(.*?)\]", loader, re.S)
        listed = set(re.findall(r"['\"]([a-z0-9-]+)['\"]", m.group(1))) if m else set()
        placed = set(re.findall(r'data-partial="([a-z0-9-]+)"', index))
        detail["partials_listed"] = sorted(listed)
        detail["partials_placed"] = sorted(placed)

        ctx.check("the partial loader was served and declares its panels",
                  bool(listed), actual=len(listed),
                  note="if this is empty the loader 404'd or was renamed, and "
                       "the dashboard is a page of empty placeholders")
        if not listed:
            return detail

        orphan_list = sorted(listed - placed)   # loaded, nowhere to put it
        orphan_place = sorted(placed - listed)  # placeholder nobody fills
        ctx.check("every panel the loader fetches has a placeholder to land in",
                  not orphan_list,
                  expected="PARTIALS subset of data-partial",
                  actual=", ".join(orphan_list) or "all placed",
                  note="the loader does `if (!ph) return;` — a panel with no "
                       "placeholder is skipped in SILENCE, so the tab is simply "
                       "blank and nothing anywhere reports a problem")
        ctx.check("every placeholder is filled by a panel the loader knows about",
                  not orphan_place,
                  expected="data-partial subset of PARTIALS",
                  actual=", ".join(orphan_place) or "all filled",
                  note="an unfilled placeholder stays an empty div for ever")

        # ---------------------------------------------------------- 3 ----
        # Every panel must actually be fetchable, at the version the loader asks
        # for. A missing one renders "Failed to load the X panel."
        vm = re.search(r"partials/\$\{name\}\.html\?v=(\d+)", loader)
        pv = vm.group(1) if vm else None
        detail["partial_version"] = pv
        missing = []
        for name in sorted(listed):
            path = f"/partials/{name}.html" + (f"?v={pv}" if pv else "")
            try:
                code, _ctype, body = _fetch(c, path)
                if code != 200:
                    missing.append(f"{name} ({code})")
                elif _is_spa_fallback(body):
                    # NOT hypothetical: nginx does `try_files $uri $uri/
                    # /index.html`, so a partial that is missing comes back 200
                    # with the ENTIRE dashboard shell as its body — which the
                    # loader then injects into the panel div. A length check
                    # passes it (105 KB), a status check passes it (200); only
                    # looking at the body catches it.
                    missing.append(f"{name} (SPA fallback — file is absent)")
                elif len(body) < 50:
                    missing.append(f"{name} (empty)")
            except Exception as exc:                          # noqa: BLE001
                missing.append(f"{name} ({str(exc)[:40]})")
        detail["partials_missing"] = missing
        ctx.check("every panel partial is really its own fragment", not missing,
                  expected=f"{len(listed)} panels", actual=", ".join(missing) or "all served",
                  note="a missing partial does not 404 — it serves index.html, "
                       "and the loader injects the whole dashboard into a tab")

        # ---------------------------------------------------------- 4 ----
        # Every versioned asset index.html references must exist. This is the
        # renamed/deleted-asset class: a 404 here is a dead dashboard.
        refs = sorted(set(re.findall(r'(?:href|src)="([^"]+\?v=\d+)"', index)))
        detail["versioned_assets"] = len(refs)
        want = {".js": "javascript", ".css": "css"}
        broken = []
        for ref in refs:
            if ref.startswith(("http://", "https://", "//")):
                continue
            code, ctype, body = _fetch(c, "/" + ref.lstrip("/"))
            ext = ".js" if ".js?" in ref else (".css" if ".css?" in ref else "")
            if code != 200:
                broken.append(f"{ref} -> {code}")
            elif ext and want[ext] not in ctype:
                # THE CHECK THAT ACTUALLY BITES. A renamed or deleted asset does
                # not 404: try_files serves index.html with Content-Type
                # text/html, so the browser receives an HTML document where it
                # expected a script and the file silently never executes.
                # Measured: /js/definitely-not-here.js -> 200 text/html.
                broken.append(f"{ref} -> {ctype or '?'} (SPA fallback)")
        detail["broken_assets"] = broken
        ctx.check("every versioned asset is served as itself, not as the shell",
                  not broken,
                  expected=f"{len(refs)} assets with their own content type",
                  actual=", ".join(broken) or f"all {len(refs)} served",
                  note="index.html carries hand-maintained ?v= cache-busters. "
                       "This cannot see a STALE one — that needs a browser "
                       "holding the old copy — but it does catch an asset "
                       "renamed or deleted out from under the reference, which "
                       "a status check CANNOT because nginx answers 200")

        # The fallback itself, asserted so a future author cannot "simplify"
        # the two checks above back into status-code checks without this
        # failing and telling them why.
        _c, _t, _b = _fetch(c, "/js/qa-ci-this-file-does-not-exist.js")
        detail["spa_fallback"] = {"status": _c, "ctype": _t}
        ctx.check("a missing asset is served as the SPA fallback, not a 404",
                  _c == 200 and "html" in _t,
                  expected="200 text/html (nginx try_files -> /index.html)",
                  actual=f"{_c} {_t}",
                  note="this is WHY the checks above compare content types and "
                       "bodies instead of status codes. If this ever starts "
                       "returning 404 the fallback was removed and those checks "
                       "can be simplified")

        # ---------------------------------------------------------- 5 ----
        # The Case Analysis iframe, the innermost cache layer, reached by
        # nothing else in this suite.
        embed = _text(c, EMBED_PATH, expect=(200, 404))
        detail["embed_bytes"] = len(embed)
        ctx.check("the Case Analysis embed target serves", len(embed) > 500,
                  expected=">500 bytes of HTML", actual=len(embed),
                  note="Case Analysis is an iframe three hand-versioned layers "
                       "deep; a change that misses the innermost one is "
                       "invisible to every API test")

        # ---------------------------------------------------------- 6 ----
        for page in PUBLIC_PAGES:
            code = c.status_of(page)
            ctx.check(f"{page} is served", code == 200, expected=200, actual=code,
                      note="the unauthenticated entry point; if this 404s a "
                           "fresh box can never be claimed")

        # ---------------------------------------------------------- 7 ----
        # The dashboard's "Open" buttons. window.services is a hand-written port
        # map; a compose port change breaks every button with no error anywhere.
        app_js = _text(c, "/js/stores/app.js?v=1", expect=(200, 404))
        ports = {k: int(v) for k, v in
                 re.findall(r"(\w+):\s*\{\s*port:\s*(\d+)", app_js)}
        detail["service_ports"] = ports
        ctx.check("the dashboard declares its service port map", bool(ports),
                  actual=ports)
        dead = []
        for name, port in sorted(ports.items()):
            if not _tcp_open(cfg.platform_host, port):
                dead.append(f"{name}:{port}")
        detail["dead_service_ports"] = dead
        ctx.check("every service the dashboard links to is listening", not dead,
                  expected="every declared port open",
                  actual=", ".join(dead) or f"{len(ports)} open",
                  note="window.services is hand-written; when a module's "
                       "published port moves, the Open button points at nothing "
                       "and the only symptom is a browser that hangs")

        # ---------------------------------------------------------- 8 ----
        # The one non-/api/ path nginx gates. Authorised through, unauthorised
        # turned away — the pair IS the assertion, as in the API sweep.
        code_auth = c.status_of(VELO_PATH)
        anon = api_lib.Client(cfg.platform_host, tl=None, scheme="https")
        try:
            code_anon = anon.s.get(anon.base + VELO_PATH, timeout=30,
                                   allow_redirects=False).status_code
        except Exception as exc:                              # noqa: BLE001
            code_anon = f"error: {str(exc)[:60]}"
        detail["velociraptor_gate"] = {"authed": code_auth, "anon": code_anon}
        # ANY of 200/301/302/307/308 — measured 302 locally and 307 in CI, and
        # which redirect nginx picks is not what this asserts. The assertion is
        # that an authenticated caller is not turned away.
        ctx.check("the Velociraptor proxy is reachable with a session",
                  code_auth == 200 or (isinstance(code_auth, int)
                                       and 300 <= code_auth < 400),
                  expected="200 or a redirect", actual=code_auth)
        ctx.check("the Velociraptor proxy refuses an unauthenticated caller",
                  code_anon in (302, 401, 403),
                  expected="redirect or refusal", actual=code_anon,
                  note="nginx gates this with auth_request /api/auth/verify; it "
                       "is the only non-/api/ path that holds case data and can "
                       "task endpoints")

        # RECORDED, not asserted: the dashboard SHELL itself is public. That is
        # a design choice — it carries no data, and everything it displays comes
        # from /api/, which is gated. Written down so a future reader does not
        # mistake the absence of a check for an oversight.
        detail["shell_is_public"] = (
            "index.html and its assets serve without a session by design: the "
            "shell holds no data and every value in it is fetched from /api/, "
            "which IS gated. Asserted for /velociraptor/ above because that one "
            "proxies a live service.")
        return detail


def _tcp_open(host, port, timeout=5):
    """Is something listening? Mirrors the probe platform.py uses for 9300."""
    import socket
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False
