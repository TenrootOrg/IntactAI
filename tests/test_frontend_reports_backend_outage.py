"""A backend outage must not be reported to the operator as malformed JSON.

When the backend is down, nginx answers /api/ with an HTML error page. The
settings store immediately does `await r.json()`, which throws

    Unexpected token '<', "<html> <h"... is not valid JSON

so the Prepare Upgrade Package modal displayed

    Fetch releases failed: Unexpected token '<', "<html>... is not valid JSON

Observed 2026-08-03 on a box where every /api/ call was 502ing. That message
sent the operator looking for a GitHub scraper -- asking whether we parse
GitHub's HTML and whether a site redesign had broken us. We do not: every
GitHub call goes through the REST API (api.github.com/repos/.../releases/...)
and release asset URLs, and the last HTML-scraping path was removed in the
commit at the head of intact-20260615 ("Probe the release ASSET, not the tag
page"). The error was pointing at the wrong system entirely.

Same failure shape as the upgrade path's "re-prepare the package with a
Wave-F-capable release", which blamed CI for a file the local prune had
deleted: a misleading message costs more than the fault it describes.

The guard lives in _fetchWithTimeout because every caller funnels through it
and surfaces e.message, so one throw fixes the wording at all call sites.

Run: docker exec intact_backend python /app/workdir/tests/test_frontend_reports_backend_outage.py
"""

import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SETTINGS_JS = os.path.join(REPO, "modules", "nginx", "html", "js", "stores",
                           "settings.js")
SRC = open(SETTINGS_JS).read()
HELPER = SRC[SRC.index("async _fetchWithTimeout"):]
HELPER = HELPER[:HELPER.index("\n        },") + 1]


def test_the_helper_detects_gateway_errors():
    """502/503/504 all mean 'nginx could not reach the backend'."""
    for code in ("502", "503", "504"):
        assert code in HELPER, (
            f"_fetchWithTimeout no longer checks for HTTP {code} — a backend "
            f"outage will again surface as a JSON parse error")


def test_the_check_happens_before_the_response_is_returned():
    """If it returned first, the caller reaches `await r.json()` and throws the
    parse error before any of this can help."""
    status_at = HELPER.index("r.status")
    ret_at = HELPER.index("return r;")
    assert status_at < ret_at, (
        "the gateway check runs after the response is returned to the caller")


def test_the_message_names_the_backend_not_json():
    """The whole point: say which system is broken."""
    msg = HELPER[HELPER.index("throw new Error"):]
    msg = msg[:msg.index(");")]
    assert "backend is not responding" in msg, msg
    assert "json" not in msg.lower(), (
        "the message still talks about JSON — the operator does not care that "
        "the body failed to parse, they need to know the backend is down")


def test_the_message_rules_out_github_explicitly():
    """This is the part that would have saved the trip. The operator's first
    instinct on 'fetch releases failed' is that something upstream changed."""
    msg = HELPER[HELPER.index("throw new Error"):]
    msg = msg[:msg.index(");")]
    assert "GitHub" in msg or "github" in msg, (
        "the message does not rule out GitHub, which is exactly where the "
        "operator looked when it said 'Unexpected token <'")


def test_the_message_says_what_to_run():
    """An error that names the system but not the next command still leaves
    the operator guessing."""
    msg = HELPER[HELPER.index("throw new Error"):]
    msg = msg[:msg.index(");")]
    assert "docker" in msg, msg


def test_we_still_do_not_scrape_github():
    """The premise of the fix. If HTML parsing ever comes back, 'this is not a
    GitHub problem' stops being reliably true and this message would mislead
    in the other direction."""
    upgrade = os.path.join(REPO, "modules", "backend", "services", "upgrade")
    bad = re.compile(r"BeautifulSoup|html\.parser|lxml|findall\(\s*r?['\"]<a ")
    for name in os.listdir(upgrade):
        if not name.endswith(".py"):
            continue
        body = open(os.path.join(upgrade, name)).read()
        assert not bad.search(body), (
            f"{name} parses HTML — GitHub release resolution must stay on the "
            f"REST API, which is versioned and contractual")


if __name__ == "__main__":
    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"PASS {name}")
            except AssertionError as e:
                failures += 1
                print(f"FAIL {name}: {e}")
            except Exception as e:      # noqa: BLE001
                failures += 1
                print(f"FAIL {name}: unexpected {type(e).__name__}: {e}")
    print("OK" if not failures else f"{failures} FAILED")
    sys.exit(1 if failures else 0)
