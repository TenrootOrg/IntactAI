"""No page may work out "how long has this been running" from the viewer's clock.

Case Analysis showed `running 1063 min` for a report that had started ten minutes
earlier. The state was right; the arithmetic was not. The banner computed
`Date.now() - new Date(stamp + 'Z')`, which is the browser's clock minus the
server's stamp -- so any drift on the viewer's machine (a suspended VM is the usual
way) is displayed as job runtime, and a healthy job reads as stuck.

How long something has been running is a SERVER fact. The server states it
(store.seconds_since -> report_generating_elapsed_s / report_phase_elapsed_s) and
the page renders it. These tests keep it that way: one fails if the browser-clock
arithmetic comes back anywhere in the UI, the others pin the server side.

A genuinely local duration -- an animation, a debounce, a client-side timeout --
is fine; mark that line `local-clock-ok` and it is allowed.
"""

import datetime
import os
import re
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UI = os.path.join(ROOT, "modules", "nginx", "html")
CASES_HTML = os.path.join(UI, "cases.html")
CASE_ROUTES = os.path.join(ROOT, "modules", "backend", "routes", "case_routes.py")

sys.path.insert(0, os.path.join(ROOT, "modules", "backend"))

# Date.now() used in a subtraction, or a server stamp parsed with a tacked-on 'Z'.
_BROWSER_CLOCK = re.compile(
    r"Date\.now\(\)\s*[-+]|[-+]\s*Date\.now\(\)|new Date\([^)\n]*\+\s*['\"]Z['\"]\)")
_ALLOW = "local-clock-ok"
_SKIP_DIRS = {"lib", "vendor", "node_modules", "downloads"}


def ui_sources():
    for dirpath, dirnames, filenames in os.walk(UI):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for f in filenames:
            if f.endswith((".js", ".html")) and not f.endswith(".min.js"):
                yield os.path.join(dirpath, f)


class NoPageComputesADurationFromTheViewersClock(unittest.TestCase):

    def test_the_whole_ui_is_clean(self):
        offenders = []
        for path in ui_sources():
            with open(path, encoding="utf-8", errors="replace") as fh:
                for n, line in enumerate(fh, 1):
                    if _BROWSER_CLOCK.search(line) and _ALLOW not in line:
                        offenders.append(f"{os.path.relpath(path, ROOT)}:{n}: {line.strip()[:110]}")
        self.assertEqual([], offenders, "the viewer's clock is not a stopwatch for server work — "
                                        "render the server's elapsed seconds, or mark the line "
                                        f"`{_ALLOW}` if the duration really is local:\n" + "\n".join(offenders))

    def test_the_banner_renders_what_the_server_measured(self):
        html = open(CASES_HTML, encoding="utf-8").read()
        self.assertIn("report_generating_elapsed_s", html)
        self.assertIn("report_phase_elapsed_s", html)
        self.assertNotIn("genStatusHtml(info.report_generating_started_at", html,
                         "the banner must be handed elapsed seconds, not a stamp to subtract")

    def test_the_case_payload_carries_both_elapsed_fields(self):
        src = open(CASE_ROUTES, encoding="utf-8").read()
        self.assertIn('"report_generating_elapsed_s": store.seconds_since(', src)
        self.assertIn('"report_phase_elapsed_s": store.seconds_since(', src)


class TheServerMeasuresElapsedItself(unittest.TestCase):

    def setUp(self):
        try:
            import _optional_deps  # noqa: F401
        except Exception:
            pass
        from services.fusion import store
        self.seconds_since = store.seconds_since

    def _iso(self, **delta):
        return (datetime.datetime.now(datetime.timezone.utc)
                + datetime.timedelta(**delta)).replace(tzinfo=None).isoformat()

    def test_a_stamp_from_ten_minutes_ago(self):
        self.assertAlmostEqual(600, self.seconds_since(self._iso(minutes=-10)), delta=5)

    def test_a_naive_stamp_is_utc_because_that_is_what_the_writers_produce(self):
        stamp = (datetime.datetime.now(datetime.timezone.utc)
                 - datetime.timedelta(hours=1)).replace(tzinfo=None).isoformat()
        self.assertAlmostEqual(3600, self.seconds_since(stamp), delta=5)

    def test_a_stamp_with_a_zone_is_honoured(self):
        stamp = (datetime.datetime.now(datetime.timezone.utc)
                 - datetime.timedelta(minutes=5)).isoformat()
        self.assertAlmostEqual(300, self.seconds_since(stamp), delta=5)

    def test_a_future_stamp_reads_as_just_started_never_negative(self):
        self.assertEqual(0, self.seconds_since(self._iso(hours=+3)))

    def test_nothing_to_measure(self):
        for bad in (None, "", "not a timestamp", 12345):
            self.assertIsNone(self.seconds_since(bad), repr(bad))


if __name__ == "__main__":
    unittest.main(verbosity=2)
