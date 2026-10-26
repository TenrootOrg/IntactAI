"""The AWS and Azure scan pages must send the time filter the backend reads.

WHY. Both pages sent {type, value} / {type, start, end} while every backend
reader (CloudTrail window, Azure collection window, the scheduler, the API
docs) reads {enabled, mode, relative_range | start_datetime, end_datetime}.
So the picker did nothing: CloudTrail always searched 24 h, Azure always 7 d,
a custom range was dropped, and the run log printed "Last 7d" over a 24 h
search (run aws_scan_1793004848443, 2026-10-26).
"""
import os
import re
import sys
import unittest
from datetime import timedelta

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (os.path.dirname(os.path.abspath(__file__)), os.path.join(ROOT, "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
_optional_deps.stub("markupsafe", "werkzeug", "werkzeug.utils")

from services.aws.cloudtrail_runner import _resolve_time_window  # noqa: E402

PAGES = {"aws": "modules/nginx/html/partials/aws.html", "azure": "modules/nginx/html/partials/azure.html"}


def _literals(page):
    with open(os.path.join(ROOT, PAGES[page])) as fh:
        return re.findall(r"timeFilter = (\{[^;]*\});", fh.read())


def _options(page):
    with open(os.path.join(ROOT, PAGES[page])) as fh:
        html = fh.read()
    sel = re.search(r'x-model="%sTimeFilter".*?</select>' % page, html, re.S).group(0)
    return [v for v in re.findall(r'<option value="([^"]+)"', sel) if v != "custom"]


class PagesSendTheBackendShape(unittest.TestCase):
    def test_both_branches_use_mode_and_backend_keys(self):
        for page in PAGES:
            lits = _literals(page)
            self.assertEqual(len(lits), 2, page)
            for lit in lits:
                self.assertIn("enabled: true", lit, page)
                self.assertNotRegex(lit, r"\btype:|\bvalue:|\bstart:|\bend:", page)
            self.assertRegex(lits[0], r"mode: 'between'.*start_datetime:.*end_datetime:", page)
            self.assertIn("mode: 'relative', relative_range:", lits[1], page)

    def test_custom_dates_are_utc_and_cover_the_end_day(self):
        for page in PAGES:
            between = _literals(page)[0]
            self.assertIn("'T00:00:00Z'", between, page)
            self.assertIn("'T23:59:59Z'", between, page)


class BackendResolvesWhatThePageSends(unittest.TestCase):
    def test_every_picker_value_is_its_own_window(self):
        want = {"1h": timedelta(hours=1), "24h": timedelta(hours=24), "7d": timedelta(days=7),
                "14d": timedelta(days=14), "30d": timedelta(days=30)}
        for page in PAGES:
            for v in _options(page):
                s, e = _resolve_time_window({"enabled": True, "mode": "relative", "relative_range": v})
                self.assertAlmostEqual((e - s).total_seconds(), want[v].total_seconds(), delta=5, msg=(page, v))

    def test_custom_range_is_used_as_given(self):
        s, e = _resolve_time_window({"enabled": True, "mode": "between",
                                     "start_datetime": "2026-10-20T00:00:00Z",
                                     "end_datetime": "2026-10-25T23:59:59Z"})
        self.assertEqual((s.isoformat(), e.isoformat()),
                         ("2026-10-20T00:00:00+00:00", "2026-10-25T23:59:59+00:00"))


if __name__ == "__main__":
    unittest.main()
