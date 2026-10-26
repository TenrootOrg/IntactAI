"""The AWS and Azure scan pages must send the time filter the backend reads.

Since 2026-10-26 both use the Case Analysis time window (start / end date+time
fields, UTC, empty end = now) through js/components/cloud-datepickers.js.

WHY. Both pages sent {type, value} / {type, start, end} while every backend
reader (CloudTrail window, Azure collection window, the scheduler, the API
docs) reads {enabled, mode, relative_range | start_datetime, end_datetime}.
So the picker did nothing: CloudTrail always searched 24 h, Azure always 7 d,
a custom range was dropped, and the run log printed "Last 7d" over a 24 h
search (run aws_scan_1793004848443, 2026-10-26).
"""
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (os.path.dirname(os.path.abspath(__file__)), os.path.join(ROOT, "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
_optional_deps.stub("markupsafe", "werkzeug", "werkzeug.utils")

from services.aws.cloudtrail_runner import _resolve_time_window  # noqa: E402

PAGES = {"aws": "modules/nginx/html/partials/aws.html", "azure": "modules/nginx/html/partials/azure.html"}
HELPER = "modules/nginx/html/js/components/cloud-datepickers.js"


def _read(rel):
    with open(os.path.join(ROOT, rel)) as fh:
        return fh.read()


class PagesUseTheCaseAnalysisTimeWindow(unittest.TestCase):
    """What the pages send is driven for real by cloud_time_window_live_page.js;
    this is the cheap guard that runs everywhere."""

    def test_both_pages_build_the_filter_from_the_shared_fields(self):
        for page, rel in PAGES.items():
            html = _read(rel)
            self.assertIn(f"initCloudTimeWindow('{page}')", html, page)
            self.assertIn(f"cloudTimeFilter('{page}')", html, page)
            self.assertIn(f'id="{page}-tw-start"', html, page)
            self.assertIn(f'id="{page}-tw-end"', html, page)
            self.assertNotRegex(html, r"type: 'relative'|type: 'between'|TimeFilter:|-time-start-hour", page)

    def test_helper_sends_the_backend_shape(self):
        js = _read(HELPER)
        self.assertIn("mode: 'between', start_datetime:", js)
        self.assertIn("end_datetime:", js)
        # Same calendar as Case Analysis -> Configuration -> Time window.
        self.assertIn("enableTime: true, time_24hr: true, dateFormat: 'Y-m-d\\\\TH:i:S', minuteIncrement: 5, allowInput: true", js)


class BackendResolvesWhatThePageSends(unittest.TestCase):
    def test_an_open_end_means_now(self):
        s, e = _resolve_time_window({"enabled": True, "mode": "between",
                                     "start_datetime": "2026-10-20T08:15:00Z", "end_datetime": ""})
        self.assertEqual(s.isoformat(), "2026-10-20T08:15:00+00:00")
        self.assertLess(abs((e - e.now(e.tzinfo)).total_seconds()), 5)

    def test_custom_range_is_used_as_given(self):
        s, e = _resolve_time_window({"enabled": True, "mode": "between",
                                     "start_datetime": "2026-10-20T00:00:00Z",
                                     "end_datetime": "2026-10-25T23:59:59Z"})
        self.assertEqual((s.isoformat(), e.isoformat()),
                         ("2026-10-20T00:00:00+00:00", "2026-10-25T23:59:59+00:00"))


if __name__ == "__main__":
    unittest.main()
