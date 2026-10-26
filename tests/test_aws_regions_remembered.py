"""AWS regions: chosen on the AWS page only, remembered on the box for the next scan.

WHY. There were two region settings -- Settings -> Cloud -> AWS -> Region and the
AWS page's Regions box -- and the page silently won: Settings said eu-west-2,
every scan searched us-east-1 (2026-10-26). Settings no longer has a region; the
scan route remembers what the page sent (aws.regions in the cloud config), the
page opens with it, scheduled scans with no regions follow it, and a Settings
save -- maybe from a page opened before that scan -- cannot overwrite it.

The route part needs Flask (the backend image has it; a bare dev box skips).
"""
import os
import sys
import unittest
from unittest import mock

_HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(_HERE)
for _p in (_HERE, os.path.join(ROOT, "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
_optional_deps.stub("markupsafe", "werkzeug", "werkzeug.utils")  # sigma_runner imports werkzeug; CI has none

from services.aws.boto_client import REGION_RE, default_regions  # noqa: E402


class RegionNames(unittest.TestCase):
    def test_real_regions_pass_typos_do_not(self):
        for r in ("us-east-1", "eu-west-2", "ap-southeast-3", "eu-central-2", "il-central-1",
                  "us-gov-west-1", "cn-north-1", "me-central-1"):
            self.assertRegex(r, REGION_RE)
        for r in ("us-east", "useast1", "eu-west-2a", "EU WEST 2", "us-east-1; rm", ""):
            self.assertIsNone(REGION_RE.match(r), r)

    def test_default_is_the_remembered_list_then_the_old_single_region(self):
        self.assertEqual(default_regions({"regions": ["eu-west-2", "us-east-1"], "region": "eu-west-2"}),
                         ["eu-west-2", "us-east-1"])
        self.assertEqual(default_regions({"region": "eu-west-2"}), ["eu-west-2"])
        self.assertEqual(default_regions({}), ["us-east-1"])


class PagesHaveOneRegionControl(unittest.TestCase):
    def test_settings_has_no_aws_region(self):
        with open(os.path.join(ROOT, "modules/nginx/html/partials/settings.html")) as fh:
            self.assertNotIn("cloud.aws.region", fh.read())

    def test_the_page_component_has_no_double_quote_inside(self):
        """The whole component sits in x-data="{ ... }": one " in a comment ends the
        attribute and the page silently loses every control (2026-10-26)."""
        with open(os.path.join(ROOT, "modules/nginx/html/partials/aws.html")) as fh:
            html = fh.read()
        a = html.index('x-data="{')
        b = html.index('}"', a)
        self.assertNotIn('"', html[a + len('x-data="'):b])

    def test_aws_page_opens_with_the_box_value_and_keeps_it_across_tabs(self):
        with open(os.path.join(ROOT, "modules/nginx/html/partials/aws.html")) as fh:
            html = fh.read()
        self.assertIn("awsRegions: [],", html)
        self.assertIn('id="aws-regions-dd"', html)
        self.assertNotIn('x-model="awsRegions" placeholder', html)
        self.assertIn("aws_credentials || {}).regions", html)
        self.assertIn("saveAwsRegions([...v])", html)
        self.assertIn("'awsRunning', 'awsRegions',", html)


class TheScanRouteRemembers(unittest.TestCase):
    def _app(self):
        try:
            import flask
            from routes import aws_routes, config_routes
        except ImportError as e:
            self.skipTest(f"no flask here: {e}")
        app = flask.Flask(__name__)
        app.register_blueprint(aws_routes.aws_bp)
        app.register_blueprint(config_routes.config_bp)
        return app, aws_routes, config_routes

    def test_scan_saves_regions_settings_save_keeps_them_typo_refused(self):
        app, ar, cr = self._app()
        store = {"cloud": {"provider": "aws", "aws": {"access_key_id": "AKIAX", "secret_access_key": "s3cr3t",
                                                      "region": "us-east-1", "session_token": ""}}}
        load = lambda: __import__("copy").deepcopy(store["cloud"])            # noqa: E731
        save = lambda c: store.__setitem__("cloud", __import__("copy").deepcopy(c))  # noqa: E731

        class NoThread:
            def __init__(self, *a, **k): pass
            def start(self): pass

        body = {"blueprint": "aws_quick_triage", "scope_mode": "account_wide", "cloudtrail_mode": "light",
                "time_filter": {"enabled": True, "mode": "between", "start_datetime": "2026-10-25T18:00:00Z",
                                "end_datetime": ""}}
        with mock.patch.object(ar, "_load_cloud_config", side_effect=load), \
             mock.patch.object(cr, "_load_cloud_config", side_effect=load), \
             mock.patch.object(cr, "_save_cloud_config", side_effect=save), \
             mock.patch("services.workflow_service.create_automation_run", return_value="aws_scan_test"), \
             mock.patch("services.workflow_service.update_run_status"), \
             mock.patch("services.workflow_service.register_cancel_event"), \
             mock.patch("threading.Thread", NoThread):
            c = app.test_client()
            r = c.post("/api/aws/scan", json=dict(body, regions=["eu-west-2", " US-EAST-1 ", "eu-west-2"]))
            self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
            self.assertEqual(store["cloud"]["aws"]["regions"], ["eu-west-2", "us-east-1"])
            self.assertEqual(store["cloud"]["aws"]["region"], "eu-west-2")
            self.assertEqual(store["cloud"]["aws"]["secret_access_key"], "s3cr3t")
            self.assertEqual(c.get("/api/aws/status").get_json()["aws_credentials"]["regions"],
                             ["eu-west-2", "us-east-1"])

            r = c.post("/api/aws/scan", json=dict(body, regions=["eu-west-2", "us-east"]))
            self.assertEqual(r.status_code, 400)
            self.assertIn("us-east", r.get_json()["error"])
            self.assertEqual(store["cloud"]["aws"]["regions"], ["eu-west-2", "us-east-1"])

            # The page saves on every change -- removing all included -- so a refresh shows it.
            self.assertEqual(c.put("/api/aws/regions", json={"regions": []}).status_code, 200)
            self.assertEqual(store["cloud"]["aws"]["regions"], [])
            self.assertEqual(c.get("/api/aws/status").get_json()["aws_credentials"]["regions"], [])
            self.assertEqual(c.put("/api/aws/regions", json={"regions": ["us-east"]}).status_code, 400)
            self.assertEqual(c.put("/api/aws/regions", json={"regions": ["eu-west-2", "us-east-1"]}).status_code, 200)

            # The time window: a month until changed, then whatever the page saved.
            self.assertEqual(c.get("/api/aws/status").get_json()["aws_credentials"]["time_window"], {"hours": 720})
            self.assertEqual(c.put("/api/aws/time-window", json={"hours": 168}).status_code, 200)
            self.assertEqual(store["cloud"]["aws"]["time_window"], {"hours": 168})
            fixed = {"start": "2026-09-01T00:00:00", "end": "2026-10-01T12:00:00"}
            self.assertEqual(c.put("/api/aws/time-window", json=fixed).status_code, 200)
            self.assertEqual(c.get("/api/aws/status").get_json()["aws_credentials"]["time_window"], fixed)
            open_end = {"start": "2025-09-01T10:49:00", "end": ""}
            self.assertEqual(c.put("/api/aws/time-window", json=open_end).status_code, 200)
            self.assertEqual(store["cloud"]["aws"]["time_window"], open_end)
            self.assertEqual(c.put("/api/aws/time-window", json=fixed).status_code, 200)
            for bad in ({"hours": 0}, {"hours": "x"}, {"hours": 99999}, {"start": "2026-10-01T00:00", "end": "2026-09-01T00:00"},
                        {"start": "yesterday", "end": "2026-10-01T00:00"}, []):
                self.assertEqual(c.put("/api/aws/time-window", json=bad).status_code, 400, bad)
            self.assertEqual(store["cloud"]["aws"]["time_window"], fixed)

            # A Settings page opened before the scan saves its stale copy.
            stale = {"provider": "aws", "aws": {"access_key_id": "AKIAX", "secret_access_key": "••••••••cr3t",
                                                "region": "us-east-1", "session_token": ""}}
            self.assertEqual(c.put("/api/config/cloud", json=stale).status_code, 200)
            self.assertEqual(store["cloud"]["aws"]["regions"], ["eu-west-2", "us-east-1"])
            self.assertEqual(store["cloud"]["aws"]["region"], "eu-west-2")
            self.assertEqual(store["cloud"]["aws"]["secret_access_key"], "s3cr3t")
            self.assertEqual(store["cloud"]["aws"]["time_window"], fixed)


if __name__ == "__main__":
    unittest.main()
