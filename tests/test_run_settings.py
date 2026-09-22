"""Velociraptor Collection and Hunt: expiry, timeout and CPU are editable per run.

Asked for from QA: the blueprint supplies the defaults, and the operator can
adjust them on the page. The Hunt path already sent the three values, but the
endpoint interpolated them into VQL unchecked; the Collection path did not send
them at all, so the collector always used the blueprint's settings. Collections
have no expiry -- that is a hunt setting.
"""

import os
import shutil
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "modules", "backend", "services"))
import vql_safety  # noqa: E402  -- pure module, no backend imports


def _src(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return f.read()


class TheValuesAreValidated(unittest.TestCase):

    def test_supplied_values_come_back_as_integers(self):
        out, err = vql_safety.validate_run_settings(
            {"expire_minutes": 90, "timeout_seconds": "600", "cpu_limit": 25.0}, allow_expiry=True)
        self.assertIsNone(err)
        self.assertEqual({"expire_minutes": 90, "timeout_seconds": 600, "cpu_limit": 25}, out)

    def test_missing_values_mean_the_blueprint_default(self):
        self.assertEqual(({}, None), vql_safety.validate_run_settings({}, allow_expiry=True))
        self.assertEqual(({}, None), vql_safety.validate_run_settings({"cpu_limit": None, "timeout_seconds": ""}, allow_expiry=True))
        self.assertEqual(({}, None), vql_safety.validate_run_settings(None, allow_expiry=True))

    def test_anything_that_could_reach_vql_as_text_is_rejected(self):
        for bad in ({"cpu_limit": "50); DROP"}, {"timeout_seconds": "1e3"}, {"cpu_limit": True},
                    {"cpu_limit": 2.5}, {"timeout_seconds": [600]}, {"expire_minutes": {"x": 1}}):
            out, err = vql_safety.validate_run_settings(bad, allow_expiry=True)
            self.assertIsNone(out, bad)
            self.assertIn("whole number", err)

    def test_out_of_range_values_are_rejected(self):
        for key, bad in (("cpu_limit", 0), ("cpu_limit", 101), ("timeout_seconds", 59),
                         ("timeout_seconds", 86401), ("expire_minutes", 0), ("expire_minutes", 10081)):
            out, err = vql_safety.validate_run_settings({key: bad}, allow_expiry=True)
            self.assertIsNone(out, (key, bad))
            self.assertIn("between", err)

    def test_a_collection_ignores_expiry(self):
        out, err = vql_safety.validate_run_settings({"expire_minutes": 90, "cpu_limit": 10}, allow_expiry=False)
        self.assertEqual(({"cpu_limit": 10}, None), (out, err))


class TheValuesReachVelociraptor(unittest.TestCase):

    def test_the_collection_route_validates_stores_and_passes_them(self):
        body = _src("modules/backend/routes/agentic_routes.py")
        self.assertIn("validate_run_settings(data, allow_expiry=False)", body)
        self.assertIn('"run_settings": run_settings', body)
        self.assertIn('kwargs={"run_settings": run_settings}', body)

    def test_the_pipeline_applies_them_over_the_blueprint(self):
        body = _src("modules/backend/services/agentic/pipeline/_runners.py")
        self.assertIn("run_settings=None", body)
        self.assertIn('settings["timeout"] = _rs["timeout_seconds"]', body)
        self.assertIn('settings["cpu_limit"] = _rs["cpu_limit"]', body)

    def test_the_hunt_route_validates_before_building_vql(self):
        body = _src("modules/backend/routes/velociraptor_routes.py")
        seg = body[body.index("def run_bestpractice_hunts"):]
        self.assertLess(seg.index("validate_run_settings(data, allow_expiry=True)"), seg.index("expire_minutes = "))
        self.assertNotIn("cpu_limit = data.get('cpu_limit'", seg)

    def test_the_page_offers_editable_fields_and_a_reset(self):
        html = _src("modules/nginx/html/partials/velociraptor.html")
        for field in ('id="forensics-bp-expiry"', 'id="forensics-bp-timeout"', 'id="forensics-bp-cpu"'):
            self.assertRegex(html, r'<input type="number" ' + field.replace('"', '\\"'))
        self.assertIn("resetForensicsRunSettings()", html)

    def test_the_run_says_what_its_number_of_minutes_IS(self):
        """QA could not tell what the "30m" in the run title meant — elapsed time,
        a deadline, a version. It is how long the collection may run for."""
        body = _src("modules/backend/routes/agentic_routes.py")
        self.assertIn('f"up to {collection_minutes} min"', body)
        self.assertNotIn('{collection_minutes}m"', body, "a bare 30m says nothing")
        self.assertIn("client{'' if _n == 1 else 's'}", body, "and '1 clients' is wrong")

    def test_the_settings_line_is_only_what_this_run_uses(self):
        """It printed the blueprint's stored values beside the run's own — three
        numbers for one setting, and the operator had to work out which applied."""
        body = _src("modules/backend/services/agentic/pipeline/_runners.py")
        seg = body[body.index("[Pipeline] Run settings:"):]
        seg = seg[:seg.index("[Pipeline] Clients:")]
        self.assertNotIn("adjusted for this run", seg)
        self.assertNotIn("blueprint defaults", seg)
        self.assertIn("artifact timeout", seg)
        self.assertIn("client CPU limit", seg)

    @unittest.skipIf(shutil.which("node") is None, "node is not installed")
    def test_the_real_page_sends_what_the_operator_set(self):
        r = subprocess.run(["node", os.path.join(ROOT, "tests", "forensics_run_settings.js"), ROOT],
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(0, r.returncode, r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
