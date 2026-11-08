"""The scheduler no longer offers the per-client "Velociraptor Collector" type.

QA 2026-11-08 could not schedule one: it needs its clients online when the
schedule is made ("No clients found"), and a Velociraptor Hunt runs the same
blueprint on every client. New and edited schedules refuse the type; ones made
before keep running and can still be paused (/toggle) or deleted.

Source checks: routes/ needs Flask, which the test run does not install.
"""
import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
        return fh.read()


class SchedulerHasNoCollectorType(unittest.TestCase):
    def test_the_form_does_not_offer_it_and_defaults_to_a_hunt(self):
        html, js = _read("modules/nginx/html/index.html"), _read("modules/nginx/html/js/scheduler.js")
        sel = re.search(r'<select id="schedule-blueprint-type".*?</select>', html, re.S).group(0)
        self.assertNotIn('value="agentic"', sel)
        self.assertIn('value="velociraptor"', sel)
        self.assertNotIn('schedule-collector-options', html)
        self.assertIn("getElementById('schedule-blueprint-type').value = 'velociraptor';", js)

    def test_an_old_collection_schedule_is_explained_not_opened(self):
        js = _read("modules/nginx/html/js/scheduler.js")
        edit = js[js.index("async function editSchedule("):]
        guard = edit.index("if (job.blueprint_type === 'agentic')")
        self.assertLess(guard, edit.index("classList.remove('hidden')"))

    def test_create_and_update_refuse_it(self):
        src = _read("modules/backend/routes/scheduler_routes.py")
        create = src[src.index("def create_job("):src.index("def get_job(")] if "def get_job(" in src else src
        update = src[src.index("def update_job("):src.index("def delete_job(")]
        self.assertIn("if blueprint_type == 'agentic':", create)
        self.assertIn("if data.get('blueprint_type') == 'agentic':", update)


if __name__ == "__main__":
    unittest.main()
