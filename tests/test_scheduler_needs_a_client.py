"""A schedule that runs on chosen clients cannot be saved without one.

Collector, Timesketch and Memory schedules run on the clients picked for them
(Velociraptor Hunt and AWS are environment-wide). With none, the job fires and
does nothing. The form refuses to save, and says why when no client exists at
all; the server refuses on create and on an edit that empties the list.

Source checks: routes/ needs Flask, which the test run does not install. The
picker's own empty-fleet text is driven for real in client_picker_offline_note.js.
"""
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
        return fh.read()


class ScheduleNeedsAClient(unittest.TestCase):
    def test_server_refuses_on_create_and_on_an_emptying_edit(self):
        src = _read("modules/backend/routes/scheduler_routes.py")
        self.assertIn('CLIENT_TYPES = ("agentic", "timesketch", "memory")', src)
        create = src[src.index("def create_job("):src.index("def get_job(")]
        update = src[src.index("def update_job("):src.index("def delete_job(")]
        self.assertIn("if blueprint_type in CLIENT_TYPES and not client_ids:", create)
        self.assertIn("if 'client_ids' in data and not data['client_ids']:", update)
        self.assertIn("if kind in CLIENT_TYPES:", update)

    def test_the_form_refuses_and_explains_an_empty_fleet(self):
        js = _read("modules/nginx/html/js/scheduler.js")
        save = js[js.index("    // Validation"):]
        self.assertIn("if (!envWide && clientIds.length === 0)", save)
        self.assertIn("schedulerClientManager.totalClients === 0 ? SCHEDULE_NO_CLIENTS", save)
        self.assertIn("No Velociraptor clients exist yet, online or offline.", js)


if __name__ == "__main__":
    unittest.main()
