"""Leaving the Scheduler closes its New / Edit schedule form.

The form is a page-level overlay in index.html, outside the Scheduler panel, so
switching section left it open over the next one (QA 2026-11-08). switchTab
fires `automation-tab-entered` for every section change (menu and hash); the
scheduler cancels its form on any section but its own.
"""
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
        return fh.read()


class ScheduleFormClosesOnLeave(unittest.TestCase):
    def test_switch_tab_announces_the_section(self):
        app = _read("modules/nginx/html/js/stores/app.js")
        body = app[app.index("switchTab(tab) {"):]
        self.assertIn("new CustomEvent('automation-tab-entered'", body[:1500])

    def test_the_scheduler_cancels_its_form_elsewhere(self):
        js = _read("modules/nginx/html/js/scheduler.js")
        i = js.index("window.addEventListener('automation-tab-entered'")
        listener = js[i:i + 400]
        self.assertIn("ev.detail !== 'scheduler'", listener)
        self.assertIn("closeScheduleModal()", listener)


if __name__ == "__main__":
    unittest.main()
