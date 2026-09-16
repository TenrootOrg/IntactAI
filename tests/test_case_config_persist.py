"""The Case Analysis configuration must survive a Refusion and a tab switch.

Reported: change the Time window in Configuration, press Refusion, move to the Log
or come back, and the old window is on screen again.

The backend was not at fault -- /config and /rescan both store what they are sent
(checked live on the appliance). The page was: doRefusion() posted the rail and
never re-read the case, so `curInfo` -- what every tab renders from -- still held
the settings from before the save. A second one of the same shape turned up while
checking the rest of the rail: report_altitude is served by /report, not by the
case payload, and showCase() did not merge it, so the altitude read back as "auto"
however it had been set.

tests/case_config_persist.js drives the REAL doRefusion from cases.html and then
checks the whole rail statically: every setting it renders must be supplied by the
case-detail payload or merged into `info` by the page, and every action that saves
the rail must re-read the case afterwards.
"""

import os
import shutil
import subprocess
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HARNESS = os.path.join(ROOT, "tests", "case_config_persist.js")


class TheConfigRailSurvivesARefusion(unittest.TestCase):

    @unittest.skipIf(shutil.which("node") is None, "node is not installed")
    def test_harness(self):
        r = subprocess.run(["node", HARNESS, ROOT], capture_output=True, text=True, timeout=120)
        self.assertEqual(0, r.returncode, r.stdout + r.stderr)


class TheBackendStoresWhatTheRailSends(unittest.TestCase):
    """The persistence half, without a live appliance: set_analysis_config is
    key-presence-based, so a key the rail sends must be a key it writes."""

    def setUp(self):
        with open(os.path.join(ROOT, "modules/backend/services/fusion/store.py"), encoding="utf-8") as fh:
            self.store = fh.read()
        with open(os.path.join(ROOT, "modules/nginx/html/cases.html"), encoding="utf-8") as fh:
            self.page = fh.read()

    def _rail_keys(self):
        start = self.page.index("async function _railCfg(){")
        end = self.page.index("async function doRefusion(id){")
        body = self.page[start:end]
        import re
        return {m.group(1) for m in re.finditer(r"^\s{4}([a-z_]+):", body, re.M)}

    def test_every_setting_the_rail_posts_is_one_the_backend_writes(self):
        cfg = self.store[self.store.index("def set_analysis_config(case_id, cfg)"):
                         self.store.index("def rescan(case_id, cfg=None, trigger=None)")]
        # Locked settings are written unconditionally rather than read from cfg.
        locked = {"llm_max_output_tokens", "llm_use_full_context",
                  "chat_send_full_context", "report_detail"}
        missing = [k for k in sorted(self._rail_keys())
                   if k not in locked and f'"{k}"' not in cfg]
        self.assertEqual([], missing,
                         f"the rail posts these but set_analysis_config ignores them: {missing}")

    def test_the_window_lower_bound_is_never_left_empty(self):
        cfg = self.store[self.store.index("def set_analysis_config(case_id, cfg)"):
                         self.store.index("def rescan(case_id, cfg=None, trigger=None)")]
        self.assertIn("_default_window", cfg,
                      "an empty 'from' must fall back to a concrete bound, not an open one")


if __name__ == "__main__":
    unittest.main(verbosity=2)
