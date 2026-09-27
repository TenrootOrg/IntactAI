"""A report written by an earlier analysis says so — with the numbers.

Found in the audit (jev_test): the stored report said 126 findings, the case
had 281 after the episode Timeline, and nothing said why. Every fuse had
overwritten the report's "written from" counts with the new graph's, so the
report could not even read as behind.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
for _p in (_HERE, os.path.join(_ROOT, "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import correlate  # noqa: E402


def _src(rel):
    with open(os.path.join(_ROOT, rel), encoding="utf-8") as fh:
        return fh.read()


class Backend(unittest.TestCase):
    def test_counts_are_recorded_only_when_the_report_was_rewritten(self):
        s = _src("modules/backend/services/fusion/store.py")
        block = s[s.index("# What the report was written FROM"):s.index("# File the report under the timeframe")]
        self.assertIn("if not report_dirty:", block)
        self.assertIn('_details["report_engine"] = correlate.FUSION_ENGINE', block)

    def test_engine_behind_flag(self):
        try:
            from routes.case_routes import _report_engine_behind
        except ImportError as e:
            self.skipTest(f"no flask here: {e}")
        self.assertTrue(_report_engine_behind({"report_md": "# r", "report_engine": "old"}))
        self.assertTrue(_report_engine_behind({"report_md": "# r"}))                  # legacy report
        self.assertFalse(_report_engine_behind({"report_md": "# r", "report_engine": correlate.FUSION_ENGINE}))
        self.assertFalse(_report_engine_behind({"report_md": "", "report_engine": "old"}))


class Notice(unittest.TestCase):
    def test_notice_names_the_numbers(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("no node on this host")
        src = _src("modules/nginx/html/cases.html")
        fn = re.search(r"function behindNote\(info\)\{.*?\n\}", src, re.S).group(0)
        js = ("window={_md:'# r'};\n" + fn + """
console.log(JSON.stringify([behindNote({report_engine_behind:true,report_findings_then:126,findings_now:281}),
  behindNote({report_engine_behind:false})]));""")
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as t:
            t.write(js)
        try:
            out = json.loads(subprocess.run([node, t.name], capture_output=True, text=True, check=True).stdout)
        finally:
            os.unlink(t.name)
        self.assertIn("earlier version of the analysis (126 findings then; the case now has 281)", out[0])
        self.assertEqual(out[1], "")


if __name__ == "__main__":
    unittest.main()
