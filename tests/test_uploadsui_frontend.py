"""Upload buttons / busy flags come back, tab reset keeps in-flight flags, and
the forensics Start button is guarded (QA F4, F14, F7). Frontend only."""
import os
import re
import shutil
import subprocess
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HTML = os.path.join(ROOT, "modules", "nginx", "html")


def _src(rel):
    with open(os.path.join(HTML, rel), encoding="utf-8") as f:
        return f.read()


def _keep_list(src, tab):
    m = re.search(r"TabReset\.arm\([^,]+,\s*'%s',\s*\{\s*keep:\s*\[([^\]]*)\]" % re.escape(tab), src)
    assert m, tab
    return set(re.findall(r"'([^']+)'", m.group(1)))


class TabResetKeepsInFlightFlags(unittest.TestCase):
    def test_memory_keeps_upload_flags(self):
        keep = _keep_list(_src("js/memory.js"), "modules-memory")
        for flag in ("uploading", "symUploading", "symLibLoading", "dumpsLoading", "adopting", "dispatching"):
            self.assertIn(flag, keep)

    def test_azure_keeps_custom_rule_upload(self):
        keep = _keep_list(_src("partials/azure.html"), "cloud-azure")
        self.assertIn("customRulesUploading", keep)
        self.assertIn("azureRunning", keep)

    def test_aws_still_keeps_running(self):
        self.assertIn("awsRunning", _keep_list(_src("partials/aws.html"), "cloud-aws"))


class RealPages(unittest.TestCase):
    @unittest.skipIf(shutil.which("node") is None, "node is not installed")
    def test_uploads_and_forensics_start(self):
        r = subprocess.run(["node", os.path.join(ROOT, "tests", "test_uploadsui_frontend.js"), ROOT],
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(0, r.returncode, r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
