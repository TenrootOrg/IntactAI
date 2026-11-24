"""An air-gapped box (INTACT_AIRGAP=1 in the backend .env) does not try the internet.

install.sh --package writes the flag; before it, the backend had no way to know,
and the OpenRouter catalog, the tool downloads and the on-demand Velociraptor
fetches each sat out a network timeout before failing. Each now stops at once
and says why. Nothing here touches the network: a fetch that ran would hit the
patched requests.get / urlopen / run_command and fail the test.
"""
import os
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (os.path.join(ROOT, "tests"), os.path.join(ROOT, "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services import tools_download_service as tds  # noqa: E402
from services import legacy_velociraptor_service as lvs  # noqa: E402
from services import velociraptor_collector_tool as vct  # noqa: E402
from services.llm_catalogs import openrouter  # noqa: E402


# Records every call and fails it with words the code under test never says:
# with "air-gapped" in this message the old code passed too -- it caught the
# error and repeated it in its own (reviewer, 2026-11-24).
_CALLS = []


def _no_network(*a, **_k):
    _CALLS.append(a)
    raise AssertionError("NETWORK CALLED")


@mock.patch.dict(os.environ, {"INTACT_AIRGAP": "1"})
class AirGapped(unittest.TestCase):
    def setUp(self):
        _CALLS.clear()

    def tearDown(self):
        self.assertEqual(_CALLS, [], "an air-gapped box went to the network")

    def test_openrouter_catalog_is_not_fetched(self):
        with mock.patch.object(openrouter.requests, "get", _no_network):
            r = openrouter.refresh_catalog(logger=lambda *a, **k: None)
        self.assertFalse(r["success"])
        self.assertIn("air-gapped", r["error"])

    def test_tools_are_not_downloaded_but_cached_ones_count(self):
        cfg = {"event_log_tools": [
            {"name": "cached", "type": "direct_url", "url": "https://x/c.exe", "filename": "c.exe"},
            {"name": "gh", "type": "github_release", "repo": "a/b", "pattern": r"b\.zip"},
        ]}
        with tempfile.TemporaryDirectory() as d, \
                mock.patch.object(tds.requests, "get", _no_network):
            open(os.path.join(d, "c.exe"), "wb").close()
            r = tds.download_tools_from_config(d, cfg, logger=lambda *a, **k: None)
        self.assertIn("cached", r["already_exists"])
        self.assertIn("gh (air-gapped)", r["skipped"])
        self.assertEqual(r["failed"], [])

    def test_legacy_binary_is_not_fetched(self):
        with tempfile.TemporaryDirectory() as d, \
                mock.patch.object(lvs, "LEGACY_CACHE_DIR", d), \
                mock.patch.object(lvs.urllib.request, "urlopen", _no_network):
            with self.assertRaisesRegex(RuntimeError, "air-gapped"):
                lvs.get_legacy_binary("0.7.1", "windows-amd64", source="online")

    def test_collector_is_not_fetched(self):
        with mock.patch.object(vct, "run_command", _no_network), \
                mock.patch.object(vct.os, "makedirs"), \
                mock.patch.object(vct.os.path, "exists", return_value=False):
            r = vct._ensure_velociraptor_collector_tool("0.77.3", source="github")
        self.assertFalse(r["success"])
        self.assertIn("air-gapped", r["error"])


if __name__ == "__main__":
    unittest.main()
