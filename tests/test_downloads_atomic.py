"""Tool downloads land under their final name only when complete (E12), and the
tool-inventory / MSI paths use the shared Velociraptor API config loader (E11).

E12: download_file() and the legacy online fetch wrote straight to the final
name. A backend killed mid-download left a truncated tool that every later run
reported as cached; the legacy online path did the same on a plain network error
once more than 1 MB had arrived.
E11: tools_download_service and msi_generator_service kept a private
/tmp/api.config.yaml, written only when missing and never re-read, so after a CA
restore it went stale and "Configure tools" / "Generate MSI" failed.
"""
import io
import os
import sys
import tempfile
import types
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (os.path.join(ROOT, "tests"), os.path.join(ROOT, "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services import tools_download_service as tds  # noqa: E402
from services import legacy_velociraptor_service as lvs  # noqa: E402
from services import msi_generator_service as msi  # noqa: E402
from services import velociraptor_service as vs  # noqa: E402
from services import velo_org  # noqa: E402

DATA = b"x" * 50000


class Crash(BaseException):
    """Stands in for the process dying: escapes every `except Exception`."""


def fake_response(body, die_after=None):
    def iter_content(chunk_size=8192):
        for i in range(0, len(body), chunk_size):
            if die_after is not None and i >= die_after:
                raise Crash()
            yield body[i:i + chunk_size]
    return types.SimpleNamespace(
        status_code=200, headers={"content-length": str(len(body))},
        iter_content=iter_content, raise_for_status=lambda: None, close=lambda: None)


class DownloadFile(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.final = os.path.join(self.d, "tool.zip")

    def get(self, body, die_after=None):
        return mock.patch.object(tds.requests, "get",
                                 lambda *a, **k: fake_response(body, die_after))

    def test_crash_mid_download_leaves_no_final_file_and_next_run_completes(self):
        with self.get(DATA, die_after=16384), self.assertRaises(Crash):
            tds.download_file("http://x/tool.zip", self.d, logger=lambda m: None)
        self.assertFalse(os.path.exists(self.final), "a truncated file must not take the final name")
        self.assertTrue(os.path.exists(self.final + ".part"))

        with self.get(DATA):
            got = tds.download_file("http://x/tool.zip", self.d, logger=lambda m: None)
        self.assertEqual(("tool.zip", False), got)       # downloaded, not "cached"
        with open(self.final, "rb") as f:
            self.assertEqual(DATA, f.read())             # stale .part discarded, not appended to
        self.assertFalse(os.path.exists(self.final + ".part"))

    def test_short_transfer_never_takes_the_final_name(self):
        short = fake_response(DATA[:1000])
        short.headers["content-length"] = str(len(DATA))
        with mock.patch.object(tds.requests, "get", lambda *a, **k: short), \
                mock.patch.object(tds.time, "sleep", lambda s: None):
            self.assertIsNone(tds.download_file("http://x/tool.zip", self.d, logger=lambda m: None))
        self.assertEqual([], os.listdir(self.d))

    def test_part_file_is_not_a_cached_tool(self):
        open(os.path.join(self.d, "tool.zip.part"), "wb").close()
        cfg = {"event_log_tools": [{"name": "T", "type": "direct_url", "url": "http://x/tool.zip",
                                    "cache_pattern": r"tool\.zip"}]}
        calls = []
        with mock.patch.object(tds, "download_file",
                               lambda *a, **k: calls.append(a) or ("tool.zip", False)):
            res = tds.download_tools_from_config(self.d, cfg, logger=lambda m, l="info": None)
        self.assertEqual(1, len(calls), "a crashed .part must not count as cached")
        self.assertEqual(["T"], res["downloaded"])


class LegacyOnline(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.saved = lvs.LEGACY_CACHE_DIR
        lvs.LEGACY_CACHE_DIR = self.d
        self.dest = os.path.join(self.d, lvs._binary_filename("0.7.1", "windows-amd64"))

    def tearDown(self):
        lvs.LEGACY_CACHE_DIR = self.saved

    def urlopen(self, body, length=None, die=False):
        class Resp(io.BytesIO):
            headers = {"Content-Length": str(length if length is not None else len(body))}

            def read(self, n=-1):
                chunk = super().read(n)
                if die and self.tell() > 2 * 1024 * 1024:
                    raise ConnectionResetError("network dropped")
                return chunk

            def __exit__(self, *a):
                return False
        return mock.patch.object(lvs.urllib.request, "urlopen", lambda *a, **k: Resp(body))

    def test_network_error_leaves_nothing_that_counts_as_cached(self):
        big = b"v" * (4 * 1024 * 1024)
        with self.urlopen(big, die=True), self.assertRaises(RuntimeError):
            lvs.get_legacy_binary("0.7.1", source="online")
        self.assertEqual([], os.listdir(self.d))

    def test_length_mismatch_is_rejected(self):
        big = b"v" * (2 * 1024 * 1024)
        with self.urlopen(big, length=len(big) + 10), self.assertRaises(RuntimeError):
            lvs.get_legacy_binary("0.7.1", source="online")
        self.assertEqual([], os.listdir(self.d))

    def test_complete_download_lands_under_final_name(self):
        big = b"v" * (2 * 1024 * 1024)
        with self.urlopen(big):
            self.assertEqual(self.dest, lvs.get_legacy_binary("0.7.1", source="online"))
        self.assertEqual([os.path.basename(self.dest)], os.listdir(self.d))
        self.assertTrue(os.access(self.dest, os.X_OK))


class SharedApiConfig(unittest.TestCase):
    def test_both_paths_use_the_shared_loader_in_the_root_org(self):
        seen = []
        chan = object()

        def shared():
            seen.append(velo_org.current())
            return chan
        tok = velo_org.set_current("OFM5G")            # operator picked another org
        try:
            with mock.patch.object(vs, "setup_velociraptor_connection", shared), \
                    mock.patch.object(vs.subprocess, "run",
                                      side_effect=AssertionError("must not exec for its own copy")):
                self.assertIs(chan, tds.setup_velociraptor_connection())
                self.assertIs(chan, msi.setup_velociraptor_connection())
        finally:
            velo_org._org.reset(tok)
        self.assertEqual(["", ""], seen)               # server-wide: root, not the dropdown org


if __name__ == "__main__":
    unittest.main()
