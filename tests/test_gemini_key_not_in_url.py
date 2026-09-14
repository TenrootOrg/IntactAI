"""An API key must never reach a URL, a log line or an error message.

Found on a live appliance: `docker logs intact_backend` held a full API key.
The Gemini model-catalog fetch sent the key as a URL query parameter, the
request failed, and the failure text ("400 Client Error: Bad Request for url:
...?key=<the key>") was logged and returned as `error`. The key now travels in
the x-goog-api-key header. These tests fake a failing request and check every
place the key could escape.
"""

import os
import sys
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for p in ("/app", os.path.join(ROOT, "modules", "backend"), os.path.join(ROOT, "tests")):
    if p not in sys.path:
        sys.path.insert(0, p)
import _optional_deps  # noqa: F401,E402

try:
    import requests  # noqa: E402
    from services.llm_catalogs import gemini  # noqa: E402
except Exception as e:  # noqa: BLE001
    requests = gemini = None
    _IMPORT_ERROR = e

KEY = "sk-or-v1-THIS-IS-A-TEST-KEY-0123456789abcdef"


def _failing_get(url, params=None, headers=None, timeout=None, **_kw):
    """Behaves like requests for a 400: the exception names the full URL."""
    full = requests.Request("GET", url, params=params).prepare().url
    resp = requests.Response()
    resp.status_code, resp.url, resp.reason = 400, full, "Bad Request"
    _failing_get.seen = {"url": full, "params": params or {}, "headers": headers or {}}
    raise requests.HTTPError(f"400 Client Error: Bad Request for url: {full}", response=resp)


@unittest.skipIf(gemini is None, "requests / backend not importable here")
class TheGeminiKeyStaysOutOfUrlsLogsAndErrors(unittest.TestCase):

    def _refresh(self):
        logged = []
        with mock.patch.object(gemini.requests, "get", side_effect=_failing_get):
            out = gemini.refresh_catalog(logger=lambda msg, level="info": logged.append(msg), api_key=KEY)
        return out, logged, _failing_get.seen

    def test_the_key_is_not_in_the_url_or_query(self):
        _, _, seen = self._refresh()
        self.assertNotIn(KEY, seen["url"])
        self.assertNotIn("key", {k.lower() for k in seen["params"]})

    def test_the_key_is_sent_in_the_header(self):
        _, _, seen = self._refresh()
        self.assertEqual(KEY, seen["headers"].get("x-goog-api-key"))

    def test_a_failure_logs_and_returns_no_key(self):
        out, logged, _ = self._refresh()
        self.assertFalse(out["success"])
        self.assertTrue(logged, "the failure must still be logged")
        for line in logged:
            self.assertNotIn(KEY, line)
        self.assertNotIn(KEY, out["error"])


class NoCatalogPutsAKeyInAUrl(unittest.TestCase):
    """The same mistake anywhere else in the catalog fetchers."""

    def test_no_query_parameter_carries_a_key(self):
        import re
        d = os.path.join(ROOT, "modules/backend/services/llm_catalogs")
        for name in sorted(os.listdir(d)):
            if not name.endswith(".py"):
                continue
            with open(os.path.join(d, name), encoding="utf-8") as f:
                src = f.read()
            self.assertIsNone(re.search(r"params\s*=\s*\{[^}]*['\"](?:key|api_key|apikey|token)['\"]", src),
                              f"{name} puts a key in the query string")
            self.assertIsNone(re.search(r"[?&](?:key|api_key|apikey|token)=\{", src),
                              f"{name} builds a URL with a key in it")



try:
    from services import support_bundle  # noqa: E402
except Exception:  # noqa: BLE001
    support_bundle = None


@unittest.skipIf(support_bundle is None, "support_bundle not importable here")
class ASupportBundleMasksAKeyAlreadyInTheLogs(unittest.TestCase):
    """The container log written before the fix still holds the key, and a
    support bundle collects those logs. Redaction must catch it."""

    def _redact(self, text):
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False, encoding="utf-8") as f:
            f.write(text)
        try:
            support_bundle._redact_file(f.name)
            with open(f.name, encoding="utf-8") as g:
                return g.read()
        finally:
            os.unlink(f.name)

    def test_the_exact_leaked_line_is_masked(self):
        line = ("[GEMINI-CATALOG] [warning] Fetch failed: 400 Client Error: Bad Request for url: "
                f"https://generativelanguage.googleapis.com/v1beta/models?key={KEY}&pageSize=200\n")
        out = self._redact(line)
        self.assertNotIn(KEY, out)
        self.assertIn("pageSize=200", out, "the rest of the URL stays readable")

    def test_provider_key_shapes_are_masked_anywhere(self):
        for secret in (KEY, "sk-ant-api03-" + "a" * 40, "sk-proj-" + "b1" * 20, "AIza" + "c" * 35):
            self.assertNotIn(secret, self._redact(f"calling provider with {secret} now\n"), secret)

    def test_ordinary_lines_are_left_alone(self):
        lines = ("sorted by key=lambda x: x[0]\n"
                 "GET /api/cases?page=2&sort=name HTTP/1.1 200\n"
                 "task-runner started, disk-usage 40%\n")
        self.assertEqual(lines, self._redact(lines))


if __name__ == "__main__":
    unittest.main(verbosity=2)
