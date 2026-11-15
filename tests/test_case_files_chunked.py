"""Case files over 100 MB are sent in chunks (tus, purpose "case_file") and then
added by their upload id, with no size cap (QA 2026-11-08: External data refused
anything over 100 MB). Before sending, the page warns what the file means for the
model: its size in context windows, the most the model is ever given, the cost.
"""
import hashlib
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (_HERE, os.path.join(os.path.dirname(_HERE), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import case_files, external_logs, store  # noqa: E402

UID = "875bd5fffc1da5fd9a402def5378467b"


class FinishedUpload(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        p = mock.patch.object(case_files, "UPLOADS_DIR", self.tmp)
        p.start()
        self.addCleanup(p.stop)

    def put(self, data, size=None, purpose="case_file", uid=UID):
        with open(os.path.join(self.tmp, uid), "wb") as f:
            f.write(data)
        # tusd's filestore leaves Offset at 0 even when the upload is complete
        with open(os.path.join(self.tmp, uid + ".info"), "w") as f:
            json.dump({"ID": uid, "Size": len(data) if size is None else size, "Offset": 0,
                       "MetaData": {"purpose": purpose}}, f)

    def test_complete_upload(self):
        self.put(b"abc")
        self.assertEqual(os.path.join(self.tmp, UID), case_files.finished_upload(UID))

    def test_partial_other_purpose_or_bad_id(self):
        self.put(b"abc", size=10)
        self.assertIsNone(case_files.finished_upload(UID))
        self.put(b"abc", purpose="velociraptor")
        self.assertIsNone(case_files.finished_upload(UID))
        for bad in ("../etc/passwd", "", None, "ABC"):
            self.assertIsNone(case_files.finished_upload(bad))


class AddFromChunks(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.d = {"name": "qa"}

        def mut(cid, field, fn):
            self.d[field] = fn(self.d.get(field) or [])
        for t, a, v in ((case_files, "DATA_DIR", os.path.join(self.tmp, "cf")), (case_files, "MAX_BYTES", 10),
                        (store, "get_case", lambda cid: self.d), (store, "_mutate_list_field", mut),
                        (store, "log_case_event", mock.Mock()), (store, "_report_behind", mock.Mock())):
            p = mock.patch.object(t, a, v)
            p.start()
            self.addCleanup(p.stop)

    def test_moved_in_hashed_and_not_capped(self):
        data = b"x" * 1000                                 # over the (patched) 10-byte cap
        src = os.path.join(self.tmp, UID)
        with open(src, "wb") as f:
            f.write(data)
        item = case_files.add("c1", None, "big.bin", name="disk image", description="d", src_path=src)
        self.assertNotIn("error", item)
        self.assertEqual((1000, hashlib.sha256(data).hexdigest(), True), (item["size"], item["sha256"], item["stored"]))
        self.assertFalse(os.path.exists(src))
        with open(case_files.path_of("c1", item["id"]), "rb") as f:
            self.assertEqual(data, f.read())

    def test_the_form_path_keeps_its_cap_and_points_at_chunks(self):
        out = case_files.add("c1", io.BytesIO(b"y" * 1000), "big.bin", name="n", description="d")
        self.assertIn("sent in chunks", out["error"])


class ModelWindowForTheWarning(unittest.TestCase):
    def test_price_subscription_and_the_most_the_model_reads(self):
        from services.agentic.analyzers import _llm
        from services.agentic import subscription_cli
        external_logs._WINDOW_CACHE.update(at=0.0, v=None)
        self.addCleanup(external_logs._WINDOW_CACHE.update, at=0.0, v=None)
        with mock.patch.object(store, "_configured_fusion_model", lambda: ("gpt-x", "openrouter", "x")), \
                mock.patch.object(_llm, "get_model_context_length", lambda m, p: 272_000), \
                mock.patch.object(_llm, "_estimate_llm_cost", lambda m, i, o: 1.25 * i / 1e6), \
                mock.patch.object(subscription_cli, "is_subscription_provider", lambda p: False):
            w = external_logs.model_window()
        self.assertEqual((1.25, False, 272_000), (w["usd_per_m_input"], w["subscription"], w["context_tokens"]))
        self.assertEqual(w["budget_chars"] + external_logs.LLM_CHUNK_CHARS * external_logs.LLM_MAX_CHUNKS,
                         w["model_max_chars"]["log"])
        self.assertEqual(external_logs.LLM_CHUNK_CHARS * external_logs.NOTES_MAX_CHUNKS, w["model_max_chars"]["notes"])


if __name__ == "__main__":
    unittest.main()
