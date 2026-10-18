"""A log attachment no reader recognises is given to the case's model whole (as much
as the selected model's context window holds) for a description, and that
description reaches chat's and the report's context next to the rest of the case,
apart from what the customer said. Recognised files are not described.

Executed against the real code: external_logs.ingest / describe_unrecognised /
data_descriptions, store._reported and llm_sim.analyst_context.
"""
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

for _p in (os.path.dirname(os.path.abspath(__file__)),
           os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import external_logs as X, llm_sim  # noqa: E402

# Prose-like lines with no structure, IP or account: nothing a reader recognises.
ODD = "\n".join(f"step {i}: the appliance copied the archive to the staging share and reported done"
                for i in range(1, 41))
CSV = ("Timestamp,DeviceName,AccountName,FileName,AlertTitle,Severity\n"
       "2026-10-01T10:05:00Z,WS01,CORP\\jdoe,mimi.exe,Credential dumping,High\n"
       "2026-10-01T10:06:00Z,WS01,CORP\\jdoe,cmd.exe,Recon,Low\n")
WINDOW = {"model": "gpt-test", "provider": "openai", "context_tokens": 128_000, "budget_chars": 100_000}


class FakeModel:
    def __init__(self):
        self.calls = []

    def __call__(self, system, user):
        self.calls.append((system, user))
        if system == X.DESCRIBE_SYSTEM:
            return "Staging activity: an archive copied to a share (L1-L40); no attack indicator."
        return "[]"                                        # llm_extract: no events


class Describe(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.p = mock.patch.object(X, "downloads_dir", lambda rid: os.path.join(self.tmp, rid))
        self.p.start()

    def tearDown(self):
        self.p.stop()

    def _ingest(self, text, model, window=WINDOW):
        src = os.path.join(self.tmp, "f.log")
        with open(src, "w") as f:
            f.write(text)
        with mock.patch.object(X, "_model", lambda *a: (model, None, None) if model else None), \
                mock.patch.object(X, "model_window", lambda: dict(window)):
            return X.ingest("c", "external_log_1", src, "edr", lambda m, l="info": None)

    def test_an_unrecognised_file_is_described_whole(self):
        m = FakeModel()
        s = self._ingest(ODD, m)
        d = s.get("description")
        self.assertTrue(d and d["text"].startswith("Staging activity"))
        self.assertEqual((40, 40, False), (d["lines_described"], d["lines_total"], d["truncated"]))
        sent = [json.loads(u) for sys_, u in m.calls if sys_ == X.DESCRIBE_SYSTEM]
        self.assertEqual(1, len(sent))
        self.assertEqual(40, len(sent[0]["lines"]))         # every line, numbered
        self.assertTrue(sent[0]["lines"][0].startswith("L1: "))

    def test_the_window_limits_what_is_sent_and_says_so(self):
        small = dict(WINDOW, budget_chars=len(X.DESCRIBE_SYSTEM) + 500 + 4_000)
        s = self._ingest("\n".join(f"{i} " + "x" * 300 for i in range(100)), FakeModel(), small)
        d = s["description"]
        self.assertTrue(d["truncated"])
        self.assertLess(d["lines_described"], d["lines_total"])

    def test_a_recognised_file_is_not_described(self):
        m = FakeModel()
        s = self._ingest(CSV, m)
        self.assertNotIn("description", s)
        self.assertFalse([c for c in m.calls if c[0] == X.DESCRIBE_SYSTEM])

    def test_no_model_no_description(self):
        self.assertNotIn("description", self._ingest(ODD, None))


class Window(unittest.TestCase):
    def setUp(self):
        X._WINDOW_CACHE.update(at=0.0, v=None)

    def tearDown(self):
        X._WINDOW_CACHE.update(at=0.0, v=None)

    def _w(self, ctx, provider="openai"):
        from services.fusion import store
        with mock.patch.object(store, "_configured_fusion_model", lambda: ("m", provider, None)), \
                mock.patch("services.agentic.analyzers._llm.get_model_context_length", lambda m, p: ctx):
            return X._model_window()

    def test_the_selected_models_window_sizes_the_budget(self):
        w = self._w(200_000)
        self.assertEqual(200_000, w["context_tokens"])
        self.assertGreater(w["budget_chars"], 400_000)      # most of 200k tokens, at ~4 chars each
        self.assertLess(w["budget_chars"], 800_000)          # never the whole window
        self.assertEqual(X.DESCRIBE_FALLBACK_CHARS, self._w(None)["budget_chars"])
        self.assertLessEqual(self._w(1_000_000, "codex-subscription")["budget_chars"], 1_048_576)


class IntoTheContext(unittest.TestCase):
    def test_descriptions_are_apart_from_what_the_customer_said(self):
        fact = {"kind": "impact", "what": "payroll server encrypted", "source": "call.txt"}
        desc = {"kind": "data_description", "source": "fw.log", "description": "Outbound to 1.2.3.4 (L5)",
                "lines_described": 9, "lines_total": 9}
        out = llm_sim.analyst_context(reported=[fact, desc])
        self.assertEqual([fact], out["reported_by_customer_not_verified"])
        self.assertEqual([{"source": "fw.log", "description": "Outbound to 1.2.3.4 (L5)",
                           "lines_described": 9, "lines_total": 9}], out["log_data_described_by_model"])

    def test_only_switched_in_log_runs_are_read(self):
        runs = [{"automation_type": X.RUN_TYPE, "details": {"data_type": "edr", "file_name": "a.log",
                                                            "description": {"text": "A"}}},
                {"automation_type": X.RUN_TYPE, "details": {"data_type": "edr", "file_name": "b.log",
                                                            "use_in_analysis": False,
                                                            "description": {"text": "B"}}},
                {"automation_type": X.RUN_TYPE, "details": {"data_type": X.NOTES, "description": {"text": "N"}}}]
        with mock.patch("services.workflow_service.get_automation_runs_by_case", lambda cid: runs):
            got = X.data_descriptions("c")
        self.assertEqual([("a.log", "A")], [(g["source"], g["description"]) for g in got])


if __name__ == "__main__":
    unittest.main()
