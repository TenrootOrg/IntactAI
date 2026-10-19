"""Update catalog tests the big vendors' AI models; nothing in it can crash.

The AI-model picker offered ~470 OpenRouter models alike while this account cannot
use many of them (zero-data-retention policy) and some list with no endpoint. A
Settings -> Actions job now sends each model of the chosen vendors one 1-token
call; the picker marks and orders them. Every failure is a result, never a crash.
"""
import json
import os
import sys
import tempfile
import types
import unittest
from unittest import mock

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_BACKEND = os.path.join(_ROOT, "modules/backend")
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)
for _pkg, _rel in (("services", "services"), ("services.llm_catalogs", "services/llm_catalogs")):
    if _pkg not in sys.modules:
        _m = types.ModuleType(_pkg)
        _m.__path__ = [os.path.join(_BACKEND, _rel)]
        sys.modules[_pkg] = _m
if "requests" not in sys.modules:
    sys.modules["requests"] = types.ModuleType("requests")
    sys.modules["requests"].post = None
    sys.modules["requests"].get = None

from services.llm_catalogs import model_probe as mp  # noqa: E402


class _R:
    def __init__(self, status, body=None, text=None):
        self.status_code, self._b = status, body
        self.text = text if text is not None else json.dumps(body)

    def json(self):
        if self._b is None:
            raise ValueError("not json")
        return self._b


def m(mid, prompt="0.000001"):
    return {"id": mid, "pricing": {"prompt": prompt, "completion": "0.000002"}}


class ProbeOne(unittest.TestCase):
    def probe(self, side_effect):
        with mock.patch.object(mp.requests, "post", side_effect=side_effect):
            return mp.probe_model("openai/x", "k")

    def test_kinds_and_never_raises(self):
        self.assertTrue(self.probe([_R(200, {"choices": [{"message": {"content": "O"}}]})])["ok"])
        self.assertEqual("policy", self.probe([_R(404, {"error": {"message": "... your data policy. ZDR violation"}})])["kind"])
        self.assertEqual("not_served", self.probe([_R(404, {"error": {"message": "No endpoints found"}})])["kind"])
        self.assertEqual("credit", self.probe([_R(402, {"error": {"message": "Insufficient credits"}})])["kind"])
        self.assertEqual("auth", self.probe([_R(401, None, text="nope")])["kind"])
        self.assertEqual("rate", self.probe([_R(429, {"error": {"message": "slow down"}})])["kind"])
        self.assertEqual("unreachable", self.probe(OSError("no route"))["kind"])
        self.assertEqual("other", self.probe([_R(200, None, text="<html>")])["kind"])     # 200, not JSON
        self.assertEqual("other", self.probe([_R(200, {"choices": []})])["kind"])        # 200, no answer
        self.assertEqual("unreachable", self.probe(RuntimeError("anything"))["kind"])   # any exception: a result

    def test_batch_only_models_cost_no_call(self):
        with mock.patch.object(mp.requests, "post") as post:
            r = mp.probe_model("google/gemini-4-argon:batch", "k")
        post.assert_not_called()
        self.assertEqual(("batch", False), (r["kind"], r["ok"]))
        self.assertEqual(3, mp.rank({"probe": r}))                # with the failures, at the bottom

    def test_vendors_and_variable_prices(self):
        self.assertEqual(["openai/a", "anthropic/b"],
                         mp.selectable([m("openai/a"), m("anthropic/b"), m("someone/c"),
                                        m("openai/router", prompt="-1"), {"id": ""}, None, {"pricing": {}}]))


class Job(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "p.json")
        self.p = mock.patch.object(mp, "PROBES_PATH", self.path)
        self.p.start()
        self.logs, self.dones = [], []

    def tearDown(self):
        self.p.stop()
        self.tmp.cleanup()

    def run_job(self, models, probe):
        with mock.patch.object(mp, "probe_model", side_effect=probe):
            mp.run("r1", "k", models, lambda msg, lvl="info": self.logs.append((lvl, msg)),
                   lambda s, err, det: self.dones.append((s, err, det)))
        return self.dones[-1]

    def test_results_are_saved_merged_and_counted(self):
        with open(self.path, "w") as f:
            json.dump({"someone/old": {"ok": True, "kind": "ok", "why": ""}}, f)
        models = [m(f"openai/m{i}") for i in range(10)]
        s, err, det = self.run_job(models, lambda mid, k: {"ok": mid != "openai/m3", "kind": "ok" if mid != "openai/m3" else "policy", "why": ""})
        self.assertEqual("completed", s)
        saved = mp.load()
        self.assertEqual(11, len(saved))                         # earlier results kept
        self.assertEqual({"ok": 9, "policy": 1}, det["counts"])

    def test_running_at_once_and_marks_saved_as_it_goes(self):
        saves = []
        real_save = mp._save
        with mock.patch.object(mp, "_save", side_effect=lambda d: (saves.append(len(d)), real_save(d))):
            self.run_job([m(f"openai/m{i}") for i in range(80)],
                         lambda mid, k: {"ok": True, "kind": "ok", "why": ""})
        self.assertEqual("running", self.dones[0][0])
        self.assertEqual("completed", self.dones[-1][0])
        self.assertGreaterEqual(len(saves), 3)                    # every 25, then the end
        self.assertEqual(80, len(mp.load()))

    def test_batch_models_do_not_hide_an_outage(self):
        def probe(mid, k):
            return dict(mp.BATCH) if mid.endswith(":batch") else \
                {"ok": False, "kind": "auth", "why": "HTTP 401: key refused"}
        s, err, _ = self.run_job([m("openai/a:batch")] + [m(f"openai/m{i}") for i in range(20)], probe)
        self.assertEqual("failed", s); self.assertIn("key refused", err)

    def test_a_total_outage_stops_early_and_saves_nothing(self):
        calls = []

        def probe(mid, k):
            calls.append(mid)
            return {"ok": False, "kind": "unreachable", "why": "unreachable (ConnectionError)"}
        s, err, _ = self.run_job([m(f"openai/m{i}") for i in range(50)], probe)
        self.assertEqual("failed", s); self.assertIn("unreachable", err)
        self.assertEqual(mp.OUTAGE_STOP_AFTER, len(calls))
        self.assertEqual({}, mp.load())

    def test_anything_unexpected_ends_the_run_never_the_caller(self):
        with mock.patch.object(mp, "selectable", side_effect=RuntimeError("boom")):
            s, err, _ = self.run_job([m("openai/a")], lambda mid, k: {})
        self.assertEqual("failed", s); self.assertIn("boom", err)
        self.assertFalse(mp._lock.locked())                       # and the next run may start

    def test_one_job_at_a_time(self):
        mp._lock.acquire()
        try:
            s, err, _ = self.run_job([m("openai/a")], lambda mid, k: {"ok": True, "kind": "ok", "why": ""})
        finally:
            mp._lock.release()
        self.assertEqual("failed", s); self.assertIn("already running", err)

    def test_a_broken_results_file_reads_as_never_tested(self):
        for bad in ("{not json", "[1, 2]"):
            with open(self.path, "w") as f:
                f.write(bad)
            self.assertEqual({}, mp.load())


class PickerSearch(unittest.TestCase):
    def test_sorted_before_the_page_is_cut(self):
        from services.llm_catalogs import openrouter
        rows = [{"id": f"openai/m{i}", "name": f"m{i}"} for i in range(30)]
        probes = {"openai/m25": {"ok": True, "kind": "ok", "why": ""},
                  "openai/m0": {"ok": False, "kind": "not_served", "why": "x"},
                  "openai/m1": {"ok": False, "kind": "policy", "why": "y"}}
        with mock.patch.object(openrouter.store, "search",
                               side_effect=lambda q="", limit=10, offset=0: {"models": rows[offset:offset + limit], "total": 30}), \
             mock.patch.object(mp, "load", return_value=probes):
            page = openrouter.search(limit=5)["models"]
            last = openrouter.search(limit=5, offset=25)["models"]
        self.assertEqual("openai/m25", page[0]["id"])            # the one that works, first
        self.assertEqual(["openai/m1", "openai/m0"], [x["id"] for x in last[-2:]])   # policy, then failed, last

    def test_no_or_broken_results_change_nothing(self):
        from services.llm_catalogs import openrouter
        plain = {"models": [{"id": "openai/a"}], "total": 1}
        with mock.patch.object(openrouter.store, "search", return_value=plain), \
             mock.patch.object(mp, "load", side_effect=OSError("disk")):
            self.assertEqual(plain, openrouter.search())


if __name__ == "__main__":
    unittest.main()
