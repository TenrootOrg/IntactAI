"""Agentic Investigate v2: the masking contract and the pivot tool.

The v1 loop sent RAW evidence rows to the model — the only LLM path that bypassed
the per-case anonymizer. v2's contract, tested here against the real package:

  - the model sees ONLY pseudonyms (question + every tool result masked in transit),
  - tool ARGS arrive in pseudonym space and are reverted BEFORE execution
    (per string VALUE, never on serialized JSON — 'DOMAIN\\user' substituted into a
    JSON string would inject an invalid escape),
  - the analyst gets real names back (final answer + step trace reverted),
  - masking off / absent stays a no-op,
  - pivot: value match across event attrs + host labels, window filter, capped.

Run in-container (its true runtime):
    docker exec intact_backend sh -lc \
      'PYTHONPATH=/app python3 /app/tests/test_investigate_v2.py'
"""
import datetime as _dt
import json
import os
import sys
import types
import unittest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in ("/app", os.path.join(_ROOT, "modules/backend"), _ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from services.fusion import investigate, llm_sim, schema  # noqa: E402

_T0 = _dt.datetime(2026, 1, 1, 12, 0, 0, tzinfo=_dt.timezone.utc)


def _ts(day=0, hour=0):
    return (_T0 + _dt.timedelta(days=day, hours=hour)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _fake_mask(mapping):
    """The mask helpers only need .mapping / .reverse_mapping (duck-typed like
    DataAnonymizer), so the contract is testable without the anonymizer stack."""
    return types.SimpleNamespace(mapping=dict(mapping),
                                 reverse_mapping={v: k for k, v in mapping.items()})


MASK = _fake_mask({"ALDC02": "Hostname1", "adatumlab\\srv": "USER1"})


class _Patched:
    """Monkeypatch module attrs for one test, always restored."""

    def __init__(self, obj, **attrs):
        self.obj, self.attrs, self.saved = obj, attrs, {}

    def __enter__(self):
        for k, v in self.attrs.items():
            self.saved[k] = getattr(self.obj, k)
            setattr(self.obj, k, v)
        return self

    def __exit__(self, *a):
        for k, v in self.saved.items():
            setattr(self.obj, k, v)


class MaskRoundTrip(unittest.TestCase):
    def test_apply_then_revert_is_identity_on_raw_row(self):
        row = json.dumps({"Computer": "ALDC02", "cmd": "whoami /all"})
        masked = llm_sim._apply_mask(row, MASK)
        self.assertNotIn("ALDC02", masked)
        self.assertIn("Hostname1", masked)
        self.assertEqual(llm_sim._revert_mask(masked, MASK), row)

    def test_backslash_identity_masked_in_json_reverted_in_prose(self):
        # json.dumps escapes 'adatumlab\srv' to 'adatumlab\\srv' in the wire text;
        # the shipped mask still catches that form (so the model never sees the
        # account), and the model's ANSWER — prose, never re-parsed as JSON — reverts
        # to the real single-backslash value. Byte-identity on JSON text is NOT the
        # contract (revert yields the unescaped original); semantic round-trip is.
        masked = llm_sim._apply_mask(json.dumps({"User": "adatumlab\\srv"}), MASK)
        self.assertIn("USER1", masked)
        self.assertNotIn("srv", masked)
        self.assertEqual(llm_sim._revert_mask("USER1 logged on", MASK),
                         "adatumlab\\srv logged on")

    def test_none_mask_is_noop(self):
        self.assertEqual(llm_sim._apply_mask("ALDC02", None), "ALDC02")
        self.assertEqual(llm_sim._revert_mask("Hostname1", None), "Hostname1")

    def test_revert_obj_survives_backslash_originals(self):
        # the reason args are reverted per-VALUE: 'adatumlab\srv' inside a JSON
        # string would be an invalid escape if substituted into serialized JSON.
        args = {"query": "USER1", "nested": [{"value": "Hostname1"}], "n": 3}
        out = investigate._revert_obj(args, MASK)
        self.assertEqual(out["query"], "adatumlab\\srv")
        self.assertEqual(out["nested"][0]["value"], "ALDC02")
        self.assertEqual(out["n"], 3)


class LoopMaskingContract(unittest.TestCase):
    """Scripted _real_llm: the model asks for a pseudonym, the tool must get the
    real value, the convo must stay pseudonym-only, the answer comes back real."""

    def _run(self, script, mask=MASK, **kw):
        calls = {"sent": [], "tools": [], "sys": []}
        it = iter(script)

        def fake_llm(system, user, **_kw):
            calls["sys"].append(system)
            calls["sent"].append(user)
            return next(it)

        def fake_tool(case_id, name, args):
            calls["tools"].append((name, args))
            return [{"artifact": "X", "row": "event on ALDC02 by adatumlab\\srv"}]

        with _Patched(llm_sim, _real_llm=fake_llm), \
             _Patched(investigate, _tool=fake_tool,
                      _mask_for_case=lambda d, g, r: mask), \
             _Patched(investigate.store, get_case=lambda c: {"id": c},
                      load_graph=lambda c: schema.FusionGraph(case_id=c)):
            res = investigate.investigate("case_t", "what did ALDC02 do?", **kw)
        return res, calls

    def test_args_reverted_results_masked_answer_reverted(self):
        res, calls = self._run([
            '{"tool":"search","args":{"query":"Hostname1"}}',
            '{"final":"Hostname1 was accessed by USER1"}'])
        # tool executed with the REAL value
        self.assertEqual(calls["tools"], [("search", {"query": "ALDC02"})])
        # everything sent to the model is pseudonym-only (question + tool result)
        for sent in calls["sent"]:
            self.assertNotIn("ALDC02", sent)
            self.assertNotIn("adatumlab\\srv", sent)
        self.assertIn("Hostname1", calls["sent"][1])   # masked tool result fed back
        # the analyst reads real names
        self.assertEqual(res["answer"], "ALDC02 was accessed by adatumlab\\srv")
        self.assertEqual(res["steps"], [{"tool": "search", "args": {"query": "ALDC02"}}])
        self.assertFalse(res["truncated"])
        # identity legend prepended when masked
        self.assertTrue(calls["sys"][0].startswith(llm_sim._MASK_IDENTITY_LEGEND))

    def test_no_mask_passes_through(self):
        res, calls = self._run([
            '{"tool":"search","args":{"query":"ALDC02"}}',
            '{"final":"ALDC02 answer"}'], mask=None)
        self.assertEqual(calls["tools"], [("search", {"query": "ALDC02"})])
        self.assertIn("ALDC02", calls["sent"][0])      # question unmasked
        self.assertEqual(res["answer"], "ALDC02 answer")
        self.assertNotIn("IDENTITY KEY", calls["sys"][0])

    def test_step_budget_forces_reverted_final(self):
        res, calls = self._run(
            ['{"tool":"search","args":{"query":"Hostname1"}}'] * 3
            + ['{"final":"USER1 did it"}'], max_steps=3)
        self.assertTrue(res["truncated"])
        self.assertEqual(len(res["steps"]), 3)
        self.assertEqual(res["answer"], "adatumlab\\srv did it")

    def test_enable_pivot_false_hides_and_refuses_pivot(self):
        res, calls = self._run([
            '{"tool":"pivot","args":{"value":"Hostname1"}}',
            '{"final":"done"}'], enable_pivot=False)
        self.assertNotIn("pivot(", calls["sys"][0])    # tool not advertised
        self.assertEqual(calls["tools"], [])           # and never executed
        self.assertIn("unknown tool", calls["sent"][1])


class PivotTool(unittest.TestCase):
    def _graph(self, n_events=3, host="ALDC02", user="adatumlab\\srv"):
        g = schema.FusionGraph(case_id="case_t")
        aid = f"asset:{host}"
        g.entities[aid] = schema.Entity(id=aid, type="asset", label=host)
        for i in range(n_events):
            eid = f"event:{i}"
            g.entities[eid] = schema.Entity(
                id=eid, type="event", label=f"logon {i}",
                attrs={"ev_user": user, "ev_proc": "lsass.exe", "_assets": [aid]},
                first_seen=_ts(day=i))
        return g

    def _pivot(self, g, args):
        with _Patched(investigate.store, load_graph=lambda c: g):
            return investigate._tool("case_t", "pivot", args)

    def test_matches_account_and_host(self):
        g = self._graph(3)
        self.assertEqual(self._pivot(g, {"value": "adatumlab\\srv"})["total_matches"], 3)
        self.assertEqual(self._pivot(g, {"value": "ALDC02"})["total_matches"], 3)
        self.assertEqual(self._pivot(g, {"value": "nosuchthing"})["total_matches"], 0)

    def test_window_filters(self):
        g = self._graph(5)                     # events on days 0..4
        r = self._pivot(g, {"value": "lsass.exe",
                            "window": {"start": _ts(1), "end": _ts(3)}})
        self.assertEqual(r["total_matches"], 3)   # days 1,2,3

    def test_capped_at_15_but_reports_total(self):
        r = self._pivot(self._graph(20), {"value": "lsass.exe"})
        self.assertEqual(r["total_matches"], 20)
        self.assertEqual(r["shown"], 15)
        self.assertEqual(len(r["events"]), 15)

    def test_empty_value_errors(self):
        self.assertIn("error", self._pivot(self._graph(1), {}))


if __name__ == "__main__":
    unittest.main(verbosity=2)
