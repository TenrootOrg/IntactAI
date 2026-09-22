"""A case holds several reports — one per scope — and can go back to the full one.

QA TASK-12679 ("I entered a specific scope, how do I get back?"): "Analyze this
scope" wrote the phase window + "every other host excluded" onto the case and
re-fused, and since a case has ONE report slot the macro narrative was gone. The
scope machinery saves that whole state (window, hosts, report, fused graph) and
restores it, with no model call.
"""
import json
import os
import shutil
import sys
import tempfile
import types
import unittest
from unittest import mock

for _p in (os.path.dirname(os.path.abspath(__file__)),
           os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import store  # noqa: E402

CASE = "case_1"
MACRO_MD = "# Incident Case Report\n\nThe whole case, 14 months, 20 hosts.\n"
PHASE_MD = "# Incident Case Report\n\nOne week, one host.\n"
MACRO_WIN = {"start": "2025-06-01T00:00:00", "end": "2026-08-01T00:00:00"}
PHASE_WIN = {"start": "2026-06-16T00:00:00", "end": "2026-06-23T00:00:00"}


class ScopeCase(unittest.TestCase):
    """The case details live in a dict; get_case/_merge_case_details work on it, so
    everything below exercises the REAL scope code against real sidecar files."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.d = {"time_window": dict(MACRO_WIN), "excluded_hosts": ["DESKTOP-16OJFO6"],
                  "report_md": MACRO_MD, "report_written_at": "2026-09-20T11:26:04",
                  "report_config_id": "cfg-macro", "fused_run_ids": ["r1"],
                  "min_severity": "medium"}
        self.fused = []
        patches = [
            mock.patch.object(store, "_FUSION_GRAPH_DIR", self.tmp),
            mock.patch.object(store, "get_case", side_effect=lambda cid: dict(self.d)),
            mock.patch.object(store, "_merge_case_details",
                              side_effect=lambda cid, patch: self.d.update(patch)),
            mock.patch.object(store, "_mutate_list_field",
                              side_effect=lambda cid, f, m: self.d.update(
                                  {f: m(self.d.get(f) or [])})),
            mock.patch.object(store, "log_case_event"),
            mock.patch.object(store, "load_baseline", return_value=None),
            mock.patch.object(store, "_members_for_case", return_value=["r1"]),
            mock.patch.object(store, "_env_key_from_members", return_value=None),
            mock.patch.object(store, "stale_member_runs", return_value=[]),
            mock.patch.object(store, "fuse_case", side_effect=self._fuse),
        ]
        for p in patches:
            p.start(); self.addCleanup(p.stop)
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self._write_graph({"entities": {"a": {"type": "asset"}}, "findings": [], "relationships": []})

    def _fuse(self, case_id, force_report=False, trigger=None, allow_llm=True):
        self.fused.append((force_report, allow_llm))
        self._write_graph({"entities": {"rebuilt": {"type": "asset"}}, "findings": [],
                           "relationships": []})
        # rescan() reads counts off the returned graph
        return types.SimpleNamespace(entities={}, relationships=[], findings=[])

    def _write_graph(self, fg):
        os.makedirs(self.tmp, exist_ok=True)
        with open(store._graph_path(CASE), "w") as f:
            json.dump(fg, f)

    def _graph(self):
        with open(store._graph_path(CASE)) as f:
            return json.load(f)

    # ---- entering a scope keeps the macro state -----------------------------
    def _zoom(self):
        sid = store.enter_scope(CASE, "Phase 3 — Ransomware prep", PHASE_WIN)
        # what the zoom route's rescan does next:
        self.d.update({"time_window": dict(PHASE_WIN), "excluded_hosts": ["HOSTB", "HOSTC"],
                       "report_md": PHASE_MD, "report_config_id": "cfg-phase"})
        self._write_graph({"entities": {"phase": {"type": "asset"}}, "findings": [],
                           "relationships": []})
        return sid

    def test_zoom_saves_the_full_case_under_its_own_scope(self):
        self._zoom()
        full = next(s for s in self.d["report_scopes"] if s["id"] == "full")
        self.assertEqual(full["report_md"], MACRO_MD)
        self.assertEqual(full["window"], MACRO_WIN)
        self.assertEqual(full["excluded_hosts"], ["DESKTOP-16OJFO6"])
        self.assertTrue(full["cached"])
        self.assertTrue(os.path.exists(store._scope_path(CASE, "full")))
        self.assertEqual(self.d["active_scope"], store.scope_id_for_window(PHASE_WIN))

    def test_switching_back_restores_report_window_and_hosts(self):
        self._zoom()
        res = store.switch_scope(CASE, "full")
        self.assertEqual(self.d["report_md"], MACRO_MD)       # byte for byte
        self.assertEqual(self.d["time_window"], MACRO_WIN)
        self.assertEqual(self.d["excluded_hosts"], ["DESKTOP-16OJFO6"])
        self.assertEqual(self.d["report_config_id"], "cfg-macro")
        self.assertFalse(res["refused"], "an unchanged case must reuse the cached graph")
        self.assertEqual(self.fused, [], "no re-fusion, and never a model call")
        self.assertIn("a", self._graph()["entities"])         # the macro graph is back

    def test_the_scope_left_behind_keeps_its_own_report(self):
        sid = self._zoom()
        store.switch_scope(CASE, "full")
        store.switch_scope(CASE, sid)
        self.assertEqual(self.d["report_md"], PHASE_MD)
        self.assertEqual(self.d["time_window"], PHASE_WIN)
        self.assertIn("phase", self._graph()["entities"])

    def test_a_changed_case_rebuilds_the_graph_but_keeps_the_report(self):
        self._zoom()
        self.d["dispositions"] = [{"target": "f1", "verdict": "false_positive"}]
        res = store.switch_scope(CASE, "full")
        self.assertTrue(res["refused"])
        self.assertEqual(self.fused, [(False, False)],
                         "force_report=False, or a template would overwrite the saved "
                         "report; allow_llm=False, or navigating back would buy a "
                         "narration (or a checklist) the operator never asked for")
        self.assertEqual(self.d["report_md"], MACRO_MD)

    def test_new_data_invalidates_the_cache(self):
        self._zoom()
        with mock.patch.object(store, "stale_member_runs", return_value=["r2"]):
            self.assertTrue(store.switch_scope(CASE, "full")["refused"])

    def test_re_read_evidence_invalidates_the_cache(self):
        """Fetch re-reads a member run and re-fuses it with the SAME run ids and the
        same settings, so every other check agrees while the cache holds the rows
        from before the fetch. Only graph_built_at catches it."""
        self._zoom()
        self.d["graph_built_at"] = "2026-09-22T09:00:00"     # a fuse happened since
        self.assertTrue(store.switch_scope(CASE, "full")["refused"])

    def test_re_entering_the_same_timeframe_overwrites_that_scope(self):
        sid = self._zoom()
        store.switch_scope(CASE, "full")
        again = store.enter_scope(CASE, "Phase 3 — Ransomware prep", PHASE_WIN)
        self.assertEqual(again, sid)
        self.assertEqual(len([s for s in self.d["report_scopes"] if s["id"] == sid]), 1)

    def test_a_report_in_flight_blocks_the_switch(self):
        self._zoom()
        self.d["report_generating"] = True
        self.d["report_generating_started_at"] = store._now_iso()
        with self.assertRaises(store.ReportGenerationBusy):
            store.switch_scope(CASE, "full")
        self.assertEqual(self.d["report_md"], PHASE_MD, "nothing may change on a refusal")

    def test_unknown_scope_is_an_error_not_a_silent_no_op(self):
        self._zoom()
        with self.assertRaises(KeyError):
            store.switch_scope(CASE, "tf_nope")

    def test_eviction_bounds_the_disk_and_deletes_the_cache_file(self):
        self._zoom()
        for i in range(store.MAX_SCOPES + 3):
            win = {"start": f"2026-01-{i + 1:02d}T00:00:00", "end": f"2026-01-{i + 2:02d}T00:00:00"}
            store.enter_scope(CASE, f"Phase {i}", win)
            store.switch_scope(CASE, "full")
        self.assertLessEqual(len(self.d["report_scopes"]), store.MAX_SCOPES)
        ids = {s["id"] for s in self.d["report_scopes"]}
        self.assertIn("full", ids, "the way back is never evicted")
        for f in os.listdir(self.tmp):
            if f.startswith(f"{CASE}__"):
                self.assertIn(f[len(CASE) + 2:-5], ids, "an evicted scope left its graph behind")

    def test_deleting_the_case_removes_every_scope_cache(self):
        self._zoom()
        store._delete_graph_sidecar(CASE)
        self.assertEqual([f for f in os.listdir(self.tmp) if f.startswith(CASE)], [])

    def test_payload_carries_labels_not_markdown(self):
        self._zoom()
        rows = store.scopes_for_payload(self.d)
        self.assertEqual({r["id"] for r in rows}, set(s["id"] for s in self.d["report_scopes"]))
        self.assertTrue(any(r["active"] for r in rows))
        self.assertFalse(any("report_md" in r for r in rows))
        self.assertEqual([r["label"] for r in rows if r["id"] == "full"], ["Full case"])


class AHandPickedWindowIsItsOwnScope(ScopeCase):
    """QA's follow-up: "what happens when the user selects a different timeframe in
    Configuration? That isn't related to the macro." It used to overwrite whatever
    scope was on screen — silently destroying the macro report on the next switch."""

    CUSTOM = {"start": "2026-01-02T00:00:00", "end": "2026-01-09T00:00:00"}

    def _rescan(self, win, hosts=None):
        return store.rescan(CASE, {"time_window": dict(win),
                                   "excluded_hosts": hosts or []})

    def test_a_new_window_forks_a_scope_and_rescues_the_full_case(self):
        # A case that never zoomed has no scopes at all — the fork is what creates
        # "full", so the macro report is saved rather than overwritten.
        res = self._rescan(self.CUSTOM)
        ids = {s["id"]: s for s in self.d["report_scopes"]}
        self.assertIn("full", ids)
        self.assertEqual(ids["full"]["report_md"], MACRO_MD)
        self.assertEqual(ids["full"]["window"], MACRO_WIN)
        self.assertEqual(self.d["active_scope"], store.scope_id_for_window(self.CUSTOM))
        self.assertTrue(res["scope_label"].startswith("Custom 2026-01-02"))

    def test_the_same_window_again_edits_in_place(self):
        self._rescan(self.CUSTOM)
        n = len(self.d["report_scopes"])
        self.assertIsNone(self._rescan(self.CUSTOM)["scope_label"], "no second fork")
        self.assertEqual(len(self.d["report_scopes"]), n)

    def test_changing_only_the_hosts_does_not_fork(self):
        self.assertIsNone(self._rescan(MACRO_WIN, ["HOSTB"])["scope_label"],
                          "a host is an edit of the timeframe you are in")
        self.assertEqual(self.d.get("report_scopes"), None)

    def test_picking_an_existing_scopes_window_returns_to_it(self):
        self._rescan(self.CUSTOM)
        res = self._rescan(MACRO_WIN)                    # back to the full case's own window
        self.assertEqual(self.d["active_scope"], "full", res)
        self.assertEqual(self.d["report_md"], MACRO_MD)

    def test_the_zoom_path_does_not_fork_twice(self):
        store.enter_scope(CASE, "Phase 3", PHASE_WIN)
        n = len(self.d["report_scopes"])
        self.assertIsNone(self._rescan(PHASE_WIN)["scope_label"],
                          "the zoom already entered this scope")
        self.assertEqual(len(self.d["report_scopes"]), n)
        self.assertEqual(self.d["active_scope"], store.scope_id_for_window(PHASE_WIN))

    def test_a_verdict_marks_every_saved_report_behind(self):
        self._rescan(self.CUSTOM)
        store._report_behind(CASE)
        full = next(s for s in self.d["report_scopes"] if s["id"] == "full")
        self.assertTrue(full["report_dirty"], "the macro report predates the verdict too")


class TheChipsAreOnThePage(unittest.TestCase):
    PAGE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "modules/nginx/html/cases.html")

    def setUp(self):
        with open(self.PAGE) as f:
            self.html = f.read()

    def test_every_tab_renders_the_scope_row(self):
        # In the case HEADER, not inside renderReport: a zoomed case must say so on
        # Timeline, Risk, Identities and Chat too, and the way back must be there.
        hdr = self.html.split('<div id="statbar"')[1].split('<div class="tabs">')[0]
        self.assertIn("scopeChipsHtml(info)", hdr)
        self.assertNotIn("scopeChipsHtml", self.html.split("function renderReport(")[1]
                         .split("function ")[0])
        self.assertIn("scopePrefix(info)", self.html)
        self.assertIn("function switchScope(", self.html.replace("async function switchScope(",
                                                                 "function switchScope("))
        self.assertIn("/scope'", self.html)

    def test_the_config_rail_says_a_scope_owns_the_window(self):
        self.assertIn("scopeRailNote(info)", self.html)

    def test_the_zoom_sends_the_card_label_so_the_chip_is_readable(self):
        self.assertIn("label:(t.name?('Phase '+t.n+' — '+t.name):t.title)", self.html)


if __name__ == "__main__":
    unittest.main()
