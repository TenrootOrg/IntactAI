"""A scope is a LENS over one fused case, not a second copy of it.

The case is fused once and keeps one set of data — every event, identity, finding
and verdict. A scope is a saved time window: it shows, and sends to the model,
only what falls inside it. Nothing about a scope is fused, so switching one costs
a filter (measured: 1 ms against 36 s to re-fuse the same window) and stores
nothing but its own report and chat.

This pins the primitive that makes that true, including the two ways a naive
window filter destroys a graph: dropping the structural pivots that anchor every
edge, and dropping evidence a kept finding cites.
"""
import os
import sys
import unittest

for _p in (os.path.dirname(os.path.abspath(__file__)),
           os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from unittest import mock  # noqa: E402
from services.fusion import store, schema  # noqa: E402

WIN = {"start": "2026-06-14T00:00:00", "end": "2026-06-21T00:00:00"}
INSIDE, BEFORE, AFTER = "2026-06-16T10:00:00Z", "2025-01-02T10:00:00Z", "2026-09-01T10:00:00Z"


def _g():
    """One small case: two events in the window, one long before it, an account and
    an IOC that anchor them, and a finding citing an event whose own first_seen is
    outside the window."""
    g = schema.FusionGraph(case_id="c")
    for e in (
        schema.Entity(id="asset:a", type="asset", label="ALDC02"),
        schema.Entity(id="account:srv", type="account", label="ADATUMLAB\\srv",
                      first_seen=BEFORE, attrs={"_assets": ["asset:a"]}),
        schema.Entity(id="ioc:1.2.3.4", type="ioc", label="1.2.3.4", first_seen=BEFORE,
                      attrs={"_assets": ["asset:a"]}),
        schema.Entity(id="ev:in", type="event", label="in window", first_seen=INSIDE,
                      attrs={"_assets": ["asset:a"]}),
        schema.Entity(id="ev:out", type="event", label="out of window", first_seen=BEFORE,
                      last_seen=BEFORE, attrs={"_assets": ["asset:a"]}),
        schema.Entity(id="ev:cited", type="event", label="cited by an in-window finding",
                      first_seen=BEFORE, last_seen=BEFORE, attrs={"_assets": ["asset:a"]}),
        schema.Entity(id="ev:straddle", type="event", label="started before, ran into it",
                      first_seen=BEFORE, last_seen=INSIDE, attrs={"_assets": ["asset:a"]}),
        schema.Entity(id="ev:notime", type="event", label="no timestamp at all",
                      attrs={"_assets": ["asset:a"]}),
    ):
        g.upsert(e)
    for r in (schema.Relationship("account:srv", "ev:in", "ran"),
              schema.Relationship("account:srv", "ev:out", "ran"),
              schema.Relationship("ioc:1.2.3.4", "ev:in", "contacted")):
        g.relate(r)
    g.findings = [
        schema.Finding(id="f_in", title="in the window", severity="high", confidence="high",
                       summary="", entity_ids=["ev:in", "ev:cited"], asset_ids=["asset:a"],
                       ts=INSIDE),
        schema.Finding(id="f_out", title="outside it", severity="high", confidence="high",
                       summary="", entity_ids=["ev:out"], asset_ids=["asset:a"], ts=AFTER),
    ]
    g.rebuild_indexes()
    return g


class TheWindowFilter(unittest.TestCase):

    def setUp(self):
        self.g = _g()
        self.v = store._filter_graph_by_window(self.g, WIN)

    def test_the_findings_are_the_ones_in_the_window(self):
        self.assertEqual(["f_in"], [f.id for f in self.v.findings])

    def test_an_event_outside_the_window_is_dropped(self):
        self.assertNotIn("ev:out", self.v.entities)

    def test_the_structural_pivots_survive_or_the_graph_goes_edgeless(self):
        """Accounts, IOCs, assets and identities are never time-judged — the fuse
        exempts them for the same reason, and without them a scoped graph has no
        edges left to reason over."""
        for pivot in ("asset:a", "account:srv", "ioc:1.2.3.4"):
            self.assertIn(pivot, self.v.entities, pivot)

    def test_evidence_a_kept_finding_cites_is_kept(self):
        """f_in cites ev:cited, whose own time is outside. Dropping it would render
        a finding with its evidence missing."""
        self.assertIn("ev:cited", self.v.entities)

    def test_activity_that_straddles_the_window_is_kept(self):
        self.assertIn("ev:straddle", self.v.entities)

    def test_an_entity_with_no_timestamp_is_never_silently_dropped(self):
        self.assertIn("ev:notime", self.v.entities)

    def test_no_relationship_is_left_dangling(self):
        ids = set(self.v.entities)
        for r in self.v.relationships:
            self.assertIn(r.src, ids)
            self.assertIn(r.dst, ids)

    def test_the_edge_to_a_dropped_event_goes_with_it(self):
        self.assertNotIn(("account:srv", "ev:out"), [(r.src, r.dst) for r in self.v.relationships])

    def test_no_window_is_the_whole_case(self):
        self.assertIs(self.g, store._filter_graph_by_window(self.g, None))

    def test_the_case_graph_is_untouched(self):
        """A lens, not a copy: filtering must never mutate what the case holds."""
        self.assertEqual(8, len(self.g.entities))
        self.assertEqual(2, len(self.g.findings))
        self.assertEqual(3, len(self.g.relationships))


CASE = "case_scope_1"
MACRO_MD = "# the whole case\n"
PHASE_WIN = {"start": "2026-06-14T00:00:00", "end": "2026-06-21T00:00:00"}
OTHER_WIN = {"start": "2015-01-01T00:00:00", "end": "2018-01-01T00:00:00"}


class ScopesAreLensesNotCopies(unittest.TestCase):
    """The case is fused once. Creating, switching and deleting a scope must never
    fuse, never call the model, and never touch the evidence."""

    def setUp(self):
        self.d = {"name": "QA", "report_md": MACRO_MD, "report_written_at": "2026-09-22T09:00:00",
                  "chat_messages": [{"role": "user", "content": "who is srv?"}],
                  "dispositions": [{"target": "f_in", "verdict": "false_positive"}],
                  "timeline_validations": [{"finding_id": "f_in", "status": "true_positive"}],
                  "fused_at": "2026-09-22T09:00:00"}
        patches = [
            mock.patch.object(store, "get_case", side_effect=lambda cid: dict(self.d)),
            mock.patch.object(store, "_merge_case_details",
                              side_effect=lambda cid, patch: self.d.update(patch)),
            mock.patch.object(store, "_mutate_list_field",
                              side_effect=lambda cid, f, m: self.d.update({f: m(self.d.get(f) or [])})),
            mock.patch.object(store, "log_case_event"),
            mock.patch.object(store, "fuse_case", side_effect=AssertionError("a scope must never fuse")),
            mock.patch.object(store, "load_graph", return_value=_g()),
        ]
        for p in patches:
            p.start(); self.addCleanup(p.stop)

    def test_creating_a_scope_keeps_the_full_case_report(self):
        store.create_scope(CASE, "Phase 2", PHASE_WIN)
        full = next(s for s in self.d["scopes"] if s["id"] == "full")
        self.assertEqual(MACRO_MD, full["report_md"])
        self.assertEqual(store.scope_id_for_window(PHASE_WIN), self.d["active_scope"])
        self.assertEqual("", self.d["report_md"], "a new window opens with no report")
        self.assertEqual([], self.d["chat_messages"], "and its own empty conversation")

    def test_switching_back_restores_the_report_and_the_chat(self):
        store.create_scope(CASE, "Phase 2", PHASE_WIN)
        self.d["report_md"] = "# phase 2 report\n"          # as a generation would
        self.d["chat_messages"] = [{"role": "user", "content": "what happened here?"}]
        store.switch_scope(CASE, "full")
        self.assertEqual(MACRO_MD, self.d["report_md"])
        self.assertEqual("who is srv?", self.d["chat_messages"][0]["content"])
        store.switch_scope(CASE, store.scope_id_for_window(PHASE_WIN))
        self.assertEqual("# phase 2 report\n", self.d["report_md"])
        self.assertEqual("what happened here?", self.d["chat_messages"][0]["content"])

    def test_the_evidence_and_the_verdicts_are_the_cases_not_the_scopes(self):
        """The operator's rule: one set of data for the whole case, and each scope
        shows the part of it in its window."""
        store.create_scope(CASE, "Phase 2", PHASE_WIN)
        store.switch_scope(CASE, "full")
        self.assertEqual([{"target": "f_in", "verdict": "false_positive"}], self.d["dispositions"])
        self.assertEqual([{"finding_id": "f_in", "status": "true_positive"}],
                         self.d["timeline_validations"])

    def test_the_selected_window_is_what_every_view_narrows_to(self):
        store.create_scope(CASE, "Phase 2", PHASE_WIN)
        self.assertEqual(PHASE_WIN, store.active_scope_window(self.d))
        self.assertEqual(["f_in"], [f.id for f in store.view_graph(CASE, self.d).findings])
        store.switch_scope(CASE, "full")
        self.assertIsNone(store.active_scope_window(self.d))
        self.assertEqual(2, len(store.view_graph(CASE, self.d).findings), "the whole case")

    def test_the_same_window_twice_is_one_scope(self):
        a = store.create_scope(CASE, "Phase 2", PHASE_WIN)
        store.switch_scope(CASE, "full")
        b = store.create_scope(CASE, "Phase 2 again", PHASE_WIN)
        self.assertEqual(a, b)
        self.assertEqual(1, len([s for s in self.d["scopes"] if s["id"] == a]))

    def test_deleting_a_scope_destroys_no_evidence(self):
        sid = store.create_scope(CASE, "Phase 2", PHASE_WIN)
        store.delete_scope(CASE, sid)
        self.assertNotIn(sid, [s["id"] for s in self.d["scopes"]])
        self.assertEqual("full", self.d["active_scope"], "and leaves you somewhere real")
        self.assertEqual(MACRO_MD, self.d["report_md"])
        self.assertEqual(2, len(store.view_graph(CASE, self.d).findings))

    def test_the_full_case_cannot_be_deleted(self):
        with self.assertRaises(ValueError):
            store.delete_scope(CASE, "full")

    def test_a_scope_needs_a_start_date(self):
        with self.assertRaises(ValueError):
            store.create_scope(CASE, "nope", {"end": "2026-01-01T00:00:00"})

    def test_the_dropdown_lists_the_full_case_first_and_no_markdown(self):
        store.create_scope(CASE, "Phase 2", PHASE_WIN)
        store.create_scope(CASE, "2015-2018", OTHER_WIN)
        rows = store.scopes_for_payload(self.d)
        self.assertEqual("full", rows[0]["id"])
        self.assertTrue(any(r["active"] for r in rows))
        self.assertFalse(any("report_md" in r or "chat_messages" in r for r in rows))


class WhatTheOperatorReadsBack(unittest.TestCase):
    """The names, the log stamps and the report's home — the four things QA found
    wrong on the first live run."""

    def setUp(self):
        self.d = {"name": "QA", "report_md": "# whole case\n", "chat_messages": [],
                  "time_window": {"start": "2016-09-22T10:00:23", "end": "2026-09-22T10:00:23"},
                  "fused_at": "t0"}
        patches = [
            mock.patch.object(store, "get_case", side_effect=lambda cid: dict(self.d)),
            mock.patch.object(store, "_merge_case_details",
                              side_effect=lambda cid, patch: self.d.update(patch)),
            mock.patch.object(store, "_mutate_list_field",
                              side_effect=lambda cid, f, m: self.d.update({f: m(self.d.get(f) or [])})),
            mock.patch.object(store, "log_case_event"),
            mock.patch.object(store, "load_graph", return_value=_g()),
            mock.patch.object(store, "fuse_case", side_effect=AssertionError("must not fuse")),
        ]
        for p in patches:
            p.start(); self.addCleanup(p.stop)

    def test_a_scope_is_named_by_its_timeframe_to_the_second(self):
        """Two phases of the same day are different timeframes, so the name cannot
        stop at the date."""
        store.create_scope(CASE, None, {"start": "2026-06-14T09:39:49",
                                        "end": "2026-06-21T14:35:13"})
        labels = [r["label"] for r in store.scopes_for_payload(self.d)]
        self.assertIn("2026-06-14 09:39:49 → 2026-06-21 14:35:13", labels)
        self.assertFalse(any("Phase" in l for l in labels))

    def test_there_is_no_full_case_entry_only_the_whole_timeframe(self):
        """No parent sitting above the others: the default entry is named by the
        case's own dates, like every other entry in the list."""
        store.create_scope(CASE, None, PHASE_WIN)
        rows = store.scopes_for_payload(self.d)
        full = next(r for r in rows if r["id"] == "full")
        self.assertEqual("2016-09-22 10:00:23 → 2026-09-22 10:00:23", full["label"])
        self.assertFalse(any(r["label"] == "Full case" for r in rows))

    def test_the_whole_timeframe_relabels_when_the_case_window_changes(self):
        self.d["time_window"] = {"start": "2015-01-01T00:00:00", "end": "2018-01-01T00:00:00"}
        rows = store.scopes_for_payload(self.d)
        self.assertEqual("2015-01-01 00:00:00 → 2018-01-01 00:00:00", rows[0]["label"])

    def test_a_report_lands_in_the_scope_it_was_generated_for(self):
        """It runs for minutes and the operator is free to read elsewhere: the
        narrative must not follow the view."""
        sid = store.create_scope(CASE, None, PHASE_WIN)
        store.switch_scope(CASE, "full")                 # walked away mid-generation
        on_screen = store.write_report_for_scope(CASE, sid, {"report_md": "# june\n",
                                                             "report_dirty": False})
        self.assertFalse(on_screen, "and the caller is told it is not on screen")
        self.assertEqual("# whole case\n", self.d["report_md"], "the view is untouched")
        entry = next(s for s in self.d["scopes"] if s["id"] == sid)
        self.assertEqual("# june\n", entry["report_md"], "it is saved where it belongs")
        store.switch_scope(CASE, sid)
        self.assertEqual("# june\n", self.d["report_md"], "and is there when you go back")

    def test_a_report_in_flight_no_longer_blocks_reading_another_timeframe(self):
        sid = store.create_scope(CASE, None, PHASE_WIN)
        self.d["report_generating"] = True
        self.d["report_generating_started_at"] = store._now_iso()
        store.switch_scope(CASE, "full")                 # must not raise
        self.assertEqual("full", self.d["active_scope"])

    def test_the_log_stamps_scope_work_and_leaves_case_work_alone(self):
        for act in ("Report saved", "Chat · sending to LLM", "Checklist · complete"):
            self.assertTrue(store._SCOPE_STAMPED_ACTIONS.match(act), act)
        for act in ("Refusion · starting", "Config · Time window", "Scope · switched to X",
                    "New data landed", "Configuration saved"):
            self.assertIsNone(store._SCOPE_STAMPED_ACTIONS.match(act), act)


class HostsInATimeframe(unittest.TestCase):
    """Hosts are structural, so the window filter keeps every one of them. Counting
    asset nodes made every scope report every host in the case — a window that
    touched 7 machines read "9 hosts", measured live."""

    def test_a_host_with_nothing_in_the_window_is_not_in_the_scope(self):
        """Risk listed every host in the case for every scope, with "no findings in
        window" against the ones the timeframe never touched."""
        g = _g()
        g.upsert(schema.Entity(id="asset:b", type="asset", label="QUIET-HOST"))
        v = store._filter_graph_by_window(g, WIN)
        self.assertNotIn("asset:b", v.entities)
        self.assertIn("asset:a", v.entities, "the host the window's evidence ran on stays")
        self.assertEqual(1, store._counts_from_graph(v)["hosts"], "and the header agrees")

    def test_a_host_excluded_in_configuration_cannot_leak_back(self):
        """A surviving entity's _assets may still name an excluded host."""
        g = _g()
        g.entities["ev:in"].attrs["_assets"] = ["asset:a", "asset:gone"]
        self.assertEqual(1, store._active_hosts(g), "asset:gone is no longer a node")


class OnlyThePeopleAndPivotsTheWindowReaches(unittest.TestCase):
    """Identities showed all 19 people of the case in a two-week scope, because the
    filter kept every account. 162 accounts, of which 2 were linked to anything in
    the window — measured live."""

    def _g2(self):
        g = _g()
        for e in (schema.Entity(id="account:ghost", type="account", label="adatumlab\\ghost",
                                first_seen=BEFORE, attrs={"_assets": ["asset:a"]}),
                  schema.Entity(id="account:almogs", type="account", label="adatumlab\\almogs",
                                first_seen=BEFORE, attrs={"_assets": ["asset:a"]}),
                  schema.Entity(id="ioc:old", type="ioc", label="9.9.9.9", first_seen=BEFORE)):
            g.upsert(e)
        # AlmogS is named ONLY as an event's user — no link to him at all.
        g.entities["ev:in"].attrs["ev_user"] = "ADATUMLAB\\AlmogS"
        g.rebuild_indexes()
        return g

    def test_an_account_nothing_in_the_window_touches_is_not_in_the_scope(self):
        v = store._filter_graph_by_window(self._g2(), WIN)
        self.assertNotIn("account:ghost", v.entities)

    def test_a_user_named_only_by_an_event_attribute_is_kept(self):
        """The Timeline names him; Identities must not drop him."""
        v = store._filter_graph_by_window(self._g2(), WIN)
        self.assertIn("account:almogs", v.entities)

    def test_an_indicator_nothing_in_the_window_touches_is_dropped(self):
        v = store._filter_graph_by_window(self._g2(), WIN)
        self.assertNotIn("ioc:old", v.entities)
        self.assertIn("ioc:1.2.3.4", v.entities, "the one an in-window event contacted stays")

    def test_a_user_named_only_by_a_profile_folder_is_kept(self):
        """On Windows the profile folder in a path is often the ONLY place an
        account is named — a file on C:\\Users\\adim_std\\Desktop has no user
        field. Live: one of the three people a window named appeared only there."""
        g = self._g2()
        g.upsert(schema.Entity(id="account:adim", type="account", label="adatumlab\\adim_std",
                               first_seen=BEFORE, attrs={"_assets": ["asset:a"]}))
        g.entities["ev:in"].attrs["path"] = "C:\\Users\\adim_std\\Desktop\\tool.exe"
        g.rebuild_indexes()
        self.assertIn("account:adim", store._filter_graph_by_window(g, WIN).entities)

    def test_shared_profile_folders_name_nobody(self):
        g = self._g2()
        g.upsert(schema.Entity(id="account:public", type="account", label="public",
                               first_seen=BEFORE))
        g.entities["ev:in"].attrs["path"] = "C:\\Users\\Public\\Downloads\\x.exe"
        g.rebuild_indexes()
        self.assertNotIn("account:public", store._filter_graph_by_window(g, WIN).entities)

    def test_the_whole_case_is_untouched(self):
        g = self._g2()
        self.assertIs(g, store._filter_graph_by_window(g, None))
        self.assertIn("account:ghost", g.entities)


class RefusionAndTimeframes(unittest.TestCase):
    """The operator's rule: Refusion with the timeframe already on screen just
    applies the other edits; Refusion with a different one reads that timeframe."""

    def setUp(self):
        self.d = {"name": "QA", "report_md": "# whole case\n", "chat_messages": [],
                  "time_window": {"start": "2016-09-22T10:00:23", "end": "2026-09-22T10:00:23"}}
        patches = [
            mock.patch.object(store, "get_case", side_effect=lambda cid: dict(self.d)),
            mock.patch.object(store, "_merge_case_details",
                              side_effect=lambda cid, patch: self.d.update(patch)),
            mock.patch.object(store, "_mutate_list_field",
                              side_effect=lambda cid, f, m: self.d.update({f: m(self.d.get(f) or [])})),
            mock.patch.object(store, "log_case_event"),
            mock.patch.object(store, "load_graph", return_value=_g()),
        ]
        for p in patches:
            p.start(); self.addCleanup(p.stop)

    def test_the_same_timeframe_makes_no_new_scope(self):
        cfg, win = store._scope_from_rescan(CASE, {"time_window": dict(self.d["time_window"]),
                                                   "excluded_hosts": ["HOSTB"]})
        self.assertIsNone(win, "nothing new to read — just apply the other edits")
        self.assertEqual({"excluded_hosts": ["HOSTB"]}, cfg)

    def test_a_different_timeframe_becomes_a_scope(self):
        cfg, win = store._scope_from_rescan(CASE, {"time_window": PHASE_WIN})
        self.assertEqual(PHASE_WIN, win)

    def test_the_window_never_narrows_what_the_case_fuses(self):
        """If it did, reading one week would empty every other scope — the case
        would silently lose the rest of itself."""
        cfg, _ = store._scope_from_rescan(CASE, {"time_window": PHASE_WIN,
                                                 "min_severity": "high"})
        self.assertNotIn("time_window", cfg)
        self.assertEqual({"min_severity": "high"}, cfg)

    def test_the_timeframe_is_compared_against_the_scope_on_screen(self):
        store.create_scope(CASE, None, PHASE_WIN)
        _, win = store._scope_from_rescan(CASE, {"time_window": dict(PHASE_WIN)})
        self.assertIsNone(win, "already reading it")
        _, win2 = store._scope_from_rescan(CASE, {"time_window": OTHER_WIN})
        self.assertEqual(OTHER_WIN, win2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
