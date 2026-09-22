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
import types
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

    def test_a_name_matches_only_the_account_on_the_machine_it_was_named_on(self):
        """Live: "srv" came back with 5 accounts in a scope that named it on one
        host, including one on a machine the window never reached."""
        g = self._g2()
        g.upsert(schema.Entity(id="asset:far", type="asset", label="FAR-HOST"))
        g.upsert(schema.Entity(id="account:almogs_far", type="account", label="almogs",
                               first_seen=BEFORE, attrs={"_assets": ["asset:far"]}))
        g.rebuild_indexes()
        v = store._filter_graph_by_window(g, WIN)
        self.assertIn("account:almogs", v.entities, "the one on the host that named him")
        self.assertNotIn("account:almogs_far", v.entities,
                         "a same-name account elsewhere is somebody else's evidence")

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


class TheLogAndTheBannerDescribeTheRightScope(unittest.TestCase):
    """Both found in one live run: new data landed while the operator switched
    between the whole case and a two-week scope."""

    def setUp(self):
        self.d = {"name": "QA", "report_md": "# r\n", "chat_messages": [],
                  "time_window": {"start": "2016-09-22T11:08:10", "end": "2026-09-22T11:08:10"},
                  "activity_log": []}
        self.logged = []
        def _mutate(cid, f, m):
            self.d.update({f: m(self.d.get(f) or [])})
        patches = [
            mock.patch.object(store, "get_case", side_effect=lambda cid: dict(self.d)),
            mock.patch.object(store, "_merge_case_details",
                              side_effect=lambda cid, patch: self.d.update(patch)),
            mock.patch.object(store, "_mutate_list_field", side_effect=_mutate),
            mock.patch.object(store, "load_graph", return_value=_g()),
        ]
        for p in patches:
            p.start(); self.addCleanup(p.stop)
        # capture what log_case_event would append, through the real function
        ws = mock.Mock()
        ws.mutate_run_details.side_effect = lambda cid, fn: (fn(self.d), True)[1]
        p = mock.patch.object(store, "_ws", return_value=ws); p.start(); self.addCleanup(p.stop)
        store.log_case_event.__wrapped__ if hasattr(store.log_case_event, "__wrapped__") else None
        self.sid = None
        with mock.patch.object(store, "log_case_event"):
            self.sid = store.create_scope(CASE, None, PHASE_WIN)
        store._GEN_SCOPE.pop(CASE, None)
        self.addCleanup(store._GEN_SCOPE.pop, CASE, None)

    def _last(self):
        return (self.d.get("activity_log") or [{}])[-1].get("action", "")

    def test_a_report_run_stamps_its_own_scope_not_the_one_on_screen(self):
        """Live: a whole-case run's "phase 3 of 6 — answered" was stamped with the
        two-week window the operator had switched to meanwhile."""
        store._GEN_SCOPE[CASE] = "full"              # the run belongs to the whole case
        self.d["active_scope"] = self.sid            # ...the operator reads the phase
        store.log_case_event(CASE, "Report · phase 3 of 6 — answered", "info", "")
        self.assertIn("2016-09-22 11:08:10 → 2026-09-22 11:08:10", self._last())
        self.assertNotIn("2026-06-14", self._last())

    def test_the_whole_case_is_stamped_once_a_case_has_scopes(self):
        self.d["active_scope"] = "full"
        store.log_case_event(CASE, "Report saved", "success", "")
        self.assertIn("· 2016-09-22 11:08:10 → 2026-09-22 11:08:10", self._last())

    def test_a_chat_turn_uses_the_scope_on_screen(self):
        store._GEN_SCOPE[CASE] = "full"              # a report runs for the whole case
        self.d["active_scope"] = self.sid            # while the operator chats here
        store.log_case_event(CASE, "Chat · sending to LLM", "info", "")
        self.assertIn("2026-06-14", self._last())

    def test_case_work_stays_unstamped(self):
        store.log_case_event(CASE, "Refusion · starting", "info", "")
        self.assertNotIn(" · 20", self._last())


class ABannerOnlyWhenTheScopeMoved(unittest.TestCase):
    """Live: a new host's 21 findings all fell outside a two-week scope, its
    counts did not move, and it still said "New data has landed … click Regenerate
    report" — asking for a model run that would reproduce the same text."""

    def _behind(self, d, now):
        with mock.patch.object(store, "report_stale_runs", return_value=["new_run"]), \
             mock.patch.object(store, "scope_counts", return_value=now):
            return store.report_behind_runs(CASE, d)

    def test_data_outside_the_window_does_not_flag_the_scope(self):
        d = {"active_scope": "w1", "scopes": [{"id": "w1", "window": PHASE_WIN}],
             "report_counts": {"findings": 10, "entities": 122, "links": 69}}
        self.assertEqual([], self._behind(d, {"findings": 10, "entities": 122, "links": 69}))

    def test_data_inside_the_window_does(self):
        d = {"active_scope": "w1", "scopes": [{"id": "w1", "window": PHASE_WIN}],
             "report_counts": {"findings": 10, "entities": 122, "links": 69}}
        self.assertEqual(["new_run"], self._behind(d, {"findings": 12, "entities": 140, "links": 71}))

    def test_the_whole_case_keeps_the_run_based_answer(self):
        """New data in the case IS new data for the whole-case report."""
        self.assertEqual(["new_run"], self._behind({"report_counts": {"findings": 1}}, {"findings": 1}))

    def test_a_report_that_recorded_nothing_keeps_the_run_based_answer(self):
        d = {"active_scope": "w1", "scopes": [{"id": "w1", "window": PHASE_WIN}]}
        self.assertEqual(["new_run"], self._behind(d, {"findings": 10}))


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
        cfg, win, _ = store._scope_from_rescan(CASE, {"time_window": dict(self.d["time_window"]),
                                                      "excluded_hosts": ["HOSTB"]})
        self.assertIsNone(win, "nothing new to read — just apply the other edits")
        self.assertEqual({"excluded_hosts": ["HOSTB"]}, cfg)

    def test_a_different_timeframe_becomes_a_scope(self):
        cfg, win, _ = store._scope_from_rescan(CASE, {"time_window": PHASE_WIN})
        self.assertEqual(PHASE_WIN, win)

    def test_the_window_never_narrows_what_the_case_fuses(self):
        """If it did, reading one week would empty every other scope — the case
        would silently lose the rest of itself."""
        cfg, _, _ = store._scope_from_rescan(CASE, {"time_window": PHASE_WIN,
                                                    "min_severity": "high"})
        self.assertNotIn("time_window", cfg)
        self.assertEqual({"min_severity": "high"}, cfg)

    def test_the_timeframe_is_compared_against_the_scope_on_screen(self):
        store.create_scope(CASE, None, PHASE_WIN)
        _, win, _ = store._scope_from_rescan(CASE, {"time_window": dict(PHASE_WIN)})
        self.assertIsNone(win, "already reading it")
        # a different window INSIDE the case (one past its bound grows the case
        # instead — AWindowPastTheCaseGrowsTheCase)
        inside = {"start": "2020-01-01T00:00:00", "end": "2021-01-01T00:00:00"}
        _, win2, _ = store._scope_from_rescan(CASE, {"time_window": inside})
        self.assertEqual(inside, win2)


class AWindowPastTheCaseGrowsTheCase(unittest.TestCase):
    """Live: scopes starting 2016-09-01 and 2011-06-01 on a case bounded at
    2016-09-22 showed exactly the whole case's data — nothing older was ever fused —
    and each bought a full six-phase report of the same 151 findings."""

    BOUND = {"start": "2016-09-22T11:08:10", "end": "2026-09-22T11:08:10"}

    def test_reaching_past_the_start_grows_the_case_instead_of_making_a_scope(self):
        with mock.patch.object(store, "get_case", return_value={"time_window": dict(self.BOUND)}):
            cfg, win, grew = store._scope_from_rescan(CASE, {"time_window": {
                "start": "2011-06-01T11:08:00", "end": "2026-09-22T11:08:10"}})
        self.assertTrue(grew)
        self.assertIsNone(win, "a window past the case is not a scope")
        self.assertEqual({"start": "2011-06-01T11:08:00", "end": "2026-09-22T11:08:10"},
                         cfg["time_window"], "the fuse bound widens to cover it")

    def test_an_open_end_reaches_past_a_fixed_one(self):
        self.assertTrue(store._reaches_outside({"start": "2020-01-01T00:00:00", "end": None},
                                               self.BOUND))

    def test_a_window_inside_the_case_is_still_a_scope(self):
        with mock.patch.object(store, "get_case", return_value={"time_window": dict(self.BOUND)}):
            cfg, win, grew = store._scope_from_rescan(CASE, {"time_window": PHASE_WIN})
        self.assertFalse(grew)
        self.assertEqual(PHASE_WIN, win)
        self.assertNotIn("time_window", cfg, "a scope never narrows what the case fuses")

    def test_the_union_takes_the_earlier_start_and_the_later_or_open_end(self):
        self.assertEqual({"start": "2011-06-01T00:00:00", "end": "2026-09-22T11:08:10"},
                         store._union_window(self.BOUND, {"start": "2011-06-01T00:00:00",
                                                          "end": "2020-01-01T00:00:00"}))
        self.assertIsNone(store._union_window(self.BOUND, {"start": "2011-06-01T00:00:00",
                                                           "end": None})["end"])

    def test_growing_keeps_every_narrower_scope(self):
        """The argument-order slip that would have deleted them all."""
        d = {"time_window": dict(self.BOUND), "active_scope": "full",
             "scopes": [{"id": "full"},
                        {"id": store.scope_id_for_window(PHASE_WIN), "window": PHASE_WIN,
                         "report_md": "# phase\n"}]}
        with mock.patch.object(store, "get_case", side_effect=lambda cid: dict(d)), \
             mock.patch.object(store, "_merge_case_details", side_effect=lambda c, p: d.update(p)), \
             mock.patch.object(store, "_mutate_list_field",
                               side_effect=lambda c, f, m: d.update({f: m(d.get(f) or [])})), \
             mock.patch.object(store, "log_case_event"), \
             mock.patch.object(store, "fuse_case", return_value=types.SimpleNamespace(
                 entities={}, relationships=[], findings=[])):
            store.rescan(CASE, {"time_window": {"start": "2011-06-01T00:00:00",
                                                "end": "2026-09-22T11:08:10"}})
        ids = [x["id"] for x in d["scopes"]]
        self.assertIn(store.scope_id_for_window(PHASE_WIN), ids,
                      "a narrower scope is still a scope, report and all")
        self.assertEqual({"start": "2011-06-01T00:00:00", "end": "2026-09-22T11:08:10"},
                         d["time_window"], "and the case now covers the wider window")


class EachTimeframeHasItsOwnHosts(unittest.TestCase):
    """Hiding a host in one timeframe hides it there only. Excluding ALCA01 in
    Configuration moved every scope's [N hosts] — the operator asked for each
    timeframe to keep its own list."""

    def setUp(self):
        self.d = {"name": "QA", "report_md": MACRO_MD, "fused_at": "2026-09-22T09:00:00"}
        g = _g()
        g.upsert(schema.Entity(id="asset:b", type="asset", label="ALCA01"))
        g.upsert(schema.Entity(id="ev:b", type="event", label="on ALCA01", first_seen=INSIDE,
                               attrs={"_assets": ["asset:b"]}))
        g.rebuild_indexes()
        patches = [
            mock.patch.object(store, "get_case", side_effect=lambda cid: dict(self.d)),
            mock.patch.object(store, "_merge_case_details",
                              side_effect=lambda cid, patch: self.d.update(patch)),
            mock.patch.object(store, "_mutate_list_field",
                              side_effect=lambda cid, f, m: self.d.update({f: m(self.d.get(f) or [])})),
            mock.patch.object(store, "log_case_event"),
            mock.patch.object(store, "fuse_case", side_effect=AssertionError("hiding must not fuse")),
            mock.patch.object(store, "load_graph", side_effect=lambda cid: g),
        ]
        for p in patches:
            p.start(); self.addCleanup(p.stop)

    def _hosts(self):
        return store.scope_host_counts(CASE, self.d)

    def test_hiding_moves_only_the_selected_scope(self):
        before = store.create_scope(CASE, None, {"start": "2025-01-01T00:00:00",
                                                 "end": "2025-01-05T00:00:00"})
        here = store.create_scope(CASE, None, WIN)
        self.assertEqual(2, self._hosts()[here])
        was = self._hosts()[before]
        store.set_scope_hidden_hosts(CASE, ["ALCA01"])
        counts = self._hosts()
        self.assertEqual(1, counts[here], "the scope it was hidden in drops it")
        self.assertEqual(was, counts[before], "another timeframe is untouched")
        self.assertEqual(2, counts["full"], "the whole case keeps it")
        self.assertNotIn("asset:b", store.view_graph(CASE, self.d).entities)
        self.assertNotIn("ALCA01", self.d.get("excluded_hosts") or [], "never case-wide")

    def test_the_list_survives_switching_away_and_back(self):
        sid = store.create_scope(CASE, None, WIN)
        store.set_scope_hidden_hosts(CASE, ["ALCA01"])
        store.switch_scope(CASE, "full")
        self.assertIn("asset:b", store.view_graph(CASE, self.d).entities)
        store.switch_scope(CASE, sid)
        self.assertEqual(["ALCA01"], store.active_scope_hidden_hosts(self.d))
        self.assertNotIn("asset:b", store.view_graph(CASE, self.d).entities)

    def test_configuration_hosts_are_the_timeframe_on_screen(self):
        """Live: unticking a host in Configuration while reading 2016-09-01 moved
        the whole case and every other timeframe from 10 hosts to 9."""
        here = store.create_scope(CASE, None, WIN)
        store.set_analysis_config(CASE, {"scope_hidden_hosts": ["ALCA01"], "excluded_hosts": []})
        self.assertEqual(["ALCA01"], store.active_scope_hidden_hosts(self.d))
        self.assertEqual([], self.d.get("excluded_hosts"), "nothing case-wide")
        counts = self._hosts()
        self.assertEqual(1, counts[here])
        self.assertEqual(2, counts["full"], "the whole case is untouched")

    def test_saving_the_same_list_again_is_not_a_change(self):
        store.set_scope_hidden_hosts(CASE, ["ALCA01"])
        with mock.patch.object(store, "log_case_event") as log:
            store.set_scope_hidden_hosts(CASE, ["ALCA01"])
        log.assert_not_called()

    def test_the_whole_case_can_hide_a_host_too(self):
        store.set_scope_hidden_hosts(CASE, ["ALCA01"])
        self.assertEqual(1, store.scope_counts(CASE, self.d)["hosts"])
        self.assertEqual(1, self._hosts()["full"])


class GrowingLosesNoTimeframe(unittest.TestCase):
    """Live on test1: on a leftover 2011 scope (older than the 2016 case), the
    operator unticked a module and pressed Refusion. The untouched 2011 dates grew
    the case, the 2011 scope was dropped as a duplicate, and the 2016 whole case —
    timeframe and 51,852-char report — was gone."""

    BOUND = {"start": "2016-06-02T11:08:00", "end": "2026-09-22T11:08:10"}
    OLD = {"start": "2011-06-01T11:08:00", "end": "2026-09-22T11:08:10"}

    def setUp(self):
        self.d = {"time_window": dict(self.BOUND), "active_scope": "full",
                  "report_md": "# 2016 whole case\n", "chat_messages": [{"role": "user"}],
                  "scopes": [{"id": "full", "report_md": "# 2016 whole case\n"},
                             {"id": store.scope_id_for_window(self.OLD), "window": dict(self.OLD),
                              "report_md": "# 2011\n", "chat_messages": []}]}
        d = self.d
        patches = [
            mock.patch.object(store, "get_case", side_effect=lambda cid: dict(d)),
            mock.patch.object(store, "_merge_case_details", side_effect=lambda c, p: d.update(p)),
            mock.patch.object(store, "_mutate_list_field",
                              side_effect=lambda c, f, m: d.update({f: m(d.get(f) or [])})),
            mock.patch.object(store, "log_case_event"),
            mock.patch.object(store, "load_graph", return_value=_g()),
            mock.patch.object(store, "modules_with_runs", return_value=[]),
            mock.patch.object(store, "fuse_case", return_value=types.SimpleNamespace(
                entities={}, relationships=[], findings=[])),
        ]
        for p in patches:
            p.start(); self.addCleanup(p.stop)

    def _ids(self):
        return {x["id"]: x for x in self.d["scopes"]}

    def test_the_dates_on_screen_untouched_never_grow_the_case(self):
        store.switch_scope(CASE, store.scope_id_for_window(self.OLD))
        cfg, win, grew = store._scope_from_rescan(CASE, {"time_window": dict(self.OLD),
                                                         "min_severity": "high"})
        self.assertFalse(grew)
        self.assertIsNone(win)
        self.assertEqual({"min_severity": "high"}, cfg, "only the other edits apply")

    def test_growing_keeps_the_old_whole_case_as_a_scope_with_its_report(self):
        store.rescan(CASE, {"time_window": {"start": "2010-01-01T00:00:00",
                                            "end": "2026-09-22T11:08:10"}})
        old = self._ids()[store.scope_id_for_window(self.BOUND)]
        self.assertEqual("# 2016 whole case\n", old["report_md"])
        self.assertEqual(self.BOUND, old["window"])
        self.assertIn(store.scope_id_for_window(self.OLD), self._ids(), "2011 is narrower now")
        self.assertEqual("full", self.d["active_scope"])

    def test_a_scope_that_becomes_the_whole_case_hands_over_its_report(self):
        store.switch_scope(CASE, store.scope_id_for_window(self.OLD))
        store.switch_scope(CASE, "full")
        store.rescan(CASE, {"time_window": dict(self.OLD)})      # typed on the whole case
        ids = self._ids()
        self.assertEqual("# 2011\n", ids["full"]["report_md"], "the 2011 report is the case's now")
        self.assertNotIn(store.scope_id_for_window(self.OLD), ids, "not duplicated")
        self.assertEqual("# 2016 whole case\n", ids[store.scope_id_for_window(self.BOUND)]["report_md"])
        self.assertEqual("# 2011\n", self.d["report_md"], "and it is what is on screen")


class ModulesThatFuseNothing(unittest.TestCase):

    def test_refusion_is_refused_when_no_run_matches_the_modules(self):
        with mock.patch.object(store, "modules_with_runs", return_value=["velociraptor_agentic"]), \
             mock.patch.object(store, "fuse_case", side_effect=AssertionError("must not fuse")), \
             mock.patch.object(store, "set_analysis_config",
                               side_effect=AssertionError("must not save")):
            with self.assertRaises(ValueError):
                store.rescan(CASE, {"fusion_modules": ["memory", "aws"]})

    def test_an_empty_graph_keeps_the_written_report(self):
        src = open(store.__file__).read()
        self.assertIn('_empty_keep = bool(d.get("report_md") and force_report and not g.entities)', src)
        self.assertIn('if d.get("report_md") and (not force_report or _empty_keep):', src)


class ARefusionReportIsTheTimeframes(unittest.TestCase):
    """Live on test1: a Refusion from 2016-09-01 with ALDC03 hidden sent the model
    byte-identical phases to the run before — the Refusion path narrated the whole
    case, whatever timeframe was on screen. Drives the real fuse_case."""

    def _fuse(self, d, switch_to=None):
        g = _g()
        g.upsert(schema.Entity(id="asset:b", type="asset", label="ALDC03"))
        g.upsert(schema.Entity(id="ev:b", type="event", label="on ALDC03", first_seen=INSIDE,
                               attrs={"_assets": ["asset:b"]}))
        g.findings.append(schema.Finding(id="f_b", title="on ALDC03", severity="high",
                                         confidence="high", summary="", entity_ids=["ev:b"],
                                         asset_ids=["asset:b"], ts=INSIDE))
        g.rebuild_indexes()
        seen = {}

        def _report(graph, window=None, **kw):
            seen["findings"] = sorted(f.id for f in graph.findings)
            seen["window"] = window
            if switch_to:                       # the operator moves while the model runs
                store.switch_scope(CASE, switch_to)
            return "# the report\n"
        ws = mock.MagicMock()
        ws.update_run_status.side_effect = lambda cid, st, details=None: d.update(details or {})
        patches = [
            mock.patch.object(store, "get_case", side_effect=lambda cid: dict(d)),
            mock.patch.object(store, "_merge_case_details", side_effect=lambda c, p: d.update(p)),
            mock.patch.object(store, "_mutate_list_field",
                              side_effect=lambda c, f, m: d.update({f: m(d.get(f) or [])})),
            mock.patch.object(store, "log_case_event"),
            mock.patch.object(store, "_ws", return_value=ws),
            mock.patch.object(store, "_members_for_case", return_value=[]),
            mock.patch.object(store, "_write_graph_sidecar", return_value=True),
            mock.patch.object(store.correlate, "assemble", return_value=g),
            mock.patch.object(store.llm_sim, "generate_report", side_effect=_report),
            mock.patch.object(store.llm_sim, "generate_disposition_checklist", return_value=[]),
            mock.patch.object(store.llm_sim, "_use_real", return_value=False),
        ]
        for p in patches:
            p.start()
        try:
            store.fuse_case(CASE, contributions_override=[], force_report=True,
                            trigger=store.TRIGGER_MANUAL_REFUSION, allow_llm=False)
        finally:
            for p in patches:
                p.stop()
        return seen

    def _case(self):
        sid = store.scope_id_for_window(WIN)
        return sid, {"name": "QA", "report_md": "# old\n", "active_scope": sid,
                     "time_window": {"start": "2011-01-01T00:00:00", "end": "2026-12-31T00:00:00"},
                     "scopes": [{"id": "full", "report_md": "# whole case\n"},
                                {"id": sid, "window": dict(WIN), "hidden_hosts": ["ALDC03"],
                                 "report_md": "# old\n"}]}

    def test_the_report_sees_the_timeframes_window_and_hosts(self):
        _, d = self._case()
        seen = self._fuse(d)
        self.assertEqual(["f_in"], seen["findings"], "f_out is outside the window, f_b is on ALDC03")
        self.assertEqual(WIN, seen["window"])
        self.assertEqual("# the report\n", d["report_md"])

    def test_switching_away_mid_run_files_the_report_under_its_timeframe(self):
        sid, d = self._case()
        self._fuse(d, switch_to="full")
        entry = next(s for s in d["scopes"] if s["id"] == sid)
        self.assertEqual("# the report\n", entry["report_md"])
        self.assertEqual("# whole case\n", d["report_md"], "the whole case keeps its own")


if __name__ == "__main__":
    unittest.main(verbosity=2)
