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

    def test_a_report_in_flight_blocks_a_switch(self):
        store.create_scope(CASE, "Phase 2", PHASE_WIN)
        self.d["report_generating"] = True
        self.d["report_generating_started_at"] = store._now_iso()
        with self.assertRaises(store.ReportGenerationBusy):
            store.switch_scope(CASE, "full")

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


if __name__ == "__main__":
    unittest.main(verbosity=2)
