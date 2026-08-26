"""Manual Refusion rebuilds. Everything else adds.

WHY THE SPLIT IS THE RIGHT ONE, and it is about correctness before speed.
correlate.assemble applies the case's window and severity floor AT INGEST, so
the stored graph is the FILTERED set — its own comment says changing those
"requires a Refusion (it's no longer a free re-render)". Module selection,
included runs, the environment baseline and operator dispositions are global in
the same way: a triage verdict can re-open or suppress findings the new run
never touched.

So: a global parameter moved -> rebuild. Only new data arrived -> the graph is
still exactly right for every prior run, and the new one is added to it.

Cheap, too, but that is the smaller half. Measured on a real case: mapping every
member run costs 27-54s while the correlation itself is ~1s, so a full rebuild
after a run lands spends nearly a minute reproducing a graph we already have.

WHAT MAKES ADDING SAFE. Both merge primitives are keyed and idempotent —
FusionGraph.upsert merges an entity already present, relate() dedupes on
Relationship.key() — so the derivation passes can run again over the merged
graph without duplicating what they created last time. Findings are the
exception and are cleared: every one is derived from entities (mappers return
only entities and relationships), and re-deriving is what lets a landing run
change the severity or cross-host status of a finding it never touched.
"""

import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STORE = os.path.join(ROOT, "modules/backend/services/fusion/store.py")
CORRELATE = os.path.join(ROOT, "modules/backend/services/fusion/correlate.py")
SCHEMA = os.path.join(ROOT, "modules/backend/services/fusion/schema.py")


def read(p):
    with open(p, encoding="utf-8") as fh:
        return fh.read()


class TestOnlyTheAutomaticPathAdds(unittest.TestCase):
    def setUp(self):
        src = read(STORE)
        self.decision = src[src.index("seed_graph = None            # set below"):
                            src.index("def _contributions():")]

    def test_a_manual_refusion_rebuilds(self):
        self.assertIn("trig == TRIGGER_AUTOMATIC_RUN_LANDED", self.decision,
                      "anything other than a landing run must rebuild")
        for manual in ("TRIGGER_MANUAL_REFUSION", "TRIGGER_MANUAL_RESCAN",
                       "TRIGGER_DISPOSITION", "TRIGGER_TIMELINE", "TRIGGER_IDENTITY"):
            self.assertNotIn(manual, self.decision,
                             f"{manual} would take the additive path")

    def test_an_override_never_seeds(self):
        # contributions_override is a caller supplying its own data (calibration,
        # baseline capture); seeding it onto a case graph would mix them.
        self.assertIn("not contributions_override", self.decision)

    def test_it_needs_something_already_in_the_graph(self):
        self.assertIn("bool(_already)", self.decision)

    def test_only_unfused_runs_are_mapped(self):
        self.assertIn("if rid not in set(_already)", self.decision,
                      "the additive path is re-mapping runs already in the graph")


class TestWhatForcesARebuild(unittest.TestCase):
    """Everything global. Each of these can change a part of the graph that the
    landing run has no relationship with, so none can be applied incrementally."""

    def setUp(self):
        src = read(STORE)
        self.sig = src[src.index("def _graph_filter_signature"):
                       src.index("def _stable_hash")]

    def test_the_signature_covers_every_global_filter(self):
        for key in ("window", "min_severity", "modules", "included",
                    "is_baseline", "baseline", "dispositions"):
            self.assertIn(f'"{key}"', self.sig, f"{key} is not in the signature")

    def test_the_signature_is_compared_before_seeding(self):
        src = read(STORE)
        decision = src[src.index("seed_graph = None            # set below"):
                       src.index("def _contributions():")]
        self.assertIn('d.get("graph_filter_sig") == _sig', decision)

    def test_the_signature_is_stamped_with_the_graph(self):
        src = read(STORE)
        self.assertIn('"graph_filter_sig": _sig_full', src)

    def test_the_baseline_is_resolved_before_the_decision(self):
        # It is part of the signature, so deciding first and discovering the
        # baseline afterwards would seed a graph built under a different one.
        src = read(STORE)
        decision = src[src.index("seed_graph = None            # set below"):
                       src.index("def _contributions():")]
        self.assertIn("_baseline_for_sig", decision)


class TestAddingCannotDuplicate(unittest.TestCase):
    """The three ways a second pass over the same graph could corrupt it."""

    def test_entity_merge_is_keyed_and_idempotent(self):
        seg = read(SCHEMA)
        body = seg[seg.index("def upsert(self, e: Entity)"):]
        body = body[:body.index("\n    def ", 10)]
        self.assertIn("self.entities.get(e.id)", body)
        self.assertIn("_union(cur.sources", body)

    def test_relationship_merge_is_keyed_and_idempotent(self):
        seg = read(SCHEMA)
        body = seg[seg.index("def relate(self, r: Relationship)"):]
        body = body[:body.index("\n    def ", 10)]
        self.assertIn("k = r.key()", body)
        self.assertIn("self._rel_index.get(k)", body)

    def test_a_reloaded_graph_rebuilds_its_indexes(self):
        # from_dict must go through relate(), or the dedupe index is empty and
        # every derived relationship is appended a second time.
        seg = read(SCHEMA)
        body = seg[seg.index("def from_dict(cls, d: dict) -> \"FusionGraph\""):]
        body = body[:body.index("\n\n", 10) + 1] if "\n\n" in body else body
        self.assertIn("g.relate(Relationship.from_dict(rd))", body,
                      "relationships are loaded without populating the dedupe index")

    def test_evidence_is_merged_not_appended(self):
        """THE ONE THAT WAS NOT IDEMPOTENT, and it was found by measuring.

        sources and flags were unioned; evidence was extend()ed. Harmless while
        every fuse rebuilt from nothing — and not harmless once fusion became
        incremental, because "Fetch results" drops a run from fused_run_ids and
        the additive path then maps that run onto a stored graph that still
        contains it.

        Measured on a two-run case, re-fetching one of them three times:
            59,047 -> 59,412 -> 59,777 -> 60,142      (+365 every time)
        which is precisely that run's whole evidence trail, re-appended. After
        the fix it holds at 22,191 across the same four rounds — and note the
        baseline moved too: deduping also removes ~37,000 duplicates that a
        single ordinary fuse was already accumulating.
        """
        seg = read(SCHEMA)
        body = seg[seg.index("def upsert(self, e: Entity)"):]
        body = body[:body.index("\n    def ", 10)]
        self.assertIn("_union_evidence(cur.evidence, e.evidence)", body)
        self.assertNotIn("cur.evidence.extend(", body,
                         "evidence is appended again, so re-fusing a run doubles it")

    def test_the_evidence_key_is_the_whole_ref(self):
        # module+run_id+locator. Keying on anything less would collapse genuinely
        # distinct observations of the same entity.
        seg = read(SCHEMA)
        body = seg[seg.index("def _union_evidence"):seg.index("class EvidenceRef")]
        self.assertIn("(e.module, e.run_id, e.locator)", body)

    def test_findings_are_cleared_when_seeding(self):
        seg = read(CORRELATE)
        body = seg[seg.index("def assemble("):seg.index("def _stamp_finding_watermarks")]
        self.assertIn("g.findings = []", body,
                      "seeded findings would be doubled by the derivation passes")

    def test_the_derivation_passes_still_run_over_the_merged_graph(self):
        # The point of re-deriving: a landing run may change the severity or
        # cross-host status of a finding belonging to an earlier run.
        seg = read(CORRELATE)
        body = seg[seg.index("def assemble("):seg.index("def _stamp_finding_watermarks")]
        for p in ("_derive_findings(g", "_cross_host_findings(g", "_corroboration(g",
                  "_apply_dispositions(g", "_score_assets(g"):
            self.assertIn(p, body, f"{p} no longer runs on the merged graph")


class TestAPrunedGraphIsNeverSeeded(unittest.TestCase):
    """A graph at the storage cap was pruned on the way to disk. Adding to it
    would compound the loss quietly on every landing run, and the case would
    decay instead of grow."""

    def test_the_cap_is_checked(self):
        src = read(STORE)
        decision = src[src.index("seed_graph = None            # set below"):
                       src.index("def _contributions():")]
        self.assertIn("len(seed_graph.entities) >= _cap", decision)

    def test_an_empty_or_unreadable_graph_falls_back_to_a_rebuild(self):
        src = read(STORE)
        decision = src[src.index("seed_graph = None            # set below"):
                       src.index("def _contributions():")]
        self.assertIn("not seed_graph.entities", decision)
        self.assertIn("stored graph unreadable", decision)


if __name__ == "__main__":
    unittest.main(verbosity=2)
