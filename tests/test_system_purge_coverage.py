"""System Purge must actually reach the data it claims to remove.

Two things were wrong on a live appliance, both silent, and both found by asking
"is the fusion data from a deleted case actually gone?"

1. THE ELK SECTION PURGED NOTHING. `_scan_elk_artifacts` and `_purge_elk_artifacts`
   asked Elasticsearch for its index list WITHOUT CREDENTIALS. ES on this appliance
   requires auth, so the probe returned 401, the `!= 200` branch reported
   "elasticsearch unreachable", and the row scanned 0 and deleted 0 while looking
   like it had worked. The credentials were in the container's environment the
   whole time (ELASTICSEARCH_USER / ELASTICSEARCH_PASSWORD).

2. THE CROSS-CASE KB WAS REACHABLE BY NO SECTION. `kb.INDEX` is
   "intact_fusion_entities", and the only ES section deletes indices matching
   `artifact_*`, so it never matched. delete_case() cleans a case's KB entries as
   it goes -- with a comment explaining that entities left behind "keep resurfacing
   as prior sightings in unrelated future cases" -- but the PURGE path stripped the
   graph and the report and left the KB. Measured: 32 entities from two deleted
   cases still indexed.

Also pinned: the fused-graph sidecars are deleted by the workflows purge but were
counted by nothing, so the dialog under-reported what it would free.
"""

import io
import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "modules/backend/routes/maintenance_routes.py")
STORE = os.path.join(ROOT, "modules/backend/services/fusion/store.py")


def _src(path=SRC):
    return io.open(path, encoding="utf-8").read()


class TheElkSectionMustAuthenticate(unittest.TestCase):
    def _calls(self, verb):
        """Every `req.<verb>(...)` with the 200 chars after it. Deliberately not a
        balanced-paren match: `_es_base()` closes the first paren, and a regex that
        stopped there passed a call whose auth= sat just beyond it."""
        return [_src()[m.start():m.start() + 200]
                for m in re.finditer(r"req\.%s\(" % verb, _src())]

    def test_no_unauthenticated_index_probe_remains(self):
        """The exact shape of the bug: a bare GET to _cat/indices."""
        probes = [c for c in self._calls("get") if "_cat/indices" in c]
        self.assertTrue(probes, "no index probe found at all -- test is stale")
        for c in probes:
            self.assertIn("auth=", c,
                          "an unauthenticated _cat/indices probe is back; it "
                          "returns 401 and the section silently purges nothing")

    def test_index_deletion_is_authenticated(self):
        dels = self._calls("delete")
        self.assertTrue(dels, "no index deletion found at all -- test is stale")
        for c in dels:
            self.assertIn("auth=", c)

    def test_credentials_come_from_the_environment(self):
        s = _src()
        self.assertIn("ELASTICSEARCH_USER", s)
        self.assertIn("ELASTICSEARCH_PASSWORD", s)

    def test_unreachable_is_still_distinguishable_from_empty(self):
        """_es_indices returns None for unreachable and [] for 'no indices' --
        collapsing them is how the 401 masqueraded as an empty result."""
        s = _src()
        self.assertRegex(s, r"def _es_indices\(\):")
        self.assertIn("return None", s.split("def _es_indices():")[1][:600])


class TheKnowledgeBaseMustBePurgeable(unittest.TestCase):
    def test_purging_runs_also_clears_those_cases_from_the_kb(self):
        body = _src().split("def _delete_runs_preserve_cases")[1].split("\ndef ")[0]
        self.assertIn("kb.delete_case_entities", body,
                      "the purge stripped the graph and report but left the KB, so "
                      "a purged box kept enriching new cases from deleted evidence")

    def test_there_is_an_orphan_sweep(self):
        s = _src()
        self.assertIn("def _purge_kb_orphans", s)
        body = s.split("def _purge_kb_orphans")[1].split("\ndef ")[0]
        # It must decide from the CASE ROWS, not from a hardcoded list.
        self.assertIn("automation_type = 'case'", body)
        self.assertIn("delete_case_entities", body)

    def test_the_sweep_only_removes_cases_that_are_gone(self):
        body = _src().split("def _purge_kb_orphans")[1].split("\ndef ")[0]
        self.assertIn("not in live", body,
                      "a sweep that does not compare against live cases would "
                      "delete the KB for cases that still exist")

    def test_delete_case_still_cleans_up_too(self):
        """The per-case path was already right; the purge path is the addition."""
        body = _src(STORE).split("def delete_case")[1].split("\ndef ")[0]
        self.assertIn("_delete_graph_sidecar", body)
        self.assertIn("delete_case_entities", body)


class TheDialogMustNotUnderreportWhatItFrees(unittest.TestCase):
    def test_the_graph_sidecars_are_counted(self):
        body = _src().split("def _scan_workflows")[1].split("\ndef ")[0]
        self.assertIn("fusion_graphs", body,
                      "the workflows purge deletes the sidecars but nothing "
                      "counted them, so the dialog under-reported")
