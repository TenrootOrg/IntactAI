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


class TheEstimateMustNotPromiseTheSameDiskTwice(unittest.TestCase):
    """Measured on a live purge: the dialog said ~41 GB and 24 GB came back.

    Docker Deep Prune scans Images + Build Cache reclaimable -- literally the same
    numbers those two rows display (a screenshot showed "Docker Images 185.2 MB"
    beside "Docker Deep Prune 185.2 MB") -- and the modal summed every ticked row.
    Deep Prune's own log line then read "Freed 0 B", because the rows above it had
    already taken the bytes it was counting.
    """

    def test_the_overlap_is_declared_in_one_place(self):
        s = _src()
        self.assertIn("_SECTION_COVERS", s)
        body = s.split("_SECTION_COVERS = {")[1].split("}")[0]
        self.assertIn("docker_deep", body)
        self.assertIn("docker_images", body)
        self.assertIn("docker_build_cache", body)

    def test_deep_prune_does_not_claim_volumes(self):
        """Its own UI text says it leaves volumes alone; the scan agrees, so
        listing them as covered would under-report instead."""
        body = _src().split("_SECTION_COVERS = {")[1].split("}")[0]
        self.assertNotIn("docker_volumes", body)

    def test_the_api_tells_the_ui_about_the_overlap(self):
        self.assertIn('"covers"', _src())

    def test_the_ui_subtracts_covered_rows_from_both_totals(self):
        js = _src(os.path.join(ROOT, "modules/nginx/html/js/stores/settings.js"))
        self.assertIn("_purgeCovered", js)
        for fn in ("purgeSelectedTotalBytes", "purgeGrandTotalLabel"):
            body = js.split(fn)[1][:400]
            self.assertIn("_purgeSum", body, f"{fn} still sums naively")


class TheVelociraptorEstimateMustMatchWhatIsRemoved(unittest.TestCase):
    """It `du`-ed the whole datastore minus /public, but the purge removes
    collected hunt/flow/monitoring data and KEEPS EVERY CLIENT by design. Live:
    estimated 6.8 GB, freed 4.5 GB, and 2.3 GB was still listed afterwards --
    1.3 GB of it server_artifacts/Custom.Elastic.Flows.Upload, which no section
    touches at all."""

    def test_the_scan_no_longer_measures_the_whole_datastore(self):
        body = _src().split("def _scan_velociraptor")[1].split("\ndef ")[0]
        self.assertNotIn("--exclude=public", body,
                         "back to du-ing everything, which counts server_artifacts "
                         "and client records the purge never deletes")

    def test_server_artifacts_are_not_counted(self):
        body = _src().split("def _scan_velociraptor")[1].split("\ndef ")[0]
        self.assertNotIn("server_artifacts", body.split('"""')[-1])

    def test_the_detail_string_says_what_is_kept(self):
        body = _src().split("def _scan_velociraptor")[1].split("\ndef ")[0]
        self.assertIn("kept", body,
                      "the operator must be told clients/server artifacts survive")


class EverySectionHoldingDataMustSayWhat(unittest.TestCase):
    """The dialog is a decision surface: an operator ticks a row and loses what
    is in it. Most rows explain themselves -- "441 investigation runs",
    "63 artifact_* indices" -- but uploads and report downloads hardcoded "", so
    a live box showed "1.1 GB" and "3.6 KB" beside a dash with no way to judge
    whether purging was safe. Found by the e2e's purge_scan phase."""

    def test_no_scanner_returns_a_hardcoded_empty_detail(self):
        src = _src()
        for m in re.finditer(r"def (_scan_\w+)\(\):(.*?)(?=\ndef )", src, re.S):
            name, body = m.group(1), m.group(2)
            self.assertNotRegex(
                body, r"return [^\n]*,\s*\"\"\s*$",
                f"{name} reports a size with no explanation")

    def test_the_two_that_were_blank_now_describe_themselves(self):
        src = _src()
        self.assertIn("_dir_detail(p, \"uploaded file\")", src)
        self.assertIn('_dir_detail("/data/downloads", "export")', src)

    def test_a_missing_directory_is_described_not_counted_as_zero_files(self):
        """'nothing staged' and '0 files' mean different things to an operator."""
        body = _src().split("def _dir_detail")[1].split("\ndef ")[0]
        self.assertIn("nothing staged", body)
