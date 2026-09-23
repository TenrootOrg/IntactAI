"""Pulling another case's memory findings in by workflow id.

Modelled on tests/test_velociraptor_adopt.py, which covers the same feature for
Velociraptor. The two differ in one important way: Velociraptor copies NOTHING
— it re-reads the rows from a server that still holds them. VolWeb cannot,
because cleanup reclaims the per-evidence dir that holds the yarascan results
along with the image, so this one copies the findings snapshot.

Copying is where the danger is. A run row names storage its case owns, and the
case purge acts on those names: carrying `host_path` into the copy would mean
deleting THIS case destroys the OTHER case's 9 GB memory image and its VolWeb
evidence. These tests pin the omissions down by executing the function that
builds the copied details, not by reading the route and hoping.
"""

import ast
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROUTES = os.path.join(ROOT, "modules/backend/routes/memory_routes.py")
VELO = os.path.join(ROOT, "modules/backend/routes/velociraptor_routes.py")


def _load(path, name, extra=None):
    with open(path, encoding="utf-8") as fh:
        src = fh.read()
    fn = next(n for n in ast.parse(src).body
              if isinstance(n, ast.FunctionDef) and n.name == name)
    ns = {"os": os, "Any": object}
    ns.update(extra or {})
    exec(compile(ast.get_source_segment(src, fn), path, "exec"), ns)
    return ns[name]


def _read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
        return fh.read()


# A source run as the pipeline leaves it: every field, including the ones that
# name storage the source case owns.
SOURCE_DETAILS = {
    "trigger": "manual",
    "mode": "layered",
    "client_id": "C.fe85a6ed0f357dc8",
    "client_name": "DESKTOP-566AT85",
    "case_name": "Cust X",
    "blueprint": "Memory Analysis: Curated standard (recommended)",
    "blueprint_id": "memory_layered_default",
    "keep_dump": True,
    "host_path": "/data/memory_dumps/DESKTOP-566AT85-F.123.raw",
    "upload_dir": "/data/memory_dumps/_uploads/abc123",
    "evidence_id": 7,
    "evidence_filename": "DESKTOP-566AT85-F.123.raw",
    "_cleanup_state": {"flow_id": "F.123", "host_path": "/data/memory_dumps/x.raw"},
    "report_md": "# a 50 KB report belonging to the other case",
}


class TestTheCopyOwnsNoneOfTheSourcesStorage(unittest.TestCase):
    """The single most destructive mistake available here: the copied run
    keeping a path the case purge acts on. Deleting the case that BORROWED the
    findings would delete the image and evidence of the case that owns them."""

    def setUp(self):
        self.build = _load(ROUTES, "_adopt_details",
                           {"_ADOPT_CARRY": ("client_id", "client_name", "case_name",
                                             "mode", "blueprint", "blueprint_id")})
        self.out = self.build(SOURCE_DETAILS, "memory_1790012609712")

    def test_no_key_names_the_sources_storage(self):
        for k in ("host_path", "upload_dir", "_cleanup_state",
                  "evidence_id", "evidence_filename"):
            self.assertNotIn(k, self.out, f"{k} would let this case destroy the other's data")

    def test_nothing_nested_smuggles_a_path_back_in(self):
        """A shallow key check passes a copy that carried the whole details
        dict one level down."""
        import json
        blob = json.dumps(self.out)
        self.assertNotIn("/data/memory_dumps", blob)

    def test_the_other_cases_report_is_not_claimed(self):
        self.assertNotIn("report_md", self.out)

    def test_it_keeps_what_identifies_the_host(self):
        self.assertEqual(self.out["client_name"], "DESKTOP-566AT85")
        self.assertEqual(self.out["client_id"], "C.fe85a6ed0f357dc8")

    def test_it_records_where_it_came_from(self):
        self.assertEqual(self.out["adopted_from"], "memory_1790012609712")
        self.assertEqual(self.out["trigger"], "adopt")

    def test_a_thin_source_does_not_produce_null_fields(self):
        """A run that died early has almost no details; the copy should be
        small, not a row of Nones that read as real values in the UI."""
        out = self.build({"client_name": "HOST"}, "memory_1")
        self.assertEqual(set(out), {"client_name", "trigger", "adopted_from"})


class TestTheSnapshotIsFoundWhereverItLives(unittest.TestCase):
    """Two download roots exist depending on how the backend is mounted; the
    fusion reader probes both and so must this."""

    # The function does its own `import os`, so the real module is patched.
    FN = staticmethod(_load(ROUTES, "_payload_path"))

    def test_both_roots_are_probed(self):
        from unittest import mock
        for base in ("/app/data/downloads", "/data/downloads"):
            with mock.patch("os.path.exists", lambda p, b=base: p.startswith(b)):
                self.assertEqual(self.FN("memory_1"),
                                 f"{base}/memory_1/memory_payload.json")

    def test_a_run_with_no_snapshot_returns_none(self):
        from unittest import mock
        with mock.patch("os.path.exists", lambda p: False):
            self.assertIsNone(self.FN("memory_1"))


class TestTheRouteRefusesBeforeItCopies(unittest.TestCase):
    """Order matters: every refusal has to happen before a run row is created,
    or the operator collects empty rows they then have to clean up."""

    SRC = _read("modules/backend/routes/memory_routes.py")
    BODY = SRC[SRC.index("def adopt_memory_run"):]

    def _before_create(self, needle):
        return self.BODY.index(needle) < self.BODY.index("create_automation_run(")

    def test_the_id_shape_is_checked_first(self):
        """The id builds filesystem paths below — ../.. must never reach them."""
        self.assertTrue(self._before_create("_is_workflow_run_id(source_run_id)"))

    def test_it_reuses_the_velociraptor_id_check(self):
        self.assertIn("from routes.velociraptor_routes import _is_workflow_run_id", self.BODY)
        self.assertIn("def _is_workflow_run_id", _read("modules/backend/routes/velociraptor_routes.py"))

    def test_a_non_memory_run_is_refused(self):
        self.assertTrue(self._before_create('source.get("automation_type") != "memory"'))

    def test_the_same_case_is_a_duplicate(self):
        self.assertTrue(self._before_create('source.get("case_id") == case_id'))

    def test_pulling_the_same_source_twice_is_a_duplicate(self):
        self.assertTrue(self._before_create('.get("adopted_from") == source_run_id'))

    def test_a_failed_copy_does_not_block_a_retry(self):
        """Same rule as the Velociraptor adopt: a failed attempt left nothing
        behind, so counting it as a duplicate strands the operator."""
        blk = self.BODY[self.BODY.index('.get("adopted_from")') - 400:
                        self.BODY.index('.get("adopted_from")')]
        self.assertIn('"failed", "cancelled", "error", "stopped"', blk)

    def test_a_run_with_no_findings_is_refused(self):
        self.assertTrue(self._before_create("src_payload = _payload_path(source_run_id)"))

    def test_a_fresh_id_is_minted(self):
        """Reusing the source id would let this case's purge delete the other
        case's payload — case_bundle.py says why at length."""
        self.assertIn("create_automation_run(", self.BODY)
        self.assertNotIn("run_id=source_run_id", self.BODY)

    def test_it_ends_terminal_so_the_fuse_arms(self):
        """Without a terminal status the copy is never folded into the case and
        the findings never appear in Case Analysis."""
        self.assertIn('update_run_status(run_id, "completed", progress=100)', self.BODY)

    def test_the_copy_is_a_case_member(self):
        """`memory` must be in AGENTIC_TYPES or the row is not a case member
        and fusion never sees it."""
        self.assertIn('"memory"', _read("modules/backend/services/workflow_service.py")
                      [:_read("modules/backend/services/workflow_service.py").index("_TERMINAL_STATUSES")])


if __name__ == "__main__":
    unittest.main(verbosity=2)
