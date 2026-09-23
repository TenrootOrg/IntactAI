"""Keeping the memory image — who asked, and what survives.

The image is the expensive thing in this module: ~9 GB and 20+ minutes off a
live endpoint. Three separate code paths can destroy it (the pipeline's own
cleanup, the boot reaper's replay, the case purge), and until now the only way
to keep it was a heuristic the pipeline applied to itself. An operator switch
is only worth anything if it survives ALL of them, so these tests execute the
real cleanup logic against fakes rather than asserting on source text.

The one design rule they pin down: an operator keep holds exactly ONE copy of
the memory (the .raw on the shared volume, which is also VolWeb's staging
file), while the automatic "the extraction produced nothing" keep also holds
the untouched Velociraptor-side original — because in THAT case the extracted
.raw is itself a suspect.
"""

import ast
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLEANUP = os.path.join(ROOT, "modules/backend/services/memory/cleanup.py")


def _load(path, name):
    """The real function, executed without importing its package — the backend
    pulls in grpc/pyvelociraptor at import time and this test box has neither
    (same trick as tests/test_fuse_memory_guard.py)."""
    with open(path, encoding="utf-8") as fh:
        src = fh.read()
    fn = next(n for n in ast.parse(src).body
              if isinstance(n, ast.FunctionDef) and n.name == name)
    # The snippet is compiled without the module's `from __future__ import
    # annotations`, so its parameter annotations are evaluated — stub the
    # names they mention.
    ns = {"os": os, "Any": object, "Callable": __import__("typing").Callable,
          "VolWebClient": object, "VolWebError": Exception}
    exec(compile(ast.get_source_segment(src, fn), path, "exec"), ns)
    return ns[name], ns


cleanup_after_run, NS = _load(CLEANUP, "cleanup_after_run")


def _run_cleanup(**over):
    """Execute the real cleanup_after_run with every destructive step faked,
    and report which ones it decided to take."""
    called = {"flow": False, "host": False, "media_raw": False}
    NS["cleanup_velociraptor_flow"] = lambda *a, **k: called.__setitem__("flow", True)
    NS["_remove_host_dump"] = lambda *a, **k: called.__setitem__("host", True)
    NS["_remove_volweb_media_raw"] = lambda *a, **k: called.__setitem__("media_raw", True)
    NS["_remove_volweb_media_dir"] = lambda *a, **k: None

    kwargs = dict(
        client_id="C.abc", flow_id="F.123",
        host_path="/data/memory_dumps/HOST-F.123.raw",
        evidence_id=7, evidence_filename="HOST-F.123.raw",
        volweb_client=None, logger=lambda m, level="info": None,
    )
    kwargs.update(over)
    cleanup_after_run(**kwargs)
    return called


class TestWhoAskedDecidesWhatSurvives(unittest.TestCase):

    def test_by_default_everything_is_reclaimed(self):
        """The unchanged behaviour. A 9 GB leak per run is the failure here."""
        self.assertEqual(_run_cleanup(), {"flow": True, "host": True, "media_raw": True})

    def test_an_operator_keep_holds_exactly_one_copy(self):
        """The no-duplicates rule: the fs copy stays, the Velociraptor copy goes.
        Keeping both would store the same memory twice (~1.5x the dump)."""
        c = _run_cleanup(preserve_dump="operator")
        self.assertFalse(c["host"], "the operator asked to keep the .raw")
        self.assertFalse(c["media_raw"], "same inode as the host .raw — removing it removes the kept image")
        self.assertTrue(c["flow"], "the Velociraptor copy must go, or the image is stored twice")

    def test_an_automatic_keep_also_holds_the_untouched_original(self):
        """Nothing came out of the image, so the extracted .raw is a suspect —
        the server-side copy is the only original left to retry from."""
        c = _run_cleanup(preserve_dump="no_results")
        self.assertEqual(c, {"flow": False, "host": False, "media_raw": False})

    def test_a_bare_true_still_means_the_automatic_keep(self):
        """Callers that predate the reason string (and the boot reaper reading
        an older row) must not silently become operator keeps."""
        self.assertEqual(_run_cleanup(preserve_dump=True),
                         {"flow": False, "host": False, "media_raw": False})


class TestThePipelineHonoursTheOperatorOverItsOwnGuess(unittest.TestCase):
    """The pipeline sets the keep reason from what the extraction did. An
    operator instruction is not a guess and must outrank both outcomes —
    including the success path, which is precisely where the old code reset
    the flag and deleted the image."""

    @staticmethod
    def _resolve(keep_dump, plugins_done, plugin_map):
        """The two assignments from pipeline.run_memory_pipeline, in order."""
        dump_preserved = "operator" if keep_dump else ""
        if dump_preserved != "operator":                      # before the wait
            dump_preserved = "no_results"
        if dump_preserved != "operator":                      # after the wait
            dump_preserved = "" if (plugins_done and plugin_map) else "no_results"
        return dump_preserved

    def test_a_successful_run_reclaims_when_not_asked(self):
        self.assertEqual(self._resolve(False, True, {"pslist": []}), "")

    def test_a_successful_run_keeps_when_asked(self):
        self.assertEqual(self._resolve(True, True, {"pslist": []}), "operator")

    def test_an_empty_extraction_keeps_itself(self):
        self.assertEqual(self._resolve(False, True, {}), "no_results")

    def test_a_timeout_keeps_itself(self):
        self.assertEqual(self._resolve(False, False, {}), "no_results")

    def test_an_operator_keep_is_never_downgraded(self):
        for done, pmap in ((True, {"pslist": []}), (True, {}), (False, {})):
            self.assertEqual(self._resolve(True, done, pmap), "operator")


class TestTheKeepSurvivesARestart(unittest.TestCase):
    """register_cleanup's closure is in-memory only. The boot reaper replays
    cleanup from details._cleanup_state, and if the reason is not persisted
    there the next restart deletes the image the operator kept."""

    @staticmethod
    def _read(rel):
        with open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
            return fh.read()

    def test_the_reaper_passes_the_persisted_reason(self):
        src = self._read("modules/backend/app.py")
        blk = src[src.index('if _w.get("automation_type") == "memory":'):][:1600]
        self.assertIn('preserve_dump=_state.get("preserve_dump")', blk,
                      "the reaper drops the keep and deletes a kept image")

    def test_the_pipeline_persists_it(self):
        self.assertIn('_persist_cleanup_state(run_id, preserve_dump="operator")',
                      self._read("modules/backend/services/memory/pipeline.py"))


class TestTheRouteResolvesTheSwitch(unittest.TestCase):
    """Precedence: request > blueprint > off. An explicit false has to be able
    to override a blueprint that says true, which a plain `or` chain cannot."""

    @staticmethod
    def _resolve(requested, bp_keep):
        fn, _ = _load(os.path.join(ROOT, "modules/backend/routes/memory_routes.py"),
                      "_resolve_keep_dump")
        bp = {"settings": {"keep_dump": bp_keep}} if bp_keep is not None else None
        return fn(requested, bp)

    def test_off_by_default(self):
        self.assertFalse(self._resolve(None, None))

    def test_the_request_wins(self):
        self.assertTrue(self._resolve(True, None))

    def test_a_blueprint_can_ask_for_it(self):
        self.assertTrue(self._resolve(None, True))

    def test_an_explicit_false_beats_the_blueprint(self):
        self.assertFalse(self._resolve(False, True))


if __name__ == "__main__":
    unittest.main(verbosity=2)
