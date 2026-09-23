"""Uploading a memory image goes through tus, as a workflow, like Velociraptor.

A 1.5 GB image uploaded from the Memory panel died with

    parse error: Unexpected token '<', "<html> <h"... is not valid JSON

because the panel POSTed the whole file to /api/memory/upload and nginx refuses
a body over `client_max_body_size` (500M) with an HTML 413 page. The request
never reached Flask, so there was no workflow row, no log line, no error
handling and nothing to resume -- the operator got a JSON parse error for a
file that was simply too big to send that way.

Velociraptor has not had this problem since it moved to tus: chunked, resumable,
size-unbounded, and the tusd hook opens the workflow row before the first byte
lands. Memory uses the same road now.

Two rules these tests exist to hold:

  * the row must be type `memory`, not `memory_upload` -- that is what makes it
    a case member (AGENTIC_TYPES), what fusion dispatches to the memory
    contribution, and what the restart reaper knows how to reap. A type of its
    own would upload perfectly and contribute nothing, silently.
  * the direct API route keeps working for scripts, with a limit that fits a
    memory image, so nobody meets the HTML-413 again.
"""

import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
        return fh.read()


class TestTheHookAcceptsAMemoryUpload(unittest.TestCase):

    SRC = _read("modules/backend/routes/upload_routes.py")

    def test_memory_is_an_allowed_purpose(self):
        line = next(l for l in self.SRC.splitlines() if "if purpose not in [" in l)
        self.assertIn("'memory'", line, "tusd would reject the upload at pre-create")

    def test_the_accepted_extensions_match_what_the_picker_offers(self):
        """A file the browser let the operator choose must never be refused
        server-side -- that reads as a bug in the upload, not a wrong file."""
        panel = _read("modules/nginx/html/partials/memory.html")
        offered = set(re.findall(r'accept="([^"]+)"', panel)[0].split(","))
        blk = self.SRC[self.SRC.index("elif purpose == 'memory':"):][:900]
        allowed = set(re.search(r"allowed_extensions = \[([^\]]+)\]", blk)
                      .group(1).replace("'", "").replace(" ", "").split(","))
        self.assertEqual(offered, allowed)

    def test_the_row_is_a_memory_run_not_an_upload_run(self):
        blk = self.SRC[self.SRC.index("workflow_type = 'case_import'"):][:900]
        self.assertIn("workflow_type = 'memory'", blk)
        self.assertNotIn("workflow_type = 'memory_upload'", self.SRC)

    def test_that_type_is_a_case_member_and_gets_reaped(self):
        ws = _read("modules/backend/services/workflow_service.py")
        self.assertIn('"memory"', ws[:ws.index("_TERMINAL_STATUSES")],
                      "a memory run must be in AGENTIC_TYPES or it never fuses")
        self.assertIn('"memory"', _read("modules/backend/app.py")
                      [_read("modules/backend/app.py").index("_REAP_TYPES"):][:300],
                      "an interrupted upload would hang at running for ever")


class TestTheUploadedImageReachesThePipeline(unittest.TestCase):

    SRC = _read("modules/backend/routes/upload_routes.py")
    BLK = SRC[SRC.index("def run_memory_upload"):][:7600]

    def test_it_is_staged_onto_the_volume_volweb_can_read(self):
        """/data/memory_dumps IS VolWeb's media/staging. Anywhere else and the
        extraction workers cannot open the file."""
        self.assertIn("/data/memory_dumps/_uploads/", self.BLK)

    def test_it_moves_rather_than_copies(self):
        self.assertIn("shutil.move(file_path, dest)", self.BLK)

    def test_the_operators_choices_survive_the_round_trip(self):
        for key in ("mode", "blueprint_id", "case_name", "keep_dump"):
            self.assertIn(f"metadata.get('{key}'", self.BLK,
                          f"{key} chosen in the panel never reaches the pipeline")

    def test_a_zip_is_unpacked_like_the_direct_route_does(self):
        self.assertIn("extract_memory_from_upload", self.BLK)

    def test_every_failure_lands_on_the_run(self):
        self.assertIn('update_run_status(run_id, "failed"', self.BLK)
        self.assertIn('"error"', self.BLK)

    def test_it_refuses_to_run_without_a_workflow_row(self):
        """Silently analysing with nowhere to report is worse than not running:
        the operator would watch Workflows for a row that never appears."""
        tail = self.SRC[self.SRC.index("def run_memory_upload"):][:6500]
        self.assertIn("if not run_id:", tail)

    def test_the_tus_file_is_not_left_on_the_upload_volume(self):
        self.assertIn("os.remove(file_path)", self.BLK)


class TestTheBrowserUsesTheResumablePath(unittest.TestCase):

    JS = _read("modules/nginx/html/js/memory.js")

    def test_it_uploads_with_tus(self):
        self.assertIn("new TusUploader({", self.JS)
        self.assertIn("purpose: 'memory'", self.JS)

    def test_the_giant_post_is_gone(self):
        blk = self.JS[self.JS.index("startUpload()"):][:2500]
        self.assertNotIn("/api/memory/upload", blk,
                         "the panel is still POSTing the whole file")
        self.assertNotIn("new XMLHttpRequest", blk)

    def test_a_failure_is_reported_rather_than_parsed(self):
        blk = self.JS[self.JS.index("startUpload()"):][:2500]
        self.assertIn("onError:", blk)
        self.assertNotIn("JSON.parse", blk,
                         "parsing an error page is what produced 'Unexpected token <'")


class TestTheDirectApiRouteStillFitsAMemoryImage(unittest.TestCase):
    """Scripts and curl still post straight to the API. 500M does not fit a
    memory dump, and nginx's refusal is an HTML page."""

    CONF = _read("modules/nginx/config/nginx.conf")

    def test_the_upload_endpoint_has_its_own_location(self):
        self.assertIn("location = /api/memory/upload {", self.CONF)

    def test_it_lifts_the_size_cap(self):
        blk = self.CONF[self.CONF.index("location = /api/memory/upload {"):][:1200]
        self.assertIn("client_max_body_size 0;", blk)

    def test_it_streams_instead_of_buffering_gigabytes_in_nginx(self):
        blk = self.CONF[self.CONF.index("location = /api/memory/upload {"):][:1200]
        self.assertIn("proxy_request_buffering off;", blk)

    def test_it_allows_more_than_the_default_five_minutes(self):
        blk = self.CONF[self.CONF.index("location = /api/memory/upload {"):][:1200]
        self.assertIn("proxy_read_timeout 3600s;", blk)

    def test_the_general_api_cap_is_untouched(self):
        """Lifting it for everything would make every other endpoint an
        unbounded ingestion point."""
        self.assertIn("client_max_body_size 500M;", self.CONF)




class TestStoppingAnUploadActuallyStopsTheWork(unittest.TestCase):
    """tus knows nothing about workflows. Pressing Stop marks the run
    cancelled, the browser keeps sending chunks, and post-finish arrives
    minutes later -- so an upload that was stopped 28 seconds in still staged
    1.5 GB onto the dumps volume and registered VolWeb evidence for a run that
    was already over. Measured, with the gigabytes left behind."""

    SRC = _read("modules/backend/routes/upload_routes.py")

    def test_there_is_a_stopped_check(self):
        self.assertIn("def _run_was_stopped(", self.SRC)

    def test_it_reads_the_row_not_the_cancel_event(self):
        """request_stop() pops the in-memory cancel registry as it fires, so by
        post-finish there is nothing left to ask -- the row is the only truth."""
        blk = self.SRC[self.SRC.index("def _run_was_stopped("):][:900]
        self.assertIn("get_workflow(run_id)", blk)
        for state in ("cancelled", "stopped", "failed"):
            self.assertIn(state, blk)

    def test_a_stopped_run_is_never_staged_or_dispatched(self):
        # Anchored on the dispatch, not on `elif purpose == 'memory'` — that
        # appears twice (pre-create validation, then post-finish dispatch).
        blk = self.SRC[self.SRC.index("memory upload has no run row"):][:1600]
        self.assertIn("if _run_was_stopped(run_id):", blk)
        self.assertLess(blk.index("if _run_was_stopped(run_id):"),
                        blk.index("threading.Thread(target=run_memory_upload"),
                        "the check must come BEFORE the work is dispatched")

    def test_the_operator_is_told_the_upload_was_thrown_away(self):
        """add_log_to_run drops writes to a cancelled run as post-stop
        residue. This one is not residue, it is the outcome: without force
        the run's last word is "Stop requested by user" and nothing says that
        gigabytes finished uploading and were discarded."""
        blk = self.SRC[self.SRC.index("memory upload has no run row"):][:1600]
        self.assertIn('force=True', blk)

    def test_the_discarded_image_is_removed(self):
        blk = self.SRC[self.SRC.index("memory upload has no run row"):][:1600]
        self.assertIn("os.remove(file_path)", blk)

    def test_a_stop_during_staging_is_caught_too(self):
        """Staging a multi-GB image takes long enough for a Stop to land in the
        middle of it, and the pipeline would not notice: the cancel event it
        registers is a fresh one, never set."""
        blk = self.SRC[self.SRC.index("def run_memory_upload"):][:6000]
        self.assertIn("if _run_was_stopped(run_id):", blk)
        self.assertLess(blk.index("if _run_was_stopped(run_id):"),
                        blk.index("memory_pipeline.run_memory_pipeline("))


class TestTheRowMovesWhileBytesArrive(unittest.TestCase):
    """The bar and the log were updated together, only at 10% boundaries, so a
    multi-GB upload sat frozen at "2%" for minutes and read as a hung run --
    which is exactly when an operator stops an upload that is working fine."""

    SRC = _read("modules/backend/routes/upload_routes.py")
    BLK = SRC[SRC.index("elif event_type == 'post-receive':"):][:2200]

    def test_progress_is_written_for_every_chunk(self):
        prog = self.BLK.index('update_run_status(run_id, "running", progress=int(percentage / 10))')
        gate = self.BLK.index("if should_log or percentage >= 99:")
        self.assertLess(prog, gate, "the bar is still gated behind the log interval")

    def test_the_log_is_still_rate_limited(self):
        """Moving the bar per chunk must not mean a log line per chunk."""
        blk = self.BLK[self.BLK.index("if should_log or percentage >= 99:"):][:300]
        self.assertIn("add_log_to_run", blk)


class TestStopReachesTheUploadItself(unittest.TestCase):
    """SHARED upload layer, not memory-only.

    js/upload.js has had an abort() since it was written and nothing ever
    called it — not the Velociraptor collector import, not Timesketch, not the
    memory upload. So "Stop" marked the row cancelled while the browser carried
    on streaming, and the hook fired minutes later for a run that was over.
    The backend guard added alongside this catches that server-side; this
    stops the bytes at the source, for every module that uploads.
    """

    JS = _read("modules/nginx/html/js/upload.js")
    WF = _read("modules/nginx/html/js/stores/workflows.js")

    def test_an_upload_is_registered_once_tusd_names_it(self):
        self.assertIn("_registerActive(upload)", self.JS)
        self.assertIn("TusUploader._active.set(id, this)", self.JS)

    def test_it_is_forgotten_when_it_finishes_or_fails(self):
        """A registry that only grows would abort a later upload that happened
        to reuse the id, and holds the File alive."""
        self.assertEqual(2, self.JS.count("TusUploader._active.delete(this._registeredId)"))

    def test_aborting_also_terminates_it_server_side(self):
        """abort(true) makes tus DELETE the upload, which fires tusd's
        post-terminate hook and reclaims the partial file. Without the flag the
        bytes already sent sit on the upload volume for ever."""
        blk = self.JS[self.JS.index("    abort() {"):][:600]
        self.assertIn("this.currentUpload.abort(true)", blk)

    def test_stop_aborts_before_it_asks_the_server(self):
        blk = self.WF[self.WF.index("async stopWorkflow(runId)"):][:1600]
        self.assertIn("TusUploader.abortUpload(uploadId)", blk)
        self.assertLess(blk.index("TusUploader.abortUpload(uploadId)"),
                        blk.index("/stop`, { method: 'POST' }"),
                        "stop the bytes first, then mark the row")

    def test_it_finds_the_upload_by_the_runs_own_details(self):
        """details.upload_id is the only join between a run row and the upload
        still streaming in this browser."""
        blk = self.WF[self.WF.index("async stopWorkflow(runId)"):][:1600]
        self.assertIn("(run.details || {}).upload_id", blk)

    def test_a_run_with_no_upload_is_unaffected(self):
        """Every other run type reaches this code too — it must be a no-op."""
        blk = self.WF[self.WF.index("async stopWorkflow(runId)"):][:1600]
        self.assertIn("if (uploadId && window.TusUploader", blk)


class TestTheUploadLogReadsInOrder(unittest.TestCase):
    """tusd does not serialise its hooks. The last post-receive calls routinely
    arrive AFTER post-finish, so a real run logged:

        Upload complete: 1535.9 MB received
        staging 1536 MB onto the analysis volume…
        Uploading: 98% (1504.0 / 1535.9 MB)
        Uploading: 100% (1535.9 / 1535.9 MB)

    — the end of the upload filed behind the start of the analysis, which reads
    as though the analysis began before the file had arrived.
    """

    SRC = _read("modules/backend/routes/upload_routes.py")

    def test_finished_uploads_are_remembered(self):
        self.assertIn("_finished_uploads = set()", self.SRC)
        self.assertIn("def _mark_upload_finished(", self.SRC)

    def test_a_late_progress_hook_is_dropped(self):
        blk = self.SRC[self.SRC.index("elif event_type == 'post-receive':"):][:1400]
        self.assertIn("if upload_id in _finished_uploads:", blk)
        self.assertLess(blk.index("if upload_id in _finished_uploads:"),
                        blk.index("if run_id and total_size > 0:"),
                        "the drop must come before anything is written")

    def test_the_door_closes_before_the_first_completion_line(self):
        """Marking it finished AFTER logging would leave the same race open."""
        blk = self.SRC[self.SRC.index("elif event_type == 'post-finish':"):][:3000]
        self.assertLess(blk.index("_mark_upload_finished(upload_id)"),
                        blk.index('add_log_to_run(run_id, f"Upload complete'))

    def test_the_set_does_not_grow_for_ever(self):
        """A long-lived process gathering a 32-char id per upload."""
        blk = self.SRC[self.SRC.index("def _mark_upload_finished("):][:600]
        self.assertIn("len(_finished_uploads) > 256", blk)


class TestAFailedUploadDoesNotStrandTheImage(unittest.TestCase):
    """If the run fails before the pipeline takes the image — a ZIP with no
    memory file in it, a file too small to be a dump, any exception on the way
    — the staged copy is nobody's: the pipeline's cleanup never ran and no
    other code knows the path. Caught live on a 5 MB test file, which failed
    the "too small to be a memory dump" check and left itself on the analysis
    volume. On a real dump that is gigabytes."""

    SRC = _read("modules/backend/routes/upload_routes.py")
    BLK = SRC[SRC.index("def run_memory_upload"):][:7000]

    def test_ownership_is_tracked(self):
        self.assertIn("dispatched = False", self.BLK)
        self.assertIn("dispatched = True", self.BLK)

    def test_the_pipeline_takes_ownership_immediately_before_it_runs(self):
        self.assertLess(self.BLK.index("dispatched = True"),
                        self.BLK.index("memory_pipeline.run_memory_pipeline("))

    def test_an_unowned_image_is_reclaimed(self):
        tail = self.BLK[self.BLK.index("finally:"):]
        self.assertIn("if not dispatched:", tail)
        self.assertIn("shutil.rmtree(staging", tail)

    def test_a_dispatched_run_keeps_its_image(self):
        """The pipeline owns it from that point: reclaiming it here would
        delete the image out from under a run that is still analysing it."""
        tail = self.BLK[self.BLK.index("finally:"):]
        self.assertNotIn("shutil.rmtree(staging, ignore_errors=True)\n                        add_log",
                         tail.replace("if not dispatched:", "X"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
