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
    BLK = SRC[SRC.index("def run_memory_upload"):][:5200]

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
        tail = self.SRC[self.SRC.index("def run_memory_upload"):][:4000]
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
