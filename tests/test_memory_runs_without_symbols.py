"""A memory run survives symbols it does not have.

Volatility cannot construct a single Windows plugin without the kernel's ISF,
and Microsoft ships new builds constantly — so "we do not have symbols for this
image yet" is a routine outcome, not an exceptional one. Chasing it by pinning
a symbol pack per release is not sustainable; the run has to degrade instead.

What it looked like before: `wait_for_plugin_results` raised on a symbol
failure, the exception left the extract phase, and the yarascan below it was
NEVER WAITED ON — so a layered run threw away YARA results it already had,
because of a failure that cannot affect them. A yarascan is a raw byte scan
over the image; it does not know what a symbol is.

What must hold now:

  * a symbol failure does not leave the extract phase
  * the yarascan still runs, and its hits still reach the case
  * the run is only marked FAILED when nothing at all came back
  * per-plugin failures keep isolating inside VolWeb (NetStat can die while
    the other ten succeed) — that part already worked
"""

import ast
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PIPELINE = os.path.join(ROOT, "modules/backend/services/memory/pipeline.py")


def _read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
        return fh.read()


def _load(name):
    src = _read("modules/backend/services/memory/pipeline.py")
    fn = next(n for n in ast.parse(src).body
              if isinstance(n, ast.FunctionDef) and n.name == name)
    ns = {}
    exec(compile(ast.get_source_segment(src, fn), PIPELINE, "exec"), ns)
    return ns[name]


outcome = _load("_extract_outcome_line")


class TestWhatCountsAsAFailedRun(unittest.TestCase):
    """The level is not cosmetic: add_log_to_run increments error_count and a
    non-zero count auto-flips the run to FAILED. So `error` means "this run
    produced nothing", not "something went wrong somewhere"."""

    def test_plugins_ran_and_finished(self):
        _, lvl = outcome(8, 12, 842, True, 1800)
        self.assertEqual(lvl, "success")

    def test_partial_plugins_after_a_timeout_are_still_useful(self):
        _, lvl = outcome(8, 12, 1800, False, 1800)
        self.assertEqual(lvl, "warning")

    def test_no_symbols_but_yara_hits_is_NOT_a_failed_run(self):
        """The case gets 84 real hits. Failing the run would hide them behind a
        red row and tell the operator nothing was collected."""
        msg, lvl = outcome(0, 12, 40, True, 1800, yara_hits=84)
        self.assertEqual(lvl, "warning")
        self.assertIn("84 hit(s)", msg)
        self.assertIn("do not depend on symbols", msg)

    def test_nothing_at_all_is_a_failed_run(self):
        _, lvl = outcome(0, 12, 40, True, 1800, yara_hits=0)
        self.assertEqual(lvl, "error")

    def test_a_timeout_with_yara_hits_is_also_survivable(self):
        _, lvl = outcome(0, 12, 1800, False, 1800, yara_hits=3)
        self.assertEqual(lvl, "warning")

    def test_a_timeout_with_nothing_is_not(self):
        _, lvl = outcome(0, 12, 1800, False, 1800)
        self.assertEqual(lvl, "error")

    def test_the_message_says_which_of_the_two_happened(self):
        """"finished without extracting anything" (symbols) and "hit the budget"
        (slow) send the operator to completely different places."""
        done, _ = outcome(0, 12, 40, True, 1800)
        timed, _ = outcome(0, 12, 1800, False, 1800)
        self.assertIn("finished without extracting anything", done)
        self.assertIn("budget", timed)


class TestTheSymbolFailureStaysInsideThePhase(unittest.TestCase):

    SRC = _read("modules/backend/services/memory/pipeline.py")

    def test_the_plugin_wait_is_caught(self):
        blk = self.SRC[self.SRC.index("plugin_map, plugins_done = client.wait_for_plugin_results"):][:1400]
        self.assertIn("except VolWebError", blk)

    def test_it_does_not_re_raise(self):
        """Re-raising is exactly what skipped the yarascan."""
        blk = self.SRC[self.SRC.index("except VolWebError as _pe:"):][:600]
        self.assertNotIn("raise", blk)

    def test_the_yarascan_is_still_reached(self):
        """The catch must sit BEFORE the yarascan, or nothing changed."""
        self.assertLess(self.SRC.index("except VolWebError as _pe:"),
                        self.SRC.index("hit_count, _yara_done = client.wait_for_yarascan"))

    def test_the_outcome_is_judged_after_the_yarascan(self):
        """Judging it before means deciding whether the run failed without
        knowing whether the yarascan returned anything."""
        self.assertLess(self.SRC.index("hit_count, _yara_done = client.wait_for_yarascan"),
                        self.SRC.index("msg, level = _extract_outcome_line("))

    def test_the_operator_is_told_the_yarascan_is_unaffected(self):
        self.assertIn("needs no symbols", self.SRC)

    def test_a_plugin_only_run_has_nothing_to_fall_back_on(self):
        """With no yarascan there is no second source, and the log should say
        so rather than implying something else might still arrive."""
        self.assertIn("Nothing else in this run can produce results.", self.SRC)


class TestNothingBelowDecidesTheVerdict(unittest.TestCase):
    """The client aborts the plugin wait and raises. It used to log that at
    `error` first — and error-level lines increment error_count, which
    auto-flips the run to FAILED at the end. So a run whose plugins could not
    construct was marked failed even while the parallel yarascan was still
    running and about to return hits. Seen live: "0/12 plugins" logged as an
    error at 3s, yarascan still scanning 393s later.

    The verdict belongs to the caller, once BOTH halves are in."""

    SRC = _read("modules/backend/services/memory/volweb_client.py")

    def test_the_abort_is_a_warning_not_an_error(self):
        blk = self.SRC[self.SRC.index("reached a terminal state ") - 900:]
        blk = blk[:blk.index("raise VolWebError(reason)")]
        self.assertIn('"warning",', blk)
        self.assertNotIn('"error",', blk)

    def test_it_says_why_the_level_matters(self):
        self.assertIn("auto-flips it to FAILED", self.SRC)


class TestTheSymbolLibraryAccumulates(unittest.TestCase):
    """Vol3 writes a downloaded ISF into its OWN PACKAGE directory, which is
    container filesystem. Measured: 3 ISFs / 1.1 MB downloaded in one day;
    recreating the worker took the package dir to 0 while the volume kept all
    3. Without harvesting, every recreate and every VolWeb upgrade threw away
    every symbol the box had resolved — and an air-gapped appliance could never
    accumulate any at all."""

    SRC = _read("modules/backend/services/memory/volweb_client.py")

    def test_there_is_a_harvest(self):
        self.assertIn("def harvest_symbols(self)", self.SRC)

    def test_it_reads_the_worker_not_the_backend(self):
        """Volatility runs in the extraction worker, so that is the only
        container the downloads land in. Pointed at the backend it finds 0 and
        silently does nothing — which is how the first cut was written."""
        blk = self.SRC[self.SRC.index("def harvest_symbols(self)"):][:2600]
        self.assertIn('_config_value("worker_container"', blk)
        self.assertNotIn("_resolve_backend_container()", blk)

    def test_it_copies_into_the_volume_on_vol3s_search_path(self):
        blk = self.SRC[self.SRC.index("def harvest_symbols(self)"):][:2600]
        self.assertIn("/home/app/web/media/symbols", blk)

    def test_it_never_moves_and_never_overwrites(self):
        """The package dir must stay valid for the running process, and an ISF
        an operator seeded by hand always wins."""
        blk = self.SRC[self.SRC.index("def harvest_symbols(self)"):][:2600]
        self.assertIn("cp -rn", blk)
        self.assertNotIn("mv ", blk)

    def test_it_cannot_break_a_finished_run(self):
        """Housekeeping after the results are already in."""
        blk = self.SRC[self.SRC.index("def harvest_symbols(self)"):][:3400]
        self.assertIn("except Exception:", blk)
        self.assertIn("return -1", blk)

    def test_the_pipeline_calls_it_and_survives_it_failing(self):
        pipe = _read("modules/backend/services/memory/pipeline.py")
        self.assertIn("client.harvest_symbols()", pipe)
        blk = pipe[pipe.index("client.harvest_symbols()") - 400:]
        blk = blk[:800]
        self.assertIn("except Exception as _se:", blk)


if __name__ == "__main__":
    unittest.main(verbosity=2)
