"""A plugin that crashed must not read like a plugin that found nothing.

VolWeb stores both the same way: no rows, `error_message` empty. So the run log
said "missing (no row or empty results): NetScan, NetStat, UserAssist" for a
real image where, in truth:

  * UserAssist ran fine and the host genuinely had no entries
  * NetScan ran fine and returned nothing
  * NetStat CRASHED — vol3 logged "Could not run plugin: Unable to find
    _PrimitiveObject__new_value for type ...String" right after announcing it

Read as one list, that invites an analyst to conclude "no network connections
on this host". It is the difference between a fact about the evidence and a
hole in it, which in a forensics report is the whole game.

The worker log is the only place the difference is written down, so these tests
pin the attribution: the failure line does NOT name its plugin, and is
attributed to the last one announced.
"""

import ast
import os
import re
import subprocess
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT = os.path.join(ROOT, "modules/backend/services/memory/volweb_client.py")

# A real excerpt, trimmed: the shapes vol3 and Celery actually emit.
LOG = """
[2026-09-23 12:04:52,476: INFO/ForkPoolWorker-84] RUNNING: volatility3.plugins.windows.registry.userassist.UserAssist
[2026-09-23 12:04:52,957: WARNING/ForkPoolWorker-84] UserAssist key not found in \\??\\C:\\Users\\v\\ntuser.dat
[2026-09-23 12:04:53,638: INFO/ForkPoolWorker-84] RUNNING: volatility3.plugins.windows.pstree.PsTree
[2026-09-23 12:15:05,341: INFO/ForkPoolWorker-84] RUNNING: volatility3.plugins.windows.netscan.NetScan
[2026-09-23 12:15:39,244: INFO/ForkPoolWorker-84] RUNNING: volatility3.plugins.windows.netstat.NetStat
[2026-09-23 12:15:39,411: INFO/ForkPoolWorker-84] Download PDB file...
[2026-09-23 12:15:44,596: WARNING/ForkPoolWorker-84] Could not run plugin: Unable to find _PrimitiveObject__new_value for type <class 'volatility3.framework.objects.String'>
[2026-09-23 12:15:44,698: INFO/ForkPoolWorker-84] RUNNING: volatility3.plugins.windows.psscan.PsScan
"""


def _load_method(name, extra=None):
    with open(CLIENT, encoding="utf-8") as fh:
        src = fh.read()
    cls = next(n for n in ast.parse(src).body
               if isinstance(n, ast.ClassDef) and n.name == "VolWebClient")
    fn = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == name)
    ns = {"re": re, "subprocess": subprocess, "os": os,
          "_config_value": lambda *a, **k: None,
          "_VOLWEB_WORKER_CONTAINER": "intact_volweb_workers"}
    ns.update(extra or {})
    exec(compile(ast.get_source_segment(src, fn), CLIENT, "exec"), ns)
    return ns[name]


def _with_log(text, *, fail=None):
    """The method under test, with `docker logs` replaced by `text`."""
    class _Proc:
        def run(self, *a, **k):
            if fail:
                raise fail
            return type("R", (), {"stdout": text, "stderr": ""})
        TimeoutExpired = subprocess.TimeoutExpired
    return _load_method("plugins_that_failed", {"subprocess": _Proc()})


class _Self:
    pass


class TestOnlyTheCrashedPluginIsNamed(unittest.TestCase):

    def setUp(self):
        self.f = _with_log(LOG)

    def test_the_failure_is_attributed_to_the_plugin_that_was_running(self):
        got = self.f(_Self(), ["NetScan", "NetStat", "UserAssist"])
        self.assertEqual(list(got), ["NetStat"])
        self.assertIn("_PrimitiveObject__new_value", got["NetStat"])

    def test_a_plugin_that_merely_found_nothing_is_not_accused(self):
        got = self.f(_Self(), ["NetScan", "UserAssist"])
        self.assertEqual(got, {}, "a quiet plugin must not be reported as failed")

    def test_a_plugin_nobody_asked_about_is_not_reported(self):
        """The scan sees the whole log, including other runs' plugins."""
        self.assertEqual(self.f(_Self(), ["PsScan"]), {})

    def test_full_class_paths_are_accepted_too(self):
        got = self.f(_Self(), ["volatility3.plugins.windows.netstat.NetStat"])
        self.assertEqual(list(got), ["NetStat"])

    def test_nothing_asked_means_nothing_scanned(self):
        self.assertEqual(self.f(_Self(), []), {})
        self.assertEqual(self.f(_Self(), None), {})


class TestItNeverTurnsASuccessIntoAFailure(unittest.TestCase):
    """Best-effort by design: this runs at the END of a completed extraction,
    so any trouble reading the log must leave the old message intact."""

    def test_no_docker_is_not_a_plugin_failure(self):
        f = _with_log("", fail=FileNotFoundError("docker"))
        self.assertEqual(f(_Self(), ["NetStat"]), {})

    def test_a_timeout_is_not_a_plugin_failure(self):
        f = _with_log("", fail=subprocess.TimeoutExpired("docker", 30))
        self.assertEqual(f(_Self(), ["NetStat"]), {})

    def test_an_empty_log_is_not_a_plugin_failure(self):
        self.assertEqual(_with_log("")(_Self(), ["NetStat"]), {})

    def test_a_failure_with_no_running_line_before_it_is_ignored(self):
        f = _with_log("[x] WARNING Could not run plugin: something\n")
        self.assertEqual(f(_Self(), ["NetStat"]), {},
                         "an unattributable failure must not be pinned on a plugin")


class TestItOnlyReadsThisRunsSliceOfTheLog(unittest.TestCase):
    """The same plugin can crash in one run and succeed in the next — a missing
    PDB downloads once and then works. Scanning a fixed hour of log would pin a
    stale failure on a plugin that merely found nothing this time, which is the
    original mistake pointing the other way."""

    SRC = open(CLIENT, encoding="utf-8").read()

    def test_the_call_site_bounds_the_window_by_the_run(self):
        self.assertIn("since_s=int(time.time() - started_at) + 60", self.SRC)

    def test_the_window_is_passed_as_docker_since(self):
        f = _load_method("plugins_that_failed", {"subprocess": self._recorder()})
        f(_Self(), ["NetStat"], since_s=42)
        self.assertIn("42s", self.seen, "the window never reached docker logs")

    def _recorder(self):
        outer = self

        class _Proc:
            TimeoutExpired = subprocess.TimeoutExpired

            def run(self, argv, *a, **k):
                outer.seen = " ".join(argv)
                return type("R", (), {"stdout": "", "stderr": ""})
        return _Proc()


class TestThePreserveMessageDoesNotInventAFlow(unittest.TestCase):
    """A re-analysis or an uploaded dump never had a Velociraptor flow, and
    "The Velociraptor flow (none) is removed as usual" reads like a fault."""

    SRC = open(os.path.join(ROOT, "modules/backend/services/memory/cleanup.py"),
               encoding="utf-8").read()

    def test_the_flow_sentence_is_conditional(self):
        self.assertIn("if flow_id else \"\"", self.SRC)

    def test_it_no_longer_prints_a_none_flow(self):
        self.assertNotIn("Velociraptor flow {flow_id or '(none)'} is removed", self.SRC)


if __name__ == "__main__":
    unittest.main(verbosity=2)
