"""Every Windows MEMORY run on this appliance failed, and none of it looked
like what it was.

Volatility3 has no Windows symbols of its own. It finds the kernel in the dump,
reads its PDB GUID, and downloads ntkrnlmp.pdb from msdl.microsoft.com. When
that download fails — an air-gapped site, a blocked egress — vol3 raises
UnsatisfiedException, VolWeb's engine catches it, and the Celery task ends:

    Symbol file could not be downloaded from remote server
    Unsatisfied requirements:
    Task VolWeb.SelectiveEngine[...] succeeded in 36.09s: None

Zero plugins constructed, task reports SUCCESS, 36 seconds. Downstream, three
things then went wrong, and this file pins all three plus the fourth bug found
alongside them:

  1. the wait loop could not tell "finished, produced nothing" from "still
     working", so it sat out the full 1800 s budget and reported a TIMEOUT —
     sending QA after wall-clock and dump size, neither of which was involved;
  2. cleanup then deleted the 9.2 GB image from the host, from VolWeb staging
     and from Velociraptor, so the retry cost a full re-acquisition from the
     endpoint for a run that never got past symbol resolution;
  3. "All plugins (deep dive)" expanded `['*']` by asking VolWeb which plugins
     it had registered FOR THIS EVIDENCE — rows that only exist AFTER an
     extraction — so it silently ran the same curated set as "standard";
  4. and six of the class paths we ask VolWeb to run do not exist in its
     registry at all. It drops unknown names with no row and no error, so
     "Memory Analysis: Credentials" ran one of its three plugins and the
     curated set could only ever reach 11 of the 12 it counted.

Verified against forensicxlab/volweb-backend:3.16.0 (volatility3 2.28.0), the
image this appliance runs.
"""

import os
import sys
import tempfile
import unittest

for _p in (os.path.dirname(os.path.abspath(__file__)),
           os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402

from services.memory import cleanup as cleanup_mod  # noqa: E402
from services.memory import pipeline as pipeline_mod  # noqa: E402
from services.memory.defaults import CURATED_PLUGINS, KNOWN_VOL3_PLUGINS  # noqa: E402
from services.memory.volweb_client import VolWebClient, VolWebError  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BLUEPRINTS = os.path.join(ROOT, "modules/backend/config/default_blueprints.yaml")

CATALOG = tuple(path for _group, path in KNOWN_VOL3_PLUGINS)

SYMBOL_REASON = (
    "Volatility could not get kernel symbols for this image — no plugin could "
    "run. The image needs the ISF for ntkrnlmp.pdb 3006AD7D…2. "
    "See docs/MEMORY_SYMBOLS_AIRGAP.md."
)


def _client():
    """A VolWebClient that never talks to anything. Constructed with explicit
    credentials so __init__ does not go looking at config.yaml or the config DB."""
    c = VolWebClient("http://volweb.invalid", "u", "p")
    c.logged = []
    c._logger = lambda msg, level="info": c.logged.append((level, msg))
    return c


class TestWeOnlyAskForPluginsVolWebCanRun(unittest.TestCase):
    """engine.py:start_selective_extraction filters the requested list against
    its own JSON registry (`[p for p in selected_plugins if p in all_main]`) and
    silently drops the rest. A name that is not in the registry is not a slow
    plugin or a failed one — it is a plugin that never runs, with nothing in the
    log to say so. KNOWN_VOL3_PLUGINS is our mirror of that registry, so
    everything we dispatch has to be in it."""

    def test_the_catalog_is_the_whole_registry_and_has_no_duplicates(self):
        self.assertEqual(len(CATALOG), len(set(CATALOG)))
        # 66 main + 2 misc windows plugins in volweb-backend:3.16.0.
        self.assertEqual(len(CATALOG), 68)

    def test_the_mirror_matches_the_image_not_the_volatility_docs(self):
        """Spot-check both directions against volweb_plugins.json inside
        volweb-backend:3.16.0. Everything on the left is a real Volatility 3
        plugin that VolWeb does NOT register — all six were in our catalog and
        five were in shipped blueprints. Everything on the right VolWeb runs and
        we never offered."""
        w = "volatility3.plugins.windows."
        for absent in ("registry.printkey.PrintKey", "handles.Handles",
                       "hollowfind.Hollowfind", "hashdump.Hashdump",
                       "lsadump.Lsadump", "mftscan.MFTScan"):
            self.assertNotIn(w + absent, CATALOG)
        for present in ("registry.hashdump.Hashdump", "registry.lsadump.Lsadump",
                        "shimcachemem.ShimcacheMem", "mftscan.ADS",
                        "unhooked_system_calls.unhooked_system_calls",
                        "registry.scheduled_tasks.ScheduledTasks"):
            self.assertIn(w + present, CATALOG)

    def test_every_curated_plugin_is_one_volweb_registers(self):
        missing = [p for p in CURATED_PLUGINS if p not in CATALOG]
        self.assertEqual(missing, [], "these can never produce a row")

    def test_every_shipped_blueprint_only_names_plugins_volweb_registers(self):
        """This is the one that fails against the old YAML: it named
        registry.printkey.PrintKey, handles.Handles, hollowfind.Hollowfind,
        hashdump.Hashdump and lsadump.Lsadump — none of which VolWeb 3.16.0
        has."""
        import yaml
        with open(BLUEPRINTS, encoding="utf-8") as fh:
            blueprints = yaml.safe_load(fh).get("memory") or []
        self.assertTrue(blueprints, "no memory blueprints found to check")
        offenders = {}
        for bp in blueprints:
            for path in ((bp.get("settings") or {}).get("plugin_set") or []):
                if path != "*" and path not in CATALOG:
                    offenders.setdefault(bp.get("id"), []).append(path)
        self.assertEqual(offenders, {})

    def test_the_credentials_blueprint_can_still_dump_credentials(self):
        """It asked for hashdump/lsadump/cachedump and got ONE of the three:
        VolWeb registers the first two under registry.*. A blueprint that runs
        a third of what it promises is worse than one that refuses."""
        import yaml
        with open(BLUEPRINTS, encoding="utf-8") as fh:
            blueprints = yaml.safe_load(fh).get("memory") or []
        creds = next(b for b in blueprints if b["id"] == "memory_credentials_deep")
        plugins = (creds["settings"] or {})["plugin_set"]
        self.assertEqual(len([p for p in plugins if p in CATALOG]), len(plugins))
        self.assertTrue(any("hashdump" in p for p in plugins))
        self.assertTrue(any("lsadump" in p for p in plugins))


class TestTheDeepDiveRunsEveryPlugin(unittest.TestCase):
    """`['*']` used to resolve through client.list_plugins(evidence_id), which
    is structurally empty before the first extraction — the rows are written BY
    the run being dispatched. So it fell back to the curated set every time and
    "deep dive" was a synonym for "standard"."""

    def setUp(self):
        self.logged = []
        self.log = lambda m, lvl="info": self.logged.append((lvl, m))

    def resolve(self, plugin_set):
        return pipeline_mod._resolve_plugin_set(
            {"settings": {"plugin_set": plugin_set}}, self.log)

    def test_star_expands_to_every_plugin_volweb_can_run(self):
        self.assertEqual(sorted(self.resolve(["*"])), sorted(CATALOG))

    def test_star_is_not_quietly_the_curated_set(self):
        got = self.resolve(["*"])
        self.assertGreater(len(got), len(CURATED_PLUGINS) * 2)
        # The one plugin the curated set deliberately excludes for cost is
        # exactly what a deep dive is for.
        self.assertIn("volatility3.plugins.windows.hollowprocesses.HollowProcesses", got)

    def test_it_needs_no_evidence_and_no_volweb_round_trip(self):
        """Resolution happens BEFORE the extraction exists. Any signature that
        still wanted an evidence id or a client could not be called here."""
        import inspect
        params = list(inspect.signature(pipeline_mod._resolve_plugin_set).parameters)
        self.assertEqual(params, ["blueprint", "log"])

    def test_an_explicit_set_is_still_honoured_and_empty_falls_back(self):
        self.assertEqual(self.resolve(["a.b.C"]), ("a.b.C",))
        self.assertEqual(self.resolve([]), CURATED_PLUGINS)


class TestAnExtractionThatProducedNothingFailsFast(unittest.TestCase):
    """The task id is what makes this knowable. VolWeb's view writes it to
    evidence.celery_task_id before answering the POST; the task's finally block
    clears it when it ends, whichever way it ended. Ours no longer being there,
    with zero rows, means nothing is coming."""

    def setUp(self):
        self.client = _client()
        self.client.list_plugins = lambda _e: self.rows
        self.client.extraction_failure_reason = lambda **_k: SYMBOL_REASON
        self.rows = []
        self.snapshot = {"celery_task_id": "", "status": -1}
        self.client._evidence_snapshot = lambda _e: self.snapshot

    def wait(self, **kw):
        kw.setdefault("timeout_s", 1800)
        kw.setdefault("poll_s", 1)
        return self.client.wait_for_plugin_results(7, CURATED_PLUGINS, **kw)

    def test_it_aborts_instead_of_waiting_out_the_budget(self):
        with self.assertRaises(VolWebError):
            self.wait(task_id="T-1")

    def test_the_error_names_symbols_and_never_says_timed_out(self):
        with self.assertRaises(VolWebError) as caught:
            self.wait(task_id="T-1")
        self.assertIn("kernel symbols", str(caught.exception))
        self.assertNotIn("timed out", str(caught.exception).lower())
        self.assertIn("MEMORY_SYMBOLS_AIRGAP", str(caught.exception))

    def test_it_says_so_at_error_level_with_the_task_id(self):
        with self.assertRaises(VolWebError):
            self.wait(task_id="T-1")
        errors = [m for lvl, m in self.client.logged if lvl == "error"]
        self.assertTrue(errors, "an abort must be logged, never silent")
        self.assertIn("T-1", errors[-1])

    def test_without_the_task_id_the_same_run_only_ever_times_out(self):
        """The old behaviour, still reachable: no authoritative signal, so the
        loop can only spend the budget and report 0/N. This is what a 36-second
        failure looked like for 30 minutes."""
        plugin_map, completed = self.wait(timeout_s=0)
        self.assertEqual(plugin_map, {})
        self.assertFalse(completed)

    def test_a_task_still_running_is_left_alone(self):
        self.snapshot = {"celery_task_id": "T-1", "status": 0}
        plugin_map, completed = self.wait(task_id="T-1", timeout_s=0)
        self.assertFalse(completed, "a running task must not be aborted")

    def test_an_unreadable_evidence_row_is_not_evidence_of_anything(self):
        """A restarting daphne answers 502. 'Don't know' must never be read as
        'finished' — that would abort healthy runs on a flaky read."""
        self.client._evidence_snapshot = lambda _e: None
        plugin_map, completed = self.wait(task_id="T-1", timeout_s=0)
        self.assertFalse(completed)

    def test_results_that_did_land_are_kept_not_aborted(self):
        self.rows = [{"name": CURATED_PLUGINS[0], "results": [{"pid": 4}]}]
        plugin_map, completed = self.wait(task_id="T-1", timeout_s=0)
        self.assertIn(CURATED_PLUGINS[0], plugin_map)

    def test_the_generic_fallback_still_points_at_the_worker_log(self):
        """No symbol failure in the log: the abort is still right, the reason is
        just less specific. It must not go silent."""
        self.client.extraction_failure_reason = lambda **_k: None
        with self.assertRaises(VolWebError) as caught:
            self.wait(task_id="T-1")
        self.assertIn("intact_volweb_workers", str(caught.exception))


class TestTheDumpSurvivesAnExtractionThatProducedNothing(unittest.TestCase):
    """9.2 GB re-acquired from a customer endpoint because a symbol download
    failed. The image is exactly what the retry needs."""

    def setUp(self):
        self.calls = []
        self.logged = []
        for name in ("_remove_host_dump", "_remove_volweb_media_raw",
                     "cleanup_velociraptor_flow"):
            setattr(cleanup_mod, name,
                    (lambda n: lambda *a, **k: self.calls.append(n))(name))
        self.kw = dict(
            client_id="C.1", flow_id="F.1", host_path="/data/memory_dumps/x.raw",
            evidence_id=3, evidence_filename="x.raw", volweb_client=None,
            logger=lambda m, lvl="info": self.logged.append((lvl, m)),
        )

    def test_all_three_copies_are_kept(self):
        cleanup_mod.cleanup_after_run(preserve_dump=True, **self.kw)
        self.assertEqual(self.calls, [])

    def test_and_the_log_says_where_they_are(self):
        cleanup_mod.cleanup_after_run(preserve_dump=True, **self.kw)
        said = " ".join(m for _lvl, m in self.logged)
        for expected in ("PRESERVING", "/data/memory_dumps/x.raw", "x.raw", "F.1"):
            self.assertIn(expected, said)

    def test_a_normal_run_still_reclaims_every_one_of_them(self):
        """Non-vacuous: without the flag this must delete all three, or the test
        above proves nothing."""
        cleanup_mod.cleanup_after_run(**self.kw)
        self.assertEqual(sorted(self.calls),
                         ["_remove_host_dump", "_remove_volweb_media_raw",
                          "cleanup_velociraptor_flow"])


class _FakeClient:
    """Stands in for VolWebClient across a whole pipeline run."""

    def __init__(self, outcome, **_kw):
        self.outcome = outcome
        self.task_ids = []

    def ensure_case(self, _name): return 1
    def upload_evidence(self, *_a, **_k): return 9
    def get_evidence(self, _i): return {"name": "dump.raw", "celery_task_id": "T-9"}
    def stage_media_dir(self, _i): return None
    def yarascan_history(self, _i): return []
    def list_plugins(self, _i): return []
    def fetch_plugin(self, *_a, **_k): return None

    def trigger_extraction(self, _e, _p):
        self.task_ids.append("T-9")
        return "T-9"

    def wait_for_plugin_results(self, _e, plugins, **_kw):
        if isinstance(self.outcome, Exception):
            raise self.outcome
        return self.outcome


class TestThePipelineKeepsTheDumpWhenTheExtractionGaveNothing(unittest.TestCase):
    """Executed, not asserted about: the real run_memory_pipeline drives a fake
    VolWeb from upload to cleanup, and we read the kwargs cleanup was actually
    called with."""

    def setUp(self):
        self.cleanup_kwargs = []
        self.logged = []
        self.patched = {}
        fake = {
            "add_log_to_run": lambda rid, msg, lvl="info": self.logged.append((lvl, msg)),
            "update_run_status": lambda *a, **k: None,
            "mutate_run_details": lambda *a, **k: None,
            "register_cleanup": lambda *a, **k: None,
            "unregister_cancel": lambda *a, **k: None,
            "register_cancel_event": lambda _rid: type("E", (), {"is_set": staticmethod(lambda: False)})(),
            "cleanup_after_run": lambda **kw: self.cleanup_kwargs.append(kw),
        }
        for name, impl in fake.items():
            self.patched[name] = getattr(pipeline_mod, name)
            setattr(pipeline_mod, name, impl)
        self.dump = tempfile.NamedTemporaryFile(suffix=".raw", delete=False)
        self.dump.write(b"MEMORY")
        self.dump.close()

    def tearDown(self):
        for name, impl in self.patched.items():
            setattr(pipeline_mod, name, impl)
        os.unlink(self.dump.name)

    def run_pipeline(self, outcome):
        pipeline_mod.VolWebClient = lambda **kw: _FakeClient(outcome, **kw)
        try:
            pipeline_mod.run_memory_pipeline(
                run_id="r1", mode="plugin", from_upload_path=self.dump.name,
                case_name="c",
            )
        finally:
            pipeline_mod.VolWebClient = VolWebClient
        self.assertTrue(self.cleanup_kwargs, "cleanup must run on every path")
        return self.cleanup_kwargs[-1]

    def test_zero_plugins_preserves_the_dump(self):
        self.assertTrue(self.run_pipeline(({}, True))["preserve_dump"])

    def test_an_aborted_extraction_preserves_the_dump(self):
        kw = self.run_pipeline(VolWebError(SYMBOL_REASON))
        self.assertTrue(kw["preserve_dump"])

    def test_and_the_run_log_carries_the_real_cause(self):
        self.run_pipeline(VolWebError(SYMBOL_REASON))
        said = " ".join(m for _lvl, m in self.logged)
        self.assertIn("kernel symbols", said)

    def test_a_timeout_with_partial_results_still_preserves_it(self):
        """`completed=False` means plugins were still outstanding when the
        budget ran out — the image is still the cheapest way to get them."""
        partial = ({CURATED_PLUGINS[0]: {"results": [1]}}, False)
        self.assertTrue(self.run_pipeline(partial)["preserve_dump"])

    def test_a_successful_run_still_reclaims_the_disk(self):
        """Non-vacuous the other way: a working run must NOT start hoarding
        multi-GB images."""
        full = ({p: {"results": [1]} for p in CURATED_PLUGINS}, True)
        self.assertFalse(self.run_pipeline(full)["preserve_dump"])


class TestTheSymbolStoreIsReportedNotGuessed(unittest.TestCase):
    """Install, upgrade and the failure message all answer 'does this box have
    symbols' from the same place VolWeb reads them from."""

    def test_the_client_counts_isfs_where_volweb_actually_looks(self):
        import services.memory.volweb_client as vc
        self.assertEqual(vc._VOLWEB_SYMBOLS_DIR, "/home/app/web/media/symbols")

    def test_an_unreachable_docker_is_unknown_not_zero(self):
        c = _client()
        c._resolve_backend_container = lambda: None
        self.assertIsNone(c.windows_symbol_isf_count())

    def test_the_failure_reason_is_none_when_the_log_shows_no_symbol_failure(self):
        c = _client()
        import subprocess
        real = subprocess.run
        subprocess.run = lambda *a, **k: type(
            "R", (), {"returncode": 0, "stdout": "Task succeeded\n", "stderr": ""})()
        try:
            self.assertIsNone(c.extraction_failure_reason())
        finally:
            subprocess.run = real

    def test_the_failure_reason_quotes_the_worker_and_the_pdbconv_command(self):
        c = _client()
        c._resolve_backend_container = lambda: None
        import subprocess
        real = subprocess.run
        log = (
            "[2026-09-22 10:00:00: INFO/MainProcess] Symbol file could not be "
            "downloaded from remote server\n"
            "[2026-09-22 10:00:00: INFO/MainProcess] The symbols can be downloaded "
            "later using pdbconv.py -p ntkrnlmp.pdb -g 3006AD7DBD884D8EB8F92EC21FFCEE4E2\n"
        )
        # Celery logs to stderr; reading only stdout finds nothing.
        subprocess.run = lambda *a, **k: type(
            "R", (), {"returncode": 0, "stdout": "", "stderr": log})()
        try:
            reason = c.extraction_failure_reason()
        finally:
            subprocess.run = real
        self.assertIn("kernel symbols", reason)
        self.assertIn("ntkrnlmp.pdb", reason)
        self.assertIn("3006AD7DBD884D8EB8F92EC21FFCEE4E2", reason)
        self.assertIn("MEMORY_SYMBOLS_AIRGAP", reason)


if __name__ == "__main__":
    unittest.main()
