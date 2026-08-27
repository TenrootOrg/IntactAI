"""Getting TimeSketch into the case graph without dragging the timeline in.

WHY THIS EXISTS. A single-host KAPE timeline measured 380,038 events at ~1 KB
each — 390 MB, 90% of it registry keys. Nothing about that belongs in a 2500-
entity case graph, so the integration is built entirely around *selection*:

  * WHICH events exist to select is decided by the analyzers Timesketch runs
    (they write the tags); the curated AUTO_SKETCH_ANALYZERS list is that
    control, and dropping the flood analyzers is what makes "has a tag" mean
    something. Measured after curation: 3,542 tagged docs across 4 tags.
  * WHICH tagged events are read is bounded by the case's time window, applied
    inside the OpenSearch query so out-of-window events are never serialized.
  * HOW MANY reach the graph is bounded twice — per tag, and absolutely.

Three failures this file exists to prevent, all of which shipped once:

  * A run that completes before its analyzers do. `timesketch` is in
    AGENTIC_TYPES, so completion arms the case auto-fuse 60 seconds later; on
    the real import all 75 analyzer tasks were still PENDING at that moment and
    `_exists_:tag` matched exactly 0 documents. Nothing re-armed when the tags
    landed, so TimeSketch contributed nothing to the case forever.
  * A window filter that also hides starred events. An analyst's star is a
    human judgment, and the events most worth starring — timestomped files,
    whose timestamps are absurd by construction (this index's minimum is 1970)
    — are precisely the ones a window would cut.
  * A distiller whose only cap is per-tag. That is bounded only while the tag
    vocabulary is: sigma tags per RULE NAME, so one broad ruleset turns
    "5 per tag" into thousands of events.
"""

import ast
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STORE = os.path.join(ROOT, "modules/backend/services/fusion/store.py")
TSSVC = os.path.join(ROOT, "modules/backend/services/timesketch_service.py")
MAPPER = os.path.join(ROOT, "modules/backend/services/fusion/mappers/timesketch.py")
WS = os.path.join(ROOT, "modules/backend/services/workflow_service.py")
APP = os.path.join(ROOT, "modules/backend/app.py")
CONF = os.path.join(ROOT, "modules/timesketch/config/timesketch.conf.template")
LEGACY_CONF = os.path.join(ROOT, "modules/timesketch/config/timesketch_legacy.conf.template")
DEPLOY = os.path.join(ROOT, "lib/modules/timesketch.sh")


def read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def load_func(path, name, extra_globals=None):
    """Exec one function out of its module. Importing the backend for a pure
    helper drags grpc, the storage layer and a DB connection along with it."""
    src = read(path)
    tree = ast.parse(src)
    ns = dict(extra_globals or {})
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            exec(compile(ast.Module([node], []), path, "exec"), ns)
            return ns[name]
    raise AssertionError(f"{name} not found in {path}")


def func_source(path, name):
    src = read(path)
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return ast.get_source_segment(src, node)
    raise AssertionError(f"{name} not found in {path}")


# ---------------------------------------------------------------- the window

class TestTheWindowBoundsTheQueryNotTheResult(unittest.TestCase):
    """The case window has to reach the OpenSearch query. Applied afterwards it
    is a filter on 390 MB that has already crossed the wire."""

    def setUp(self):
        self.clause = load_func(TSSVC, "_ts_window_clause")

    def test_a_normal_window_becomes_a_range(self):
        got = self.clause({"start": "2026-08-01T00:00:00", "end": "2026-08-27T00:00:00"})
        self.assertEqual(got, "datetime:[2026-08-01T00:00:00 TO 2026-08-27T00:00:00]")

    def test_a_half_open_window_wildcards_the_missing_side(self):
        self.assertEqual(self.clause({"start": "2026-08-01"}), "datetime:[2026-08-01 TO *]")
        self.assertEqual(self.clause({"end": "2026-08-27"}), "datetime:[* TO 2026-08-27]")

    def test_no_window_is_no_clause(self):
        for empty in (None, {}, {"start": "", "end": ""}, {"start": None, "end": None}):
            with self.subTest(empty=empty):
                self.assertEqual(self.clause(empty), "")

    def test_a_degenerate_window_widens_to_open_rather_than_excluding_everything(self):
        # Mirrors correlate.in_window: start >= end is operator error, and
        # answering it with an empty case is the least useful reading.
        self.assertEqual(self.clause({"start": "2026-08-27", "end": "2026-08-01"}), "")
        self.assertEqual(self.clause({"start": "2026-08-01", "end": "2026-08-01"}), "")


class TestStarredEventsOutrankTheWindow(unittest.TestCase):
    """An analyst starring an event is a human judgment about the case. It has
    to survive a filter the analyst may not even know is set."""

    def setUp(self):
        self.src = func_source(TSSVC, "fetch_sketch_events")

    def test_the_window_constrains_only_the_tag_arm(self):
        self.assertIn('f"(_exists_:tag AND {clause}) "', self.src)
        self.assertIn('f"OR label:__ts_star OR label:__ts_comment"', self.src)

    def test_without_a_window_the_query_is_unchanged_from_before(self):
        self.assertIn('query = "_exists_:tag OR label:__ts_star OR label:__ts_comment"',
                      self.src)

    def test_the_limit_is_enforced_client_side_too(self):
        # explore(max_entries=) is best-effort in the API client: it pages 10k
        # at a time, so a 2000 cap can return ~10,000 without this backstop.
        self.assertIn("if len(events) >= limit:", self.src)
        self.assertIn("break", self.src)

    def test_the_opensearch_id_is_kept(self):
        self.assertIn('src["_ts_id"] = str(o["_id"])', self.src)


# ------------------------------------------------------------- the distiller

class TestTheDistillerIsBoundedTwice(unittest.TestCase):
    """Per-tag alone is bounded only while the tag vocabulary is."""

    def setUp(self):
        # _distill_ts_events does `from .anomaly import score_row` at call
        # time, so the exec namespace needs package context for the relative
        # import to resolve — and the `services` shim below keeps
        # services/__init__.py (grpc) out of it. Real score_row, not a stub:
        # the absolute cap has to pick the highest-scoring events, and a fake
        # scorer would let a broken ranking pass.
        import sys
        import types
        backend = os.path.join(ROOT, "modules/backend")
        if "services" not in sys.modules:
            shim = types.ModuleType("services")
            shim.__path__ = [os.path.join(backend, "services")]
            sys.modules["services"] = shim
        self.distill = load_func(
            STORE, "_distill_ts_events",
            {"__name__": "services.fusion.store",
             "__package__": "services.fusion"})

    def _ev(self, tag, msg="x"):
        return {"tag": [tag], "message": msg}

    def test_per_tag_cap_keeps_every_distinct_detection(self):
        events = [self._ev("logon-event") for _ in range(3480)]
        events += [self._ev("rare-domain") for _ in range(20)]
        out = self.distill(events, per_tag=5)
        # The real distribution, measured: 3,480 logons must not bury 20
        # rare-domain hits.
        self.assertEqual(len(out), 10)

    def test_the_absolute_cap_bites_when_the_vocabulary_explodes(self):
        # One sigma tag per rule name is how a "5 per tag" bound becomes 5,000.
        events = [self._ev(f"sigma_rule_{i}") for i in range(1000)]
        out = self.distill(events, per_tag=5, cap=600)
        self.assertEqual(len(out), 600)

    def test_the_cap_is_off_when_asked(self):
        events = [self._ev(f"t{i}") for i in range(700)]
        self.assertEqual(len(self.distill(events, per_tag=5, cap=0)), 700)

    def test_an_untagged_event_still_survives(self):
        # Starred events carry no tag but are fetched deliberately.
        out = self.distill([{"message": "starred thing"}], per_tag=5)
        self.assertEqual(len(out), 1)

    def test_non_list_tags_and_junk_rows_do_not_crash_it(self):
        out = self.distill([{"tag": "single-string"}, "not a dict", None, {}], per_tag=5)
        self.assertEqual(len(out), 2)   # the string-tagged one + the bare {}

    def test_the_highest_scoring_events_win_the_ceiling(self):
        # score_row keys off the row text; a row naming a critical term must
        # outrank filler when the cap forces a choice.
        events = [{"tag": [f"t{i}"], "message": "routine"} for i in range(50)]
        events.append({"tag": ["t99"], "message": "mimikatz credential dump"})
        out = self.distill(events, per_tag=5, cap=1)
        self.assertEqual(len(out), 1)
        self.assertIn("mimikatz", out[0]["message"])


# ----------------------------------------------------------------- the mapper

class TestTheMapperKeepsWhyTheEventWasSelected(unittest.TestCase):
    """Fusion selects TimeSketch events by tag. Dropping the tag on the way
    into the graph records the event but not the detection — a rare-domain hit
    and a routine logon end up indistinguishable."""

    def setUp(self):
        # The mapper uses package-relative imports (keys / schema / anomaly),
        # so it must be imported as a package member rather than loaded from a
        # path. Those siblings are pure, but services/__init__.py is not — it
        # pulls in velociraptor_service and therefore grpc. Register a bare
        # `services` package pointing at the real directory so only the fusion
        # subtree is executed.
        import sys
        import types
        import importlib
        backend = os.path.join(ROOT, "modules/backend")
        if "services" not in sys.modules:
            shim = types.ModuleType("services")
            shim.__path__ = [os.path.join(backend, "services")]
            sys.modules["services"] = shim
        self.mod = importlib.import_module("services.fusion.mappers.timesketch")

    def _map(self, events):
        return self.mod.map_timesketch(events, run_id="r1",
                                       asset="asset:endpoint:C.1", hostname="HOST1")

    def test_tags_reach_the_event_entity(self):
        ents, _ = self._map([{"datetime": "2026-08-01T00:00:00Z",
                              "message": "logon", "tag": ["logon-event", "rare-domain"]}])
        ev = [e for e in ents if e.type == "event"]
        self.assertEqual(len(ev), 1)
        self.assertEqual(ev[0].attrs.get("tags"), ["logon-event", "rare-domain"])

    def test_an_untagged_event_carries_no_empty_tag_list(self):
        ents, _ = self._map([{"datetime": "2026-08-01T00:00:00Z", "message": "x"}])
        ev = [e for e in ents if e.type == "event"][0]
        self.assertNotIn("tags", ev.attrs)

    def test_the_locator_addresses_the_real_timesketch_event(self):
        # event/row=i indexes the DISTILLED list, which renumbers whenever the
        # analyzer tags change — it points at a different event next fetch.
        ents, _ = self._map([{"datetime": "2026-08-01T00:00:00Z", "message": "x",
                              "_ts_id": "abc123"}])
        ev = [e for e in ents if e.type == "event"][0]
        self.assertEqual(ev.evidence[0].locator, "sketch/event/abc123")

    def test_it_falls_back_to_the_row_index_without_an_id(self):
        ents, _ = self._map([{"datetime": "2026-08-01T00:00:00Z", "message": "x"}])
        ev = [e for e in ents if e.type == "event"][0]
        self.assertEqual(ev.evidence[0].locator, "event/row=0")

    def test_domains_in_the_message_become_iocs(self):
        # The docstring always promised domains; the regex was compiled and
        # never used, so the domain/phishy_domains analyzers produced tags with
        # nothing to correlate against.
        ents, _ = self._map([{"datetime": "2026-08-01T00:00:00Z",
                              "message": "beacon to evil-c2.example.net"}])
        iocs = [e for e in ents if e.type == "ioc"]
        self.assertTrue(any(e.label == "evil-c2.example.net" for e in iocs), iocs)

    def test_filenames_are_not_mistaken_for_domains(self):
        ents, _ = self._map([{"datetime": "2026-08-01T00:00:00Z",
                              "message": "ran svchost.exe and read NTUSER.DAT"}])
        iocs = [e.label for e in ents if e.type == "ioc"]
        self.assertEqual(iocs, [])

    def test_private_addresses_are_not_iocs(self):
        ents, _ = self._map([{"datetime": "2026-08-01T00:00:00Z",
                              "message": "connect 192.168.1.5 then 8.8.8.8"}])
        iocs = sorted(e.label for e in ents if e.type == "ioc")
        self.assertEqual(iocs, ["8.8.8.8"])


class TestATagIsADetectionAndScoresLikeOne(unittest.TestCase):
    """Found by running the thing: a real fuse pulled 382 tagged events and put
    ONE asset node in the graph. Every event had been selected for its analyzer
    tag, then dropped by the case's default `medium` severity floor because
    anomaly scoring keyword-matches the row text and a crash report does not say
    'mimikatz'. Selecting by detection and then ignoring the detection when
    scoring it is the same mistake twice."""

    def setUp(self):
        import sys
        import types
        import importlib
        backend = os.path.join(ROOT, "modules/backend")
        if "services" not in sys.modules:
            shim = types.ModuleType("services")
            shim.__path__ = [os.path.join(backend, "services")]
            sys.modules["services"] = shim
        self.mod = importlib.import_module("services.fusion.mappers.timesketch")

    def _sev(self, tag, msg="a routine looking message"):
        ents, _ = self.mod.map_timesketch(
            [{"datetime": "2026-08-01T00:00:00Z", "message": msg, "tag": [tag]}],
            run_id="r1", asset="asset:endpoint:C.1", hostname="H")
        return [e for e in ents if e.type == "event"][0].severity

    def test_a_detection_tag_clears_the_default_medium_floor(self):
        # Measured tags from the real import.
        self.assertEqual(self._sev("rare-domain"), "medium")

    def test_a_strong_detection_tag_goes_higher(self):
        for tag in ("win_crash", "sigma_rule_whatever", "phishy-domain",
                    "timestomp", "ssh-bruteforce"):
            with self.subTest(tag=tag):
                self.assertEqual(self._sev(tag), "high")

    def test_routine_bookkeeping_tags_are_not_promoted(self):
        # 3,480 logon events on one host, measured. Promoting an arbitrary 5 of
        # them to medium is noise wearing a detection's clothes; they still
        # reach the graph if the operator drops the floor to informational.
        for tag in ("logon-event", "logoff-event", "session-id", "known-domain"):
            with self.subTest(tag=tag):
                self.assertEqual(self._sev(tag), "informational")

    def test_the_floor_never_lowers_a_rows_own_score(self):
        # It is a floor, not an override: a routine tag (floor 0) must leave a
        # genuinely suspicious row exactly where its own scoring put it.
        import services.fusion.severity as sev
        plain = self._sev("logon-event", "an ordinary logon")
        scary = self._sev("logon-event", "mimikatz sekurlsa::logonpasswords")
        self.assertEqual(plain, "informational")
        self.assertTrue(sev.at_least(scary, "medium"),
                        f"a scary row must outrank a plain one, got {scary}")

    def test_a_detection_tag_does_not_cap_a_worse_row(self):
        both = self._sev("rare-domain", "mimikatz sekurlsa::logonpasswords")
        import services.fusion.severity as sev
        self.assertTrue(sev.at_least(both, "medium"))

    def test_an_untagged_event_is_unaffected(self):
        self.assertEqual(self._sev_untagged(), "informational")

    def _sev_untagged(self):
        ents, _ = self.mod.map_timesketch(
            [{"datetime": "2026-08-01T00:00:00Z", "message": "plain"}],
            run_id="r1", asset="asset:endpoint:C.1", hostname="H")
        return [e for e in ents if e.type == "event"][0].severity


class TestExtractedIndicatorsAreReal(unittest.TestCase):
    """Turning on domain extraction immediately put two non-indicators into a
    real case graph, so the guards get their own tests."""

    def setUp(self):
        import sys
        import types
        import importlib
        backend = os.path.join(ROOT, "modules/backend")
        if "services" not in sys.modules:
            shim = types.ModuleType("services")
            shim.__path__ = [os.path.join(backend, "services")]
            sys.modules["services"] = shim
        self.keys = importlib.import_module("services.fusion.keys")

    def test_a_report_filename_is_not_a_domain(self):
        # Observed live: this entered a case graph as an IOC.
        self.assertIsNone(self.keys.classify_indicator(
            "WER.dbfb444b-5eca-4272-8f20-c6a3bd94e688.tmp.csv"))

    def test_common_data_extensions_are_rejected(self):
        for name in ("report.csv", "dump.jsonl", "notes.md", "book.xlsx",
                     "mail.eml", "archive.7z", "disk.vhdx", "core.dmp"):
            with self.subTest(name=name):
                self.assertIsNone(self.keys.classify_indicator(name))

    def test_a_benign_subdomain_is_rejected_like_its_parent(self):
        # Observed live: microsoft.com was listed, fs.microsoft.com was not.
        for dom in ("fs.microsoft.com", "ctldl.windowsupdate.com",
                    "www.msftncsi.com", "ssl.gstatic.com"):
            with self.subTest(dom=dom):
                self.assertIsNone(self.keys.classify_indicator(dom))

    def test_a_lookalike_of_a_benign_domain_is_still_an_ioc(self):
        # endswith on "." + domain, so this must NOT be swallowed.
        self.assertEqual(self.keys.classify_indicator("notmicrosoft.com"), "domain")
        self.assertEqual(self.keys.classify_indicator("microsoft.com.evil.ru"), "domain")

    def test_real_indicators_still_classify(self):
        self.assertEqual(self.keys.classify_indicator("evil-c2.example.net"), "domain")
        self.assertEqual(self.keys.classify_indicator("8.8.8.8"), "ip")
        self.assertEqual(
            self.keys.classify_indicator("3365ee1650ea7a4ff016dd7cade20c73"), "hash")


# ------------------------------------------------------- the completion order

class TestTheRunWaitsForItsAnalyzers(unittest.TestCase):
    """Completion arms the case auto-fuse 60s later. Completing before the
    analyzers settle hands that fuse a sketch with zero tags."""

    def setUp(self):
        self.src = read(os.path.join(ROOT, "modules/backend/services/kape_upload_service.py"))

    def test_the_wait_precedes_the_terminal_status(self):
        # Scoped to the successful-import block: the earlier _status(completed)
        # is the no_events early return, which never built a sketch and so has
        # no analyzers to wait for.
        body = func_source(os.path.join(ROOT, "modules/backend/services/kape_upload_service.py"),
                           "process_kape_upload")
        block = body[body.index("if result:"):]
        self.assertLess(block.index("_wait_for_sketch_analyzers"),
                        block.index('_status("completed"'),
                        "analyzers must settle before the run goes terminal")

    def test_the_sketch_locator_is_written_to_the_run(self):
        # Without it fusion resolves the sketch BY NAME, which picks the wrong
        # sketch as soon as two runs share a name or one is renamed.
        self.assertIn('"sketch_id": result.get("sketch_id")', self.src)
        self.assertIn('"timeline_id": result.get("timeline_id")', self.src)

    def test_an_analyzer_failure_never_fails_the_import(self):
        helper = func_source(
            os.path.join(ROOT, "modules/backend/services/kape_upload_service.py"),
            "_wait_for_sketch_analyzers")
        self.assertIn("except Exception as e:", helper)
        self.assertNotIn("raise", helper)


class TestTheAnalyzerWaitSettles(unittest.TestCase):
    """Executes the wait loop against fake status payloads."""

    def _wait(self, sequences, **kw):
        calls = {"logs": [], "polls": 0}

        class FakeSketch:
            def get_analyzer_status(_self):
                calls["polls"] += 1
                idx = min(calls["polls"] - 1, len(sequences) - 1)
                out = sequences[idx]
                if isinstance(out, Exception):
                    raise out
                return out

        class FakeApi:
            session = type("s", (), {"close": staticmethod(lambda: None)})()

            def get_sketch(_self, _sid):
                return FakeSketch()

        ns = {
            "_connect_timesketch_api": lambda *a, **k: FakeApi(),
            "time": type("t", (), {"time": staticmethod(lambda: calls["polls"] * 1.0),
                                   "sleep": staticmethod(lambda _s: None)}),
            "print": lambda *a, **k: None,
        }
        fn = load_func(TSSVC, "wait_for_analyzers", ns)
        return fn(1, {}, poll_interval=0,
                  logger=lambda m, l="info": calls["logs"].append((l, m)), **kw), calls

    def test_it_returns_once_every_session_is_terminal(self):
        (settled, summary), _ = self._wait([[
            {"name": "sigma", "status": "DONE"},
            {"name": "login", "status": "DONE"},
        ]])
        self.assertTrue(settled)
        self.assertEqual(summary, {"sigma": {"DONE": 1}, "login": {"DONE": 1}})

    def test_it_keeps_polling_while_anything_is_pending(self):
        (settled, summary), calls = self._wait([
            [{"name": "sigma", "status": "PENDING"}],
            [{"name": "sigma", "status": "STARTED"}],
            [{"name": "sigma", "status": "DONE"}],
        ])
        self.assertTrue(settled)
        self.assertEqual(calls["polls"], 3)

    def test_errors_count_as_settled_and_are_reported_per_analyzer(self):
        # 5 of the real import's 75 sessions errored. The run log has to name
        # which — a bare bool would hide that domain and evtx_gap failed.
        (settled, summary), _ = self._wait([[
            {"name": "domain", "status": "ERROR"},
            {"name": "sigma", "status": "DONE"},
            {"name": "feature_extraction", "status": "ERROR"},
            {"name": "feature_extraction", "status": "DONE"},
        ]])
        self.assertTrue(settled)
        self.assertEqual(summary["domain"], {"ERROR": 1})
        self.assertEqual(summary["feature_extraction"], {"ERROR": 1, "DONE": 1})

    def test_a_timeout_reports_unsettled_rather_than_hanging(self):
        (settled, summary), _ = self._wait(
            [[{"name": "sigma", "status": "PENDING"}]], timeout_seconds=3)
        self.assertFalse(settled)
        self.assertEqual(summary, {})

    def test_a_bad_sketch_id_is_refused_before_connecting(self):
        fn = load_func(TSSVC, "wait_for_analyzers", {
            "_connect_timesketch_api": lambda *a, **k: (_ for _ in ()).throw(
                AssertionError("must not connect")),
            "print": lambda *a, **k: None,
        })
        self.assertEqual(fn(None, {}), (False, {}))


# ------------------------------------------------------------ the registries

class TestTheModuleIsReachableAgain(unittest.TestCase):
    """A module absent from the picker cannot be enabled, and a run type
    outside the gate's set cannot contribute — both silently."""

    def setUp(self):
        self.store = read(STORE)

    def test_timesketch_is_selectable(self):
        ui = self.store.split("FUSION_MODULES_UI = ")[1].split("]")[0]
        avail = self.store.split("FUSION_MODULES_AVAILABLE = ")[1].split(")")[0]
        self.assertIn('"timesketch"', ui)
        self.assertIn('"timesketch"', avail)

    def test_it_is_off_by_default(self):
        # Its fetch is a live network call to the TS server on every fuse of a
        # case that has a TS run. One release of opt-in first.
        default = self.store.split("FUSION_MODULES_DEFAULT = ")[1].split("]")[0]
        self.assertNotIn('"timesketch"', default)

    def test_a_bare_upload_run_can_fuse(self):
        # Same class of bug as velociraptor_offline_import missing from
        # AGENTIC_TYPES: imported evidence that never reached the case.
        types = self.store.split('"timesketch": {')[1].split("}")[0]
        self.assertIn('"timesketch_kape_upload"', types)
        self.assertIn('"timesketch_kape_upload"',
                      read(WS).split("AGENTIC_TYPES")[1].split("}")[0])
        self.assertIn('"timesketch_kape_upload"',
                      read(APP).split("_REAP_TYPES")[1].split("}")[0])

    def test_the_contribution_dispatches_both_types(self):
        self.assertIn('if atype in ("timesketch", "timesketch_kape_upload"):', self.store)

    def test_the_empty_branch_returns_explicitly(self):
        src = func_source(STORE, "_contribution_for_run")
        ts = src[src.index('if atype in ("timesketch"'):src.index('if atype in ("aws_scan"')]
        self.assertIn("return [], []", ts)

    def test_a_refusion_ignores_the_cached_events(self):
        # Analyzers finish after the first fuse, so the cache is the stale view
        # by definition — a manual Refusion must re-read the sketch.
        src = func_source(STORE, "_contribution_for_run")
        self.assertIn("if refetch:", src)

    def test_the_case_window_reaches_the_fetch(self):
        src = func_source(STORE, "_contribution_for_run")
        self.assertIn("window=window", src)
        self.assertIn("def _contribution_for_run(run, log=None, refetch=False, window=None)",
                      self.store)


class TestTheAnalyzerSetStaysCurated(unittest.TestCase):
    """Fusion selects by tag existence, so a flood analyzer makes 'has a tag'
    meaningless — and every analyzer here now lengthens the pipeline's tail,
    because the run waits for the set to finish."""

    FLOOD = ("chain", "similarity_scorer", "sessionizer", "feature_extraction")

    def test_the_flood_analyzers_are_gone_from_both_templates(self):
        for path in (CONF, LEGACY_CONF):
            block = read(path).split("AUTO_SKETCH_ANALYZERS = [")[1].split("]")[0]
            for name in self.FLOOD:
                with self.subTest(conf=os.path.basename(path), analyzer=name):
                    self.assertNotIn(f"'{name}'", block)

    def test_the_detection_analyzers_remain(self):
        block = read(CONF).split("AUTO_SKETCH_ANALYZERS = [")[1].split("]")[0]
        for name in ("sigma", "tagger", "login", "domain", "phishy_domains",
                     "ntfs_timestomp", "evtx_gap", "win_crash", "account_finder"):
            with self.subTest(analyzer=name):
                self.assertIn(f"'{name}'", block)

    def test_an_existing_appliance_gets_curated_too(self):
        # render_timesketch_conf_templates never rewrites an existing conf, so
        # without this every box installed before the curation keeps the old
        # 15-analyzer list forever.
        deploy = read(DEPLOY)
        self.assertIn("curate_timesketch_analyzers()", deploy)
        self.assertIn("curate_timesketch_analyzers\n", deploy)


if __name__ == "__main__":
    unittest.main(verbosity=2)
