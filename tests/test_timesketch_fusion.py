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
        # Tag queries carry the window; the starred/commented query is issued
        # separately and never does.
        self.assertIn('q = f\'tag:"{safe}"\' + (f" AND {clause}" if clause else "")',
                      self.src)
        star = self.src[self.src.index("label:__ts_star OR label:__ts_comment"):]
        self.assertNotIn("clause", star.split("\n")[0])

    def test_without_a_window_the_tag_query_carries_no_clause(self):
        self.assertIn('if clause else ""', self.src)

    def test_the_limit_is_enforced_client_side_too(self):
        # explore(max_entries=) is best-effort in the API client: it pages 10k
        # at a time, so a cap can return ~10,000 without this backstop.
        self.assertIn("if added >= cap:", self.src)
        self.assertIn("if len(events) >= limit:", self.src)

    def test_the_opensearch_id_is_kept(self):
        self.assertIn('src["_ts_id"] = doc_id', self.src)


# ------------------------------------------------------------- the distiller

class TestNoDetectionClassIsStarvedByANoisyOne(unittest.TestCase):
    """Measured on a real host: 3,480 of 3,542 tagged events were `logon-event`
    and 20 were `rare-domain`. A flat "first N events" pull can therefore be
    100% logons and miss every genuine detection — and the case would look
    confidently empty. Each tag is asked for separately, rarest first."""

    def setUp(self):
        self.src = func_source(TSSVC, "fetch_sketch_events")

    def test_the_tag_vocabulary_is_discovered_before_events_are_pulled(self):
        self.assertLess(self.src.index("_sketch_tag_counts"),
                        self.src.index("for tag in queried:"))

    def test_the_rarest_tags_are_served_first(self):
        # If the budget runs out it must run out on the noisy classes.
        self.assertIn("ordered = sorted(tag_counts, key=lambda t: tag_counts[t])",
                      self.src)

    def test_each_tag_gets_a_floor_not_just_a_share(self):
        # An even split alone starves everything once the vocabulary is large.
        self.assertIn("max(per_tag_min, min(budget, limit))", self.src)

    def test_the_number_of_tag_queries_is_bounded(self):
        # A sigma ruleset tags per RULE NAME; 2,590 Windows rules would be
        # 2,590 sequential round trips.
        self.assertIn("ordered[:max_tag_queries]", self.src)

    def test_a_skipped_tag_is_announced_not_silently_dropped(self):
        # A silent cap reads as "we looked at everything".
        self.assertIn("not queried", self.src)
        self.assertIn("INTACT_TS_MAX_TAG_QUERIES", self.src)

    def test_it_still_works_without_the_aggregator(self):
        # Older servers / restricted permissions must degrade to the old
        # behaviour rather than contributing nothing.
        self.assertIn("no tag aggregation", self.src)

    def test_starred_events_are_a_separate_unfiltered_query(self):
        self.assertIn('_collect("label:__ts_star OR label:__ts_comment"', self.src)

    def test_documents_are_de_duplicated_across_the_per_tag_queries(self):
        # One event carrying two tags is returned by two queries.
        self.assertIn("if doc_id in seen:", self.src)

    def test_the_aggregator_gets_times_not_a_query_string(self):
        # field_bucket takes start_time/end_time; a Lucene clause silently
        # returns nothing and drops us back to the flat query.
        agg = func_source(TSSVC, "_sketch_tag_counts")
        self.assertIn('params["start_time"]', agg)
        self.assertIn('params["end_time"]', agg)
        self.assertNotIn("query_string", agg)

    def test_a_degenerate_window_does_not_aggregate_an_empty_range(self):
        agg = func_source(TSSVC, "_sketch_tag_counts")
        self.assertIn('params["start_time"] >= params["end_time"]', agg)


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


class TestDetectionsActuallyReachTheAnalyst(unittest.TestCase):
    """The single most consequential bug in this integration. The report
    timeline renders graph.FINDINGS, not entities, and correlate._derive_findings
    groups non-sigma detections per (host, title) keyed off the `detection` flag
    and attrs["title"]. The TimeSketch mapper stamped neither — so every
    TimeSketch event landed in the graph as a bare entity that no finding
    referenced and no operator ever saw. Measured on real tagged data before the
    fix: 12 event entities, 0 findings, nothing in the report."""

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

    def _event(self, tag):
        ents, _ = self.mod.map_timesketch(
            [{"datetime": "2026-08-01T00:00:00Z", "message": "something happened",
              "tag": [tag]}],
            run_id="r1", asset="asset:endpoint:C.1", hostname="H")
        return [e for e in ents if e.type == "event"][0]

    def test_a_detection_tag_flags_the_event_for_finding_derivation(self):
        e = self._event("rare-domain")
        self.assertIn("detection", e.flags)
        self.assertEqual(e.attrs.get("title"), "TimeSketch: rare-domain")

    def test_a_routine_tag_raises_nothing(self):
        # A logon is context for a timeline, not something to raise — the same
        # rule as the severity floor, for the same reason.
        e = self._event("logon-event")
        self.assertNotIn("detection", e.flags)
        self.assertIsNone(e.attrs.get("title"))

    def test_an_untagged_event_raises_nothing(self):
        ents, _ = self.mod.map_timesketch(
            [{"datetime": "2026-08-01T00:00:00Z", "message": "x"}],
            run_id="r1", asset="asset:endpoint:C.1", hostname="H")
        e = [x for x in ents if x.type == "event"][0]
        self.assertNotIn("detection", e.flags)

    def test_the_more_serious_tag_names_the_finding(self):
        # An event carrying two detections must group under one title, and it
        # should be the one worth reading.
        ents, _ = self.mod.map_timesketch(
            [{"datetime": "2026-08-01T00:00:00Z", "message": "x",
              "tag": ["rare-domain", "sigma_credential_dump"]}],
            run_id="r1", asset="asset:endpoint:C.1", hostname="H")
        e = [x for x in ents if x.type == "event"][0]
        self.assertEqual(e.attrs.get("title"), "TimeSketch: sigma_credential_dump")

    def test_routine_tags_do_not_mask_a_real_detection(self):
        e = self._event("logon-event")
        self.assertIsNone(e.attrs.get("title"))
        ents, _ = self.mod.map_timesketch(
            [{"datetime": "2026-08-01T00:00:00Z", "message": "x",
              "tag": ["logon-event", "rare-domain"]}],
            run_id="r1", asset="asset:endpoint:C.1", hostname="H")
        both = [x for x in ents if x.type == "event"][0]
        self.assertEqual(both.attrs.get("title"), "TimeSketch: rare-domain")

    def test_the_detection_severity_clears_the_grouping_floor(self):
        # _derive_findings only groups detections at medium or above; a flag
        # with an informational severity would still never surface.
        import services.fusion.severity as sev
        self.assertTrue(sev.at_least(self._event("rare-domain").severity, "medium"))


class TestEventLabelsAreReadable(unittest.TestCase):
    """The label is what reaches the case timeline and the LLM payload. It was
    a raw 80-character slice of a multi-line EVTX record, so it arrived with
    embedded newlines and tabs, rendered as broken text, spent tokens on
    whitespace — and cut off before saying anything useful. "[1001] Fault
    bucket 1159357481657437299, type 5" does not tell an analyst what crashed;
    the answer was on the very next line."""

    def setUp(self):
        import sys
        import types
        import importlib
        backend = os.path.join(ROOT, "modules/backend")
        if "services" not in sys.modules:
            shim = types.ModuleType("services")
            shim.__path__ = [os.path.join(backend, "services")]
            sys.modules["services"] = shim
        self.sm = importlib.import_module(
            "services.fusion.mappers.timesketch")._summarise

    def test_literal_backslash_n_is_unescaped_first(self):
        # plaso stores the record as ONE physical line containing literal "\n"
        # sequences; without unescaping there is nothing to split on.
        got = self.sm("[1001] Fault bucket 99, type 5\\nEvent Name: crashpad_log")
        self.assertIn("Fault bucket 99", got)
        self.assertIn("Event Name: crashpad_log", got)

    def test_real_newlines_work_too(self):
        got = self.sm("[4634] Logged off.\nAccount Name: bob")
        self.assertTrue(got.startswith("[4634] Logged off."))
        self.assertIn("Account Name: bob", got)

    def test_no_newlines_or_tabs_survive(self):
        got = self.sm("head\\nKey: value\\n\\tIndented: x")
        self.assertNotIn("\n", got)
        self.assertNotIn("\t", got)

    def test_bare_section_headers_are_skipped(self):
        # "Subject:" carries no value of its own.
        got = self.sm("[4634] Logged off.\\nSubject:\\nSecurity ID: S-1-5-18")
        self.assertNotIn("Subject:", got)
        self.assertIn("Security ID: S-1-5-18", got)

    def test_lines_without_a_colon_are_not_appended(self):
        got = self.sm("head\\nsome prose with no field\\nKey: value")
        self.assertNotIn("some prose", got)

    def test_it_is_bounded(self):
        got = self.sm("head\\n" + "\\n".join(f"K{i}: {'v' * 40}" for i in range(30)))
        self.assertLessEqual(len(got), 200)

    def test_empty_and_junk_are_safe(self):
        self.assertEqual(self.sm(""), "")
        self.assertEqual(self.sm(None), "")
        self.assertEqual(self.sm("   \\n  \\n "), "")

    def test_the_mapper_falls_back_to_the_parser_name(self):
        import importlib
        mod = importlib.import_module("services.fusion.mappers.timesketch")
        ents, _ = mod.map_timesketch(
            [{"datetime": "2026-08-01T00:00:00Z", "message": "", "parser": "winreg"}],
            run_id="r1", asset="asset:endpoint:C.1", hostname="H")
        self.assertEqual([e for e in ents if e.type == "event"][0].label, "winreg")


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


class TestOneBadTagDoesNotLoseTheRest(unittest.TestCase):
    """Each tag is now a separate query. Letting one propagate would throw away
    every class already collected because a single detection had an awkward name
    or its shard hiccuped — a partial result becoming no result."""

    def setUp(self):
        self.src = func_source(TSSVC, "fetch_sketch_events")

    def test_each_query_is_individually_guarded(self):
        self.assertIn("return _collect_unsafe(query, cap, into, seen)", self.src)
        guard = self.src[self.src.index("def _collect(") :
                         self.src.index("def _collect_unsafe(")]
        self.assertIn("except Exception as e:", guard)
        self.assertIn("return 0", guard)

    def test_a_failed_query_is_reported_not_swallowed_silently(self):
        self.assertIn('log(f"query failed', self.src)

    def test_a_tag_is_lucene_escaped_backslash_first(self):
        # Escaping the quote before the backslash would double-escape it.
        i_bs = self.src.index('replace("\\\\", "\\\\\\\\")')
        i_q = self.src.index("""replace('"', '\\\\"')""")
        self.assertLess(i_bs, i_q)


class TestOurOwnAnnotationsAreNotEvidence(unittest.TestCase):
    """score_row concatenates every value in a row and keyword-matches the
    blob, and "rwx" is a THREE-character _CRIT keyword worth +100. We inject
    the OpenSearch document id as `_ts_id`, so a random id containing those
    letters turned an ordinary logon into a CRITICAL finding. Reproduced live
    before the fix: {"message": "an ordinary logon", "_ts_id":
    "jXcZQqrwxBGKvPYSzpM7"} scored 100.

    A spurious critical is the worst defect class a triage tool can ship — it
    spends an analyst's attention on nothing and teaches them to distrust the
    severity column."""

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

    def _sev(self, **extra):
        row = {"datetime": "2026-08-01T00:00:00Z", "message": "an ordinary logon",
               "tag": ["logon-event"]}
        row.update(extra)
        ents, _ = self.mod.map_timesketch(
            [row], run_id="r1", asset="asset:endpoint:C.1", hostname="H")
        e = [x for x in ents if x.type == "event"][0]
        return e.anomaly, e.severity

    def test_a_document_id_containing_rwx_does_not_mint_a_critical(self):
        self.assertEqual(self._sev(_ts_id="jXcZQqrwxBGKvPYSzpM7"), (0, "informational"))

    def test_a_benign_document_id_is_unchanged(self):
        self.assertEqual(self._sev(_ts_id="jXcZQqABGKvPYSzpM7L7"), (0, "informational"))

    def test_other_injected_metadata_is_also_excluded(self):
        for key in ("__ts_timeline_id", "__ts_emojis", "_ts_id"):
            with self.subTest(key=key):
                self.assertEqual(self._sev(**{key: "rwx"}), (0, "informational"))

    def test_real_evidence_still_scores(self):
        # The filter must not blunt the scorer on actual fields.
        anom, sev = self._sev(message="process with PAGE_EXECUTE_READWRITE memory")
        self.assertGreaterEqual(anom, 100)
        self.assertEqual(sev, "critical")


class TestEveryHostKeepsItsOwnEvents(unittest.TestCase):
    """TimeSketch is not only used on one machine at a time. A multi-client run
    imports ONE TIMELINE PER CLIENT into a shared sketch, and the mapper used to
    attach every event to details.clients[0] — so a 20-host collection produced
    a graph claiming the first machine did all of it."""

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
        self.index = {
            "1": {"asset": "asset:endpoint:C.aaa", "hostname": "HOST-A"},
            "2": {"asset": "asset:endpoint:C.bbb", "hostname": "HOST-B"},
        }

    def _map(self, events, **kw):
        return self.mod.map_timesketch(
            events, run_id="r1", asset="asset:endpoint:C.aaa",
            hostname="HOST-A", **kw)

    def _ev(self, tl, msg, **extra):
        d = {"datetime": "2026-08-01T00:00:00Z", "message": msg,
             "tag": ["rare-domain"]}
        if tl is not None:
            d["__ts_timeline_id"] = tl
        d.update(extra)
        return d

    def test_events_follow_their_own_timeline(self):
        ents, _ = self._map([self._ev(1, "on A"), self._ev(2, "on B")],
                            host_index=self.index)
        by_msg = {e.label: e for e in ents if e.type == "event"}
        self.assertEqual(by_msg["on A"].attrs["_assets"], ["asset:endpoint:C.aaa"])
        self.assertEqual(by_msg["on B"].attrs["_assets"], ["asset:endpoint:C.bbb"])

    def test_every_named_host_gets_an_asset_node(self):
        ents, _ = self._map([self._ev(2, "only B")], host_index=self.index)
        assets = sorted(e.id for e in ents if e.type == "asset")
        self.assertEqual(assets, ["asset:endpoint:C.aaa", "asset:endpoint:C.bbb"])

    def test_an_unknown_timeline_falls_back_to_the_run_asset(self):
        ents, _ = self._map([self._ev(99, "orphan")], host_index=self.index)
        ev = [e for e in ents if e.type == "event"][0]
        self.assertEqual(ev.attrs["_assets"], ["asset:endpoint:C.aaa"])

    def test_computer_name_rescues_an_event_with_no_timeline_id(self):
        # plaso leaves `hostname` as the literal "N/A"; EVTX records carry
        # computer_name, registry ones do not.
        ents, _ = self._map([self._ev(None, "evtx", computer_name="HOST-B")],
                            host_index=self.index)
        ev = [e for e in ents if e.type == "event"][0]
        self.assertEqual(ev.attrs["_assets"], ["asset:endpoint:C.bbb"])

    def test_the_literal_NA_hostname_is_not_treated_as_a_host(self):
        ents, _ = self._map([self._ev(None, "reg", computer_name="N/A")],
                            host_index=self.index)
        ev = [e for e in ents if e.type == "event"][0]
        self.assertEqual(ev.attrs["_assets"], ["asset:endpoint:C.aaa"])

    def test_the_single_host_path_is_unchanged(self):
        ents, _ = self._map([self._ev(1, "solo")])
        assets = [e.id for e in ents if e.type == "asset"]
        self.assertEqual(assets, ["asset:endpoint:C.aaa"])

    def test_a_client_name_that_prefixes_another_does_not_steal_its_timeline(self):
        # Timelines are named "<client_name>_<stamp>". A bare startswith lets
        # ALClient01 claim ALClient012's timeline and files an entire host's
        # events under the wrong machine. This box really does have ALClient01,
        # ALClient04, ALClient09 and ALClient022.
        src = func_source(STORE, "_contribution_for_run")
        self.assertIn('low.startswith(cname.lower() + "_")', src)
        self.assertIn("key=lambda c: len(str(c.get(\"client_name\") or \"\")),", src)
        self.assertIn("reverse=True", src)

    def test_iocs_are_scoped_to_the_host_that_saw_them(self):
        ents, _ = self._map([self._ev(2, "beacon to evil-c2.example.net")],
                            host_index=self.index)
        ioc = [e for e in ents if e.type == "ioc"][0]
        self.assertEqual(ioc.attrs["_assets"], ["asset:endpoint:C.bbb"])


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
            "_TS_ANALYZER_TIMEOUT": 7200,
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

    def test_the_default_timeout_survives_a_real_timeline(self):
        # Measured: a _KapeTriage import is 4.16M events and 72 sequential
        # analyzer sessions. 30 minutes expires mid-queue and hands the
        # auto-fuse an untagged sketch — the exact failure the wait prevents.
        src = read(TSSVC)
        self.assertIn('INTACT_TS_ANALYZER_TIMEOUT", "7200"', src)

    def test_a_timeout_reports_unsettled_rather_than_hanging(self):
        (settled, summary), _ = self._wait(
            [[{"name": "sigma", "status": "PENDING"}]], timeout_seconds=3)
        self.assertFalse(settled)
        self.assertEqual(summary, {})

    def test_a_bad_sketch_id_is_refused_before_connecting(self):
        fn = load_func(TSSVC, "wait_for_analyzers", {
            "_TS_ANALYZER_TIMEOUT": 7200,
            "_connect_timesketch_api": lambda *a, **k: (_ for _ in ()).throw(
                AssertionError("must not connect")),
            "print": lambda *a, **k: None,
        })
        self.assertEqual(fn(None, {}), (False, {}))


# ------------------------------------------------------------ the registries

class TestTheCachedEventsBelongToTheirWindow(unittest.TestCase):
    """The distilled set written back to the run is whatever the window at the
    time selected — but only MANUAL fuses set refetch. So after an operator
    narrows the window in the Configuration rail, the next automatic fuse would
    rebuild the graph (its filter signature changed) while still reading events
    fetched for the OLD window: a case that silently disagrees with its own
    configuration."""

    def setUp(self):
        self.src = func_source(STORE, "_contribution_for_run")

    def test_the_window_is_stamped_next_to_the_cache(self):
        self.assertIn('"timeline_events_window": _win_sig', self.src)

    def test_a_mismatched_window_discards_the_cache(self):
        self.assertIn('det.get("timeline_events_window") != _win_sig', self.src)
        self.assertIn("evs = None", self.src)

    def test_the_signature_is_order_independent(self):
        # dict ordering must not look like a window change.
        self.assertIn("sort_keys=True", self.src)

    def test_the_operator_is_told_why_it_re_read(self):
        self.assertIn("fetched for a", self.src)


class TestTheLogShowsTheFunnel(unittest.TestCase):
    """An operator looking at a case with 10 TimeSketch events out of a 380,000
    event timeline needs to see where the other 379,990 went, or the module
    looks broken rather than selective."""

    def setUp(self):
        self.src = func_source(STORE, "_contribution_for_run")

    def test_it_reports_fetched_versus_kept(self):
        self.assertIn("tagged event(s) -> ", self.src)
        self.assertIn("_n_fetched", self.src)

    def test_it_names_the_detection_classes(self):
        self.assertIn("detection class(es)", self.src)

    def test_module_notes_reach_the_persistent_case_log(self):
        # `log` is an optional callable only /fuse and /rescan pass (for their
        # HTTP response), so these notes were invisible to the automatic fuse
        # and absent from the Log tab an operator actually reads.
        fuse = func_source(STORE, "_fuse_case_locked")
        self.assertIn("def _contrib_log(", fuse)
        self.assertIn('_plog("Refusion · module note"', fuse)
        self.assertIn("_contribution_for_run(run, log=_contrib_log", fuse)


class TestBothSourcesStampTimeTheSameWay(unittest.TestCase):
    """Found by comparing a real Velociraptor collection against a real
    TimeSketch run on the SAME host: Velociraptor entities carried
    "2026-08-26T05:19:34.7568747Z" and TimeSketch ones "2026-08-26T05:19:34".

    Nothing errored — the graph just quietly stopped being able to relate them.
    keys.event_id embeds the timestamp, so one real moment seen by two modules
    minted two entities that could never merge; correlation-by-time could never
    fire across sources; and in_window's string comparison behaved differently
    depending on which module produced the row."""

    def setUp(self):
        import sys
        import types
        import importlib
        backend = os.path.join(ROOT, "modules/backend")
        if "services" not in sys.modules:
            shim = types.ModuleType("services")
            shim.__path__ = [os.path.join(backend, "services")]
            sys.modules["services"] = shim
        self.F = importlib.import_module("services.fusion.mappers.fieldspec")
        self.keys = importlib.import_module("services.fusion.keys")

    def test_velociraptors_rendering_is_normalised(self):
        # The exact value observed on the appliance.
        got = self.F.first_ts({"Mtime": "2026-08-26T05:19:34.7568747Z"})
        self.assertEqual(got, "2026-08-26T05:19:34")

    def test_it_agrees_with_the_normaliser_everything_else_uses(self):
        for raw in ("2026-08-26T05:19:34.7568747Z", "2026-08-26T05:19:34",
                    "2026-08-26 05:19:34", 1787817574, "1787817574"):
            with self.subTest(raw=raw):
                self.assertEqual(self.F.first_ts({"Mtime": raw}),
                                 self.keys.norm_ts(raw))

    def test_two_renderings_of_one_moment_now_produce_one_event_id(self):
        a = self.F.first_ts({"Mtime": "2026-08-26T05:19:34.7568747Z"})
        b = self.F.first_ts({"Mtime": "2026-08-26T05:19:34"})
        self.assertEqual(self.keys.event_id("asset:endpoint:C.1", a, "same message"),
                         self.keys.event_id("asset:endpoint:C.1", b, "same message"))

    def test_a_missing_timestamp_is_still_none(self):
        self.assertIsNone(self.F.first_ts({}))
        self.assertIsNone(self.F.first_ts({"Mtime": ""}))


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

    def test_the_conf_admits_feature_extraction_comes_back(self):
        # Timesketch expands AUTO_SKETCH_ANALYZERS through
        # analyzers/manager.py:_build_dependencies, and both `domain` and
        # `account_finder` declare DEPENDENCIES = {"feature_extraction"}.
        # Removing it from the list does NOT stop it running: measured, 44 of
        # 72 scheduled sessions on a 4.16M-event timeline were
        # feature_extraction. A comment claiming otherwise would send the next
        # reader hunting for a bug that is upstream behaviour.
        conf = read(CONF)
        self.assertIn("_build_dependencies", conf)
        self.assertIn("removes 3 sessions", conf)

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


class TestSigmaHasRulesToDetectWith(unittest.TestCase):
    """The sigma analyzer ran on every timeline and found nothing: the
    sigmarule table ships EMPTY and the only mounted rule was an upstream Linux
    zmap sample, useless against a Windows KAPE timeline. Fusion selects
    TimeSketch events BY TAG, so an analyzer that never tags contributes
    nothing at all."""

    def setUp(self):
        self.src = read(DEPLOY)

    def test_the_installer_imports_rules(self):
        self.assertIn("import_timesketch_sigma_rules()", self.src)
        self.assertIn("import_timesketch_sigma_rules\n", self.src)

    def test_only_stable_rules_are_staged(self):
        # sigma_tagger.py skips every other status, so importing all 2,403
        # Windows rules would write 2,349 rows that can never run.
        self.assertIn("grep -rl '^status: stable'", self.src)

    def test_rules_using_an_unsupported_modifier_are_skipped(self):
        # ONE rule using `windash` aborts the whole import with a KeyError —
        # measured: 10 rules in, 43 never imported.
        self.assertIn("windash", self.src)

    def test_a_missing_ruleset_is_not_an_error(self):
        # Air-gapped appliances have no /opt/sigma-rules.
        self.assertIn('if [[ ! -d "$src" ]]', self.src)

    def test_a_failed_import_never_fails_the_deploy(self):
        seg = self.src[self.src.index("import_timesketch_sigma_rules() {"):]
        seg = seg[:seg.index("\ndeploy_timesketch()")]
        self.assertIn("log_warn", seg)
        self.assertNotIn("return 1", seg)


if __name__ == "__main__":
    unittest.main(verbosity=2)
