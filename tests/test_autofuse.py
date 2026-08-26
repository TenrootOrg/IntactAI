"""The debounced auto-fuse: what it must do, and everything it must not.

A fuse rebuilds the whole case graph — measured on a live appliance at 29s for
one 9-host capture, 53s for two — because its cost is O(all data in the case).
Anything that fuses per landing run would turn a 20-host hunt into twenty full
rebuilds. So the whole design is a debounce, and almost every rule below exists
to stop the automatic path doing damage the manual one cannot:

  - the FUSE itself must never call the model — narration is a separate step
    afterwards, so a graph rebuild stays fast and lands even if narration does
    not (the report half is TestItRenarratesAfterTheFuse below);
  - it must never drop data on a collision — the previous background path used
    `except: pass` and a fuse could vanish, leaving the graph stale with nothing
    in the log;
  - it must stop the moment an operator opts out, or the case is deleted;
  - it must be a no-op when there is nothing new, so a stray timer costs nothing.

autofuse imports its collaborators lazily through _store(), so the REAL module
runs here against a fake store with no backend import. Timings are module-level
and reduced to milliseconds, so these drive real threading.Timer objects rather
than mocking the clock — the concurrency is genuinely exercised.
"""

import os
import sys
import threading
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "modules/backend/services/fusion"))

import autofuse  # noqa: E402 — near-leaf by design; see its docstring


class FusionBusy(RuntimeError):
    pass


class ReportGenerationBusy(RuntimeError):
    pass


class FakeStore:
    """Stands in for services.fusion.store. Records everything, so a test can
    assert on what was NOT done as easily as what was."""

    FusionBusy = FusionBusy
    ReportGenerationBusy = ReportGenerationBusy
    TRIGGER_AUTOMATIC_RUN_LANDED = "AUTOMATIC — a member run finished"
    CASE_TYPE = "case"

    def __init__(self, case=None, stale=None):
        # store.get_case returns {} for "no such case" (see its early return), so a
        # REAL case always carries details. A fake handing back {} would be claiming
        # the case was deleted, which is a different test.
        self.case = {"name": "QA case"} if case is None else case
        self._stale = ["run_1"] if stale is None else stale
        self._per_case = {}
        self.all_runs = []
        self.merges = []
        self.fuses = []          # kwargs of every fuse_case call
        self.events = []         # (action, status, detail)
        self.busy_times = 0      # raise FusionBusy this many times, then succeed
        self.raise_always = None
        self.reports = []        # (kind, kwargs) of every report regeneration
        self.report_busy_times = 0   # raise ReportGenerationBusy this often, then succeed
        self.report_raises = None
        self.report_behind = True    # what report_stale_runs answers for this case
        self.lock = threading.Lock()

    def get_case(self, cid):
        return self.case

    # --- what catch_up() reaches for --------------------------------------
    def _ws(self):
        return self

    def get_all_automation_runs(self):
        return list(self.all_runs)

    def _stale_for(self, cid):
        # Staleness is PER CASE in the real store; sharing one list here let one
        # case's fuse silently satisfy another's, which looked like a scheduler bug.
        return self._per_case.setdefault(cid, list(self._stale))

    def stale_member_runs(self, cid, d=None):
        return list(self._stale_for(cid))

    def fuse_case(self, cid, **kw):
        with self.lock:
            self.fuses.append(kw)
            if self.raise_always:
                raise self.raise_always
            if self.busy_times > 0:
                self.busy_times -= 1
                raise FusionBusy("a fuse is already running for this case")
            self._per_case[cid] = []          # a real fuse clears THIS case
        return object()

    # --- the narration half -----------------------------------------------
    def _record_report(self, kind, cid, kw):
        with self.lock:
            self.reports.append((kind, dict(kw)))
            if self.report_raises:
                raise self.report_raises
            if self.report_busy_times > 0:
                self.report_busy_times -= 1
                raise ReportGenerationBusy("a report is already being generated")

    def regenerate_report(self, cid, **kw):
        # Present so a test can prove the automatic path does NOT call it: the
        # unlocked entry point is the operator's click, and an automatic report
        # racing a manual one is exactly what the lock exists to stop.
        self._record_report("unlocked", cid, kw)
        return {"report_md": "..."}

    def regenerate_report_async(self, cid, **kw):
        self._record_report("locked", cid, kw)
        return {"status": "started"}

    def report_stale_runs(self, cid, d=None):
        return ["run_1"] if self.report_behind else []

    def report_kinds(self):
        return [k for k, _kw in self.reports]

    def report_llm_flags(self):
        return [kw.get("use_llm") for _k, kw in self.reports]

    def _merge_case_details(self, cid, patch):
        with self.lock:
            self.case.update(patch)
            self.merges.append(dict(patch))

    def log_case_event(self, cid, action, status="ok", detail="", **kw):
        with self.lock:
            self.events.append((action, status, detail))

    def actions(self):
        return [a for a, _s, _d in self.events]


class _FakeLlmSim:
    """`_regenerate_report` asks the SAME question the manual Regenerate asks —
    llm_sim._use_real() — to choose between the model and the deterministic
    narrator. Injected as a real module so both branches are reachable here;
    without it the import fails, which the code treats as "no model", and every
    test would silently only ever exercise the free path."""
    use_real = False

    @classmethod
    def _use_real(cls):
        return cls.use_real


def _install_fake_llm_sim():
    import types
    services = sys.modules.setdefault("services", types.ModuleType("services"))
    fusion = sys.modules.setdefault("services.fusion", types.ModuleType("services.fusion"))
    services.fusion = fusion
    fusion.llm_sim = _FakeLlmSim
    sys.modules["services.fusion.llm_sim"] = _FakeLlmSim


class _Base(unittest.TestCase):
    def setUp(self):
        self.store = FakeStore()
        autofuse._store = lambda: self.store
        _install_fake_llm_sim()
        _FakeLlmSim.use_real = False
        autofuse.REPORT_RETRY_SECONDS = 0.02
        # real timers, just fast ones
        self._orig = (autofuse.QUIET_SECONDS, autofuse.BUSY_RETRY_SECONDS,
                      autofuse.MAX_BUSY_RETRIES)
        autofuse.QUIET_SECONDS = 0.05
        autofuse.BUSY_RETRY_SECONDS = 0.02
        for cid in list(autofuse._TIMERS):
            autofuse.cancel(cid)

    def tearDown(self):
        for cid in list(autofuse._TIMERS) + list(autofuse._REPORT_TIMERS):
            autofuse.cancel(cid)
        (autofuse.QUIET_SECONDS, autofuse.BUSY_RETRY_SECONDS,
         autofuse.MAX_BUSY_RETRIES) = self._orig

    def settle(self, seconds=2.0):
        """Wait for quiescence: no timer pending AND no new fuse/log for a beat.

        Watching _TIMERS alone races — _fire() removes its timer BEFORE calling the
        store, so the registry can be empty while the fuse is still being recorded.
        """
        deadline = time.time() + seconds
        stable = 0
        last = None
        while time.time() < deadline:
            now = (len(autofuse._TIMERS), len(autofuse._REPORT_TIMERS),
                   len(self.store.fuses), len(self.store.reports),
                   len(self.store.events))
            if now == last and not autofuse._TIMERS and not autofuse._REPORT_TIMERS:
                stable += 1
                if stable >= 5:
                    return
            else:
                stable = 0
            last = now
            time.sleep(0.02)


class TestItFusesOnce(_Base):

    def test_a_landing_run_eventually_fuses(self):
        autofuse.schedule("case_1", "run finished")
        self.settle()
        self.assertEqual(len(self.store.fuses), 1)

    def test_it_does_not_fuse_before_the_quiet_period(self):
        """Arming must not fuse inline — schedule() is called under a lock."""
        autofuse.schedule("case_1")
        self.assertEqual(self.store.fuses, [])

    def test_twenty_runs_landing_together_produce_one_fuse(self):
        """The reason this is a debounce at all: a 20-host hunt."""
        for i in range(20):
            autofuse.schedule("case_1", "run %d" % i)
            time.sleep(0.005)          # they trickle in, as a real hunt does
        self.settle()
        self.assertEqual(len(self.store.fuses), 1,
                         "each landing run must re-arm, not queue another fuse")

    def test_a_later_run_extends_the_wait(self):
        autofuse.schedule("case_1")
        time.sleep(0.03)
        autofuse.schedule("case_1")     # re-arms the full quiet period
        time.sleep(0.03)
        self.assertEqual(self.store.fuses, [], "the timer should have been re-armed")
        self.settle()
        self.assertEqual(len(self.store.fuses), 1)

    def test_separate_cases_do_not_share_a_timer(self):
        autofuse.schedule("case_1")
        autofuse.schedule("case_2")
        self.settle()
        self.assertEqual(len(self.store.fuses), 2)

    def test_scheduling_reports_whether_it_armed(self):
        self.assertTrue(autofuse.schedule("case_1"))
        self.assertFalse(autofuse.schedule(None), "no case, nothing to arm")
        self.assertFalse(autofuse.schedule(""))


class TestTheFuseItselfNeverCallsTheModel(_Base):
    """The fuse call, specifically. The report step that follows it may.

    Keeping the model out of fuse_case is what makes the graph rebuild
    predictable: it lands in ~30s and cannot be held up, retried or failed by a
    provider. Narration is billed and slow, so it is a separate call that can
    fail on its own without taking the graph with it.
    """

    def test_the_fuse_forbids_the_llm(self):
        autofuse.schedule("case_1")
        self.settle()
        self.assertEqual(self.store.fuses[0].get("allow_llm"), False,
                         "an automatic fuse must never be billed or rewrite the narrative")

    def test_it_does_not_force_a_report_rebuild(self):
        autofuse.schedule("case_1")
        self.settle()
        self.assertNotEqual(self.store.fuses[0].get("force_report"), True)

    def test_the_fuse_makes_no_model_call_at_all(self):
        """allow_llm=False must reach EVERY model call in fuse_case, not most.

        It reached the report and the advisory and missed the disposition
        checklist, which is generated on a case that has none — i.e. on the FIRST
        automatic fuse of every case. So the automatic path made a billed call
        while documented, and tested, as making none. With a model configured but
        unreachable it blocked the fuse for up to 600s holding the case's fuse
        lock, and data landing behind it got FusionBusy and retried. Measured on
        a live appliance: the fuse sat in "LLM · calling OpenAI (Subscription)"
        and never reached "Refusion complete".

        Asserted on the source, because the fake store cannot see inside
        fuse_case: every llm_sim call in it must sit under an allow_llm guard.
        """
        import re
        src_path = os.path.join(ROOT, "modules/backend/services/fusion/store.py")
        with open(src_path, encoding="utf-8") as fh:
            src = fh.read()
        body = src[src.index("def _fuse_case_locked"):src.index("def stale_member_runs")]
        code = "\n".join(l.split("#", 1)[0] for l in body.splitlines())
        for m in re.finditer(r"llm_sim\.(generate_report|analyze|generate_disposition_checklist)\(",
                             code):
            head = code[:m.start()]
            guard = head.rfind("allow_llm")
            branch = max(head.rfind("\n    if "), head.rfind("\n    else:"))
            self.assertGreater(guard, branch,
                               f"llm_sim.{m.group(1)} is not under an allow_llm guard")

    def test_it_labels_itself_automatic(self):
        autofuse.schedule("case_1")
        self.settle()
        self.assertIn("AUTOMATIC", self.store.fuses[0].get("trigger", ""))


class TestItRenarratesAfterTheFuse(_Base):
    """New data must update the WORDS, not just the numbers.

    The old behaviour rebuilt the graph and left the report frozen behind a
    banner asking the operator to press Regenerate. The counts moved, the
    Executive Summary did not, and nobody pressed the button — so the report an
    analyst read routinely described the previous collection.
    """

    def test_a_fuse_is_followed_by_a_report(self):
        autofuse.schedule("case_1")
        self.settle()
        self.assertEqual(len(self.store.reports), 1,
                         "the graph moved; the narrative describing it must move too")

    def test_without_a_model_it_still_writes_a_report(self):
        _FakeLlmSim.use_real = False
        autofuse.schedule("case_1")
        self.settle()
        self.assertEqual(self.store.report_llm_flags(), [False],
                         "an air-gapped box gets the deterministic narrator, not a "
                         "connection timeout on every collection")

    def test_with_a_model_it_narrates(self):
        _FakeLlmSim.use_real = True
        autofuse.schedule("case_1")
        self.settle()
        self.assertEqual(self.store.report_llm_flags(), [True])

    def test_it_always_takes_the_report_lock(self):
        # Both the deterministic and the LLM report go through the guarded entry
        # point. An automatic deterministic render finishing while an operator's
        # LLM narrative is in flight would otherwise replace a real report with a
        # template — silently, and in the operator's favour exactly never.
        for real in (False, True):
            with self.subTest(model_configured=real):
                self.setUp()
                _FakeLlmSim.use_real = real
                autofuse.schedule("case_1")
                self.settle()
                self.assertEqual(self.store.report_kinds(), ["locked"])

    def test_a_missing_llm_sim_is_not_an_error(self):
        # An import failure means "no model configured", which is the ordinary
        # state of an air-gapped appliance — never a reason to log a failure.
        sys.modules.pop("services.fusion.llm_sim", None)
        import services.fusion as _f
        del _f.llm_sim
        autofuse.schedule("case_1")
        self.settle()
        self.assertEqual(self.store.report_llm_flags(), [False])
        self.assertNotIn("Report refresh failed", self.store.actions())

    def test_nothing_new_means_no_report_either(self):
        self.store._stale = []; self.store._per_case.clear()
        autofuse.schedule("case_1")
        self.settle()
        self.assertEqual(self.store.reports, [],
                         "no new data, no rebuild, and above all no billed call")

    def test_a_failed_fuse_does_not_narrate(self):
        # Narrating a graph that was not rebuilt would write a report describing
        # data the case does not have.
        self.store.raise_always = RuntimeError("boom")
        autofuse.schedule("case_1")
        self.settle()
        self.assertEqual(self.store.reports, [])

    def test_an_opted_out_case_narrates_nothing(self):
        self.store.case = {"name": "QA case", "auto_fuse": False}
        autofuse.schedule("case_1")
        self.settle()
        self.assertEqual(self.store.reports, [])

    def test_narration_can_be_turned_off_on_its_own(self):
        # The support escape hatch: keep the graph current, stop spending tokens.
        self.store.case = {"name": "QA case", "auto_report": False}
        autofuse.schedule("case_1")
        self.settle()
        self.assertEqual(len(self.store.fuses), 1, "the graph half must still run")
        self.assertEqual(self.store.reports, [])

    def test_absent_auto_report_reads_as_on(self):
        self.assertTrue(autofuse._report_enabled({}))
        self.assertTrue(autofuse._report_enabled({"auto_report": True}))
        self.assertFalse(autofuse._report_enabled({"auto_report": False}))

    def test_a_report_failure_does_not_undo_the_fuse(self):
        # The crash-loop flag is the fuse's, and it was cleared before this step.
        # A narration failure must not set it again, or the NEXT automatic fuse
        # stands down over a report problem.
        self.store.report_raises = RuntimeError("provider exploded")
        autofuse.schedule("case_1")
        self.settle()
        self.assertEqual(len(self.store.fuses), 1)
        self.assertIs(self.store.case.get("auto_fuse_incomplete"), False)
        self.assertIn("Report refresh failed", self.store.actions())

    def test_a_report_failure_is_named_as_a_report_failure(self):
        # It used to be possible for this to escape into _fire's handler and be
        # logged as "Refusion failed" — blaming the fuse, which had succeeded.
        self.store.report_raises = RuntimeError("provider exploded")
        autofuse.schedule("case_1")
        self.settle()
        self.assertNotIn("Refusion failed", self.store.actions())


class TestABusyReportIsRetried(_Base):
    """An LLM report runs for minutes; a second collection can land inside one.

    The in-flight report was started from the PREVIOUS graph, so it will finish
    describing data the case has already moved past. Dropping the second request
    leaves exactly the stale report this feature exists to prevent.
    """

    def test_a_busy_report_is_retried(self):
        self.store.report_busy_times = 1
        autofuse.schedule("case_1")
        self.settle()
        self.assertEqual(len(self.store.reports), 2)

    def test_the_deferral_is_recorded(self):
        self.store.report_busy_times = 1
        autofuse.schedule("case_1")
        self.settle()
        self.assertIn("Report refresh deferred", self.store.actions())

    def test_it_gives_up_after_a_bounded_number_of_tries(self):
        self.store.report_busy_times = 99
        autofuse.schedule("case_1")
        self.settle(seconds=4.0)
        self.assertEqual(len(self.store.reports), autofuse.MAX_REPORT_RETRIES)
        self.assertIn("Report not refreshed", self.store.actions())

    def test_the_retry_does_not_re_fuse(self):
        # Re-arming the FUSE timer would be useless: the graph is already current,
        # so _fire finds nothing stale and returns before reaching the report.
        self.store.report_busy_times = 2
        autofuse.schedule("case_1")
        self.settle()
        self.assertEqual(len(self.store.fuses), 1)
        self.assertEqual(len(self.store.reports), 3)

    def test_cancel_stops_a_pending_report_retry(self):
        self.store.report_busy_times = 99
        autofuse.schedule("case_1")
        deadline = time.time() + 2.0
        while time.time() < deadline and not autofuse._REPORT_TIMERS:
            time.sleep(0.005)
        self.assertTrue(autofuse.cancel("case_1"))
        self.assertEqual(autofuse._REPORT_TIMERS, {})

    def test_a_retry_stands_down_once_the_report_has_caught_up(self):
        # The report that was busy a minute ago has finished and already covers
        # this data. Narrating again would rewrite a current report with an
        # identical one — and with a model configured, pay for it.
        self.store.report_busy_times = 1
        autofuse.schedule("case_1")
        deadline = time.time() + 2.0
        while time.time() < deadline and not autofuse._REPORT_TIMERS:
            time.sleep(0.005)
        self.store.report_behind = False       # someone else covered it
        self.settle()
        self.assertEqual(len(self.store.reports), 1,
                         "the retry must not buy a second narration of the same data")

    def test_a_fresh_fuse_cancels_an_armed_retry(self):
        """THE DUPLICATE-BILLING BUG.

        A retry is waiting on a busy report; new data lands; _fire regenerates
        successfully; the orphaned retry then fires and narrates the same data a
        second time. With a model configured that is a real invoice.

        The retry delay is set LONGER than the quiet period on purpose. With the
        defaults inverted the retry always fires first and the collision never
        happens, so the test would pass against the broken code — which is exactly
        what it did before this comment was written.
        """
        autofuse.REPORT_RETRY_SECONDS = 5.0        # long: it must still be armed
        self.store.report_busy_times = 1
        autofuse.schedule("case_1")
        deadline = time.time() + 2.0
        while time.time() < deadline and not autofuse._REPORT_TIMERS:
            time.sleep(0.005)
        self.assertTrue(autofuse._REPORT_TIMERS, "precondition: a retry is armed")

        # New data lands while that retry is still pending.
        self.store._per_case["case_1"] = ["run_2"]
        autofuse.schedule("case_1")
        self.settle()

        self.assertEqual(autofuse._REPORT_TIMERS, {},
                         "the superseded retry must not still be armed")
        self.assertEqual(len(self.store.fuses), 2)
        # busy(1) + the fuse's own regeneration = 2. A third would be the orphan.
        self.assertEqual(len(self.store.reports), 2,
                         "an armed retry plus a fresh fuse must not narrate twice")

    def test_a_broken_staleness_probe_does_not_strand_the_report(self):
        # The probe is a saving, not a gate. If it cannot answer, retry anyway —
        # a report left permanently behind is the worse failure.
        def boom(cid, d=None):
            raise RuntimeError("db down")
        self.store.report_stale_runs = boom
        self.store.report_busy_times = 1
        autofuse.schedule("case_1")
        self.settle()
        self.assertEqual(len(self.store.reports), 2)

    def test_report_timers_are_daemon_threads(self):
        self.store.report_busy_times = 99
        autofuse.schedule("case_1")
        deadline = time.time() + 2.0
        while time.time() < deadline and not autofuse._REPORT_TIMERS:
            time.sleep(0.005)
        for t in autofuse._REPORT_TIMERS.values():
            self.assertTrue(t.daemon, "a retry timer must never hold up a shutdown")


class TestEveryDataModuleIsCovered(_Base):
    """Which run types regenerate the report, pinned as a contract.

    Asked for explicitly for MEMORY, and it already worked — memory was in
    AGENTIC_TYPES and in FUSION_MODULES_DEFAULT, so it armed the fuse and passed
    the fusion gate without anything being added. Verified end to end on a live
    appliance: a memory run reaching 'completed' produced one fuse and one
    narrated report; the same run reaching 'failed' produced neither.

    That is exactly the kind of guarantee that gets removed by accident, by
    someone tidying a set they do not realise is load-bearing. Two independent
    lists have to agree for a module to work, and neither says so locally:

      workflow_service.AGENTIC_TYPES     -> whether a landing run arms the fuse
      store.FUSION_MODULES_DEFAULT       -> whether its data may enter the graph
                                            (a member that fails the gate is not
                                            'stale', so the fuse is a no-op)

    Source-level, because both live in modules the fake store deliberately does
    not import.
    """

    WF = os.path.join(ROOT, "modules/backend/services/workflow_service.py")
    STORE = os.path.join(ROOT, "modules/backend/services/fusion/store.py")

    def _read(self, path):
        with open(path, encoding="utf-8") as fh:
            return fh.read()

    def test_memory_runs_arm_the_fuse(self):
        block = self._read(self.WF)
        block = block[block.index("AGENTIC_TYPES = {"):]
        block = block[:block.index("}") + 1]
        self.assertIn('"memory"', block,
                      "a finished memory workflow would no longer refresh the report")

    def test_memory_data_is_fused_by_default(self):
        # Being in AGENTIC_TYPES is not enough: _run_passes_gate drops runs whose
        # module is off for the case, and stale_member_runs skips them too — so
        # the fuse would arm, find nothing stale, and silently do nothing.
        block = self._read(self.STORE)
        block = block[block.index("FUSION_MODULES_DEFAULT = ["):]
        self.assertIn('"memory"', block[:block.index("]") + 1],
                      "memory runs would arm a fuse that then ignores them")

    def test_the_collection_modules_are_all_covered(self):
        block = self._read(self.WF)
        block = block[block.index("AGENTIC_TYPES = {"):]
        block = block[:block.index("}") + 1]
        for t in ("velociraptor_collection", "velociraptor_hunt",
                  "velociraptor_upload", "memory", "timesketch",
                  "aws_scan", "azure_scan"):
            self.assertIn(f'"{t}"', block, f"{t} no longer refreshes the report")

    def test_only_success_arms_it(self):
        # "as long as it succeeded" — a failed or cancelled run has produced no
        # new data, so arming would schedule a fuse that finds nothing.
        block = self._read(self.WF)
        block = block[block.index("_TERMINAL_STATUSES = ("):]
        block = block[:block.index(")") + 1]
        self.assertIn('"completed"', block)
        self.assertIn('"success"', block)
        for bad in ("failed", "cancelled", "running"):
            self.assertNotIn(f'"{bad}"', block, f"{bad} must not arm a fuse")


class TestItIsANoOpWhenNothingIsNew(_Base):

    def test_nothing_stale_means_no_fuse(self):
        self.store._stale = []; self.store._per_case.clear()
        autofuse.schedule("case_1")
        self.settle()
        self.assertEqual(self.store.fuses, [],
                         "someone already fused it — do not rebuild for nothing")

    def test_a_deleted_case_is_not_fused(self):
        self.store.case = {}          # store.get_case's "no such case" answer
        autofuse.schedule("case_1")
        self.settle()
        self.assertEqual(self.store.fuses, [])

    def test_no_log_noise_when_there_is_nothing_to_do(self):
        self.store._stale = []; self.store._per_case.clear()
        autofuse.schedule("case_1")
        self.settle()
        self.assertEqual(self.store.events, [],
                         "a quiet no-op must not write to the case activity log")


class TestTheOperatorCanStopIt(_Base):

    def test_an_explicit_opt_out_prevents_the_fuse(self):
        self.store.case = {"name": "QA case", "auto_fuse": False}
        autofuse.schedule("case_1")
        self.settle()
        self.assertEqual(self.store.fuses, [])

    def test_absent_reads_as_on(self):
        """Off-by-default would mean the feature does nothing until every existing
        case is visited and ticked."""
        self.store.case = {"name": "QA case"}
        autofuse.schedule("case_1")
        self.settle()
        self.assertEqual(len(self.store.fuses), 1)

    def test_explicit_true_is_on(self):
        self.store.case = {"name": "QA case", "auto_fuse": True}
        autofuse.schedule("case_1")
        self.settle()
        self.assertEqual(len(self.store.fuses), 1)

    def test_cancel_stops_a_pending_fuse(self):
        autofuse.schedule("case_1")
        self.assertTrue(autofuse.pending("case_1"))
        self.assertTrue(autofuse.cancel("case_1"))
        self.settle()
        self.assertEqual(self.store.fuses, [])

    def test_cancelling_nothing_is_harmless(self):
        self.assertFalse(autofuse.cancel("case_never_scheduled"))

    def test_cancel_only_affects_the_named_case(self):
        autofuse.schedule("case_1")
        autofuse.schedule("case_2")
        autofuse.cancel("case_1")
        self.settle()
        self.assertEqual(len(self.store.fuses), 1)


class TestCollisionsAreNeverDropped(_Base):
    """The previous background path swallowed FusionBusy with `except: pass`, so
    an automatic fuse could vanish and leave the graph stale with no explanation."""

    def test_a_busy_case_is_retried(self):
        self.store.busy_times = 1
        autofuse.schedule("case_1")
        self.settle(2.0)
        self.assertEqual(len(self.store.fuses), 2, "it must try again, not give up")
        self.assertEqual(self.store._stale_for("case_1"), [],
                         "the retry must actually have fused")

    def test_the_deferral_is_recorded(self):
        self.store.busy_times = 1
        autofuse.schedule("case_1")
        self.settle(2.0)
        self.assertIn("Refusion deferred", self.store.actions())

    def test_it_gives_up_after_a_bounded_number_of_tries(self):
        autofuse.MAX_BUSY_RETRIES = 3
        self.store.busy_times = 99
        autofuse.schedule("case_1")
        self.settle(3.0)
        self.assertEqual(len(self.store.fuses), 3, "retries must be bounded")
        self.assertIn("Refusion skipped", self.store.actions())

    def test_giving_up_says_what_to_do(self):
        autofuse.MAX_BUSY_RETRIES = 2
        self.store.busy_times = 99
        autofuse.schedule("case_1")
        self.settle(3.0)
        detail = [d for a, _s, d in self.store.events if a == "Refusion skipped"]
        self.assertTrue(detail and "Refusion" in detail[0],
                        "the operator must be told a manual Refusion is needed")


class TestFailuresAreLoggedNotSwallowed(_Base):

    def test_a_fuse_error_is_recorded(self):
        self.store.raise_always = RuntimeError("disk full")
        autofuse.schedule("case_1")
        self.settle()
        self.assertIn("Refusion failed", self.store.actions())
        self.assertTrue(any("disk full" in d for _a, _s, d in self.store.events))

    def test_a_fuse_error_does_not_kill_the_scheduler(self):
        self.store.raise_always = RuntimeError("boom")
        autofuse.schedule("case_1")
        self.settle()
        self.store.raise_always = None
        autofuse.schedule("case_2")
        self.settle()
        self.assertEqual(len(self.store.fuses), 2)

    def test_a_broken_store_does_not_raise_out_of_the_timer(self):
        """A timer thread dying with a traceback helps nobody."""
        class Exploding:
            FusionBusy = FusionBusy
            TRIGGER_AUTOMATIC_RUN_LANDED = "x"
            def get_case(self, cid):
                raise RuntimeError("database gone")
            def log_case_event(self, *a, **k):
                raise RuntimeError("log gone too")
        autofuse._store = lambda: Exploding()
        autofuse.schedule("case_1")
        self.settle()      # the assertion is simply that nothing propagated


class TestBookkeeping(_Base):

    def test_the_timer_is_forgotten_once_it_fires(self):
        autofuse.schedule("case_1")
        self.settle()
        self.assertFalse(autofuse.pending("case_1"),
                         "a fired timer must not leak into the registry")

    def test_re_arming_does_not_leak_timers(self):
        for _ in range(50):
            autofuse.schedule("case_1")
        self.assertEqual(len(autofuse._TIMERS), 1)
        self.settle()
        self.assertEqual(len(autofuse._TIMERS), 0)

    def test_timers_are_daemon_threads(self):
        """A pending auto-fuse must never hold up a backend shutdown."""
        autofuse.schedule("case_1", delay=5)
        t = autofuse._TIMERS["case_1"]
        self.assertTrue(t.daemon)
        autofuse.cancel("case_1")

    def test_concurrent_scheduling_is_safe(self):
        """update_run_status can fire from many worker threads at once."""
        threads = [threading.Thread(target=autofuse.schedule, args=("case_1",))
                   for _ in range(40)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(5)
        self.assertLessEqual(len(autofuse._TIMERS), 1)
        self.settle()
        self.assertEqual(len(self.store.fuses), 1)


class TestCrashLoopBreaker(_Base):
    """A fuse can die where no `except` will ever see it: a big case OOMs the
    process (measured — five 547 MB member runs peaked at 5.6 GB and the kernel
    killed it). Automatic retry then becomes fuse-die-restart-fuse-die."""

    def test_a_flag_is_set_before_the_fuse_and_cleared_after(self):
        autofuse.schedule("case_1")
        self.settle()
        self.assertEqual([m.get("auto_fuse_incomplete") for m in self.store.merges],
                         [True, False],
                         "the marker must be written BEFORE the fuse and cleared after")

    def test_a_case_left_marked_is_not_retried(self):
        """This is the loop being broken."""
        self.store.case = {"name": "QA case", "auto_fuse_incomplete": True}
        autofuse.schedule("case_1")
        self.settle()
        self.assertEqual(self.store.fuses, [],
                         "a case whose last automatic fuse vanished must stand down")

    def test_standing_down_tells_the_operator_what_to_do(self):
        self.store.case = {"name": "QA case", "auto_fuse_incomplete": True}
        autofuse.schedule("case_1")
        self.settle()
        detail = [d for a, _s, d in self.store.events if a == "Refusion skipped"]
        self.assertTrue(detail and "Refusion" in detail[0],
                        "it must point at the manual path, not just go quiet")

    def test_a_busy_collision_does_not_leave_the_case_marked(self):
        """Nothing was attempted, so nothing is incomplete."""
        self.store.busy_times = 99
        autofuse.MAX_BUSY_RETRIES = 1
        autofuse.schedule("case_1")
        self.settle(2.0)
        self.assertFalse(self.store.case.get("auto_fuse_incomplete"))

    def test_a_raised_failure_does_not_leave_the_case_marked(self):
        """It raised rather than vanished — the next run may as well try."""
        self.store.raise_always = RuntimeError("transient")
        autofuse.schedule("case_1")
        self.settle()
        self.assertFalse(self.store.case.get("auto_fuse_incomplete"))

    def test_catch_up_also_respects_the_marker(self):
        self.store.all_runs = [{"run_id": "case_1", "automation_type": "case",
                                "details": {"name": "c", "auto_fuse_incomplete": True}}]
        self.store.case = {"name": "c", "auto_fuse_incomplete": True}
        autofuse.catch_up(stagger=0.01)
        self.settle()
        self.assertEqual(self.store.fuses, [],
                         "a restart must not resume the fuse that caused it")


class TestStartupCatchUp(_Base):
    """Timers live in memory. Data that landed in the minute before a restart
    would otherwise wait for the NEXT run to arrive — leaving the operator to
    click, which is the manual step this feature exists to remove."""

    def _case(self, cid, **det):
        det.setdefault("name", "QA case")
        return {"run_id": cid, "automation_type": "case", "details": det}

    def test_a_case_with_unfused_data_is_armed(self):
        self.store.all_runs = [self._case("case_1")]
        self.assertEqual(autofuse.catch_up(stagger=0.01), 1)
        self.settle()
        self.assertEqual(len(self.store.fuses), 1)

    def test_a_current_case_is_not_armed(self):
        self.store.all_runs = [self._case("case_1")]
        self.store._stale = []
        self.store._per_case.clear()
        self.assertEqual(autofuse.catch_up(stagger=0.01), 0)

    def test_an_opted_out_case_is_not_armed(self):
        self.store.all_runs = [self._case("case_1", auto_fuse=False)]
        self.assertEqual(autofuse.catch_up(stagger=0.01), 0)

    def test_non_case_rows_are_ignored(self):
        self.store.all_runs = [{"run_id": "velociraptor_upload_1",
                                "automation_type": "velociraptor_upload", "details": {}}]
        self.assertEqual(autofuse.catch_up(stagger=0.01), 0)

    def test_several_cases_are_staggered_not_simultaneous(self):
        """Ten graphs rebuilding at once on a box that has just come up is worse
        than the problem being solved."""
        self.store.all_runs = [self._case("case_%d" % i) for i in range(4)]
        autofuse.catch_up(stagger=0.05)
        delays = sorted(t.interval for t in autofuse._TIMERS.values())
        self.assertEqual(len(delays), 4)
        self.assertTrue(all(b > a for a, b in zip(delays, delays[1:])),
                        "each case must be armed further out than the last: %r" % delays)
        for cid in list(autofuse._TIMERS):
            autofuse.cancel(cid)

    def test_one_broken_case_does_not_stop_the_rest(self):
        bad = {"run_id": "case_bad", "automation_type": "case", "details": None}
        self.store.all_runs = [bad, self._case("case_ok")]
        armed = autofuse.catch_up(stagger=0.01)
        self.assertGreaterEqual(armed, 1)

    def test_a_store_that_cannot_be_read_returns_zero(self):
        class Broken:
            CASE_TYPE = "case"
            def _ws(self):
                raise RuntimeError("db down")
        autofuse._store = lambda: Broken()
        self.assertEqual(autofuse.catch_up(stagger=0.01), 0)

    def test_catch_up_arms_nothing_when_there_are_no_cases(self):
        self.store.all_runs = []
        self.assertEqual(autofuse.catch_up(stagger=0.01), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
