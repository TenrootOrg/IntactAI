"""Static guards for the qa/ harness.

The harness drives a ~2-hour run: install an appliance, enrol a client, sweep
the API. Every defect these tests catch would otherwise surface an hour and a
half in, on a runner, after the box had already been destroyed and rebuilt — a
typo in a phase name, a `needs=` pointing at a phase that no longer registers, a
credential quietly dropped from the redaction set.

Deliberately zero-dependency and offline: tests/run_tests.sh runs on a dev box,
in CI and on a live appliance, so nothing here may import requests, paramiko or
yaml, or touch the network. That rules out importing the phase modules, so the
checks below read the source instead. Less precise, and it runs everywhere.
"""

import ast
import os
import re
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
QA = os.path.join(ROOT, "qa")

PHASE_FILES = ("platform.py", "endpoint.py", "endpoint_linux.py",
               "features.py", "pipelines.py", "upgrade.py", "workflows.py",
               "wrapup.py")


def _read(*parts):
    with open(os.path.join(QA, *parts), encoding="utf-8") as fh:
        return fh.read()


def _phase_decls(src):
    """(name, needs) for every @runner.phase in a module, by parsing the AST.

    A regex over the decorator would miss multi-line calls and match the ones
    inside docstrings; the AST cannot.
    """
    out = []
    for node in ast.walk(ast.parse(src)):
        if not isinstance(node, ast.FunctionDef):
            continue
        for dec in node.decorator_list:
            if not isinstance(dec, ast.Call):
                continue
            f = dec.func
            if not (isinstance(f, ast.Attribute) and f.attr == "phase"):
                continue
            name = None
            if dec.args and isinstance(dec.args[0], ast.Constant):
                name = dec.args[0].value
            needs = ()
            for kw in dec.keywords:
                if kw.arg == "needs" and isinstance(kw.value, (ast.Tuple, ast.List)):
                    needs = tuple(e.value for e in kw.value.elts
                                  if isinstance(e, ast.Constant))
            if name:
                out.append((name, needs))
    return out


class TestPhaseModules(unittest.TestCase):

    def test_every_phase_module_parses(self):
        for fn in PHASE_FILES:
            with self.subTest(module=fn):
                ast.parse(_read("phases", fn))

    def test_needs_graph_has_no_dangling_names(self):
        """A `needs=` naming a phase nobody registers silently skips forever.

        The runner reports it as "not reached", which looks like a deliberate
        skip rather than a broken reference — so this class of typo can survive
        for weeks while quietly removing coverage.
        """
        declared, edges = set(), []
        for fn in PHASE_FILES:
            for name, needs in _phase_decls(_read("phases", fn)):
                declared.add(name)
                edges += [(name, n) for n in needs]

        # `wipe` is legitimately absent when the operator skips it (a fresh CI
        # runner has nothing to tear down); the runner treats an operator skip
        # as satisfying the dependency.
        allowed = declared | {"wipe"}
        dangling = sorted({(a, b) for a, b in edges if b not in allowed})
        self.assertFalse(
            dangling,
            "phase(s) depend on something never registered: "
            + ", ".join(f"{a} needs {b}" for a, b in dangling))

    def test_the_linux_profile_registers_its_own_phases(self):
        names = {n for n, _ in _phase_decls(_read("phases", "endpoint_linux.py"))}
        self.assertEqual(names, {"enrol_linux", "teardown_linux"})

    def test_run_qa_registers_every_phase_module(self):
        src = _read("run_qa.py")
        for mod in ("platform", "endpoint", "endpoint_linux", "features",
                    "pipelines", "upgrade", "workflows", "wrapup"):
            with self.subTest(module=mod):
                self.assertIn(f"{mod}.register(runner, cfg)", src,
                              f"{mod} is never registered, so its phases can "
                              f"never run")


class TestWindowsIsOptional(unittest.TestCase):
    """A Linux-only profile must be able to start at all.

    Before this split, REQUIRED demanded Windows credentials and the critical
    preflight phase failed on any Windows-SSH exception — so a run without a
    Windows box aborted before doing anything.
    """

    def test_required_is_split_but_secret_fields_are_not(self):
        src = _read("lib", "config.py")
        self.assertIn("PLATFORM_REQUIRED", src)
        self.assertIn("WINDOWS_REQUIRED", src)
        self.assertIn("REQUIRED = PLATFORM_REQUIRED + WINDOWS_REQUIRED", src)
        # The load-bearing one. Redaction must cover every credential
        # regardless of which half a given profile requires -- this repo is
        # public, and a Windows password that is set but not *required* is
        # still a password.
        self.assertIn("SECRET_FIELDS = REQUIRED", src)

    def test_windows_phases_do_not_register_without_a_target(self):
        src = _read("phases", "endpoint.py")
        self.assertRegex(
            src, r"def register\(runner, cfg\):(?:.|\n)*?if not cfg\.windows_enabled:\s*\n\s*return",
            "endpoint.register must return early without a Windows target, or "
            "its phases fail for a machine that is not part of the run")

    def test_preflight_gates_its_windows_block(self):
        src = _read("phases", "platform.py")
        self.assertIn("if not cfg.windows_enabled:", src)
        self.assertIn("if cfg.windows_enabled:", src)


class TestWaitContract(unittest.TestCase):
    """tl.wait(describe=...) takes a CALLABLE, not a description string.

    Found the expensive way: a string passed here raised TypeError from inside
    tl.wait — and only on the success path, because describe(value) is reached
    solely when the probe returns something. So the phase worked perfectly, then
    crashed while logging its own success, and the run reported an error for a
    thing that had actually succeeded. Static, because the failure needs a live
    appliance and ten minutes of install to reach.
    """

    def test_every_wait_passes_a_callable_describe(self):
        offenders = []
        for fn in PHASE_FILES:
            tree = ast.parse(_read("phases", fn))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                f = node.func
                if not (isinstance(f, ast.Attribute) and f.attr == "wait"):
                    continue
                for kw in node.keywords:
                    if kw.arg != "describe":
                        continue
                    if isinstance(kw.value, ast.Constant):
                        offenders.append(f"{fn}:{kw.value.lineno} describe="
                                         f"{kw.value.value!r}")
        self.assertFalse(offenders,
                         "tl.wait(describe=) must be callable — a constant "
                         "raises TypeError only when the wait SUCCEEDS: "
                         + "; ".join(offenders))


class TestFeatureSweepSafety(unittest.TestCase):

    def test_nothing_the_sweep_calls_is_on_the_denylist(self):
        """The denylist is not advisory.

        /api/maintenance/purge destroys the appliance's data and
        /api/auth/login locks the account for 15 minutes after 10 failures.
        Either one turns a diagnostic run into an outage.
        """
        src = _read("phases", "features.py")
        tree = ast.parse(src)
        deny, called = set(), set()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            target = node.targets[0]
            if not isinstance(target, ast.Name):
                continue
            if target.id == "DENYLIST" and isinstance(node.value, ast.Dict):
                deny = {k.value for k in node.value.keys
                        if isinstance(k, ast.Constant)}
            if target.id in ("TIER0", "TIER0_VELOCIRAPTOR") and \
                    isinstance(node.value, ast.List):
                for row in node.value.elts:
                    if isinstance(row, ast.Tuple) and len(row.elts) >= 2 and \
                            isinstance(row.elts[1], ast.Constant):
                        called.add(row.elts[1].value)

        self.assertTrue(deny, "DENYLIST did not parse — the guard is vacuous")
        self.assertTrue(called, "TIER0 did not parse — the guard is vacuous")
        self.assertFalse(sorted(called & deny),
                         "the sweep calls a denylisted endpoint")

    def test_the_auth_counterweight_exists(self):
        """The sweep runs WITH a session and expects to get through, which on
        its own is satisfied by an appliance that lets everybody through. The
        counterweight asks for the same guarded paths with no session and
        requires a refusal; without it the phase proves only half of what it
        appears to."""
        src = _read("phases", "features.py")
        self.assertIn("_tier0_auth_counterweight", src)
        self.assertRegex(src, r"code in \(401, 403\)")

    def test_the_sweep_does_not_use_a_loopback_client(self):
        """Measured on a live appliance, not inferred from the code.

        auth_service.gate_decision() exempts 127.0.0.1, and the backend is
        published on 127.0.0.1:5001, which reads like "curl localhost and skip
        auth". It is not: the backend is in a container, so a request through
        the published port arrives NATed from the bridge gateway and every
        /api/ path answers 401 from the host — 200 only from inside the
        container. A sweep built on that misreading would report the entire
        product as broken.
        """
        src = _read("phases", "features.py")
        self.assertNotIn('Client("127.0.0.1:5001"', src,
                         "the sweep must use the auth phase's session client; "
                         "a loopback client 401s on every request from the host")
        self.assertIn('lb = ctx.get("client")', src)

    def test_external_credential_endpoints_are_recorded_not_silently_dropped(self):
        src = _read("phases", "features.py")
        self.assertIn("SKIPPED_EXTERNAL", src)
        for needle in ("/api/aws/scan", "/api/azure/scan", "/api/config/llm/test"):
            self.assertIn(needle, src,
                          f"{needle} must be listed as skipped with a reason, "
                          f"so a green report is not read as full coverage")


class TestIngestTraps(unittest.TestCase):
    """The three ways a green ingest can mean nothing.

    Each of these was measured on a live appliance, and each produces a run the
    dashboard reports as COMPLETED while having accomplished nothing.
    """

    def test_plaso_parser_is_always_explicit(self):
        """The tus hook defaults plaso_parser to 'win7'.

        win7 against Linux logs extracts zero events, the pipeline logs "No
        events extracted", marks the run completed and returns WITHOUT creating
        a sketch. Omitting the key is therefore not a neutral default — it is
        the silent-failure path.
        """
        src = _read("phases", "pipelines.py")
        # A fixed window after the marker rather than a brace match: the dict
        # contains f-strings, and their braces close a naive regex early.
        starts = [m.end() for m in
                  re.finditer(r'"purpose":\s*"timesketch"', src)]
        self.assertTrue(starts, "no timesketch tus upload found to check")
        for pos in starts:
            window = src[pos:pos + 400]
            self.assertIn("plaso_parser", window,
                          "every timesketch upload must set plaso_parser "
                          "explicitly; the hook's default is win7")

    def test_the_event_count_is_asserted_against_the_evidence(self):
        """A completed run with zero events creates no sketch and still
        reports success -- but ">0" is not enough either. Three events from
        twenty megabytes of logs is a parser that stopped matching, and it
        passes a bare non-zero check. Every ingest must compare the count to a
        floor derived from what was actually uploaded."""
        src = _read("phases", "pipelines.py")
        floors = re.findall(r"^\s*floor = .*$", src, re.M)
        self.assertTrue(floors,
                        "no proportional floor found; the ingest assertions "
                        "have reverted to a bare >0")
        for line in floors:
            self.assertIn("//", line,
                          f"a floor that is not derived from the evidence size "
                          f"is just a magic number: {line.strip()}")
        checks = re.findall(r"\(events or 0\)\s*(>=?)\s*(\w+)", src)
        self.assertTrue(checks, "no event-count assertion found at all")
        for op, rhs in checks:
            self.assertEqual(
                (op, rhs), (">=", "floor"),
                "an event count must be compared against the proportional "
                f"floor, not `{op} {rhs}`")

    def test_memory_image_is_uploaded_bare(self):
        """Inside a ZIP the floor is 200 MB and smaller members are discarded as
        metadata; bare, it is 16 MB. Zipping the image is how a working
        acquisition turns into 'no recognisable memory image'."""
        src = _read("phases", "pipelines.py")
        self.assertIn("/api/memory/upload", src)
        self.assertNotRegex(
            src, r"/api/memory/upload(?:.|\n){0,400}?\.zip",
            "the memory image must be uploaded bare, never zipped")


class TestUpgradeRoutes(unittest.TestCase):
    """The two facts about upgrades that a harness gets wrong by default."""

    def test_the_harness_asserts_exit_code_not_status(self):
        """rc 3 is reported as "completed".

        upgrade_launcher maps 0 AND 3 to "completed" with force=True, because a
        degraded run necessarily logged an ERROR line that would otherwise flip
        it to failed. A harness that asserts on status therefore scores "applied
        but degraded" as a pass -- the exact outcome an upgrade test exists to
        catch."""
        src = _read("phases", "upgrade.py")
        self.assertIn("exit_code", src)
        self.assertRegex(src, r"rc\s*==\s*up\.RC_CLEAN",
                         "the upgrade phase must assert the exit code is 0, "
                         "not merely that the status says completed")

    def test_the_cli_route_pins_the_engine_through_sudo_env(self):
        """scripts/upgrade.sh execs the bootstrap unless INTACT_UPGRADE_REEXEC
        is set -- and sudo resets the environment, so setting it in the parent
        does nothing. Measured: both a plain env dict and preserve_env came back
        empty. `sudo env VAR=1` is the form that works."""
        src = _read("lib", "upgrade.py")
        self.assertIn('"env", "INTACT_UPGRADE_REEXEC=1"', src,
                      "the engine pin must be passed as `sudo env VAR=1`; an "
                      "env dict is stripped by sudo and silently ignored")

    def test_every_scenario_maps_to_a_known_route(self):
        src = _read("phases", "upgrade.py")
        tree = ast.parse(src)
        routes, mapped = set(), set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and any(
                    isinstance(t, ast.Name) and t.id == "UPGRADE_ROUTES"
                    for t in node.targets) and isinstance(node.value, ast.Dict):
                routes = {k.value for k in node.value.keys
                          if isinstance(k, ast.Constant)}
            if isinstance(node, ast.Dict):
                for k, v in zip(node.keys, node.values):
                    if isinstance(k, ast.Constant) and isinstance(v, ast.Constant) \
                            and isinstance(v.value, str) and "-" in str(k.value):
                        mapped.add(v.value)
        self.assertTrue(routes, "UPGRADE_ROUTES did not parse")
        unknown = sorted(mapped - routes)
        self.assertFalse(unknown,
                         "scenario(s) map to a route that does not exist: "
                         + ", ".join(unknown))


class _FakeCtx:
    """The smallest thing Runner will accept: a timeline that swallows events,
    a check buffer, and a run directory to persist into."""

    class _Timeline:
        def stage(self, *a, **k): pass
        def ok(self, *a, **k): pass
        def warn(self, *a, **k): pass
        def fail(self, *a, **k): pass

    def __init__(self, run_dir):
        self.run_dir = run_dir
        self.tl = self._Timeline()
        self.results = {}
        self.redact = lambda text: text

    def take_checks(self):
        return []


class _StubCfg:
    """Enough of a config to register phases, with no appliance anywhere."""

    def __init__(self, scenario, hop_via=None):
        self.scenario = scenario
        self.platform_host = "10.0.0.1"
        self.windows_host = None
        self.linux_client = True
        self.feature_sweep = True
        self.pipelines = True
        self.plant_evidence = True
        self.repo_dir = "/mnt/intact"
        self.upgrade_to = "intact-20260818"
        self.upgrade_package = None
        self.upgrade_extra = ()
        self.downgrade_tag = None
        self.hop_via = hop_via
        self.sudo_user = "runner"
        self.sudo_password = "x"

    def get(self, *a, **kw):
        return kw.get("default")

    def secrets(self):
        return []

    def __getattr__(self, name):        # anything else a phase module reads
        return None


class TestRunDirectoryRedaction(unittest.TestCase):
    """The product writes into the run directory, and those files are uploaded.

    run_bootstrap and run_cli pass `--log <path>` pointing INTO the run
    directory, so the engine writes there itself and ctx.redact never sees it.
    That is how a configured credential reached an uploaded artifact while
    every harness-written file was clean. The sweep exists to close that, and
    it must not touch the one file whose job is to hold the credential.
    """

    def _run(self, tmp, secret):
        sys.path.insert(0, os.path.join(ROOT, "qa"))
        from phases import wrapup

        class _Ctx:
            run_dir = tmp
            redact = staticmethod(
                lambda text: text.replace(secret, "[REDACTED]"))

        return wrapup._redact_run_directory(_Ctx())

    def test_a_log_the_product_wrote_is_cleaned(self):
        import shutil
        import tempfile
        tmp = tempfile.mkdtemp(prefix="qa-redact-")
        try:
            os.makedirs(os.path.join(tmp, "logs"))
            engine_log = os.path.join(tmp, "logs", "upgrade-cli.log")
            with open(engine_log, "w", encoding="utf-8") as fh:
                fh.write("connecting as hunter2 to the appliance\n")
            changed = self._run(tmp, "hunter2")
            body = open(engine_log, encoding="utf-8").read()
            self.assertEqual(changed, 1)
            self.assertNotIn("hunter2", body)
            self.assertIn("[REDACTED]", body)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_the_credential_file_is_left_alone(self):
        """It exists to hold the credential; redacting it would make a run
        undescribable and the leak check cry wolf."""
        import shutil
        import tempfile
        tmp = tempfile.mkdtemp(prefix="qa-redact-")
        try:
            creds = os.path.join(tmp, "dashboard-credentials.txt")
            with open(creds, "w", encoding="utf-8") as fh:
                fh.write("password: hunter2\n")
            self._run(tmp, "hunter2")
            self.assertIn("hunter2", open(creds, encoding="utf-8").read())
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_binaries_are_not_rewritten(self):
        import shutil
        import tempfile
        tmp = tempfile.mkdtemp(prefix="qa-redact-")
        try:
            blob = os.path.join(tmp, "memory.raw")
            with open(blob, "wb") as fh:
                fh.write(b"\x00\x01hunter2\xff")
            self._run(tmp, "hunter2")
            self.assertEqual(open(blob, "rb").read(), b"\x00\x01hunter2\xff")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestResultsJsonIsFinal(unittest.TestCase):
    """results.json must reflect every phase, including the last one.

    It used to be written from inside the `report` phase, so report's own
    result did not exist yet and never appeared in the counts. The redaction
    canary and the credential scan both run in that phase -- so a run that
    found a genuine secret leak wrote "fail: 0" and CI passed the job.
    """

    def test_main_rewrites_it_after_the_run(self):
        src = _read("run_qa.py")
        self.assertIn("_write_results_json(run_dir, tl.run_id, results, counts)",
                      src,
                      "results.json is only written from inside a phase, so "
                      "that phase's own verdict can never reach CI")
        run_pos = src.index("results = runner.run(")
        write_pos = src.index("_write_results_json(run_dir")
        self.assertLess(run_pos, write_pos,
                        "results.json must be written AFTER runner.run()")


class TestPhaseOrderPerScenario(unittest.TestCase):
    """Every phase's dependencies must run BEFORE it, in every scenario.

    A `needs=` naming a phase that ends up later in the list is not an error at
    runtime -- the phase is simply SKIPPED, and a skip is not a failure. So the
    failure mode is a green job that never did the thing it exists to do.

    That is not hypothetical. `auth` was reordered after `upgrade` for every
    upgrade scenario, to suit the shell routes on old boxes that have no auth
    system to claim yet. The dashboard routes are driven THROUGH the
    authenticated API and declare needs=("auth",), so all four UI scenarios
    would have skipped the upgrade entirely and reported success.
    """

    def setUp(self):
        sys.path.insert(0, os.path.join(ROOT, "qa"))

    def _phases_for(self, scenario, hop_via=None):
        import shutil
        import tempfile
        import run_qa
        from lib import runner as runner_lib

        class _TL:
            def __getattr__(self, n):
                return lambda *a, **k: None

        tmp = tempfile.mkdtemp(prefix="qa-order-")
        try:
            os.makedirs(os.path.join(tmp, "phases"), exist_ok=True)
            cfg = _StubCfg(scenario, hop_via)
            ctx = runner_lib.PhaseContext(cfg, _TL(), tmp, {}, lambda t: t)
            return run_qa.build_runner(ctx, cfg).phases
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_every_scenario_orders_its_dependencies_correctly(self):
        import scenarios
        problems = []
        for row in scenarios.SCENARIOS:
            phases = self._phases_for(
                row["name"], scenarios.ROLES.get(row.get("hop_via")))
            order = {p["name"]: i for i, p in enumerate(phases)}
            for p in phases:
                for dep in p["needs"]:
                    if dep in order and order[dep] > order[p["name"]]:
                        problems.append(
                            f"{row['name']}: {p['name']} needs {dep}, which "
                            f"runs later -- {p['name']} would be silently "
                            f"skipped")
        self.assertFalse(problems, "phases that can never run:\n  "
                         + "\n  ".join(problems))

    def test_the_hop_runs_before_the_box_is_claimed(self):
        """A hop exists because the starting box cannot do the job itself.

        ui-online-full and ui-import-full start on intact-20260726, which has
        no auth system -- /api/auth/status answers 404 -- and `auth` is
        critical. The hop to intact-20260811 is what puts an auth system on the
        box, so running it inside the upgrade phase meant the run aborted
        before the hop it depended on had happened."""
        import scenarios
        checked = 0
        for row in scenarios.SCENARIOS:
            hop = scenarios.ROLES.get(row.get("hop_via"))
            if not hop:
                continue
            names = [p["name"] for p in self._phases_for(row["name"], hop)]
            self.assertIn("hop", names, f"{row['name']} declares hop_via but "
                                        f"registers no hop phase")
            self.assertLess(names.index("install"), names.index("hop"))
            if "auth" in names:
                self.assertLess(
                    names.index("hop"), names.index("auth"),
                    f"{row['name']}: the box has no auth system until the hop "
                    f"has installed one")
            checked += 1
        self.assertTrue(checked, "no hop scenarios found to check")

    def test_security_is_asserted_against_the_final_box(self):
        """It checks TODAY's hardening. An upgrade scenario that starts on an
        old release would otherwise fail nine checks describing what that
        release simply was."""
        import scenarios
        for row in scenarios.SCENARIOS:
            if not row.get("route"):
                continue
            names = [p["name"] for p in self._phases_for(
                row["name"], scenarios.ROLES.get(row.get("hop_via")))]
            self.assertLess(
                names.index("upgrade"), names.index("security"),
                f"{row['name']}: hardening is checked before the upgrade, so "
                f"it describes the box the run started from")

    def test_the_ui_routes_authenticate_before_they_upgrade(self):
        """Stated separately because it is the specific thing that broke, and
        because 'the upgrade phase actually runs' is the whole point of those
        four scenarios."""
        import scenarios
        for row in scenarios.SCENARIOS:
            if not (row.get("route") or "").startswith("ui_"):
                continue
            names = [p["name"] for p in self._phases_for(
                row["name"], scenarios.ROLES.get(row.get("hop_via")))]
            self.assertIn("auth", names, row["name"])
            self.assertIn("upgrade", names, row["name"])
            self.assertLess(
                names.index("auth"), names.index("upgrade"),
                f"{row['name']}: a dashboard upgrade is driven through the "
                f"authenticated API, so auth must precede it")


class TestSelfAssertingScenarios(unittest.TestCase):
    """A scenario excused from "exited cleanly" must assert something instead.

    `rollback` is supposed to end with a non-zero exit code, so it is exempted
    from the generic check and asserts its own outcome in `_post_upgrade`. The
    hazard is an exemption with nothing behind it: a name added to the exempt
    set but never given a branch would silently assert NOTHING about the one
    outcome the scenario exists to observe, and would pass every time.
    """

    def setUp(self):
        self.src = _read("phases", "upgrade.py")

    def _exempt(self):
        m = re.search(r"_SELF_ASSERTING\s*=\s*frozenset\(\{(.*?)\}\)",
                      self.src, re.S)
        self.assertTrue(m, "_SELF_ASSERTING is not defined as a frozenset")
        return set(re.findall(r'"([^"]+)"', m.group(1)))

    def test_the_exempt_set_is_defined_and_not_empty(self):
        self.assertTrue(self._exempt(),
                        "an empty exempt set means the branch is dead code")

    def test_every_exempt_scenario_asserts_its_own_outcome(self):
        post = self.src.split("def _post_upgrade", 1)
        self.assertEqual(len(post), 2, "could not find _post_upgrade")
        body = post[1]
        for name in self._exempt():
            self.assertIn(
                f'"{name}"', body,
                f"{name} is excused from the clean-exit check but has no "
                f"branch in _post_upgrade, so its exit code is never asserted "
                f"at all")

    def test_every_exempt_scenario_exists_in_the_catalogue(self):
        sys.path.insert(0, os.path.join(ROOT, "qa"))
        import scenarios
        known = {row["name"] for row in scenarios.SCENARIOS}
        unknown = sorted(self._exempt() - known)
        self.assertFalse(unknown,
                         "exempted scenarios that do not exist: "
                         + ", ".join(unknown))


class TestReportSurvivesAnAbort(unittest.TestCase):
    """A critical failure must still leave a report behind.

    Measured, not theorised: in run 32353670435 every one of nine failing
    scenarios reached CI as the same line -- "the harness produced no
    results.json" -- because `report` is itself a phase and an abort skipped
    it, along with `collect`. Four genuinely different faults were
    indistinguishable, and the logs were discarded at the exact moment they
    became worth having.
    """

    def test_the_runner_honours_an_always_flag(self):
        """Driven for real rather than grepped: register a critical phase that
        blows up, and prove an ordinary phase is skipped while an always-phase
        still runs."""
        import shutil
        import tempfile

        sys.path.insert(0, os.path.join(ROOT, "qa"))
        from lib import runner as runner_lib

        tmp = tempfile.mkdtemp(prefix="qa-runner-test-")
        try:
            os.makedirs(os.path.join(tmp, "phases"))
            ctx = _FakeCtx(tmp)
            r = runner_lib.Runner(ctx)

            @r.phase("boom", "Fails, and is critical", critical=True)
            def boom(ctx):
                raise RuntimeError("name '_SELF_ASSERTING' is not defined")

            @r.phase("ordinary", "Must not run after the abort")
            def ordinary(ctx):
                ran.append("ordinary")

            @r.phase("report", "Must run anyway", always=True)
            def report(ctx):
                ran.append("report")

            ran = []
            results = r.run()

            self.assertEqual(results["boom"].status, runner_lib.ERROR)
            self.assertEqual(results["ordinary"].status, runner_lib.SKIP)
            self.assertEqual(results["ordinary"].skipped_because,
                             "run aborted earlier")
            self.assertIn("report", ran,
                          "the report phase did not run after a critical "
                          "abort, so a failed run leaves no results.json")
            self.assertNotIn("ordinary", ran)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_collect_and_report_are_marked_always(self):
        src = _read("phases", "wrapup.py")
        for name in ("collect", "report"):
            m = re.search(r'@runner\.phase\("%s".*?\)\s*\n\s*def ' % name,
                          src, re.S)
            self.assertTrue(m, f"{name} phase not found")
            self.assertIn("always=True", m.group(0),
                          f"{name} does not run after an abort -- which is "
                          f"precisely when it matters")

    def test_results_json_is_written_by_an_always_phase(self):
        """Whoever writes results.json must survive an abort, or the workflow's
        verdict step can never report counts for a failed run."""
        src = _read("phases", "wrapup.py")
        head = src.split("results.json")[0]
        owner = re.findall(r'@runner\.phase\("([a-z_]+)"', head)
        self.assertTrue(owner, "nothing appears to write results.json")
        self.assertEqual(owner[-1], "report",
                         "results.json moved to another phase; that phase now "
                         "needs always=True")


class TestNoHardCodedApplianceePath(unittest.TestCase):
    """CI installs to /mnt/intact, not /home/tenroot/intact."""

    def test_git_head_takes_the_repo_dir(self):
        src = _read("run_qa.py")
        self.assertIn("def _git_head(repo_dir=None):", src)
        self.assertIn("_git_head(cfg.repo_dir)", src)


if __name__ == "__main__":
    unittest.main(verbosity=2)
