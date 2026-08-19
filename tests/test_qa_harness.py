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
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
QA = os.path.join(ROOT, "qa")

PHASE_FILES = ("platform.py", "endpoint.py", "endpoint_linux.py",
               "features.py", "workflows.py", "wrapup.py")


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
                    "workflows", "wrapup"):
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


class TestNoHardCodedApplianceePath(unittest.TestCase):
    """CI installs to /mnt/intact, not /home/tenroot/intact."""

    def test_git_head_takes_the_repo_dir(self):
        src = _read("run_qa.py")
        self.assertIn("def _git_head(repo_dir=None):", src)
        self.assertIn("_git_head(cfg.repo_dir)", src)


if __name__ == "__main__":
    unittest.main(verbosity=2)
