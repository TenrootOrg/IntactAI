"""Dashboard upgrade runs: Stop, the done marker, and the purge gate.

Pinned here because each was a live-box failure shape (QA item B1/B2):

* Stop flipped the cancel event, the tailer saw it within a second and ran
  `docker rm -f` on the helper -- SIGKILLing the engine in the middle of the
  rollback Stop had just asked for, leaving a module down.
* .done.json was written in place; the tailer finalizes the moment the file
  exists, and a half-written one parsed as rc 1 -> 'failed'.
* A stale .cancel under a reused run_id cancelled the resumed run at step one.
* exit 3 finalized as 'completed' with nothing in the log saying it was not clean.
* System Purge wiped data/tmp (the lock, the run's log, rollback snapshots)
  under a live upgrade.
"""

import os
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "modules", "backend"))

import _optional_deps  # noqa: F401,E402

from services import upgrade_launcher as ul  # noqa: E402

# ul.subprocess IS the subprocess module, so patching its run() patches ours.
_real_run = subprocess.run


class _Done(Exception):
    pass


class LaunchScript(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.tmp, "scripts"))
        os.makedirs(os.path.join(self.tmp, "data", "tmp"))
        # A stand-in bootstrap: the launch script runs it as the engine.
        with open(os.path.join(self.tmp, "scripts", "bootstrap_upgrade.sh"), "w") as f:
            f.write("exit 3\n")
        self.patches = [
            mock.patch.object(ul, "WORKDIR", self.tmp),
            mock.patch.object(ul, "HOST_PATH", self.tmp),
            mock.patch.object(ul, "_current_backend_image", return_value="intact-backend:x"),
            mock.patch.object(ul, "mutate_run_details"),
            mock.patch.object(ul, "register_cleanup"),
            mock.patch.object(ul, "_start_tailer"),
            mock.patch.object(ul, "add_log_to_run"),
            mock.patch.object(ul.subprocess, "run",
                              return_value=subprocess.CompletedProcess([], 0, "", "")),
        ]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        _real_run(["rm", "-rf", self.tmp])

    def test_stale_cancel_is_removed_and_done_marker_is_atomic(self):
        cancel = os.path.join(self.tmp, "data", "tmp", "upgrade-r1.cancel")
        open(cancel, "w").close()
        self.assertIsNone(ul.launch("r1", ["intact-x"]))
        self.assertFalse(os.path.exists(cancel), "a stale .cancel survived launch()")

        script = os.path.join(self.tmp, "data", "tmp", "upgrade-launch-r1.sh")
        with open(script) as fh:
            body = fh.read()
        self.assertIn(".done.json.tmp", body)
        self.assertIn("mv -f", body)
        # Run it for real (the stub engine exits 3): the marker must hold the
        # engine's rc and no .tmp may be left behind.
        r = _real_run(["bash", script], capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 3, r.stderr)
        done = os.path.join(self.tmp, "data", "tmp", "upgrade-r1.done.json")
        with open(done) as fh:
            self.assertEqual(fh.read(), '{"rc":3}')
        self.assertFalse(os.path.exists(done + ".tmp"))


class StopWaitsForTheHelper(unittest.TestCase):
    def test_rm_only_after_the_helper_has_exited(self):
        calls = []

        def fake_run(cmd, **_kw):
            calls.append(cmd[1])
            return subprocess.CompletedProcess(cmd, 0, "", "")

        run = {"details": {"log_path": "/nonexistent.log", "done_path": "/nonexistent.done",
                           "helper_container": "intact-upgrade-runner-r1"}}
        with mock.patch.object(ul, "get_automation_run", return_value=run), \
             mock.patch.object(ul, "is_cancelled", return_value=True), \
             mock.patch.object(ul, "mutate_run_details"), \
             mock.patch.object(ul.subprocess, "run", side_effect=fake_run):
            ul._tail_and_finalize("r1")
        self.assertIn("rm", calls)
        self.assertIn("wait", calls, "the helper is removed without waiting for its unwind")
        self.assertLess(calls.index("wait"), calls.index("rm"))


class ExitThreeIsSaidOutLoud(unittest.TestCase):
    def test_rc3_completes_with_a_warning(self):
        with tempfile.NamedTemporaryFile("w", suffix=".done.json", delete=False) as f:
            f.write('{"rc":3}')
        logs = []
        try:
            with mock.patch.object(ul, "update_run_status") as urs, \
                 mock.patch.object(ul, "add_log_to_run",
                                   side_effect=lambda rid, msg, lvl="info": logs.append(lvl)), \
                 mock.patch.object(ul, "get_automation_run", return_value={}):
                ul._finalize("r1", f.name)
        finally:
            os.remove(f.name)
        self.assertEqual(urs.call_args[0][1], "completed")
        self.assertIn("warning", logs)


class BlockingUpgradeRun(unittest.TestCase):
    def test_running_row_blocks(self):
        rows = [{"automation_type": "upgrade_package_upload", "status": "running", "run_id": "u1"}]
        with mock.patch.object(ul, "get_all_automation_runs", return_value=rows), \
             mock.patch.object(ul, "_upgrade_in_flight", return_value=False):
            self.assertEqual(ul.blocking_upgrade_run(), "u1")

    def test_lock_alone_blocks(self):
        with mock.patch.object(ul, "get_all_automation_runs", return_value=[]), \
             mock.patch.object(ul, "_upgrade_in_flight", return_value=True):
            self.assertEqual(ul.blocking_upgrade_run(), "upgrade.lock")

    def test_finished_rows_and_free_lock_do_not_block(self):
        rows = [{"automation_type": "upgrade", "status": "completed", "run_id": "u1"},
                {"automation_type": "system_purge", "status": "running", "run_id": "p1"}]
        with mock.patch.object(ul, "get_all_automation_runs", return_value=rows), \
             mock.patch.object(ul, "_upgrade_in_flight", return_value=False):
            self.assertIsNone(ul.blocking_upgrade_run())


def _fake_flask():
    """Just enough flask for the route module to import: route() must keep the
    real function, which the permissive _optional_deps stub would not."""
    m = types.ModuleType("flask")

    class Blueprint:
        def __init__(self, *a, **k):
            pass

        def route(self, *a, **k):
            return lambda fn: fn

    m.Blueprint = Blueprint
    m.jsonify = lambda *a, **k: (a[0] if a else k)
    m.request = types.SimpleNamespace(get_json=lambda silent=True: {"sections": ["temp_files"]},
                                      json={}, args={})
    return m


class PurgeRefusesDuringAnUpgrade(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import importlib.util
        sys.modules.setdefault("flask", _fake_flask())
        # By path: routes/__init__.py imports every blueprint, and their flask
        # needs (session, ...) are not what this test is about.
        spec = importlib.util.spec_from_file_location(
            "maintenance_routes_under_test",
            os.path.join(HERE, "..", "modules", "backend", "routes", "maintenance_routes.py"))
        cls.mr = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.mr)

    def _assert_refused(self, route):
        with mock.patch.object(ul, "blocking_upgrade_run", return_value="u1"), \
             mock.patch.object(self.mr, "create_automation_run",
                               side_effect=_Done("a purge run was created")):
            body, code = route()
        self.assertEqual(code, 409)
        self.assertEqual(body["blocking_run_id"], "u1")

    def test_full_purge(self):
        self._assert_refused(self.mr.run_system_purge)

    def test_section_purge(self):
        self._assert_refused(self.mr.purge_selected_sections)

    def test_no_upgrade_lets_it_through(self):
        with mock.patch.object(ul, "blocking_upgrade_run", return_value=None), \
             mock.patch.object(self.mr, "create_automation_run",
                               side_effect=_Done("reached")):
            with self.assertRaises(_Done):
                self.mr.purge_selected_sections()


if __name__ == "__main__":
    unittest.main()
