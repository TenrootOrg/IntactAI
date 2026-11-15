"""Two settings workflows that ended in the wrong state.

D6. Clicking Test on the Codex subscription connector while the first test was
still running marked the first run "failed: superseded" without stopping it; its
worker then wrote 'completed' over that. Now only rows whose worker is gone
(backend restart) are closed.

D8. The Timesketch LLM save ended green 'completed' when the web UI never came
back after the restart, and a second save started a second worker that rewrote
timesketch.conf and restarted the containers again. Now: 'failed' with the
reason, and an overlapping PUT gets 409.

flask and the backend services are stubbed: the route files are loaded straight
from disk so this runs on stdlib python3 like the rest of tests/.
"""

import importlib.util
import os
import sys
import threading
import types
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROUTES = os.path.join(ROOT, "modules/backend/routes")


class _BP:
    def __init__(self, *a, **k):
        pass

    def route(self, *a, **k):
        return lambda f: f


class _Req:
    body = {}
    args = {}

    def get_json(self, silent=False):
        return self.body


def _stub(name, **attrs):
    m = types.ModuleType(name)
    m.__dict__.update(attrs)
    sys.modules[name] = m
    return m


REQ = _Req()
_stub("flask", Blueprint=_BP, jsonify=lambda *a, **k: (a[0] if a else k),
      request=REQ)
WS = _stub("services.workflow_service",
           create_automation_run=mock.Mock(return_value="run-new"),
           add_log_to_run=mock.Mock(), update_run_status=mock.Mock(),
           _system_case_id=lambda: "sys",
           get_automation_runs_by_case=mock.Mock(return_value=[]))
SUB = _stub("services.agentic.subscription_cli",
            WORKFLOW_NAMES={"test": "Test Codex CLI"},
            is_run_active=lambda rid: rid == "alive",
            _mark_active=mock.Mock())
_stub("services.agentic", subscription_cli=SUB)
_stub("services.openrouter_key", save=lambda v, **k: v,
      read_conf_value=lambda *a, **k: None)
_stub("services", workflow_service=WS, agentic=sys.modules["services.agentic"],
      openrouter_key=sys.modules["services.openrouter_key"],
      create_automation_run=WS.create_automation_run,
      add_log_to_run=WS.add_log_to_run, update_run_status=WS.update_run_status)


def _load(name):
    spec = importlib.util.spec_from_file_location(
        name, os.path.join(ROUTES, name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


cli = _load("agentic_cli_routes")
tsl = _load("timesketch_llm_routes")


class CloseOrphanedRuns(unittest.TestCase):
    def setUp(self):
        WS.update_run_status.reset_mock()
        WS.get_automation_runs_by_case.return_value = [
            {"run_id": "alive", "name": "Test Codex CLI", "status": "running"},
            {"run_id": "dead", "name": "Test Codex CLI", "status": "pending"},
            {"run_id": "other", "name": "Something else", "status": "pending"},
        ]

    def test_only_dead_worker_rows_are_closed(self):
        cli._close_orphaned_runs("codex-subscription")
        closed = [c.args[0] for c in WS.update_run_status.call_args_list]
        self.assertEqual(closed, ["dead"])
        self.assertEqual(WS.update_run_status.call_args.args[1], "failed")

    def test_new_run_is_active_before_its_thread_starts(self):
        SUB._mark_active.reset_mock()
        with mock.patch.object(cli.threading, "Thread") as T:
            T.return_value.start.side_effect = lambda: self.assertTrue(
                SUB._mark_active.called)
            cli._start_action("codex-subscription", "test", lambda *a: None)
        SUB._mark_active.assert_called_once_with("run-new")


class _Proc:
    def __init__(self, out=""):
        self.returncode, self.stdout, self.stderr = 0, out, ""


def _fake_run(cmd, **k):
    if cmd[:2] == ["docker", "inspect"]:
        return _Proc("healthy")
    if cmd[:2] == ["docker", "ps"]:
        return _Proc("Up 10 seconds")
    return _Proc()


class TimesketchSave(unittest.TestCase):
    def setUp(self):
        WS.update_run_status.reset_mock()
        if tsl._settings_save_lock.locked():
            tsl._settings_save_lock.release()

    def _worker(self):
        # Everything before the restart phase is file editing; skip to it.
        with mock.patch.object(tsl, "_ensure_conf_from_template", return_value=True), \
             mock.patch.object(tsl, "_ensure_dfiq_data"), \
             mock.patch("builtins.open", mock.mock_open(read_data="")), \
             mock.patch.object(tsl.os.path, "exists", return_value=True), \
             mock.patch.object(tsl.shutil, "copy2", create=True), \
             mock.patch.object(tsl.subprocess, "run", side_effect=_fake_run), \
             mock.patch.object(tsl.time, "sleep"), \
             mock.patch("urllib.request.urlopen", side_effect=OSError("refused")):
            tsl._settings_save_lock.acquire()
            tsl._run_timesketch_settings_workflow(
                "r1", {"llm_mode": "ollama", "ollama_url": "http://x",
                       "ollama_model": "m"})

    def test_unreachable_web_ui_is_not_green(self):
        self._worker()
        final = WS.update_run_status.call_args
        self.assertEqual(final.args[1], "failed", WS.update_run_status.call_args_list)
        self.assertIn("not reachable", final.kwargs["error"])
        self.assertFalse(tsl._settings_save_lock.locked(),
                         "worker must release the lock")

    def test_second_save_while_running_is_409(self):
        REQ.body = {"llm_mode": "ollama"}
        with mock.patch.object(tsl.threading, "Thread"):
            first = tsl.update_timesketch_llm_config()
            second = tsl.update_timesketch_llm_config()
        self.assertTrue(first["success"])
        self.assertEqual(second[1], 409)
        tsl._settings_save_lock.release()  # the mocked worker never ran

    def test_failed_start_gives_the_lock_back(self):
        REQ.body = {"llm_mode": "ollama"}
        with mock.patch.object(tsl, "create_automation_run", side_effect=RuntimeError("db")):
            self.assertEqual(tsl.update_timesketch_llm_config()[1], 500)
        self.assertFalse(tsl._settings_save_lock.locked())


if __name__ == "__main__":
    unittest.main()
