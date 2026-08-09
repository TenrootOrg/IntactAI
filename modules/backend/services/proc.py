"""Subprocess execution for the platform's own maintenance operations.

Relocated out of services/upgrade/base.py when the upgrade engine moved to
the host as upgrade.sh. run_command was never upgrade-specific -- it is how
maintenance_routes.py (26 call sites) and the Azure DFIR-O365RC collector
shell out -- and leaving it inside a package that no longer exists would have
taken the backend down with the deletion.

WORKDIR / HOST_PATH live here for the same reason: they are the container's
view of the repo and the host's path to it, which half the backend needs and
which had nothing to do with upgrading either.
"""

import os
import re
import subprocess
import threading
import time
from typing import Callable, Dict, Optional

# The repo as the CONTAINER sees it, and as the HOST sees it. They differ
# whenever the appliance is not installed at the default path, and anything
# handing a path to `docker run -v` needs the host one.
WORKDIR = os.environ.get('INTACT_PATH', '/app/workdir')
HOST_PATH = os.environ.get('INTACT_HOST_PATH', WORKDIR)


_SECRET_ARG_PATTERNS = (
    # `-e NAME=secret` / bare `NAME=secret` env assignments, where NAME looks
    # like a credential. This is the shape that actually leaked: iris.py builds
    # `docker exec -e IRIS_RESET_PW=<pw> ...` and the echo below put the
    # password into the backend's stdout, hence `docker logs`, hence every
    # support bundle collected afterwards.
    re.compile(r'((?:-e\s+)?[A-Za-z_][A-Za-z0-9_]*'
               r'(?:PASSWORD|PASSWD|_PW|TOKEN|SECRET|APIKEY|API_KEY|KEY|CREDENTIAL)'
               r'\s*=\s*)(\S+)', re.IGNORECASE),
    # `--password value`, `--password=value`, `--token ...`, `-p value`
    re.compile(r'(--(?:password|passwd|token|secret|api-key|apikey)[=\s]+)(\S+)',
               re.IGNORECASE),
    # curl's `-u user:password` / `--user user:password`. This one leaked in
    # plain sight: the ELK health gate shells out to
    #   docker exec intact_elasticsearch curl -sf -u elastic:<password> http://...
    # and the whole command line was logged verbatim, so the Elasticsearch
    # password landed in the upgrade run log -- the artifact operators download
    # and paste into tickets -- and from there into the SQLite workflows table
    # and the intact_workflow_runs index. Keeps the username, which is the part
    # that makes the log useful, and drops everything after the colon.
    re.compile(r'((?:-u|--user)\s+[^\s:]+:)(\S+)'),
)


def redact_command(cmd: str) -> str:
    """Mask credential-looking values in a command string before it is logged.

    Applied UNCONDITIONALLY by run_command below, deliberately: the one call
    site that tried to keep a password out of the logs (iris.py's IRIS admin
    reset) did so by passing `logger=None` — which does not silence anything,
    because run_command falls back to printing when no logger is given. The
    result was the operator's IRIS password sitting in
    containers/intact_backend.log inside a support bundle, i.e. the one artifact
    designed to be sent to other people. Redacting at the choke point means a
    future call site cannot make that mistake at all.

    Worth keeping broad: run logs also reach the SQLite `workflows` table and
    the `intact_workflow_runs` Elasticsearch index (whose mapping carries a
    nested `logs` array), so a leaked credential here does not stay in one file.
    """
    if not cmd:
        return cmd
    out = cmd
    for pattern in _SECRET_ARG_PATTERNS:
        out = pattern.sub(lambda m: m.group(1) + '[REDACTED]', out)
    return out


def run_command(cmd: str, cwd: str = None, timeout: int = 300, logger: Callable = None,
                run_id: Optional[str] = None) -> Dict:
    """Run a shell command and return result.

    For docker compose commands, cwd should be the WORKDIR (container) path.
    The --project-directory flag with HOST_PATH is added automatically for compose commands.

    The subprocess is always launched with Popen and polled by hand (never
    subprocess.run(..., timeout=N)): that stdlib helper's own post-timeout
    cleanup does an UNBOUNDED communicate() to drain remaining output, and
    a command that forks a long-lived helper (docker build/buildx sessions
    are the observed case) can keep the captured stdout/stderr pipes open
    via that grandchild even after the immediate child is killed — so the
    "bounded" timeout doesn't actually bound anything; the call can hang for
    hours past it (`docker compose build backend` did exactly this, wedging
    an entire Phase-2 finalizer thread). Polling by hand and never calling
    communicate() after a timeout/cancel avoids that.

    When `run_id` is supplied, the same loop also checks the workflow's
    cancel event, so Stop is honoured DURING long-running subprocesses
    (docker pull, docker save, tar), not just between them — SIGTERM'd
    (then SIGKILL'd) within ~1 second, returning success=False,
    error='cancelled'.
    """
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))
    try:
        if cmd.startswith("docker compose") and cwd:
            if cwd.startswith(WORKDIR):
                host_cwd = cwd.replace(WORKDIR, HOST_PATH, 1)
                compose_file = os.path.join(host_cwd, 'docker-compose.yaml')
                cmd = cmd.replace("docker compose", f"docker compose -f {compose_file} --project-directory {host_cwd}", 1)
                cwd = None

        # Redact BEFORE truncating: the password that leaked previously sat
        # inside the first 80 characters, so slicing is not a mitigation.
        log(f"  Running: {redact_command(cmd)[:80]}...", "info")

        try:
            from services.workflow_service import (
                get_cancel_event, register_cleanup, terminate_subprocess,
            )
            cancel_event = get_cancel_event(run_id) if run_id else None
        except Exception:
            cancel_event = None
            register_cleanup = None
            terminate_subprocess = None

        # start_new_session=True makes this its own process group leader, so
        # terminate_subprocess() (below and on cancel) can kill the WHOLE
        # subtree instead of just this one process — see its docstring.
        process = subprocess.Popen(
            cmd, shell=True, cwd=cwd,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            start_new_session=True,
        )

        def _kill(proc):
            if terminate_subprocess is not None:
                terminate_subprocess(proc)
            else:
                proc.kill()

        # Register cleanup so request_stop() can SIGTERM us instantly even
        # before our next poll tick — terminate_subprocess is idempotent +
        # safe-on-already-exited.
        if run_id and cancel_event is not None and register_cleanup is not None:
            try:
                register_cleanup(run_id, lambda p=process: _kill(p))
            except Exception:
                pass

        # Drain stdout/stderr CONTINUOUSLY in daemon threads while the poll
        # loop below only watches for exit/cancel/timeout. Popen.poll() never
        # touches the pipes — it just checks whether the process has exited —
        # so a child that writes more than the OS pipe buffer (~64KB) blocks on
        # write() waiting for a reader that was never there, and looks
        # IDENTICAL to a genuinely slow/hung command: poll() keeps returning
        # None until the timeout fires and kills it, no matter how large that
        # timeout is. Observed concretely: a Velociraptor query returning
        # 6.7MB of artifact YAML "timed out" at 8s, 20s, AND 30s — it was
        # never slow, it was deadlocked on the very first write() past 64KB.
        # Daemon reader threads plus a BOUNDED join (not communicate()) after
        # kill/exit preserves the original "never do an unbounded post-kill
        # read" guarantee from this function's docstring — a lingering
        # grandchild holding the write end open blocks the reader thread
        # forever, but it is a daemon we only join() briefly, so it can never
        # hang the caller.
        stdout_buf, stderr_buf = [], []

        def _drain_pipe(pipe, sink):
            try:
                for line in iter(pipe.readline, ''):
                    sink.append(line)
            except Exception:
                pass
            finally:
                try:
                    pipe.close()
                except Exception:
                    pass

        stdout_thread = threading.Thread(
            target=_drain_pipe, args=(process.stdout, stdout_buf), daemon=True)
        stderr_thread = threading.Thread(
            target=_drain_pipe, args=(process.stderr, stderr_buf), daemon=True)
        stdout_thread.start()
        stderr_thread.start()

        def _collect(join_s: float):
            stdout_thread.join(timeout=join_s)
            stderr_thread.join(timeout=join_s)
            return ''.join(stdout_buf), ''.join(stderr_buf)

        start = time.time()
        while process.poll() is None:
            if cancel_event is not None and cancel_event.is_set():
                log("  Command cancelled by user", "warning")
                _kill(process)
                _collect(2)
                return {"success": False, "error": "cancelled", "cancelled": True}
            if time.time() - start > timeout:
                log(f"  Command timed out after {timeout}s", "error")
                _kill(process)
                _collect(2)
                return {"success": False, "error": f"Command timed out after {timeout}s"}
            time.sleep(1.0)
        stdout, stderr = _collect(5)
        if process.returncode != 0:
            # Report what FAILED, not what happened first. `docker compose`
            # writes "Container X Creating/Created/Starting" progress to stderr
            # interleaved with real diagnostics, so a head truncation shows
            # nothing but chatter: the ELK failure's decisive line — service
            # "setup" didn't complete successfully: exit 126 — was the last one
            # in the stream, and the old [:200] cut it off. Three diagnoses of
            # that failure were wrong before anyone opened the raw log.
            # Deferred import: compose_assets imports WORKDIR from this module.
            try:
                from .compose_assets import strip_compose_progress
                detail = strip_compose_progress(stderr or '')
            except Exception:
                detail = (stderr or '')[-600:]
            log(f"  Command failed: {detail}", "warning")
            # "error" stays the raw stream — callers parse it for specific
            # substrings. "error_summary" is the operator-facing one.
            return {"success": False, "error": stderr or "",
                    "error_summary": detail, "stdout": stdout or ""}
        return {"success": True, "stdout": stdout or "", "stderr": stderr or ""}
    except Exception as e:
        log(f"  Command error: {str(e)}", "error")
        return {"success": False, "error": str(e)}
