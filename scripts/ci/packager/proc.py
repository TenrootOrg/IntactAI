"""Subprocess execution for the CI release packager.

A trimmed copy of modules/backend/services/proc.py. Two things are deliberately
gone, both of which only exist for the running backend:

  * the workflow_service cancel-event plumbing -- CI has no run_id and no
    request_stop(); a cancelled Actions job kills the container outright;
  * strip_compose_progress -- it lived in the deleted compose_assets module and
    the packager never runs `docker compose` anyway.

What is NOT trimmed is redact_command. The packager shells out with a GitHub
token in the environment and `docker save`s images by tag; a build log is a
public artifact on a public runner, so the redaction matters MORE here than it
does on a box, not less.
"""

import os
import re
import subprocess
import threading
import time
from typing import Callable, Dict

# The checkout as this process sees it, and as the DOCKER DAEMON sees it. In CI
# they are the same path (the workflow mounts $GITHUB_WORKSPACE at itself
# precisely so `-v` arguments resolve identically inside and out), but keeping
# both names means the packager code copied from the backend needs no edits.
WORKDIR = os.environ.get('INTACT_PATH', '/app/workdir')
HOST_PATH = os.environ.get('INTACT_HOST_PATH', WORKDIR)


_SECRET_ARG_PATTERNS = (
    # `-e NAME=secret` / bare `NAME=secret` env assignments where NAME looks
    # like a credential.
    re.compile(r'((?:-e\s+)?[A-Za-z_][A-Za-z0-9_]*'
               r'(?:PASSWORD|PASSWD|_PW|TOKEN|SECRET|APIKEY|API_KEY|KEY|CREDENTIAL)'
               r'\s*=\s*)(\S+)', re.IGNORECASE),
    # `--password value`, `--password=value`, `--token ...`
    re.compile(r'(--(?:password|passwd|token|secret|api-key|apikey)[=\s]+)(\S+)',
               re.IGNORECASE),
    # curl's `-u user:password`. Keeps the username, drops the secret.
    re.compile(r'((?:-u|--user)\s+[^\s:]+:)(\S+)'),
)


def redact_command(cmd: str) -> str:
    """Mask credential-looking values in a command string before it is logged."""
    if not cmd:
        return cmd
    out = cmd
    for pattern in _SECRET_ARG_PATTERNS:
        out = pattern.sub(lambda m: m.group(1) + '[REDACTED]', out)
    return out


def run_command(cmd: str, cwd: str = None, timeout: int = 300,
                logger: Callable = None, run_id=None) -> Dict:
    """Run a shell command and return {"success", "stdout", "stderr"/"error"}.

    `run_id` is accepted and ignored -- it keeps the signature identical to the
    backend's run_command so the packager body copied from
    services/upgrade/package.py needs no edits at its ~40 call sites.

    Polled by hand rather than subprocess.run(timeout=): that helper's
    post-timeout cleanup does an unbounded communicate(), and a command that
    forks a long-lived helper (docker buildx sessions are the observed case)
    keeps the captured pipes open through the grandchild, so the "bounded"
    timeout does not bound anything.

    Output is drained CONTINUOUSLY in daemon threads while the poll loop only
    watches for exit/timeout. poll() never touches the pipes, so a child that
    writes past the ~64KB OS pipe buffer blocks on write() forever and looks
    exactly like a slow command -- `docker save` of a multi-GB image hits this
    immediately.
    """
    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}", flush=True))
    try:
        # Redact BEFORE truncating: a leaked value can sit inside the first 80
        # characters, so slicing is not a mitigation.
        log(f"  Running: {redact_command(cmd)[:80]}...", "info")

        # start_new_session=True so the kill below takes the whole subtree, not
        # just the shell.
        process = subprocess.Popen(
            cmd, shell=True, cwd=cwd,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            start_new_session=True,
        )

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

        threads = [
            threading.Thread(target=_drain_pipe, args=(process.stdout, stdout_buf),
                             daemon=True),
            threading.Thread(target=_drain_pipe, args=(process.stderr, stderr_buf),
                             daemon=True),
        ]
        for t in threads:
            t.start()

        def _collect(join_s: float):
            for t in threads:
                t.join(timeout=join_s)
            return ''.join(stdout_buf), ''.join(stderr_buf)

        start = time.time()
        while process.poll() is None:
            if time.time() - start > timeout:
                log(f"  Command timed out after {timeout}s", "error")
                _kill_tree(process)
                _collect(2)
                return {"success": False,
                        "error": f"Command timed out after {timeout}s"}
            time.sleep(1.0)

        stdout, stderr = _collect(5)
        if process.returncode != 0:
            # Tail, not head: the decisive line of a docker failure is the last
            # one, and a head truncation shows nothing but layer-pull chatter.
            detail = (stderr or '')[-600:]
            log(f"  Command failed: {detail}", "warning")
            return {"success": False, "error": stderr or "",
                    "error_summary": detail, "stdout": stdout or ""}
        return {"success": True, "stdout": stdout or "", "stderr": stderr or ""}
    except Exception as e:
        log(f"  Command error: {e}", "error")
        return {"success": False, "error": str(e)}


def _kill_tree(process) -> None:
    """SIGTERM the process group, then SIGKILL what survives 2s."""
    import signal
    try:
        pgid = os.getpgid(process.pid)
    except Exception:
        try:
            process.kill()
        except Exception:
            pass
        return
    for sig, wait in ((signal.SIGTERM, 2.0), (signal.SIGKILL, 0.0)):
        try:
            os.killpg(pgid, sig)
        except Exception:
            return
        if wait:
            try:
                process.wait(timeout=wait)
                return
            except Exception:
                continue
