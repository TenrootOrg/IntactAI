"""Runs scripts/upgrade.sh as a detached sibling container, and tails its
log back into the workflow run the way every other backend-driven job does.

WHY A SIBLING CONTAINER. The FIRST thing any upgrade does is recreate
intact_backend itself (the `intact` module always runs first in
UPGRADE_ORDER) -- so the upgrade cannot be a child process of this backend;
it would kill its own parent partway through. A sibling spawned through the
mounted docker.sock is untouched by that recreate: it is not a child of this
process, docker doesn't tie its lifecycle to ours, and the two host-path
mounts every upgrade module needs (docker.sock, the identity bind at
HOST_PATH) are already on this container for exactly this purpose --
modules/backend/docker-compose.yaml's own comments say so.

WHY NOT `docker logs -f` / `--rm`. `docker logs -f` dies the moment THIS
backend dies, which is during the very first module -- so it cannot observe
the run to completion. `--rm` would erase the container (and its exit code)
before a restarted backend could ever inspect it. So the helper is launched
WITHOUT --rm, writes its own exit code to a `.done.json` marker on the
shared host mount once upgrade.sh exits, and reconciliation on the next
backend boot reads that marker rather than asking docker for a exit code
that might not exist yet, or might belong to a container already gone.

WHY THE LOG IS TAILED, NOT STREAMED FROM THE CONTAINER. --log pins
upgrade.sh's own log to a path under data/tmp/, which is on the identity
bind and therefore readable by both the dying backend and the reborn one at
the same path. A background thread tails it by line, the same file, before
and after the restart -- there is no discontinuity to paper over, only an
offset to resume from (stored in the run's own `details`).
"""

import json
import os
import re
import shlex
import subprocess
import threading
import time
from typing import List, Optional

from services.proc import WORKDIR, HOST_PATH
from services.workflow_service import (
    add_log_to_run,
    get_automation_run,
    get_all_automation_runs,
    mutate_run_details,
    update_run_status,
    is_cancelled,
    register_cancel_event,
    register_cleanup,
)

# Only the online/offline apply path goes through this launcher. Prepare
# Package never recreates the backend (it just runs prepare_package.sh as a
# plain subprocess), so it has no helper container and does not belong in
# reconcile_on_boot()'s sweep -- its own restart-recovery, if it needs any,
# is a route-level concern, not this module's.
UPGRADE_AUTOMATION_TYPES = ("upgrade",)

_DOCKER_BIN = "docker"

# upgrade.sh's own log lines are `[YYYY-MM-DD HH:MM:SS] [LEVEL] message`
# (lib/common.sh:log_info et al). plan_print_table / print_final_issues_report
# print raw, unprefixed lines straight to the log -- those fall through to
# the `info` default below rather than being dropped.
_LOG_LINE = re.compile(r'^\[[\d-]+ [\d:]+\]\s+\[(INFO|SUCCESS|WARN|ERROR)\]\s?(.*)$')
_LEVEL_MAP = {"ERROR": "error", "WARN": "warning", "SUCCESS": "info", "INFO": "info"}

# "[3/9] TIMESKETCH: 9.4.2 -> 9.4.4" -- u_begin's own banner (core.sh). Used
# to derive a coarse progress percentage; a run with no such line yet (still
# resolving the plan) just keeps whatever progress it last had.
_MODULE_BANNER = re.compile(
    r'\[(\d+)/(\d+)\]\s+([A-Z_]+):\s+(.*?)\s+->\s+(.*)$'
)

# upgrade.sh's own exit codes (lib/upgrade/args.sh's usage text), mapped to
# the terminal workflow status. 3 ("everything applied, but degraded") is
# still `completed` -- force=True is required for it because a degraded run
# necessarily logged at least one [ERROR] line, which update_run_status
# would otherwise auto-flip to 'failed' (see its own docstring). The
# distinction between "degraded" and "clean" survives in the run's `details`
# (exit_code), not in status -- the UI reads that to show the difference.
_EXIT_STATUS = {0: "completed", 3: "completed", 130: "cancelled"}


def _run_paths(run_id: str):
    log_path = f"{WORKDIR}/data/tmp/upgrade-{run_id}.log"
    done_path = f"{WORKDIR}/data/tmp/upgrade-{run_id}.done.json"
    host_log_path = f"{HOST_PATH}/data/tmp/upgrade-{run_id}.log"
    host_done_path = f"{HOST_PATH}/data/tmp/upgrade-{run_id}.done.json"
    return log_path, done_path, host_log_path, host_done_path


def _current_backend_image() -> Optional[str]:
    """The image intact_backend is ACTUALLY running right now, not a
    reconstruction from BACKEND_VERSION/.env -- avoids ever spawning the
    helper from a stale or wrong tag if those ever disagree with reality."""
    try:
        out = subprocess.run(
            [_DOCKER_BIN, "inspect", "-f", "{{.Config.Image}}", "intact_backend"],
            capture_output=True, text=True, timeout=15,
        )
        img = out.stdout.strip()
        return img or None
    except Exception:
        return None


def launch(run_id: str, cli_args: List[str]) -> Optional[str]:
    """Spawn the helper container for `run_id`, running scripts/upgrade.sh
    with `cli_args`. Returns an error string on failure, None on success --
    the caller (a route) has already created the automation run and just
    needs to know whether to report it as started.

    Stores helper_container / log_path / done_path / tail_offset in the
    run's details, which is the only state reconcile_on_boot() has to work
    with after a restart -- nothing here is kept in memory beyond the
    tailer thread this function also starts.

    PRECONDITION: the caller must already have called
    workflow_service.register_cancel_event(run_id) -- same convention every
    other route in this backend follows (create the run, register its
    cancel event, THEN start the work). register_cleanup below is a no-op
    if that has not happened yet (workflow_service's own guard), which would
    make the Stop button silently do nothing for this run.
    """
    image = _current_backend_image()
    if not image:
        return "could not determine the running intact-backend image"

    log_path, done_path, host_log_path, host_done_path = _run_paths(run_id)
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    # Truncate rather than append: a run_id is minted fresh per run
    # (workflow_service._next_run_id), so a pre-existing file here would
    # only be scratch left by a process that never reached upkg_cleanup --
    # starting clean avoids tailing stale content as if it were this run's.
    open(log_path, "w").close()

    container_name = f"intact-upgrade-runner-{run_id}"

    # sleep 3: lets the launching route's own HTTP response flush before the
    # first module (intact) recreates the backend out from under the
    # connection that's still writing it.
    inner = (
        f"sleep 3 && "
        f"bash {shlex.quote(HOST_PATH)}/scripts/upgrade.sh "
        f"{' '.join(shlex.quote(a) for a in cli_args)} "
        f"--root {shlex.quote(HOST_PATH)} --log {shlex.quote(host_log_path)}; "
        f"rc=$?; "
        f"printf '{{\"rc\":%d}}' \"$rc\" > {shlex.quote(host_done_path)}; "
        f"exit $rc"
    )

    # Carry the release-source overrides into the helper.
    #
    # The helper is a fresh `docker run`, so it inherits nothing from this
    # process -- and it is the thing that actually downloads the release. A box
    # pointed at an internal mirror (an air-gapped site serving releases from
    # its own host, or a dev box running scripts/dev/serve_local_release.sh)
    # would have every `--list`/`--plan` call honour the override, because
    # those run as plain subprocesses here, and then the real upgrade would
    # silently go to github.com and fail. Only pass what is actually set, so
    # the common case adds no arguments at all.
    env_passthrough = []
    for var in ("INTACT_GH_API_BASE", "INTACT_GH_DL_BASE", "INTACT_REPO",
                "GITHUB_TOKEN"):
        val = os.environ.get(var)
        if val:
            env_passthrough += ["-e", f"{var}={val}"]

    cmd = [
        _DOCKER_BIN, "run", "-d",
        "--name", container_name,
        "-v", "/var/run/docker.sock:/var/run/docker.sock",
        "-v", f"{HOST_PATH}:{HOST_PATH}",
        *env_passthrough,
        # No compose labels: this must not be swept by any module's
        # `--remove-orphans` teardown, which only ever looks within its own
        # project's labels -- a plain `docker run` carries none, so it is
        # already outside every project's view. Named explicitly here as
        # the property being relied on, not left implicit.
        "--entrypoint", "bash",
        image, "-c", inner,
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except Exception as e:
        return f"could not start the helper container: {e}"
    if result.returncode != 0:
        return f"docker run failed: {result.stderr.strip() or result.stdout.strip()}"

    mutate_run_details(run_id, lambda d: d.update({
        "helper_container": container_name,
        "log_path": log_path,
        "done_path": done_path,
        "tail_offset": 0,
    }))
    register_cleanup(run_id, lambda: _stop_helper(container_name))
    _start_tailer(run_id)
    return None


def _stop_helper(container_name: str) -> None:
    """Cleanup callback for the Stop button (request_stop -> registered
    callbacks). SIGTERM first so upgrade.sh's own interrupt trap
    (lib/upgrade/interrupt.sh) gets to unwind whatever module is mid-flight
    instead of the container just vanishing under it."""
    try:
        subprocess.run([_DOCKER_BIN, "stop", "-t", "30", container_name],
                        capture_output=True, timeout=40)
    except Exception:
        pass


def _start_tailer(run_id: str) -> None:
    t = threading.Thread(target=_tail_and_finalize, args=(run_id,), daemon=True,
                         name=f"upgrade-tailer-{run_id}")
    t.start()


_SESSION_DROP_NOTE = (
    "This backend is about to be recreated to load the new code — your "
    "dashboard session will drop. Refresh the page and sign in again to "
    "keep watching; the upgrade keeps running in the background regardless."
)


def _apply_line(run_id: str, line: str, progress_state: dict) -> None:
    line = line.rstrip("\n")
    if not line:
        return
    if not progress_state.get("_warned_session_drop") and "INTACT:" in line and _MODULE_BANNER.search(line):
        # The intact module is ALWAYS first (UPGRADE_ORDER) and is what
        # recreates intact_backend -- said here, at the top of that module,
        # not right before the actual `docker compose up -d backend` step:
        # by the time that step's own "ok: recreate the backend" line would
        # otherwise trigger this, the process writing it may already be
        # mid-death. Early and delivered beats precise and missed.
        progress_state["_warned_session_drop"] = True
        add_log_to_run(run_id, _SESSION_DROP_NOTE, "warning")
    m = _LOG_LINE.match(line)
    if m:
        level_word, msg = m.group(1), m.group(2)
        level = _LEVEL_MAP.get(level_word, "info")
        add_log_to_run(run_id, msg, level)
    else:
        # plan_print_table / print_final_issues_report: raw, no prefix.
        # Passed through as info rather than dropped -- this is the plan
        # table and the final issues summary, both worth keeping.
        add_log_to_run(run_id, line, "info")
        msg = line

    mb = _MODULE_BANNER.search(msg)
    if mb:
        n, total = int(mb.group(1)), int(mb.group(2))
        if total > 0:
            pct = int(round((n - 1) / total * 100))
            progress_state["pct"] = pct
            update_run_status(run_id, "running", progress=pct)


def _tail_and_finalize(run_id: str) -> None:
    run = get_automation_run(run_id)
    details = (run or {}).get("details") or {}
    log_path = details.get("log_path")
    done_path = details.get("done_path")
    if not log_path or not done_path:
        return

    offset = int(details.get("tail_offset") or 0)
    progress_state = {"pct": 0}

    while True:
        if is_cancelled(run_id):
            # request_stop's cleanup callback (_stop_helper) has already
            # fired; drain whatever the container wrote on its way out, then
            # stop -- update_run_status('cancelled') was already called by
            # request_stop itself. Container removal (not status) still
            # goes through the done_path branch below when there's a marker
            # to read -- Stop racing a container that finished naturally in
            # the same instant must not leave it un-rm'd.
            _drain_remaining(run_id, log_path, offset, progress_state)
            if os.path.isfile(done_path):
                container_name = details.get("helper_container")
                if container_name:
                    try:
                        subprocess.run([_DOCKER_BIN, "rm", "-f", container_name],
                                        capture_output=True, timeout=30)
                    except Exception:
                        pass
            return

        try:
            size = os.path.getsize(log_path)
        except OSError:
            size = offset
        if size > offset:
            with open(log_path, "r", errors="replace") as f:
                f.seek(offset)
                for line in f:
                    _apply_line(run_id, line, progress_state)
                offset = f.tell()
            mutate_run_details(run_id, lambda d, o=offset: d.update({"tail_offset": o}))

        if os.path.isfile(done_path):
            _drain_remaining(run_id, log_path, offset, progress_state)
            _finalize(run_id, done_path)
            return

        time.sleep(1)


def _drain_remaining(run_id: str, log_path: str, offset: int, progress_state: dict) -> int:
    """One last read past `offset` -- upgrade.sh can write its final lines
    (print_upgrade_report, print_final_issues_report) in the gap between
    the tailer's last poll and the container actually exiting."""
    try:
        with open(log_path, "r", errors="replace") as f:
            f.seek(offset)
            for line in f:
                _apply_line(run_id, line, progress_state)
            offset = f.tell()
    except OSError:
        pass
    mutate_run_details(run_id, lambda d, o=offset: d.update({"tail_offset": o}))
    return offset


def _finalize(run_id: str, done_path: str) -> None:
    try:
        with open(done_path, encoding="utf-8") as f:
            marker = json.load(f)
        rc = int(marker.get("rc", 1))
    except Exception:
        rc = 1

    status = _EXIT_STATUS.get(rc, "failed")
    force = status == "completed"  # see _EXIT_STATUS's comment
    update_run_status(run_id, status, details={"exit_code": rc}, force=force)

    run = get_automation_run(run_id) or {}
    container_name = (run.get("details") or {}).get("helper_container")
    if container_name:
        try:
            subprocess.run([_DOCKER_BIN, "rm", "-f", container_name],
                            capture_output=True, timeout=30)
        except Exception:
            pass


def reconcile_on_boot() -> None:
    """Called once at backend startup. A run left `running` with a
    helper_container in its details survived a backend restart mid-upgrade
    (expected -- the intact module recreates this very container) and needs
    either a resumed tailer or an immediate finalize, depending on whether
    the helper finished while nothing was watching.

    Best-effort throughout: this must never raise and block backend
    startup over a single bad run row.
    """
    try:
        runs = get_all_automation_runs()
    except Exception as e:
        print(f"[UPGRADE-LAUNCHER] reconcile_on_boot could not list runs: {e}", flush=True)
        return

    for run in runs or []:
        try:
            if run.get("automation_type") not in UPGRADE_AUTOMATION_TYPES:
                continue
            if run.get("status") != "running":
                continue
            details = run.get("details") or {}
            container_name = details.get("helper_container")
            done_path = details.get("done_path")
            if not container_name or not done_path:
                continue

            run_id = run["run_id"]
            add_log_to_run(run_id, "[Backend] restarted mid-upgrade — reattaching", "warning")

            if os.path.isfile(done_path):
                # The helper finished while nobody was watching. Drain
                # whatever it wrote, then finalize immediately.
                log_path = details.get("log_path")
                offset = int(details.get("tail_offset") or 0)
                if log_path:
                    offset = _drain_remaining(run_id, log_path, offset, {"pct": 0})
                _finalize(run_id, done_path)
                continue

            still_running = subprocess.run(
                [_DOCKER_BIN, "inspect", "-f", "{{.State.Running}}", container_name],
                capture_output=True, text=True, timeout=15,
            ).stdout.strip() == "true"
            if still_running:
                # RE-ARM STOP BEFORE TAILING. _cancel_events and
                # _cleanup_callbacks live in this process's memory, so the
                # restart we just came back from emptied them -- and the
                # `intact` module recreates this container FIRST, so that
                # happens on essentially every upgrade, within the first
                # minutes.
                #
                # Without this, request_stop() finds no event and no callback:
                # it never signals the tailer, never runs _stop_helper, and
                # still calls update_run_status(run_id, 'cancelled'). The
                # operator is told the upgrade stopped while the helper
                # container carries on swapping containers -- and because
                # add_log_to_run drops every line once a run is cancelled, the
                # log goes silent at exactly that moment, which reads as
                # confirmation that it stopped.
                register_cancel_event(run_id)
                register_cleanup(run_id, lambda cn=container_name: _stop_helper(cn))
                _start_tailer(run_id)
            else:
                # Helper is gone (killed, host reboot, `docker rm` by hand)
                # and left no marker -- genuinely unknown outcome, not a
                # clean exit to guess at.
                update_run_status(
                    run_id, "failed",
                    error="the upgrade helper container is gone with no exit marker "
                          "— outcome unknown, check the appliance by hand",
                )
        except Exception as e:
            print(f"[UPGRADE-LAUNCHER] reconcile_on_boot failed for a run: {e}", flush=True)
