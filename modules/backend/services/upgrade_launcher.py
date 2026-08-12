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
#
# 143 is 128+SIGTERM: the helper was signalled before scripts/upgrade.sh had
# installed its interrupt trap, which it does only once the bootstrap is done
# and the module loop is about to start. Stop during download/verify/extract
# therefore kills the shell outright -- which is safe, nothing has been applied
# yet -- and reports 143 rather than the 130 the trap's own unwind produces.
# Both mean the operator pressed Stop. Without this, that race (marker read
# before the cancel flag is seen) would finalize a deliberately cancelled run
# as 'failed'.
_EXIT_STATUS = {0: "completed", 3: "completed", 130: "cancelled", 143: "cancelled"}


# The engine copy baked into this image (modules/backend/Dockerfile), used only
# when the appliance has none of its own.
_BUNDLED_ENGINE = "/app/host-engine/scripts/upgrade.sh"


def _engine_for_helper():
    """(path the helper should run, whether it is the bundled fallback).

    Normally the appliance's own scripts/upgrade.sh, which is the file every
    upgrade mirrors into place and the one an operator would run by hand.

    The fallback exists for a box that has never had it: an intact-20260726
    appliance reaches this code by way of its OWN Import UI, whose Phase 1
    swaps in this image and then hands to a Phase 2 that was deleted with the
    Python engine. It comes back showing the upgrade UI with nothing on disk
    for that UI to call. Running the bundled copy against --root <appliance>
    is the same _CODE_DIR / SCRIPT_DIR split the in-package stage-0 hop uses,
    and the intact module then mirrors lib/ and scripts/ onto the box -- so
    this path is taken at most once per appliance, ever.

    WORKDIR is this container's view of the appliance; HOST_PATH is the same
    tree as the DAEMON sees it, which is what the helper must be given.
    """
    if os.path.isfile(os.path.join(WORKDIR, "scripts", "upgrade.sh")):
        return f"{HOST_PATH}/scripts/upgrade.sh", False
    return _BUNDLED_ENGINE, True


_BUNDLED_ENGINE_ROOT = "/app/host-engine"


def _upgrade_in_flight() -> bool:
    """True when an upgrade currently holds the lock.

    Non-blocking probe of the same flock scripts/upgrade.sh takes, so this
    agrees with the engine rather than guessing. Used to keep the refresh below
    from rewriting files a running upgrade might still be reading.
    """
    lock = os.path.join(WORKDIR, "data", "tmp", "upgrade.lock")
    if not os.path.exists(lock):
        return False
    try:
        import fcntl
        fd = os.open(lock, os.O_RDWR)
    except OSError:
        return False
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.flock(fd, fcntl.LOCK_UN)
        return False
    except OSError:
        return True
    finally:
        os.close(fd)


def _add_missing_env_keys() -> None:
    """Top up modules/*/.env with keys this release expects.

    The bash engine does this during its own intact module
    (_intact_add_missing_env_keys), which covers every upgrade IT drives. It
    does not cover the one that matters most here: a 0726 box is rescued by
    0726's OWN Python engine, which never runs a line of the new code, so a
    freshly rescued appliance still had no ELASTICSEARCH_USER /
    ELASTICSEARCH_PASSWORD -- observed on a real run, 0 of 2 present after an
    otherwise clean rescue. Harmless with elk disabled; on a box with elk
    enabled the backend authenticates to Elasticsearch with a blank username
    and nothing explains why.

    So it also runs here, at the first startup we control on such a box --
    the same reasoning that puts the engine install here. Shelling out to the
    engine's own lib/config.sh keeps ONE definition of what the keys are: this
    process must not grow a second, drifting copy of that list.

    Add-only (UPDATE_ENV_ADD_ONLY=1): existing values -- pins, operator-edited
    credentials -- are never rewritten.
    """
    engine_lib = os.path.join(WORKDIR, "lib", "config.sh")
    if not os.path.isfile(engine_lib):
        return
    script = (
        f'set -e; cd {shlex.quote(WORKDIR)}; '
        f'SCRIPT_DIR={shlex.quote(WORKDIR)}; '
        f'CONFIG_FILE={shlex.quote(os.path.join(WORKDIR, "config.yaml"))}; '
        'LOG_FILE=/dev/null; '
        'source lib/common.sh >/dev/null 2>&1 || true; '
        'source lib/config.sh; '
        'UPDATE_ENV_ADD_ONLY=1 update_env_files'
    )
    try:
        r = subprocess.run(["bash", "-c", script], capture_output=True,
                           text=True, timeout=120)
        if r.returncode == 0:
            print("[UPGRADE-LAUNCHER] checked modules/*/.env for keys this "
                  "release expects", flush=True)
        else:
            print(f"[UPGRADE-LAUNCHER] .env key check failed "
                  f"({r.stderr.strip()[:160]})", flush=True)
    except Exception as e:
        print(f"[UPGRADE-LAUNCHER] .env key check skipped: {e}", flush=True)


def resume_legacy_two_phase() -> bool:
    """Finish an upgrade a pre-bash release abandoned at its Phase-1 restart.

    Returns True when a resume was launched.

    THE HAND-OVER THIS CLOSES. intact-20260726 upgrades in two phases: Phase 1
    swaps the platform, writes `upgrade_state(phase='awaiting_restart', ...)`
    and recreates this container, expecting a Phase 2 to resume inside whatever
    comes up. That Phase 2 was Python, and it was deleted with the rest of the
    in-container engine -- so on a rescued box the remaining modules were simply
    never applied, and the run sat at "running" for ever.

    We do not need to reimplement it. Phase 1 already persisted everything the
    bash engine needs -- which modules, which are done, and where the package
    is -- so resuming is a translation, not a re-execution: read the row, hand
    the leftovers to scripts/upgrade.sh, done. The modules it then applies get
    the bash engine's mount-asset delivery and per-box secret generation, which
    is exactly what the Python Phase 2 lacked (elk's setup-kibana-user.sh
    exit 126, portainer's missing secrets/agent.env -- both observed on a
    customer box, three imports running).

    Read straight out of SQLite because our own storage layer dropped this
    table when the engine went (storage/base.py:167 says so). It only exists on
    a box that came from a pre-bash release, which is precisely the box this is
    for.

    Self-cleaning: the intact module runs _intact_clear_legacy_upgrade_state
    (lib/upgrade/intact/image.sh), which drops the table -- so a completed
    resume cannot re-fire on the next boot. The in-flight guard below covers the
    window before that runs.
    """
    import sqlite3

    db = os.path.join(WORKDIR, "data", "intact.db")
    if not os.path.isfile(db):
        return False
    try:
        conn = sqlite3.connect(db, timeout=5)
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT run_id, phase, target_modules, completed_modules, package_dir "
            "FROM upgrade_state WHERE phase = 'awaiting_restart' "
            "ORDER BY updated_at DESC LIMIT 1").fetchone()
        conn.close()
    except sqlite3.Error:
        # No such table on any box that never ran the old engine. Not an error.
        return False
    if not row:
        return False

    # Never start a second engine over a live one. _upgrade_in_flight() is the
    # same flock scripts/upgrade.sh itself takes, so this also covers the case
    # where a helper from the interrupted run is somehow still going.
    if _upgrade_in_flight():
        print("[STARTUP] legacy resume: an upgrade already holds the lock — leaving it alone",
              flush=True)
        return False

    def _list(v):
        try:
            out = json.loads(v or "[]")
            return [str(x) for x in out] if isinstance(out, list) else []
        except (ValueError, TypeError):
            return [x.strip() for x in (v or "").split(",") if x.strip()]

    todo = [m for m in _list(row["target_modules"])
            if m not in _list(row["completed_modules"])]
    if not todo:
        print("[STARTUP] legacy resume: Phase 1 left nothing to finish", flush=True)
        return False

    # package_dir is EITHER a JSON blob {extract_dir, package_path} OR a bare
    # path -- the old engine wrote both shapes across its life and read both
    # back (upgrade/__init__.py:1590-1610). The extracted tree is preferred:
    # it needs no re-extraction, and the engine takes a directory happily.
    raw = row["package_dir"] or ""
    pkg = ""
    try:
        paths = json.loads(raw)
        extract_dir = paths.get("extract_dir") or ""
        if extract_dir and os.path.isdir(extract_dir):
            subs = [d for d in os.listdir(extract_dir)
                    if os.path.isdir(os.path.join(extract_dir, d))]
            pkg = os.path.join(extract_dir, subs[0]) if subs else extract_dir
        elif paths.get("package_path") and os.path.exists(paths["package_path"]):
            pkg = paths["package_path"]
    except (ValueError, TypeError):
        pkg = raw if raw and os.path.exists(raw) else ""

    if not pkg:
        print(f"[STARTUP] legacy resume: the package Phase 1 used is gone "
              f"({raw or 'no path recorded'}); import it again to finish "
              f"{', '.join(todo)}", flush=True)
        return False

    run_id = row["run_id"]
    print(f"[STARTUP] legacy resume: Phase 1 stopped here; finishing "
          f"{', '.join(todo)} with the bash engine", flush=True)
    try:
        add_log_to_run(run_id,
                       "Phase 1 of a pre-bash upgrade stopped at its restart. "
                       "Finishing the remaining module(s) with the current "
                       f"engine: {', '.join(todo)}.", "info")
    except Exception:
        pass   # a missing run row must not stop the resume

    err = launch(run_id, ["--package", pkg, "--only", ",".join(todo)])
    if err:
        print(f"[STARTUP] legacy resume failed to start: {err}", flush=True)
        return False
    return True


def ensure_host_engine() -> bool:
    """Make the appliance's upgrade engine match the one in this image.

    Called once at startup. Returns True when it wrote anything.

    THE RULE: the running backend image is the authority. Whatever the previous
    version left on disk, the new code repairs it -- so a box can always be
    fixed forward by shipping a newer release, which is the only lever that
    reliably reaches an appliance in the field.

    This is the same idea phase 1 of an upgrade is built on: replace the code,
    keep only what carries state (config.yaml, the module .env files, data/),
    and let the NEW code perform the actual upgrade. upgrade_module_intact does
    exactly that for modules/backend, nginx/html, lib/, scripts/ and
    install.sh. This function is the stand-in for the one case where phase 1
    cannot: a pre-bash release doing the replacing, whose own engine only knows
    about modules/backend and nginx/html.

    And the engine is worth restoring even when nobody opens the dashboard.
    scripts/upgrade.sh is STANDALONE BY DESIGN -- it talks to docker and the
    checkout, never to this backend -- so putting it back on disk restores the
    box's ability to be upgraded from a shell while the backend is stopped,
    crash-looping, or gone. That is exactly when an operator needs it most, and
    a box that only has an engine inside a container image does not have one.

    WHY THIS EXISTS. An intact-20260726 box is upgraded through its OWN Import
    UI, and that engine only ever mirrors `modules/backend` and
    `modules/nginx/html` -- it has never heard of `lib/upgrade/` or
    `scripts/upgrade.sh`, because neither existed when it was written, and it
    is already deployed so it cannot be changed. Verified on a real 0726 box:
    the upgrade completed, VERSION and the backend image moved to the new
    release, the old Python engine was gone -- and the appliance had no
    `scripts/upgrade.sh` at all. The new UI was showing buttons with nothing on
    disk to run.

    The first moment we control on that box is this process starting. So heal
    it here: the image carries the matching engine (see the Dockerfile), the
    appliance root is bind-mounted rw, and this runs as root.

    `lib/` is refreshed too, not just `scripts/upgrade.sh`. A box arriving from
    0726 has year-old `lib/common.sh` and `lib/config.sh` next to no
    `lib/upgrade/` at all, and the engine sources those shared files -- leaving
    them stale means the new engine running against old libraries. They are
    shipped code with no operator state in them, so replacing them is safe and
    is what the box would have had anyway.

    Two things keep this from being reckless:

    * NOT WHILE AN UPGRADE IS RUNNING. The helper executes the appliance's own
      scripts/upgrade.sh, and bash reads a script as it goes -- rewriting it
      underneath a live run is a way to corrupt one. The intact module recreates
      this container mid-upgrade, so that restart lands squarely inside the
      danger window. In practice the stage-0 hop means the executing copy is the
      package's, not the box's, but the lock is cheap and the failure would be
      baffling.
    * ONLY FILES THAT DIFFER. On a healthy box every file already matches, so a
      restart writes nothing and mtimes stay put.
    """
    try:
        dst_engine = os.path.join(WORKDIR, "scripts", "upgrade.sh")
        had_engine = os.path.isfile(dst_engine)
        src_lib = os.path.join(_BUNDLED_ENGINE_ROOT, "lib")
        src_engine = os.path.join(_BUNDLED_ENGINE_ROOT, "scripts", "upgrade.sh")
        if not (os.path.isdir(src_lib) and os.path.isfile(src_engine)):
            if not os.path.isfile(dst_engine):
                print("[UPGRADE-LAUNCHER] this appliance has no scripts/upgrade.sh "
                      "and this image carries no bundled copy — upgrades from the "
                      "UI will not work until one is installed", flush=True)
            return False

        if _upgrade_in_flight():
            print("[UPGRADE-LAUNCHER] an upgrade holds the lock — leaving the "
                  "appliance's engine alone until it finishes", flush=True)
            return False

        import filecmp
        import shutil

        written = []

        def _sync(src, dst):
            if os.path.isfile(dst) and filecmp.cmp(src, dst, shallow=False):
                return
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(src, dst)
            written.append(os.path.relpath(dst, WORKDIR))

        # Both trees, file by file. scripts/ is not just upgrade.sh: a rescued
        # 0726 box keeps its year-old scripts/, and prepare_package.sh -- which
        # the Prepare Package button shells out to -- did not exist at 0726, so
        # that feature fails on a box that otherwise looks fully upgraded.
        for src_root, dst_root in ((src_lib, os.path.join(WORKDIR, "lib")),
                                   (os.path.join(_BUNDLED_ENGINE_ROOT, "scripts"),
                                    os.path.join(WORKDIR, "scripts"))):
            if not os.path.isdir(src_root):
                continue
            for root, _dirs, files in os.walk(src_root):
                for name in files:
                    s = os.path.join(root, name)
                    _sync(s, os.path.join(dst_root, os.path.relpath(s, src_root)))

        if not written:
            return False

        # Whether the box had no engine at all, not a guess from how many
        # files moved: refreshing seven stale ones is not a first install.
        first_install = not had_engine
        print(f"[UPGRADE-LAUNCHER] refreshed the appliance's upgrade engine from "
              f"this image: {len(written)} file(s)"
              + (" — this box had none (an upgrade from a pre-bash release does "
                 "not deliver one)" if first_install else ""), flush=True)
        os.chmod(dst_engine, 0o755)

        # Match the tree's owner rather than leaving root-owned files behind:
        # the checkout belongs to the operator, and install.sh fixes these up
        # for the same reason at the end of every run.
        try:
            st = os.stat(WORKDIR)
            for root, dirs, files in os.walk(os.path.join(WORKDIR, "lib")):
                for name in dirs + files:
                    os.chown(os.path.join(root, name), st.st_uid, st.st_gid)
            os.chown(os.path.join(WORKDIR, "lib"), st.st_uid, st.st_gid)
            os.chown(dst_engine, st.st_uid, st.st_gid)
        except OSError:
            pass

        return True
    except Exception as e:
        # Never block startup over this. The launcher's bundled-engine fallback
        # still makes the UI work; the box just stays dependent on it.
        print(f"[UPGRADE-LAUNCHER] could not install the upgrade engine: {e}", flush=True)
        return False


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

    # The helper's entry script, written to the shared mount rather than
    # squeezed into `docker run ... -c '<one long line>'`. It has to install a
    # signal handler and background a job, which is unreadable inline, and
    # having it on disk means a run can be inspected -- or re-run by hand --
    # exactly as it executed.
    #
    # WHY THE TRAP AND THE `wait`. scripts/upgrade.sh installs
    # `trap _u_handle_interrupt INT TERM` and exits 130 after unwinding the
    # module in flight, but it never saw the signal. The wrapper shell is PID 1
    # here, and the kernel discards signals at PID 1 unless that process
    # installed a handler -- this one had none, and would not have forwarded
    # anything to a child it was not `wait`ing on regardless. So `docker stop`
    # sat out its full 30s grace period and then SIGKILLed. Observed on a real
    # Stop: helper exited 137, no .done.json, no unwind, no rollback, i.e. Stop
    # hard-killed an upgrade in the middle of a module -- precisely what the
    # interrupt trap exists to prevent.
    #
    # Backgrounding plus `wait` is what makes bash run the trap immediately
    # rather than after the foreground command returns. The second `wait`
    # collects the child's REAL status: the first returns 128+signal the moment
    # the trap fires, while upgrade.sh is still unwinding.
    engine, bundled = _engine_for_helper()
    if bundled:
        add_log_to_run(
            run_id,
            "This appliance has no scripts/upgrade.sh yet, so the upgrade is "
            "running the engine bundled in the backend image. It will install "
            "the engine onto the box as its first step; later upgrades will "
            "use the appliance's own copy.",
            "warning")

    launch_script = f"{WORKDIR}/data/tmp/upgrade-launch-{run_id}.sh"
    host_launch_script = f"{HOST_PATH}/data/tmp/upgrade-launch-{run_id}.sh"
    with open(launch_script, "w") as fh:
        fh.write(
            "#!/usr/bin/env bash\n"
            "# Generated by services/upgrade_launcher.py -- this is exactly\n"
            "# what the upgrade helper container ran.\n"
            "\n"
            "# Let the launching request's HTTP response flush before the first\n"
            "# module (intact) recreates the backend under the connection still\n"
            "# writing it.\n"
            "sleep 3\n"
            "\n"
            f"bash {shlex.quote(engine)} "
            f"{' '.join(shlex.quote(a) for a in cli_args)} "
            f"--root {shlex.quote(HOST_PATH)} "
            f"--log {shlex.quote(host_log_path)} &\n"
            "child=$!\n"
            "trap 'kill -TERM \"$child\" 2>/dev/null' TERM INT\n"
            "wait \"$child\"\n"
            "rc=$?\n"
            "if [ \"$rc\" -gt 128 ]; then\n"
            "    wait \"$child\" 2>/dev/null\n"
            "    rc=$?\n"
            "fi\n"
            f"printf '{{\"rc\":%d}}' \"$rc\" > {shlex.quote(host_done_path)}\n"
            "exit \"$rc\"\n"
        )
    os.chmod(launch_script, 0o755)

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
        # THE HELPER MUST SEE THE HOST'S LOOPBACK.
        #
        # lib/upgrade/health/probes.sh checks the modules it just upgraded on
        # 127.0.0.1 at their PUBLISHED ports -- 5001 for the backend, 9443 for
        # portainer, and 9200/8889/8443 for the rest. That is right for the
        # shell on the box this engine was written for, and meaningless inside
        # a container, where 127.0.0.1 is the container's own namespace with
        # nothing listening on it.
        #
        # Observed on the first real UI-driven upgrade: both modules applied
        # cleanly, both were verifiably answering 200 from the host, and both
        # health gates reported "degraded ... returned 000", so the run exited
        # 3 instead of 0. That is worse than cosmetic -- EVERY dashboard-driven
        # upgrade would report degraded, which teaches an operator the health
        # gate means nothing, and then a genuinely degraded upgrade looks
        # exactly like all the others.
        #
        # Host networking gives the helper the same view of the network the
        # shell has, which is the entire premise of running one script both
        # ways. It grants nothing new: this container already mounts
        # docker.sock, which is root on the host.
        "--network", "host",
        "-v", "/var/run/docker.sock:/var/run/docker.sock",
        "-v", f"{HOST_PATH}:{HOST_PATH}",
        *env_passthrough,
        # No compose labels: this must not be swept by any module's
        # `--remove-orphans` teardown, which only ever looks within its own
        # project's labels -- a plain `docker run` carries none, so it is
        # already outside every project's view. Named explicitly here as
        # the property being relied on, not left implicit.
        # tini as PID 1. With the trap in the launch script this is belt and
        # braces, but it removes the PID-1 signal-discarding subtlety from the
        # picture entirely and reaps the script's short-lived children.
        "--init",
        "--entrypoint", "bash",
        image, host_launch_script,
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


# INFO, not a warning: nothing is wrong here, and nothing needs doing beyond
# a refresh. It said "sign in again" until 2026-08-11, which was simply untrue
# -- auth_service.session_secret_key() persists the Flask signing key in the
# secrets table, and data/ is a host bind, so the cookie outlives the
# container. Telling an operator mid-upgrade that they have been logged out
# invites them to go looking at auth while an upgrade is running.
_SESSION_DROP_NOTE = (
    "This backend is about to be recreated to load the new code, so the page "
    "will lose contact with it for a few seconds. Refresh to reconnect — you "
    "stay signed in, and the upgrade keeps running regardless."
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
        add_log_to_run(run_id, _SESSION_DROP_NOTE, "info")
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
            # request_stop itself.
            #
            # Remove the helper unconditionally, not only when a marker
            # exists. A helper that had to be SIGKILLed never wrote one, so
            # keying removal off the marker left its Exited container behind
            # forever -- observed after a Stop that predated the signal
            # forwarding fix. `docker stop` has already returned by now, so
            # there is nothing still running to cut off, and the marker-based
            # path this replaces was only ever about not leaking a container
            # when Stop raced a natural finish. Removing either way covers
            # both.
            _drain_remaining(run_id, log_path, offset, progress_state)
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
    # progress=100 explicitly on success. The only other writer is the module
    # banner in _apply_line, which computes (n-1)/total -- so a finished
    # two-module run stops at the 50% it was showing when the LAST module
    # started, and the UI leaves a completed upgrade sitting at half a bar.
    kwargs = {"progress": 100} if status == "completed" else {}
    update_run_status(run_id, status, details={"exit_code": rc}, force=force, **kwargs)

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
