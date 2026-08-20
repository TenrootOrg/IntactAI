"""Drive the upgrade, whichever way the scenario asks for.

Four routes reach the same engine, and each is a real customer path:

  bootstrap   scripts/bootstrap_upgrade.sh — the frozen doorman fetches the
              TARGET release's engine, verifies its sha256 and execs it. This
              is how a box too old to have a usable engine moves.
  cli         scripts/upgrade.sh — what the README tells operators to run.
  ui_online   POST /api/upgrade/online
  ui_import   POST /api/upgrade/prepare, then POST /api/upgrade/offline

Two facts here are load-bearing and neither is obvious from the code:

**Assert exit_code, never status.** The launcher maps rc 3 -> "completed" with
force=True, because a degraded run necessarily logged an ERROR line that would
otherwise flip it to failed. So clean (0) and degraded (3) are distinguishable
ONLY in details.exit_code. A harness that asserts status treats a degraded
upgrade as a success.

**`scripts/upgrade.sh <tag>` is not the CLI path.** It execs the bootstrap
unless INTACT_UPGRADE_REEXEC=1 — and that same variable also skips the flock,
so a caller using it must serialise externally.

Exit codes: 0 clean · 1 rolled back or needs repair · 2 refused before touching
anything · 3 applied but degraded · 130/143 interrupted.
"""

import json
import os
import time

RC_CLEAN = 0
RC_ROLLED_BACK = 1
RC_REFUSED = 2
RC_DEGRADED = 3

# A full appliance upgrade moves several GB of images and restarts ~30
# containers. Generous, but bounded: a wedged run must fail the scenario rather
# than eat the job's whole budget.
TIMEOUT_UPGRADE_S = 3600
TIMEOUT_PREPARE_S = 2400


# --- shell routes ----------------------------------------------------------


def run_bootstrap(shell, cfg, root, tag=None, package=None, engine=None,
                  extra=(), tl=None, log_path=None):
    """The doorman. Returns a CommandResult; .rc is the engine's own exit code.

    Every refusal from the bootstrap itself is exit 2 — a bad tag, a missing
    .sha256, a checksum mismatch, an unknown BOOTSTRAP_PROTOCOL. That is the
    point of it: refuse before touching anything.
    """
    argv = ["bash", os.path.join(root, "scripts/bootstrap_upgrade.sh")]
    if tag:
        argv.append(tag)
    if package:
        argv += ["--package", package]
    if engine:
        argv += ["--engine", engine]
    argv += ["--root", root]
    if log_path:
        argv += ["--log", log_path]
    argv += list(extra)
    return shell.sudo(argv, cfg.sudo_password, timeout=TIMEOUT_UPGRADE_S,
                      tl=tl, stage="upgrade", log_path=log_path,
                      preserve_env=("GITHUB_TOKEN",))


def run_cli(shell, cfg, root, tag=None, package=None, extra=(), tl=None,
            log_path=None, pin_engine=False):
    """scripts/upgrade.sh.

    `pin_engine` sets INTACT_UPGRADE_REEXEC=1 so the run uses THIS checkout's
    engine instead of hopping to the bootstrap. It also disables the flock, so
    nothing else may be upgrading at the same time.
    """
    # `sudo env VAR=1 bash ...`, not an env= dict: sudo resets the environment,
    # so a variable set only in the parent never reaches the script. Measured --
    # both a plain env dict AND preserve_env came back EMPTY, the latter because
    # it filters on os.environ and this variable is not there. The release
    # workflow already uses the `sudo env` form for exactly this variable.
    argv = ["env", "INTACT_UPGRADE_REEXEC=1"] if pin_engine else []
    argv += ["bash", os.path.join(root, "scripts/upgrade.sh")]
    if tag:
        argv.append(tag)
    if package:
        argv += ["--package", package]
    argv += ["--root", root]
    if log_path:
        argv += ["--log", log_path]
    argv += list(extra)
    return shell.sudo(argv, cfg.sudo_password, timeout=TIMEOUT_UPGRADE_S,
                      tl=tl, stage="upgrade", log_path=log_path,
                      preserve_env=("GITHUB_TOKEN",))


def plan_json(shell, cfg, root, tag):
    """`--plan <tag> --json`: read-only, no root, no lock.

    The strongest single proof a box is self-consistent is that this reports
    `noop` for a module immediately after that module was upgraded or installed.
    """
    r = shell.run(["bash", os.path.join(root, "scripts/upgrade.sh"),
                   "--plan", tag, "--json", "--root", root], timeout=600)
    for line in reversed((r.out or "").splitlines()):
        line = line.strip()
        if line.startswith("{"):
            try:
                return json.loads(line)
            except ValueError:
                continue
    return None


# --- API routes ------------------------------------------------------------


def start_online(c, target, opted_in_optional=(), opted_in_reinstall=()):
    """POST /api/upgrade/online.

    The module list is recomputed server-side from a fresh plan; what a caller
    ticks only selects from it. `opted_in_optional` picks up rows the planner
    called `install` — which is exactly the "enable a module you never had"
    case, so it must be passed for that scenario to do anything.
    """
    return c.request("POST", "/api/upgrade/online", json={
        "target": target,
        "opted_in_optional": list(opted_in_optional),
        "opted_in_reinstall": list(opted_in_reinstall),
    }, expect=(200, 202))


def start_prepare(c, target):
    return c.request("POST", "/api/upgrade/prepare", json={"target": target},
                     expect=(200, 202))


def list_packages(c):
    body = c.request("POST", "/api/upgrade/list-packages", json={},
                     expect=(200,))
    return (body or {}).get("packages") or []


def apply_package(c, package_path, selected_modules=None,
                  reinstall_modules=None, expected_sha256=None):
    """POST /api/upgrade/offline.

    `package_path` must sit under /data/uploads/ or /data/upgrade_packages/ —
    the route resolves realpath first and refuses anything else. That allowlist
    is what lets a test place a multi-GB package with `docker cp` and skip the
    tus upload entirely, while still traversing the exact apply path.
    """
    payload = {"package_path": package_path}
    if selected_modules is not None:
        payload["selected_modules"] = list(selected_modules)
    if reinstall_modules is not None:
        payload["reinstall_modules"] = list(reinstall_modules)
    if expected_sha256:
        payload["expected_sha256"] = expected_sha256
    return c.request("POST", "/api/upgrade/offline", json=payload,
                     expect=(200, 202))


def wait_for_upgrade(c, run_id, tl, timeout_s=TIMEOUT_UPGRADE_S, what=None):
    """Wait, then return (run, exit_code).

    exit_code comes from details, because status cannot tell 0 from 3. A run
    that never reports one is returned as None so the caller can say so rather
    than guess a number.
    """
    run = c.wait_for_run(run_id, timeout_s, tl, what=what or f"upgrade {run_id}")
    if not run:
        return None, None
    rc = (run.get("details") or {}).get("exit_code")
    return run, (int(rc) if isinstance(rc, (int, str)) and str(rc).lstrip("-").isdigit()
                 else None)


def stage_package_into_backend(shell, cfg, host_path, tl=None):
    """Put a package where /api/upgrade/offline will accept it.

    /data/upgrade_packages is a docker volume mounted only into intact_backend,
    so `docker cp` is the volume-agnostic way in — no need to find a mountpoint
    on the host.
    """
    name = os.path.basename(host_path)
    dest = f"/data/upgrade_packages/{name}"
    r = shell.sudo(["docker", "cp", host_path, f"intact_backend:{dest}"],
                   cfg.sudo_password, timeout=1800, tl=tl, stage="upgrade")
    return dest if r.ok else None


def describe_rc(rc):
    """What an exit code means, in words, for a report a human reads."""
    return {
        RC_CLEAN: "clean",
        RC_ROLLED_BACK: "rolled back or needs manual repair",
        RC_REFUSED: "refused before touching anything",
        RC_DEGRADED: "applied but degraded",
        130: "interrupted, unwound",
        143: "killed before the trap was installed",
    }.get(rc, f"unrecognised ({rc})")
