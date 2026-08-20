"""Upgrade the appliance the way the scenario says, then prove it landed.

One scenario per run, because an appliance is a singleton on its host —
container names, volumes and published ports are all global, so two of them
cannot share a machine. That constraint is what makes a job-per-scenario matrix
the right shape rather than a long sequential script: the scenarios are
independent by construction, so one failing cannot stop the rest.

The routes:

  bootstrap   scripts/bootstrap_upgrade.sh — the frozen doorman. Fetches the
              TARGET release's engine, verifies its sha256, execs it. How a box
              too old to have a usable engine moves at all.
  cli         scripts/upgrade.sh — the path the README documents.
  ui_online   POST /api/upgrade/online
  ui_import   POST /api/upgrade/prepare, then apply the package it built

Every one of them ends in the same verification, because the failures that have
actually happened were not "the upgrade errored" — they were "the upgrade said
it worked". A box that reports the new release while running the old image, a
module that rolled back so far it stopped existing, an evidence store quietly
emptied. So `verify_upgrade` asserts state, not exit codes.
"""

import os
import time

from lib import appliance, shell, upgrade as up

# Which routes actually perform an upgrade. Anything else is an install-only
# scenario and these phases stay out of the way entirely.
UPGRADE_ROUTES = {
    "bootstrap":  "the frozen doorman fetches the target engine",
    "cli":        "scripts/upgrade.sh, the documented operator path",
    "ui_online":  "POST /api/upgrade/online",
    "ui_import":  "prepare a package, then apply it",
}


def register(runner, cfg):
    route = _route_for(cfg.scenario)
    if not route:
        return                      # install-only scenario; nothing to add

    tl = runner.ctx.tl

    @runner.phase("upgrade", f"Upgrade via {route} ({UPGRADE_ROUTES[route]})",
                  needs=("auth",), critical=True)
    def upgrade(ctx):
        detail = {"scenario": cfg.scenario, "route": route,
                  "target": cfg.upgrade_to}
        root = cfg.repo_dir or "/mnt/intact"

        # The state to compare against afterwards, captured while the old box
        # is still the live one.
        detail["before"] = appliance.version_facts(root)
        appliance.canary_write()
        detail["canary_before"] = appliance.canary_count()

        log_path = os.path.join(ctx.run_dir, "logs", f"upgrade-{route}.log")
        os.makedirs(os.path.dirname(log_path), exist_ok=True)

        started = time.time()
        if route in ("bootstrap", "cli"):
            rc = _shell_route(ctx, cfg, root, route, log_path, detail)
        else:
            rc = _api_route(ctx, cfg, route, detail)
        detail["seconds"] = round(time.time() - started, 1)
        detail["exit_code"] = rc

        ctx.check(f"the upgrade reported an exit code", rc is not None,
                  actual=rc,
                  note="a run with no exit code never reached its own end; "
                       "the outcome is unknown rather than good")
        if rc is None:
            return detail

        # 0 and 3 both report "completed" through the UI. Only the code tells
        # them apart, and "applied but degraded" is not a pass.
        ctx.check("the upgrade exited cleanly", rc == up.RC_CLEAN,
                  expected="0 (clean)", actual=f"{rc} ({up.describe_rc(rc)})",
                  note="exit 3 is reported as 'completed' by the UI — clean and "
                       "degraded are distinguishable only in the exit code")
        return detail

    @runner.phase("verify_upgrade", "Prove the upgrade actually landed",
                  needs=("upgrade",))
    def verify_upgrade(ctx):
        detail = {}
        root = cfg.repo_dir or "/mnt/intact"
        target = cfg.upgrade_to

        if target:
            detail["after"] = appliance.assert_state(ctx, root, target, "after")
        appliance.assert_canary(ctx, "after")

        # The strongest single proof the box agrees with itself: ask the
        # planner again. Anything it upgraded must now read as a no-op —
        # except `intact`, which is a rolling tag and is re-applied by design.
        plan = up.plan_json(shell, cfg, root, target) if target else None
        if plan:
            rows = plan.get("modules") or []
            busy = [r.get("module") for r in rows
                    if r.get("action") in ("upgrade", "install")
                    and r.get("module") != "intact"]
            detail["replan_actions"] = {r.get("module"): r.get("action")
                                        for r in rows}
            ctx.check("re-planning the same target is now a no-op", not busy,
                      expected="every module noop (bar intact)",
                      actual=", ".join(busy) or "all noop",
                      note="intact is excluded on purpose — a rolling tag can "
                           "move between commits, so it is always re-applied")
        else:
            ctx.check("the planner could be re-read", False,
                      note="no JSON plan came back, so self-consistency is "
                           "unproven")
        return detail


# --- routes ----------------------------------------------------------------


def _shell_route(ctx, cfg, root, route, log_path, detail):
    pkg = cfg.upgrade_package or None
    tag = cfg.upgrade_to or None

    if route == "bootstrap":
        # A tag AND a package is legitimate: the tag names the engine, the
        # package supplies the images. Air-gapped runs pass only the package.
        r = up.run_bootstrap(shell, cfg, root, tag=None if pkg else tag,
                             package=pkg, extra=cfg.upgrade_extra,
                             tl=ctx.tl, log_path=log_path)
    else:
        # pin_engine so this genuinely tests THIS checkout's engine rather than
        # hopping to the bootstrap. It also disables the flock, which is safe
        # here only because a scenario owns its whole machine.
        r = up.run_cli(shell, cfg, root, tag=None if pkg else tag, package=pkg,
                       extra=cfg.upgrade_extra, tl=ctx.tl, log_path=log_path,
                       pin_engine=True)

    detail["argv"] = " ".join(r.argv[:6]) + " …"
    # Two refusals happen before the log file exists and can only reach stderr,
    # so the tail of the captured output is the diagnosis when rc is 2.
    tail = [l for l in (r.out or "").splitlines() if l.strip()][-6:]
    detail["tail"] = tail
    return r.rc


def _api_route(ctx, cfg, route, detail):
    c = ctx.get("client")
    if c is None:
        ctx.check("an authenticated client is available", False)
        return None

    if route == "ui_online":
        body = up.start_online(c, cfg.upgrade_to,
                               opted_in_optional=_optional_modules(ctx, cfg))
    else:
        body = _prepare_then_apply(ctx, c, cfg, detail)
        if body is None:
            return None

    run_id = (body or {}).get("run_id")
    ctx.check("the upgrade was accepted and started", bool(run_id),
              actual=run_id)
    if not run_id:
        return None
    detail["run_id"] = run_id

    run, rc = up.wait_for_upgrade(c, run_id, ctx.tl, what=f"{route} upgrade")
    detail["status"] = (run or {}).get("status")
    # The launcher writes this: a faithful, re-runnable transcript of exactly
    # what the helper container executed. The single best artifact to keep.
    detail["launch_script"] = f"data/tmp/upgrade-launch-{run_id}.sh"
    return rc


def _prepare_then_apply(ctx, c, cfg, detail):
    """Build a package with the product, then apply it with the product."""
    body = up.start_prepare(c, cfg.upgrade_to)
    prep_id = (body or {}).get("run_id")
    ctx.check("prepare-package started", bool(prep_id), actual=prep_id)
    if not prep_id:
        return None

    run = c.wait_for_run(prep_id, up.TIMEOUT_PREPARE_S, ctx.tl,
                         what="prepare package")
    ok = (run or {}).get("status") in ("completed", "success", "succeeded")
    ctx.check("prepare-package completed", ok,
              actual=(run or {}).get("status"))
    if not ok:
        return None

    packages = up.list_packages(c)
    detail["packages"] = [p.get("name") for p in packages]
    ctx.check("the prepared package is listed", bool(packages),
              actual=", ".join(detail["packages"][:3]) or "none",
              note="list-packages is how a caller discovers the path prepare "
                   "just wrote; only the newest prepared package is kept")
    if not packages:
        return None

    path = packages[0].get("path")
    detail["applied_package"] = path
    return up.apply_package(c, path)


def _optional_modules(ctx, cfg):
    """Modules the planner calls `install` — the adopt case.

    Without ticking these, an online upgrade only version-bumps what is already
    there, and a scenario meant to prove "enable a feature you never had" would
    quietly test nothing.
    """
    root = cfg.repo_dir or "/mnt/intact"
    plan = up.plan_json(shell, cfg, root, cfg.upgrade_to)
    if not plan:
        return []
    return [r.get("module") for r in (plan.get("modules") or [])
            if r.get("action") == "install"]


def _route_for(scenario):
    return {
        "bootstrap":       "bootstrap",
        "cli-upgrade":     "cli",
        "ui-online-full":  "ui_online",
        "ui-online-adopt": "ui_online",
        "ui-import-full":  "ui_import",
        "ui-import-adopt": "ui_import",
        "rollback":        "cli",
        "refuse-and-repeat": "cli",
        "data-preservation": "cli",
    }.get(scenario)
