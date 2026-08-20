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
import re
import time

from lib import appliance, shell, upgrade as up

# The tree the HARNESS was checked out into — which is the release under
# test, and not necessarily the appliance. Derived from this file rather
# than from cwd so it holds however the run was launched.
HARNESS_TREE = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

# Which routes actually perform an upgrade. Anything else is an install-only
# scenario and these phases stay out of the way entirely.
UPGRADE_ROUTES = {
    "bootstrap":  "the frozen doorman fetches the target engine",
    "cli":        "scripts/upgrade.sh, the documented operator path",
    "ui_online":  "POST /api/upgrade/online",
    "ui_import":  "prepare a package, then apply it",
}


# Scenarios whose upgrade is SUPPOSED to end badly, and which therefore assert
# their own exit code in _post_upgrade rather than being held to "exited
# cleanly". Keep this in step with the branches in _post_upgrade — a name here
# with no branch there means the run asserts nothing at all about its outcome
# and passes silently, which is worse than the crash this constant replaced.
_SELF_ASSERTING = frozenset({"rollback"})


def register(runner, cfg):
    route = _route_for(cfg.scenario)
    if not route:
        return                      # install-only scenario; nothing to add

    tl = runner.ctx.tl

    # The shell routes need only a box on disk. Depending on `auth` would be
    # wrong AND fatal for the oldest scenarios: intact-20260615 predates the
    # auth system entirely, so the auth phase cannot succeed there — and a
    # dependency on it would skip the very upgrade the scenario exists to run.
    # The API routes genuinely need a session, so they keep it.
    _needs = ("auth",) if route.startswith("ui_") else ("install",)

    @runner.phase("upgrade", f"Upgrade via {route} ({UPGRADE_ROUTES[route]})",
                  needs=_needs, critical=True)
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

        # The engine hop, when the box is too old to reach the target directly.
        if cfg.hop_via:
            detail["hop"] = _hop_via(ctx, cfg, root, cfg.hop_via)

        _pre_upgrade(ctx, cfg, root, detail, log_path)

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
        # A scenario that is SUPPOSED to fail asserts its own outcome instead.
        if cfg.scenario in _SELF_ASSERTING:
            _post_upgrade(ctx, cfg, root, detail, rc)
            return detail

        ctx.check("the upgrade exited cleanly", rc == up.RC_CLEAN,
                  expected="0 (clean)", actual=f"{rc} ({up.describe_rc(rc)})",
                  note="exit 3 is reported as 'completed' by the UI — clean and "
                       "degraded are distinguishable only in the exit code")
        _post_upgrade(ctx, cfg, root, detail, rc)
        return detail

    @runner.phase("verify_upgrade", "Prove the upgrade actually landed",
                  needs=("upgrade",))
    def verify_upgrade(ctx):
        detail = {}
        root = cfg.repo_dir or "/mnt/intact"
        target = cfg.upgrade_to

        # Every route recreates intact_backend, so a session held from before
        # the upgrade is not to be trusted afterwards -- and on the UI routes
        # there certainly IS one, because driving the upgrade required it. The
        # module checks that follow (features, pipelines, enrol_linux) all run
        # off ctx["client"], so a quietly-dead cookie would surface as a wall
        # of unrelated 401s attributed to the wrong phase.
        detail["session"] = _refresh_session(ctx, cfg)

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
        # The doorman may have to come from the TARGET tree: the boxes this
        # scenario starts from ship no upgrade scripts at all, which is the
        # reason a frozen stage 1 exists in the first place.
        script, source = up.bootstrap_script(root, HARNESS_TREE)
        detail["bootstrap_from"] = source
        ctx.check("the bootstrap script is available to run",
                  os.path.exists(script), actual=f"{script} ({source})",
                  note="an old appliance ships no doorman; the operator takes "
                       "it from the release they are upgrading to")
        if not os.path.exists(script):
            return None
        # A tag AND a package is legitimate: the tag names the engine, the
        # package supplies the images. Air-gapped runs pass only the package.
        r = up.run_bootstrap(shell, cfg, root, tag=None if pkg else tag,
                             package=pkg, extra=cfg.upgrade_extra,
                             tl=ctx.tl, log_path=log_path, script=script)
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
    """One source of truth, shared with the workflow.

    This used to be a second copy of the scenario list. Two copies of anything
    drift, and when they do here the failure is silent in the worst way: a
    scenario the harness does not recognise registers no upgrade phases at all,
    so the job installs an appliance, asserts nothing about any upgrade, and
    reports a clean pass.
    """
    import scenarios
    return scenarios.route_for(scenario)

def _pre_upgrade(ctx, cfg, root, detail, log_path):
    """Whatever this scenario needs to be true before the upgrade runs."""
    scenario = cfg.scenario

    if scenario in ("ui-online-adopt", "ui-import-adopt"):
        # The customer case: a box that never had these features, whose
        # operator now wants them. Flipping the flags is the whole setup —
        # the upgrade engine is then expected to INSTALL them.
        enabled = _enable_all_modules(ctx, cfg, root)
        detail["enabled_for_adoption"] = enabled

    elif scenario == "rollback":
        # Occupy a port the module must bind, so `compose up` fails DURING its
        # step — after the pin was written and the undo registered. That is the
        # only way to reach the unwind: a missing image or a bad mount is
        # caught by the preflight and refuses before touching anything, which
        # tests refusal rather than rollback.
        #
        # The module has to be stopped FIRST. Its own docker-proxy is holding
        # the published port, so binding it while the container runs is
        # impossible by definition — the first version of this skipped that
        # step, failed to take the port, and the upgrade sailed through
        # cleanly. Stopping the container hands the port over for the seconds
        # between here and the module's step, which is the window compose
        # needs it in.
        port = _first_published_port(root, "portainer")
        detail["held_port"] = port
        names = appliance.container_names_of(root, "portainer")
        if port and names:
            shell.run(["docker", "stop"] + list(names), timeout=120)
            detail["stopped_first"] = list(names)
            holder = _hold_port(port)
            ctx.set(_port_holder=holder)
            # Non-negotiable: if the port was not taken, this scenario tests
            # nothing. Better to fail here, naming the reason, than to report
            # a green rollback test that never provoked a rollback.
            ctx.check(f"port {port} was actually taken, so the module cannot bind",
                      holder is not None,
                      expected=f"{port} bound by the harness",
                      actual="bound" if holder else "could NOT bind — "
                             "something else still holds it",
                      note="the module step can only fail if this succeeded")
            if holder is not None:
                _release_on_unwind(holder, log_path, detail)
        else:
            ctx.check("portainer publishes a port to contend for",
                      False, actual=f"port={port} containers={names}",
                      note="without a published port there is nothing to hold "
                           "and the rollback cannot be provoked")

    elif scenario == "data-preservation":
        appliance.canary_write()
        detail["canary_seeded"] = appliance.canary_count()


def _post_upgrade(ctx, cfg, root, detail, rc):
    scenario = cfg.scenario

    if scenario == "rollback":
        holder = ctx.get("_port_holder")
        if holder is not None:
            holder.close()          # a socket now, not a subprocess
        # rc 1 is the correct answer here: a module failed and was unwound.
        ctx.check("a failed module rolls the box back", rc == up.RC_ROLLED_BACK,
                  expected="1 (rolled back)",
                  actual=f"{rc} ({up.describe_rc(rc)})",
                  note="the port was held so compose could not bind; the engine "
                       "must unwind rather than leave the module half-applied")
        text = "\n".join(detail.get("tail") or [])
        ctx.check("the report says it rolled back, not that it needs repair",
                  "ROLLBACK FAILED" not in text.upper(),
                  actual="clean unwind" if "ROLLBACK FAILED" not in text.upper()
                  else "ROLLBACK FAILED — the box needs manual repair")

    elif scenario == "refuse-and-repeat":
        # Two properties in one scenario because both are cheap and both are
        # planner regressions: a downgrade must be refused before anything is
        # touched, and re-running the same upgrade must change nothing.
        before = appliance.version_facts(root)
        older = cfg.downgrade_tag
        detail["downgrade_tag"] = older
        if older:
            r = up.run_cli(shell, cfg, root, tag=older, tl=ctx.tl,
                           pin_engine=True)
            ctx.check("a downgrade is refused", r.rc == up.RC_REFUSED,
                      expected="2 (refused before touching anything)",
                      actual=f"{r.rc} ({up.describe_rc(r.rc)})")
            after = appliance.version_facts(root)
            ctx.check("the refusal changed nothing", after == before,
                      actual="unchanged" if after == before else "state moved",
                      note="'refused' has to mean the box is exactly as it was")

        r2 = up.run_cli(shell, cfg, root, tag=cfg.upgrade_to, tl=ctx.tl,
                        pin_engine=True)
        ctx.check("re-running the same upgrade is clean", r2.rc == up.RC_CLEAN,
                  expected="0", actual=f"{r2.rc} ({up.describe_rc(r2.rc)})",
                  note="an upgrade that is not idempotent cannot safely be "
                       "retried after an interruption")

    elif scenario in ("ui-online-adopt", "ui-import-adopt"):
        _assert_adopted(ctx, root, detail)


def _assert_adopted(ctx, root, detail):
    """Prove the newly enabled modules are genuinely installed, not just present.

    Two of them are expected to fall short, and that is the finding rather than
    a flaw in the test: bootstrap_iris_api_key, seed_volweb_admin and
    seed_yara_rulesets are called only from the INSTALLER's orchestrator and
    have no counterpart anywhere in lib/upgrade/. So IRIS and VolWeb come up,
    pass their health probes, and the backend still cannot call their APIs.
    Naming that explicitly is the point.
    """
    running = set(shell.run(["docker", "ps", "--format", "{{.Names}}"]).out.splitlines())
    for module in detail.get("enabled_for_adoption") or []:
        names = appliance.container_names_of(root, module)
        if not names:
            continue
        ctx.check(f"adopt: {module} has containers running",
                  any(n in running for n in names),
                  actual=", ".join(n for n in names if n in running) or "none")

    # The integration the upgrade path does not retrofit.
    iris_key = shell.run(["docker", "exec", "intact_backend", "python3", "-c",
                          "import sqlite3;c=sqlite3.connect('/app/data/intact.db');"
                          "print(c.execute(\"select count(*) from secrets where key like '%iris%'\").fetchone()[0])"])
    detail["iris_api_key_rows"] = (iris_key.out or "").strip()
    ctx.check("adopt: the backend holds an IRIS api key",
              (iris_key.out or "").strip() not in ("", "0"),
              actual=(iris_key.out or "").strip() or "no answer",
              note="bootstrap_iris_api_key runs only from the installer's "
                   "orchestrator and has no counterpart in lib/upgrade/ — if "
                   "this fails, that is the product gap, not the test")


# --- helpers ---------------------------------------------------------------


def _enable_all_modules(ctx, cfg, root):
    """Turn every module on, in place, the way an operator would."""
    path = os.path.join(root, "config.yaml")
    r = shell.sudo(["python3", "-c",
                    "import re,sys;p=sys.argv[1];s=open(p).read();"
                    "s,n=re.subn(r'^(    enabled: )false$',r'\\1true',s,flags=re.M);"
                    "open(p,'w').write(s);print(n)", path],
                   cfg.sudo_password, timeout=60, tl=ctx.tl, stage="upgrade")
    ctx.check("adopt: modules were enabled in config.yaml", r.ok,
              actual=(r.out or "").strip()[-40:])
    return appliance.enabled_modules(root)


def _first_published_port(root, module):
    """A host port the module publishes, read from its own compose file."""
    compose = os.path.join(root, "modules", module, "docker-compose.yaml")
    try:
        text = open(compose, encoding="utf-8").read()
    except OSError:
        return None
    m = re.search(r'^\s*-\s*"?(?:127\.0\.0\.1:)?(\d{2,5}):\d{2,5}"?\s*$',
                  text, re.M)
    return int(m.group(1)) if m else None


def _hold_port(port):
    """Bind `port` in THIS process, or return None if it could not be taken.

    Held in-process on purpose. The first version spawned a child to do the
    bind, which cannot work: Popen returns a handle as soon as the fork
    succeeds, so the caller got a live-looking holder while the child was
    already dead of EADDRINUSE with its stderr on /dev/null. The scenario then
    "held" a port it did not have, the upgrade succeeded, and the only symptom
    was a rollback test that never rolled anything back.

    A socket object reports its own failure, and stays bound for exactly as
    long as the run holds a reference to it.
    """
    import socket
    s = socket.socket()
    # No SO_REUSEADDR: the whole point is to collide with anything already
    # listening, and quietly succeeding next to another listener would put us
    # straight back to a trap that does not trap.
    try:
        s.bind(("0.0.0.0", port))
        s.listen(1)
        return s
    except OSError:
        s.close()
        return None


def _refresh_session(ctx, cfg):
    """Re-authenticate after an upgrade. Returns what happened, for the report.

    Shell routes have no client yet at this point -- `auth` deliberately runs
    after them, because the oldest boxes have no auth system to claim until the
    upgrade has installed one -- so an absent client is expected, not a fault.
    """
    if ctx.get("client") is None:
        return "not authenticated yet (shell route claims the box later)"

    from lib import api as api_lib
    from phases import platform as platform_mod

    c = api_lib.Client(cfg.platform_host, tl=ctx.tl)
    try:
        how = c.ensure_session(platform_mod.QA_DASH_USER,
                               platform_mod.QA_DASH_PASSWORD)
        ok = c.is_authenticated()
    except Exception as exc:                                  # noqa: BLE001
        ctx.check("the dashboard is reachable after the upgrade", False,
                  actual=ctx.redact(str(exc))[:200],
                  note="the upgrade recreated the backend and the box did not "
                       "come back to a state that accepts a login")
        return "failed"

    ctx.check("a session can be established after the upgrade", ok,
              actual="authenticated" if ok else "login refused",
              note="an upgrade that leaves the operator unable to log back in "
                   "has failed regardless of its exit code")
    if not ok:
        return "failed"

    # Keep the run inside the same persistent case, or the post-upgrade
    # pipelines would fuse into a different workspace than the pre-upgrade
    # ones and the comparison would be meaningless.
    case_id = ctx.get("qa_case_id")
    if case_id:
        c.s.headers["X-Case-Id"] = case_id
    ctx.set(client=c)
    return f"re-authenticated ({how})"


def _release_on_unwind(holder, log_path, detail, deadline_s=2400):
    """Give the port back the instant the engine starts unwinding.

    The trap has to be released mid-run, and this is the part that is easy to
    get wrong. Holding the port for the whole upgrade breaks the very thing
    the scenario exists to observe: the undo restarts the module on its old
    pin, needs the same port to do it, and would hit the same harness socket —
    turning a clean unwind into "ROLLBACK FAILED — this module needs manual
    repair". The test would then assert against a failure it caused itself.

    lib/upgrade/core.sh logs `<module>: rolling back (...)` when it begins the
    unwind, and registers the undo commands only after. Watching for that line
    releases the port inside that window, so compose fails going forward and
    succeeds going back — which is exactly the behaviour under test.
    """
    import threading

    def watch():
        end = time.time() + deadline_s
        while time.time() < end:
            try:
                with open(log_path, encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
            except OSError:
                text = ""
            if "rolling back" in text or "is DOWN" in text:
                detail["port_released_on"] = "the engine began unwinding"
                holder.close()
                return
            time.sleep(0.25)
        # Never hold past the deadline: leaving a port bound would break the
        # verification that follows, and a rollback that never came is a
        # finding for the assertions, not a reason to wedge the box.
        detail["port_released_on"] = "deadline — no unwind was ever logged"
        holder.close()

    threading.Thread(target=watch, daemon=True).start()


def _hop_via(ctx, cfg, root, tag):
    """Move the box onto an intermediate release, the way the README says.

    "An upgrade runs the TARGET RELEASE'S OWN CODE against your live intact
    folder." That is the whole design: you do not ask the old box to upgrade
    itself, you download the newer release next to it and run that release's
    scripts/upgrade.sh --root <appliance>. The old box's code never runs.

    Which is why this hop exists at all. A 0726 appliance ships no
    scripts/upgrade.sh and no bootstrap — verified against the tag — so 0726
    itself cannot drive anything. But 0811's tree can, and pointing it at the
    0726 appliance is exactly the documented invocation.

    The hop is cheap on purpose: the 0811 asset carries `intact` alone (432 MB),
    so it moves the engine and leaves every module pin untouched. The real work
    happens afterwards, with the box genuinely AT 0811 — which is the point,
    because a UI upgrade runs on the box and can only be tested from the version
    the box actually is.
    """
    detail = {"tag": tag}
    workdir = os.path.join(ctx.run_dir, "artifacts", tag)
    os.makedirs(workdir, exist_ok=True)

    # 1. the release's own tree — this is what will drive the upgrade
    src_tgz = os.path.join(workdir, f"{tag}-source.tar.gz")
    tree = os.path.join(workdir, tag)
    os.makedirs(tree, exist_ok=True)
    r = shell.run(["curl", "-fLsS", "--retry", "3", "-o", src_tgz,
                   _release_source_url(tag)], timeout=900)
    if r.ok:
        r = shell.run(["tar", "-xzf", src_tgz, "--strip-components=1",
                       "-C", tree], timeout=300)
    engine = os.path.join(tree, "scripts/upgrade.sh")
    ctx.check(f"hop: {tag}'s own tree is on disk", os.path.isfile(engine),
              actual=engine if os.path.isfile(engine) else "no scripts/upgrade.sh",
              note="the target release's code is what performs the upgrade; "
                   "the appliance's own code is never used")
    if not os.path.isfile(engine):
        return detail

    # 2. its package — the images and the engine asset
    pkg = os.path.join(workdir, f"intact-upgrade-{tag}.tar.gz")
    r = shell.run(["curl", "-fLsS", "--retry", "3", "-o", pkg,
                   _release_asset_url(tag)], timeout=1800)
    size = os.path.getsize(pkg) if os.path.exists(pkg) else 0
    detail["package_bytes"] = size
    ctx.check(f"hop: the {tag} package downloaded", size > 100 * 2**20,
              expected=">100 MB", actual=f"{size / 2**20:.0f} MB")
    if size <= 100 * 2**20:
        return detail

    # 3. run THAT release's engine against THIS appliance
    log_path = os.path.join(ctx.run_dir, "logs", f"hop-{tag}.log")
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    res = shell.sudo(["bash", engine, "--package", pkg, "--root", root,
                      "--log", log_path],
                     cfg.sudo_password, timeout=up.TIMEOUT_UPGRADE_S,
                     tl=ctx.tl, stage="upgrade", log_path=log_path,
                     preserve_env=("GITHUB_TOKEN",))
    detail["exit_code"] = res.rc
    detail["tail"] = [l for l in (res.out or "").splitlines() if l.strip()][-6:]
    ctx.check(f"hop: the box reached {tag}", res.rc == up.RC_CLEAN,
              expected="0 (clean)", actual=f"{res.rc} ({up.describe_rc(res.rc)})",
              note="the hop moves `intact` only — module pins stay where they "
                   "were, and the next upgrade does the real work")

    detail["after"] = appliance.version_facts(root)
    on_disk = os.path.isfile(os.path.join(root, "scripts/upgrade.sh"))
    ctx.check("hop: the appliance now carries an engine of its own", on_disk,
              actual="scripts/upgrade.sh present" if on_disk else "absent",
              note="a 0726 box has none, and the dashboard upgrade this "
                   "scenario tests runs from the box itself")
    return detail


def _release_source_url(tag):
    """The release's own source tree — what the README downloads first."""
    repo = os.environ.get("INTACT_REPO", "TenrootOrg/IntactAI")
    base = os.environ.get("INTACT_GH_DL_BASE", "https://github.com")
    return f"{base}/{repo}/archive/refs/tags/{tag}.tar.gz"


def _release_asset_url(tag):
    repo = os.environ.get("INTACT_REPO", "TenrootOrg/IntactAI")
    base = os.environ.get("INTACT_GH_DL_BASE", "https://github.com")
    return f"{base}/{repo}/releases/download/{tag}/intact-upgrade-{tag}.tar.gz"
