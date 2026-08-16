"""Upgrade routes — thin wrappers over the host-side bash engine.

Restores the three UI features commit f4ab33a removed along with the
25,899-line in-container Python engine (Online Upgrade, Prepare Package,
Import Package), but as the ~400-line shim scripts/prepare_package.sh's own
header already prescribes: "one implementation, not two". Every decision
about WHAT to upgrade — module ordering, downgrade refusal, disk sizing,
version comparison — lives in lib/upgrade/*.sh and is reached here only by
calling `scripts/upgrade.sh`, never reimplemented.

WHERE EACH ENDPOINT RUNS:
  refs                  subprocess (scripts/upgrade.sh --list --json) -- the
                        ONLY local invocation, because "which releases exist?"
                        is asked before a target engine could be fetched
  plan                  subprocess (bootstrap_upgrade.sh <tag> --plan --json)
                        -- answered by the TARGET release's engine
  quota                 in-process (one direct GitHub API call)
  online, offline        HELPER CONTAINER (services.upgrade_launcher) --
                        the intact module always recreates intact_backend
                        first, so this cannot be a subprocess of this process
  prepare                subprocess, own thread (bootstrap_upgrade.sh
                        <tag> --prepare) -- built by the TARGET release's
                        packager; never recreates the backend, so no helper
                        container is needed
  package-info,          the target engine, via bootstrap_upgrade.sh
  upload-preflight       --package <p> --dry-run [--json]. This backend no
                        longer decides what a package contains: it is the
                        release being replaced, so its idea of the format is
                        by definition the old one.
  peek-manifest          the ONE remaining local parse, and non-authoritative
                        -- a pre-upload courtesy so a slow-link operator can
                        review before sending 5 GB. Degrades to success=false,
                        never to a refusal.
  list-packages,         in-process, filesystem listing only.
  upload-run, active

SECURITY: _reject_package_path is unchanged from the deleted engine and
still load-bearing -- arguably MORE so now, since a `package_path` reaching
`upgrade.sh --package` runs as root on the HOST, not merely inside a
container. Never accept a package_path without it.
"""

import fcntl
import json
import os
import re
import shlex
import shutil
import subprocess
import threading
import time
import urllib.request

from flask import Blueprint, jsonify, request, send_file

from services.proc import WORKDIR, HOST_PATH, run_command
from services.workflow_service import (
    create_automation_run,
    add_log_to_run,
    update_run_status,
    get_automation_run,
    get_all_automation_runs,
    register_cancel_event,
    register_cleanup,
    is_cancelled,
    get_cancel_event,
    terminate_subprocess,
)
from services import upgrade_launcher

upgrade_bp = Blueprint('upgrade', __name__)

# THE ONE LOCAL INVOCATION LEFT, and the only one that can be.
#
# `--list` answers "which releases exist?", which is asked BEFORE a target is
# chosen -- so there is no target engine to fetch and defer to. Everything that
# interprets a chosen release (plan, preview, prepare, apply) goes through
# BOOTSTRAP_SH below. Do not add a second use of this constant.
UPGRADE_SH = f"{WORKDIR}/scripts/upgrade.sh"
LOCK_PATH = f"{WORKDIR}/data/tmp/upgrade.lock"

# The one entry point that is allowed to decide anything about a release.
#
# THIS BACKEND IS OLD CODE ON EVERY UPGRADE, by definition -- it is the version
# being replaced. So it must not be the thing that decides how a newer release
# is packaged or applied: that is the circularity which made a .tar -> .tar.gz
# change unupgradeable, one level up from the shell path.
#
# bootstrap_upgrade.sh fetches <tag>-engine.tar.gz, verifies it, and execs it.
# Everything after that -- packaging, parsing, planning, applying -- is the
# target release's own code. This backend's only remaining knowledge of a
# release is the frozen asset name, which is the one thing that can never
# change.
BOOTSTRAP_SH = f"{WORKDIR}/scripts/bootstrap_upgrade.sh"

# Single-writer gate + run acquisition under one mutex closes the
# check-then-create TOCTOU on a double-click: two simultaneous requests
# could both see the lock free before either creates its run.
_UPGRADE_START_MUTEX = threading.Lock()


def _upgrade_gate():
    """Non-blocking probe of the SAME flock scripts/upgrade.sh itself takes
    (data/tmp/upgrade.lock, on the identity mount every container shares).
    Returns None when clear to start, else a (jsonify, 409) naming the
    blocking run -- found by asking for the newest still-running `upgrade`
    row, since the lock file itself carries no run identity.

    Caller must hold _UPGRADE_START_MUTEX across this call AND its
    create_automation_run so a concurrent request can't slip between.
    """
    os.makedirs(os.path.dirname(LOCK_PATH), exist_ok=True)
    try:
        fd = os.open(LOCK_PATH, os.O_CREAT | os.O_RDWR, 0o644)
    except OSError as e:
        print(f"[UPGRADE] gate: could not open lock file ({e}); allowing", flush=True)
        return None
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.flock(fd, fcntl.LOCK_UN)
        return None
    except OSError:
        blocking = None
        try:
            for run in (get_all_automation_runs() or []):
                # Shared with the launcher: the browser's import path continues
                # the UPLOAD's row, so an import in flight is typed
                # upgrade_package_upload. Comparing against "upgrade" alone let
                # a second upgrade start while an import was still running.
                if run.get("automation_type") not in upgrade_launcher.UPGRADE_AUTOMATION_TYPES:
                    continue
                if run.get("status") != "running":
                    continue
                if blocking is None or (run.get("updated_at") or "") > (blocking.get("updated_at") or ""):
                    blocking = run
        except Exception:
            pass
        return jsonify({
            "error": "Another upgrade is already running against this appliance.",
            "blocking_run_id": (blocking or {}).get("run_id"),
        }), 409
    finally:
        os.close(fd)


# ---------------------------------------------------------------------------
# Package-path security (unchanged from the deleted engine)
# ---------------------------------------------------------------------------

# `/data/uploads/` for what the operator uploaded through Import;
# `/data/upgrade_packages/` for what Prepare wrote. Anything else is not a
# legitimate workflow -- and a package_path reaching `upgrade.sh --package`
# is persistent root RCE on the host, not just this container.
ALLOWED_PACKAGE_DIRS = ('/data/uploads/', '/data/upgrade_packages/')


def _reject_package_path(package_path):
    """Return a (jsonify_response, 400) tuple if package_path is outside
    the allowlist; otherwise None. Callers: `err = ...; if err: return err`."""
    if not isinstance(package_path, str) or not package_path:
        return jsonify({"error": "package_path must be a non-empty string"}), 400
    try:
        real = os.path.realpath(package_path)
    except (OSError, ValueError):
        return jsonify({"error": "invalid package_path"}), 400
    if not any(real.startswith(p) for p in ALLOWED_PACKAGE_DIRS):
        return jsonify({
            "error": f"package_path must be under one of: {', '.join(ALLOWED_PACKAGE_DIRS)}"
        }), 400
    return None


def _read_package_manifest(package_path):
    """Ask the package's OWN engine what it contains.

    This used to open the tarball here and look for manifest.json. That is this
    backend -- the release being replaced -- deciding how a newer release's
    package is laid out, and it is the same circularity that made a
    .tar -> .tar.gz change unupgradeable, one level up from the shell path. It
    also silently defined the package format: the moment a release changed it,
    the preview went blank or wrong with nothing to explain why.

    So the question is delegated. The bootstrap pulls the engine out of the
    package by its one frozen name, and that engine -- the one that BUILT this
    package -- answers with `--dry-run --json`. Read-only: --dry-run acquires,
    verifies and plans, then stops without touching the appliance.

    Returns {} when the answer cannot be had, and the callers render that as
    "preview unavailable" rather than refusing the upgrade. A preview is a
    convenience; turning it into a gate is how a format change became an
    outage.
    """
    if not os.path.isfile(BOOTSTRAP_SH):
        print("[UPGRADE] no bootstrap_upgrade.sh; cannot ask the package's engine",
              flush=True)
        return {}
    cmd = (f"bash {shlex.quote(BOOTSTRAP_SH)} "
           f"--package {shlex.quote(package_path)} --dry-run --json")
    try:
        result = run_command(cmd, timeout=300)
    except Exception as e:
        print(f"[UPGRADE] package preview failed: {e}", flush=True)
        return {}
    if not result.get("success"):
        print(f"[UPGRADE] package preview exited non-zero: "
              f"{(result.get('stderr') or '')[:200]}", flush=True)
        return {}
    # plan_print_json emits ONE line, last, after the bootstrap's [INFO] lines
    # and the engine's own progress. Scan backwards for the first line that
    # parses as an object rather than slicing at the first "{" in the stream --
    # a path or a log message containing a brace would otherwise capture it.
    doc = None
    for line in reversed((result.get("stdout") or "").splitlines()):
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            doc = json.loads(line)
            break
        except ValueError:
            continue
    if doc is None:
        print("[UPGRADE] package preview produced no JSON plan", flush=True)
        return {}

    # Shape it the way this route's callers already expect. The engine answers
    # with a PLAN (what it would do to each module), which is strictly more
    # useful than the raw manifest this used to return -- `versions` is derived
    # from it so existing consumers keep working, and `plan` is passed through
    # for anything that wants the actions and the current-vs-target detail.
    entries = doc.get("modules") or []
    return {
        "versions": {e["module"]: e["target"] for e in entries
                     if e.get("target") and e.get("action") != "skip"},
        "contents": {},
        "plan": entries,
    }


# ---------------------------------------------------------------------------
# refs / plan / quota
# ---------------------------------------------------------------------------

@upgrade_bp.route('/api/upgrade/refs', methods=['POST'])
def list_upgrade_refs():
    """What could this box upgrade to. `upgrade.sh --list --json` underneath
    -- the same release-listing decision (payload > 0, shape) the CLI uses --
    translated to the field names the restored frontend expects (`name` /
    `package_mb`, not bash's own `tag` / `payload_bytes`; the bash side keeps
    its own sensible names for any other consumer of --list --json)."""
    result = run_command(f"bash {shlex.quote(UPGRADE_SH)} --list --json",
                         timeout=60)
    if not result.get("success"):
        return jsonify({"success": False, "error": result.get("error_summary")
                        or result.get("error") or "could not list releases"}), 200
    try:
        data = json.loads(result["stdout"].strip().splitlines()[-1])
    except Exception as e:
        return jsonify({"success": False, "error": f"unparseable response: {e}"}), 200
    if "error" in data:
        return jsonify({"success": False, "error": data["error"]}), 200

    releases = data.get("releases") or []

    # `label` is what the dropdown actually displays (settings.html renders
    # x-text="ref.label"), so omitting it produced a list of selectable BLANK
    # options -- the release list looked empty while being perfectly populated.
    # `kind` and `latest` are read by the same markup. The deleted resolver
    # built exactly these three; keep the wording it used.
    newest = ""
    for r in releases:
        if r.get("tag", "") > newest:
            newest = r.get("tag", "")

    refs = []
    for r in releases:
        tag = r["tag"]
        label = f"release {tag}"
        if tag == newest:
            label += " (latest)"
        refs.append({
            "kind": "tag",
            "name": tag,
            "label": label,
            "latest": tag == newest,
            "prerelease": False,
            "package_mb": round(r.get("payload_bytes", 0) / (1024 * 1024), 1),
            "shape": r.get("shape"),
        })
    return jsonify({"success": True, "refs": refs})


def _fetch_plan(tag):
    """Run `upgrade.sh --plan <tag> --json` and translate PLAN_ACTION into
    the deleted engine's forced/optional shape. Returns (plan_dict, None) or
    (None, (jsonify_response, status)) on any failure -- shared by
    compute_upgrade_plan (display) and start_online_upgrade (module
    selection needs the SAME classification the display showed, not a
    second guess at it).

    A `skip:*` PLAN_ACTION (disabled in config.yaml, excluded by --only/
    --skip -- neither of which this ever passes) is dropped from both
    lists, same as the deleted engine's compute_plan did.
    """
    result = run_command(
        # Through the bootstrap: --plan reads the TARGET release's manifest, so
        # the code doing the reading must be the target's. This engine's parser
        # only understands the formats that existed when it shipped.
        f"bash {shlex.quote(BOOTSTRAP_SH)} {shlex.quote(tag)} "
        f"--plan {shlex.quote(tag)} --json",
        timeout=60)

    # Parse BEFORE deciding the command failed. --plan reports a refusal by
    # printing its JSON reason and exiting non-zero, which is right for a CLI
    # -- but checking `success` first meant every one of those refusals came
    # back as the generic "could not compute a plan", and the specific handling
    # below (the legacy-release message) was unreachable code. Found 2026-08-11
    # pointing the online upgrade at a legacy single-bundle release: the engine
    # said exactly what was wrong, and the operator was shown a shrug.
    parsed = None
    try:
        parsed = json.loads((result.get("stdout") or "").strip().splitlines()[-1])
    except Exception:
        parsed = None

    if parsed is None:
        if not result.get("success"):
            return None, (jsonify({"success": False, "error": result.get("error_summary")
                                   or result.get("error") or "could not compute a plan"}), 200)
        return None, (jsonify({"success": False,
                               "error": "unparseable response from the upgrade engine"}), 200)
    if "error" in parsed:
        if parsed["error"] == "no-manifest-asset":
            return None, (jsonify({
                "success": False,
                "error": f"{tag} is a legacy single-bundle release; there is no "
                         "cheap way to plan one. Prepare/apply will still work.",
                "legacy": True,
            }), 200)
        return None, (jsonify({"success": False, "error": parsed["error"]}), 200)

    forced, optional, current_intact = [], [], "unknown"
    for m in parsed.get("modules") or []:
        if m["module"] == "intact":
            current_intact = m.get("current") or "unknown"
        action = m.get("action")
        if action in ("upgrade", "noop"):
            forced.append({"module": m["module"], "current": m.get("current") or "not installed",
                           "target": m.get("target"), "action": action})
        elif action == "install":
            optional.append({"module": m["module"], "target": m.get("target"), "action": action})

    return {
        "current_intact_version": current_intact,
        "target": tag,
        "chain": [tag],
        "forced": forced,
        "optional": optional,
    }, None


@upgrade_bp.route('/api/upgrade/plan', methods=['POST'])
def compute_upgrade_plan():
    """The module-selection table for a specific tag. Cheap: fetches only
    the ~0.2 MB merged manifest via `upgrade.sh --plan <tag> --json`, then
    runs the SAME plan_current_versions + plan_build the real run uses.
    --dry-run is not this cheap -- it takes the upgrade lock and downloads
    the full payload.

    Body: {"target": "intact-20260812"}

    SIMPLIFIED from the deleted engine: it also spliced a `modules.<name>`
    block into config.yaml from the release's own upstream defaults when the
    operator opted into a module with no local config block yet, and warned
    about the resulting default credentials. That side effect depended on
    fetch_upstream_config/set_module_block_in_config, both deleted with the
    Python engine; restoring it is follow-up work, not blocking this restore.
    """
    data = request.json or {}
    tag = (data.get('target') or '').strip()
    if not tag:
        return jsonify({"success": False, "error": "target required"}), 400
    plan, err = _fetch_plan(tag)
    if err:
        return err
    return jsonify({"success": True, "plan": plan})


@upgrade_bp.route('/api/upgrade/quota', methods=['GET'])
def get_upgrade_quota():
    """GitHub rate-limit state, so the UI can warn BEFORE the operator
    spends the quota a real refs/plan call would use. One direct call, no
    resolver module -- the deleted engine's version of this cached
    responses and tracked auth state across a UI session that no longer
    exists; a plain request is all a stateless route needs.
    """
    token = ""
    try:
        import yaml
        with open(f"{WORKDIR}/config.yaml", encoding="utf-8") as f:
            token = ((yaml.safe_load(f) or {}).get("options") or {}).get("github_token") or ""
    except Exception:
        pass

    req = urllib.request.Request("https://api.github.com/rate_limit")
    if token:
        req.add_header("Authorization", f"token {token}")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = json.load(resp)
        core = (body.get("resources") or {}).get("core") or body.get("rate") or {}
        return jsonify({
            "success": True,
            "remaining": core.get("remaining"),
            "limit": core.get("limit") or 60,
            "reset_hm": time.strftime("%H:%M", time.localtime(core.get("reset", time.time()))),
            "authed": bool(token),
        })
    except Exception as e:
        return jsonify({"success": False, "error": f"rate-limit endpoint unreachable: {e}"}), 200


# ---------------------------------------------------------------------------
# online / offline — helper container
# ---------------------------------------------------------------------------

# Where a package has to be for the HELPER to see it.
#
# /data/uploads and /data/upgrade_packages are docker VOLUMES mounted into
# intact_backend. The helper container mounts only docker.sock and the identity
# bind at HOST_PATH -- so a path under either of those directories exists for
# this process and does not exist for the process that actually runs
# `upgrade.sh --package`. Handing the CLI args straight through meant every
# Import and every apply-a-prepared-package died with "Package not found" the
# first time anyone used it.
#
# So relocate onto the shared bind before launching. Hard-link when the source
# and destination are on one filesystem (they are: the volume lives under
# /var/lib/docker and the bind under the appliance root, both on /) -- these
# are multi-GB files and copying them would double the disk cost of every
# import for no reason. Fall back to a copy across devices.
#
# `import-pkg-<run_id>` deliberately matches none of upkg_sweep_stale_scratch's
# patterns (upgrade-pkg-*, upgrade-unwrap-*, upgrade-dl-*, ...): the sweep runs
# at the START of the next upgrade, and a name it recognised could see a staged
# package deleted out from under a run that had not begun extracting yet. It is
# cleaned up here instead, when the run reaches a terminal state.
_HELPER_STAGE_PREFIX = "import-pkg-"


def _stage_for_helper(paths, run_id):
    """Return (host_paths, error). Places each package under
    HOST_PATH/data/tmp/import-pkg-<run_id>/ so the helper container can read
    it, and returns the paths as the HELPER will see them."""
    stage_container = os.path.join(WORKDIR, "data", "tmp",
                                   f"{_HELPER_STAGE_PREFIX}{run_id}")
    stage_host = os.path.join(HOST_PATH, "data", "tmp",
                              f"{_HELPER_STAGE_PREFIX}{run_id}")
    try:
        os.makedirs(stage_container, exist_ok=True)
    except OSError as e:
        return None, f"could not create the staging directory: {e}"

    out = []
    for p in paths:
        name = os.path.basename(p)
        dest = os.path.join(stage_container, name)
        try:
            if os.path.isdir(p):
                # A directory of per-module assets: link each file inside it.
                os.makedirs(dest, exist_ok=True)
                for f in sorted(os.listdir(p)):
                    s, d = os.path.join(p, f), os.path.join(dest, f)
                    if not os.path.isfile(s) or os.path.exists(d):
                        continue
                    try:
                        os.link(s, d)
                    except OSError:
                        shutil.copy2(s, d)
            elif not os.path.exists(dest):
                try:
                    os.link(p, dest)
                except OSError:
                    shutil.copy2(p, dest)
        except OSError as e:
            return None, f"could not stage {name} for the upgrade helper: {e}"
        out.append(os.path.join(stage_host, name))
    return out, None


def _sweep_stale_uploads(days=7):
    """Age-based cleanup of imported packages, run when a new offline upgrade
    starts.

    Nothing removed these until 2026-08-11 -- not the engine, not tusd, not
    this file. Every package an operator ever imported stayed in the volume
    forever, and these are release packages: 1.1 GB observed on this appliance
    from a single two-module test, and a full nine-module package is ~6.4 GB.
    An appliance that takes four upgrades has silently spent 25 GB on packages
    it already applied, and then the disk preflight refuses the fifth.

    Why 7 days and not on-success: an upload is the OPERATOR'S file, not this
    run's scratch (see _sweep_stale_stages -- Import owns only its own hard
    link to it). Someone who hand-carried 6 GB into an air-gapped site may
    reasonably re-apply it to a second box, or retry after a failure, so
    deleting it the moment one upgrade succeeds would be taking away something
    they still need. A week is long past either.

    Recursive because Import writes per-module assets into an 'permodule/'
    subdirectory, which is where the bulk actually sits; a top-level-only
    sweep would have reported success and freed 180 KB of manifest.
    """
    cutoff = time.time() - days * 86400
    for base in ALLOWED_PACKAGE_DIRS:
        if not os.path.isdir(base):
            continue
        for root, dirs, files in os.walk(base, topdown=False):
            for name in files:
                p = os.path.join(root, name)
                try:
                    if os.path.getmtime(p) >= cutoff:
                        continue
                    freed = os.path.getsize(p)
                    os.unlink(p)
                    print(f"[upgrade] swept imported package {p} "
                          f"({freed // (1024*1024)} MB, older than {days}d)",
                          flush=True)
                except OSError:
                    pass
            # Only ever removes a directory once its own contents are gone
            # (topdown=False), and rmdir refuses a non-empty one anyway.
            if root != base.rstrip('/'):
                try:
                    os.rmdir(root)
                except OSError:
                    pass


def _sweep_stale_stages(hours=48):
    """Age-based cleanup of previous staging dirs, run when a new offline
    upgrade starts.

    Deliberately age-based and done HERE rather than deleting a run's stage
    when it finishes: the routes layer does not own the run's terminal state
    (upgrade_launcher's tailer does, and it may be a different process
    entirely after the backend restart every upgrade causes). Copying
    upkg_sweep_stale_scratch's approach -- reclaim on the way IN, from runs
    that are definitely over -- avoids inventing a second lifecycle.

    Mostly frees nothing when the source is still on disk, since these are
    hard links; that is correct, the upload belongs to the operator and Import
    owns only its own reference to it.
    """
    base = os.path.join(WORKDIR, "data", "tmp")
    cutoff = time.time() - hours * 3600
    try:
        for name in os.listdir(base):
            if not name.startswith(_HELPER_STAGE_PREFIX):
                continue
            p = os.path.join(base, name)
            try:
                if os.path.getmtime(p) < cutoff:
                    shutil.rmtree(p, ignore_errors=True)
            except OSError:
                pass
    except OSError:
        pass


def _start_launcher_run(automation_type, name, details, cli_args, force=False):
    """Shared by online + offline: gate, create the run, launch the helper.
    Returns a Flask response tuple."""
    with _UPGRADE_START_MUTEX:
        blocked = _upgrade_gate()
        if blocked and not force:
            return blocked

        run_id = create_automation_run(automation_type, name, details)
        register_cancel_event(run_id)
        add_log_to_run(run_id, f"[Upgrade] starting: {' '.join(cli_args)}")
        update_run_status(run_id, "running", progress=0)

        err = upgrade_launcher.launch(run_id, cli_args)
        if err:
            update_run_status(run_id, "failed", error=err)
            return jsonify({"success": False, "error": err}), 500

    return jsonify({"success": True, "run_id": run_id}), 202


@upgrade_bp.route('/api/upgrade/online', methods=['POST'])
def start_online_upgrade():
    """Online upgrade: downloads AND applies a release tag in one run.

    Body: {"target": "intact-20260812", "opted_in_optional": [...],
           "opted_in_reinstall": [...], "force": bool}

    opted_in_optional/opted_in_reinstall are the operator's ticks from the
    /plan table the frontend showed -- NOT a raw --only list, because forced
    rows (already-installed modules) are not optional: every 'upgrade' row
    applies regardless of what was ticked, matching the deleted engine's own
    "operator can't opt out" rule for forced modules. So the final module
    list is recomputed here from a FRESH plan (must match what the operator
    actually saw, not trust a client-supplied module list that could have
    gone stale between viewing the plan and clicking Start) rather than
    trusting the two tick-lists alone.
    """
    data = request.json or {}
    tag = (data.get('target') or '').strip()
    if not tag:
        return jsonify({"success": False, "error": "target required"}), 400
    opted_optional = set(data.get('opted_in_optional') or [])
    opted_reinstall = set(data.get('opted_in_reinstall') or [])

    plan, err = _fetch_plan(tag)
    if err:
        return err
    modules = []
    for row in plan["forced"]:
        if row["action"] == "upgrade" or row["module"] in opted_reinstall:
            modules.append(row["module"])
    for row in plan["optional"]:
        if row["module"] in opted_optional:
            modules.append(row["module"])
    if not modules:
        return jsonify({"success": False, "error": "Nothing selected to upgrade"}), 400

    cli_args = [tag, "--only", ",".join(modules)]
    # --only alone is not enough to express "re-apply this one". It selects
    # which modules the run considers; plan.sh then still classifies an
    # already-at-target module as noop and skips it. So a reinstall tick used
    # to submit cleanly and do nothing (fixed 2026-08-11). Only the ticks that
    # are genuinely no-change rows go here -- a module being upgraded needs no
    # override, and naming it would be a confusing no-op in the log.
    reinstall = [row["module"] for row in plan["forced"]
                 if row["action"] != "upgrade" and row["module"] in opted_reinstall]
    if reinstall:
        cli_args += ["--reinstall", ",".join(reinstall)]

    return _start_launcher_run(
        "upgrade", f"Online upgrade to {tag}",
        {"kind": "online", "tag": tag, "modules": modules},
        cli_args, force=bool(data.get('force')),
    )


@upgrade_bp.route('/api/upgrade/offline', methods=['POST'])
def start_offline_upgrade():
    """Offline upgrade: apply a package (or list of per-module assets)
    already on disk -- uploaded via Import, or written by Prepare.

    Body: {
      "package_path": "/data/uploads/...",       // scalar, or:
      "package_paths": ["/data/uploads/a.tar", ...],  // list form
      "selected_modules": ["elk", "velociraptor"],  // which modules to apply
      "db_overwrite": {"timesketch": true},      // NOT honored -- see below
      "expected_sha256": "...",                  // optional digest anchor
      "upload_run_id": "<run id>",                // optional: continue this run
      "force": bool
    }

    SIMPLIFIED from the deleted engine: `db_overwrite` (per-module "wipe and
    fresh-install" flag) is accepted so the restored frontend's request body
    doesn't need editing, but not acted on -- lib/upgrade/modules/*.sh has no
    equivalent concept today (grep confirms no "overwrite"/"fresh_install"
    handling anywhere under lib/upgrade/). Restoring it is follow-up work,
    not blocking this restore; a truthy value here is currently a no-op.
    """
    data = request.json or {}
    package_paths = data.get('package_paths')
    package_path = data.get('package_path')
    if package_paths and not isinstance(package_paths, list):
        return jsonify({"success": False, "error": "package_paths must be a list"}), 400
    if package_paths and len(package_paths) == 1:
        package_path, package_paths = package_paths[0], None
    if not package_path and not package_paths:
        return jsonify({"success": False, "error": "package_path required"}), 400

    paths = [package_path] if package_path else package_paths
    for p in paths:
        err = _reject_package_path(p)
        if err:
            return err
        if not os.path.exists(p):
            return jsonify({"success": False, "error": f"Package not found: {p}"}), 400

    selected_modules = data.get('selected_modules')
    if selected_modules is not None and not isinstance(selected_modules, list):
        return jsonify({"success": False, "error": "selected_modules must be a list"}), 400

    # Which of the selected modules are "reinstall" ticks -- already at the
    # target version, re-applied on purpose. The frontend knows this (it
    # renders the row as 'reinstall' vs 'upgrade' from applyModuleAction), the
    # backend does not: working it out here would mean re-reading the package
    # manifest and comparing against installed versions, duplicating a
    # judgement the modal has already made and displayed.
    reinstall_modules = data.get('reinstall_modules') or []
    if not isinstance(reinstall_modules, list):
        return jsonify({"success": False, "error": "reinstall_modules must be a list"}), 400
    # A reinstall for a module that is not part of the run is incoherent, and
    # would reach the engine as an --only/--reinstall pair that disagree.
    if selected_modules:
        stray = [m for m in reinstall_modules if m not in selected_modules]
        if stray:
            return jsonify({"success": False,
                            "error": "reinstall_modules not in selected_modules: "
                                     + ", ".join(stray)}), 400
    expect = (data.get('expected_sha256') or '').strip()

    upload_run_id = (data.get('upload_run_id') or '').strip() or None

    # Onto the shared bind first -- see _stage_for_helper. The run id is only
    # known after create_automation_run for the ordinary path, so stage under
    # whichever id this run will actually use.
    _sweep_stale_stages()
    _sweep_stale_uploads()
    stage_id = upload_run_id or f"{os.getpid()}-{int(time.time())}"
    host_paths, stage_err = _stage_for_helper(paths, stage_id)
    if stage_err:
        return jsonify({"success": False, "error": stage_err}), 500

    cli_args = []
    for p in host_paths:
        cli_args += ["--package", p]
    if selected_modules:
        cli_args += ["--only", ",".join(selected_modules)]
        # The two lists are DISJOINT, and deliberately so.
        #
        # --only is the run's module set; --reinstall names the ones inside it
        # that are already at the target version and should be re-applied
        # anyway. A module that is genuinely upgrading or installing needs no
        # flag -- it is in the plan by virtue of its version differing.
        #
        # This briefly sent the whole selected list as --reinstall, reasoning
        # that plan.sh only consults it on the noop branch so the extra names
        # were harmless. They were harmless to the engine and wrong for the
        # operator: "--only intact,iris,portainer --reinstall
        # intact,iris,portainer" reads as "reinstall everything" in the log and
        # in the launch script, which is not what was asked for and not what
        # happens.
        if reinstall_modules:
            cli_args += ["--reinstall", ",".join(reinstall_modules)]
    if expect:
        cli_args += ["--expect-sha256", expect]
    if upload_run_id:
        # Continue the upload's own row rather than opening a second one --
        # same "one row for the whole import" shape the deleted engine used,
        # simplified: the browser already holds this id (it created the row
        # via /api/upgrade/upload-run before the tus upload even started),
        # so there is no race to resolve here the way there was matching a
        # hook-written sidecar against a concurrently-arriving request.
        with _UPGRADE_START_MUTEX:
            blocked = _upgrade_gate()
            if blocked and not data.get('force'):
                return blocked
            register_cancel_event(upload_run_id)
            add_log_to_run(upload_run_id, f"[Upgrade] applying: {' '.join(cli_args)}")
            update_run_status(upload_run_id, "running", progress=0)
            err = upgrade_launcher.launch(upload_run_id, cli_args)
            if err:
                update_run_status(upload_run_id, "failed", error=err)
                return jsonify({"success": False, "error": err}), 500
        return jsonify({"success": True, "run_id": upload_run_id}), 202

    return _start_launcher_run(
        "upgrade", "Apply uploaded package",
        {"kind": "offline", "package_paths": paths, "modules": selected_modules},
        cli_args, force=bool(data.get('force')),
    )


# ---------------------------------------------------------------------------
# prepare — plain subprocess, own thread (never recreates the backend)
# ---------------------------------------------------------------------------

_PREPARE_LOG_RE = re.compile(r'^\[prepare\](\[ERROR\])?\s?(.*)$')


def _run_prepare(run_id, tag):
    out_dir = "/data/upgrade_packages"
    os.makedirs(out_dir, exist_ok=True)

    # BUILD THE PACKAGE WITH THE TARGET RELEASE'S PACKAGER, not this one.
    #
    # A package's shape is decided by the release it is FOR, so that release
    # should be what writes it -- otherwise an old prepare_package.sh lays out a
    # package for a new engine to read, and the two disagree the first time the
    # layout moves. `--prepare` makes the bootstrap fetch <tag>'s engine and
    # exec ITS prepare_package.sh.
    #
    # `exec` means the final stdout line is still prepare_package.sh's own, so
    # the "last line is the package path" contract below is unchanged; the
    # bootstrap's few [INFO] lines ahead of it fall through to the log.
    if not os.path.isfile(BOOTSTRAP_SH):
        # NO LOCAL FALLBACK. Building with this release's packager would lay out
        # a package for a different release's engine to read, which is the
        # circularity this design removes -- and it would look identical to a
        # correct build. Refuse instead.
        update_run_status(run_id, "failed",
                          error="scripts/bootstrap_upgrade.sh is missing from this "
                                "appliance, so the target release's packager cannot "
                                "be fetched. Nothing was built.")
        return
    cmd = ["bash", BOOTSTRAP_SH, tag, "--prepare", out_dir]
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            start_new_session=True,
        )
    except Exception as e:
        update_run_status(run_id, "failed",
                          error=f"could not start {os.path.basename(cmd[1])}: {e}")
        return

    register_cleanup(run_id, lambda p=proc: terminate_subprocess(p))

    lines = []
    cancel_event = get_cancel_event(run_id)
    for raw in proc.stdout:
        if cancel_event is not None and cancel_event.is_set():
            terminate_subprocess(proc)
            return  # request_stop already set status='cancelled'
        line = raw.rstrip("\n")
        lines.append(line)
        m = _PREPARE_LOG_RE.match(line)
        if m:
            add_log_to_run(run_id, m.group(2), "error" if m.group(1) else "info")
        elif line:
            add_log_to_run(run_id, line, "info")

    rc = proc.wait()
    if rc != 0:
        update_run_status(run_id, "failed",
                          error=f"{os.path.basename(cmd[1])} exited {rc}")
        return

    # Contract (tests/test_prepare_package.sh): the script's own last stdout
    # line is the wrapper's final path. Nothing else in this stream can be
    # that path, so this is exact, not a best-effort scrape.
    final_path = next((l for l in reversed(lines) if l.strip()), None)
    if not final_path or not os.path.isfile(final_path):
        update_run_status(run_id, "failed",
                          error=f"{os.path.basename(cmd[1])} exited 0 but produced no package")
        return

    info = {
        "run_id": run_id,
        "path": final_path,
        "name": os.path.basename(final_path),
        "tag": tag,
        "size_bytes": os.path.getsize(final_path),
    }
    try:
        os.makedirs(os.path.dirname(_PACKAGE_INFO_FILE), exist_ok=True)
        with open(_PACKAGE_INFO_FILE, 'w') as f:
            json.dump(info, f, indent=2)
    except Exception as e:
        print(f"[UPGRADE] could not save package info: {e}", flush=True)

    update_run_status(run_id, "completed", progress=100,
                      details={"package_available": True, **info}, force=True)


@upgrade_bp.route('/api/upgrade/prepare', methods=['POST'])
def prepare_upgrade_package():
    """Prepare a hand-carry package for `tag`, for an air-gapped site.

    Runs the bootstrap, which fetches the TARGET release's own
    prepare_package.sh and execs that, as a plain background subprocess --
    it never touches docker.sock or recreates the backend, so it needs no
    helper container, just a thread. No lock either: two prepares racing
    into the SAME fixed output name would clobber each other, so this
    serializes on the SAME upgrade gate as online/offline instead of
    inventing a second one.

    Body: {"target": "intact-20260812"}
    """
    data = request.json or {}
    tag = (data.get('target') or '').strip()
    if not tag:
        return jsonify({"success": False, "error": "target required"}), 400

    with _UPGRADE_START_MUTEX:
        blocked = _upgrade_gate()
        if blocked and not data.get('force'):
            return blocked
        run_id = create_automation_run("prepare_package", f"Prepare package: {tag}",
                                       {"tag": tag})
        register_cancel_event(run_id)
        add_log_to_run(run_id, f"[Upgrade] preparing a package for {tag}")
        update_run_status(run_id, "running", progress=0)

        t = threading.Thread(target=_run_prepare, args=(run_id, tag), daemon=True,
                             name=f"prepare-{run_id}")
        t.start()

    return jsonify({"success": True, "run_id": run_id}), 202


_PACKAGE_INFO_FILE = "/data/upgrade_packages/prepared_package.json"


def _get_package_info():
    if os.path.exists(_PACKAGE_INFO_FILE):
        try:
            with open(_PACKAGE_INFO_FILE) as f:
                return json.load(f)
        except Exception:
            pass
    return None


@upgrade_bp.route('/api/upgrade/prepare/<run_id>/download', methods=['GET'])
def download_prepared_package(run_id):
    """Download a prepared package. Only the LAST prepared package is kept
    (fixed output dir, overwritten each time), so an older run's package is
    gone the moment a newer prepare completes."""
    pkg = _get_package_info()
    if not pkg or pkg.get('run_id') != run_id:
        newer = (pkg or {}).get('run_id')
        if newer and newer != run_id:
            err = (f"This package was overwritten by a newer preparation "
                   f"(run {newer}). Re-prepare from this run, or use the newer one.")
        else:
            err = "The prepared package is no longer available. Please prepare it again."
        return jsonify({"error": err, "superseded_by": (pkg or {}).get('run_id')}), 410

    if not os.path.exists(pkg['path']):
        return jsonify({"error": "Package file not found on server"}), 404

    return send_file(pkg['path'], as_attachment=True, download_name=pkg['name'],
                     mimetype='application/gzip')


# ---------------------------------------------------------------------------
# Read-only helpers -- lifted near-verbatim from the deleted engine, which
# never depended on it for these: pure filesystem/manifest reads.
# ---------------------------------------------------------------------------

@upgrade_bp.route('/api/upgrade/package-info', methods=['POST'])
def get_upgrade_package_info():
    """Manifest info from a local package. Body: {"package_path": "..."}"""
    data = request.json or {}
    package_path = data.get('package_path')
    if not package_path:
        return jsonify({"error": "No package_path provided"}), 400
    err = _reject_package_path(package_path)
    if err:
        return err
    if not os.path.exists(package_path):
        return jsonify({"error": "Package not found"}), 404

    manifest = _read_package_manifest(package_path)
    return jsonify({
        "success": True,
        "manifest": manifest,
        "versions": manifest.get("versions", {}),
        "contents": manifest.get("contents", {}),
    })


@upgrade_bp.route('/api/upgrade/preflight', methods=['POST'])
def preflight_upgrade_package():
    """Would this package apply cleanly? Changes nothing on the appliance.

    bootstrap_upgrade.sh --package <path> --dry-run does the real work here
    -- the package's own engine is extracted, verified and asked to plan, so
    this endpoint reuses it rather than a second validator. It briefly takes the upgrade lock (the
    same one a real apply would), which is fine: preflight is a deliberate
    pre-apply check, not something polled in the background.

    Body: {"package_path": "...", "only": "elk,timesketch"}
    """
    data = request.json or {}
    package_path = (data.get('package_path') or '').strip()
    if not package_path:
        return jsonify({"error": "package_path required"}), 400
    err = _reject_package_path(package_path)
    if err:
        return err

    only = (data.get('only') or '').strip()
    # The bootstrap finds the engine at the package's top level and hands over,
    # so the package is inspected by the release that built it.
    cmd = (f"bash {shlex.quote(BOOTSTRAP_SH)} "
           f"--package {shlex.quote(package_path)} --dry-run")
    if only:
        cmd += f" --only {shlex.quote(only)}"

    result = run_command(cmd, timeout=600)
    log_lines = (result.get("stdout") or "").splitlines()
    ok = bool(result.get("success"))
    return jsonify({
        "ok": ok,
        "log": log_lines,
        "error": None if ok else (result.get("error_summary") or result.get("error")),
    })


@upgrade_bp.route('/api/upgrade/upload-preflight', methods=['POST'])
def upload_preflight():
    """Can this host take an upload of size_bytes, and what's already
    sitting in the package directories? Called BEFORE the browser starts
    pushing a multi-GB file -- the apply's own disk check runs only after
    the whole thing has already landed."""
    try:
        data = request.json or {}
        try:
            size = int(data.get('size_bytes') or 0)
        except (TypeError, ValueError):
            size = 0

        leftovers, leftover_bytes = [], 0
        for prefix in ALLOWED_PACKAGE_DIRS:
            if not os.path.isdir(prefix):
                continue
            try:
                names = os.listdir(prefix)
            except OSError:
                continue
            for name in sorted(names):
                full = os.path.join(prefix, name)
                try:
                    st = os.stat(full)
                except OSError:
                    continue
                if os.path.isdir(full):
                    if not name.startswith('.intact-prepare-'):
                        continue
                    total = 0
                    for root, _d, files in os.walk(full):
                        for f in files:
                            try:
                                total += os.path.getsize(os.path.join(root, f))
                            except OSError:
                                pass
                    leftovers.append({'name': name, 'dir': prefix, 'size_bytes': total,
                                      'kind': 'interrupted prepare'})
                    leftover_bytes += total
                elif name.endswith(('.tar.gz', '.tgz', '.tar')):
                    leftovers.append({'name': name, 'dir': prefix, 'size_bytes': st.st_size,
                                      'kind': 'package'})
                    leftover_bytes += st.st_size
                elif name.endswith(('.info', '.run', '.lock')):
                    continue
                else:
                    if st.st_size < 1024 * 1024:
                        continue
                    label = name
                    try:
                        with open(full + '.info') as inf:
                            meta = (json.load(inf).get('MetaData') or {})
                        if meta.get('filename'):
                            label = f"{meta['filename']} (upload {name[:12]}…)"
                    except (OSError, ValueError):
                        pass
                    leftovers.append({'name': label, 'dir': prefix, 'size_bytes': st.st_size,
                                      'kind': 'interrupted upload'})
                    leftover_bytes += st.st_size

        target = '/data/uploads' if os.path.isdir('/data/uploads') else '/data'
        try:
            free = shutil.disk_usage(target).free
        except OSError:
            free = 0

        needed = int(size * 4.6) if size else 0
        return jsonify({
            "success": True,
            "free_bytes": free,
            "needed_bytes": needed,
            "upload_bytes": size,
            "ok": (free >= needed) if size else True,
            "leftovers": leftovers,
            "leftover_bytes": leftover_bytes,
            "reclaimable_ok": (free + leftover_bytes >= needed) if size else True,
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e), "ok": True}), 200


@upgrade_bp.route('/api/upgrade/list-packages', methods=['POST'])
def list_pending_packages():
    """Tarballs currently on disk in the two allowlisted package dirs, for
    the Apply Uploaded Package card's picker."""
    try:
        out = []
        for prefix in ALLOWED_PACKAGE_DIRS:
            if not os.path.isdir(prefix):
                continue
            try:
                names = os.listdir(prefix)
            except OSError:
                continue
            for name in sorted(names):
                if not (name.endswith('.tar.gz') or name.endswith('.tgz') or name.endswith('.tar')):
                    continue
                full = os.path.join(prefix, name)
                try:
                    st = os.stat(full)
                except OSError:
                    continue
                out.append({
                    'path': full, 'name': name, 'size_bytes': st.st_size,
                    'mtime': st.st_mtime,
                    'source': 'uploads' if prefix == '/data/uploads/' else 'prepare',
                })
        out.sort(key=lambda r: r['mtime'], reverse=True)
        return jsonify({"success": True, "packages": out})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@upgrade_bp.route('/api/upgrade/peek-manifest', methods=['POST'])
def peek_manifest_from_blob():
    """Extract manifest info from the FIRST few MB of a tarball blob the
    browser sliced client-side (FileReader), before committing to a full
    upload -- so the Import review modal can show what's in the file
    immediately. Body: raw tar bytes. Falls back gracefully (200,
    success=false) so the caller can fall back to the post-upload path.

    THE ONE PLACE THIS BACKEND STILL PARSES A PACKAGE, and deliberately so.
    Everything that DECIDES anything -- prepare, plan, preflight, preview,
    apply -- now goes through scripts/bootstrap_upgrade.sh and is answered by
    the target release's own engine. This does not decide: it is a courtesy
    peek at a local file so an operator on a slow air-gapped link can review a
    package before spending an hour uploading 5 GB of it. The engine still
    validates the real thing at apply time, and _read_package_manifest above
    re-answers the same question properly once the file has landed.
    Consequently a format this parser cannot read must degrade to
    success=false and NEVER to a refusal -- the caller then uploads and reviews
    afterwards, which is the target-side path. If that trade ever stops being
    worth it, delete this route: nothing downstream depends on its answer.
    """
    try:
        blob = request.get_data()
        if not blob:
            return jsonify({"success": False, "error": "empty body"}), 400
        if len(blob) > 25 * 1024 * 1024:
            return jsonify({"success": False, "error": "blob too large for peek"}), 400

        import io
        import tarfile
        try:
            with tarfile.open(fileobj=io.BytesIO(blob), mode='r|*') as tar:
                for member in tar:
                    if member.name.endswith('.index.json') and member.isfile():
                        f = tar.extractfile(member)
                        if f is None:
                            continue
                        index = json.load(f)
                        assets = index.get('assets') or {}
                        versions = {m: (e or {}).get('version') for m, e in assets.items()}
                        contents = {
                            "package_kind": "wrapper",
                            "assembled_from": sorted(assets),
                            "source_commit": index.get('source_commit'),
                            "release_tag": index.get('release_tag'),
                        }
                        return jsonify({"success": True, "manifest": {"versions": versions, "contents": contents},
                                        "versions": versions, "contents": contents, "created": None})
                    if member.name.endswith('manifest.json') and member.isfile():
                        f = tar.extractfile(member)
                        if f is None:
                            continue
                        manifest = json.load(f)
                        return jsonify({
                            "success": True, "manifest": manifest,
                            "versions": manifest.get('versions', {}),
                            "contents": manifest.get('contents', {}),
                            "created": manifest.get('created'),
                        })
        except (EOFError, tarfile.ReadError):
            pass
        return jsonify({"success": False,
                        "error": "manifest.json not found in the first chunk (likely an older tarball)"}), 200
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@upgrade_bp.route('/api/upgrade/upload-run', methods=['POST'])
def create_upgrade_upload_run():
    """Pre-create the upload's workflow row so the UI shows it the instant
    the operator clicks Apply, instead of waiting for tusd's post-create
    hook. The browser passes the returned run_id back in the tus upload
    metadata as `upload_run_id`."""
    try:
        data = request.get_json(silent=True) or {}
        filename = (data.get('filename') or 'upgrade package').strip()
        size_bytes = int(data.get('size_bytes') or 0)
        size_mb = size_bytes / (1024 * 1024) if size_bytes else 0
        run_id = create_automation_run(
            'upgrade_package_upload', f"Upload: {filename}",
            {"filename": filename, "purpose": "upgrade_package",
             "size_bytes": size_bytes, "size_mb": round(size_mb, 2)},
        )
        add_log_to_run(run_id, f"Preparing upload: {filename} ({size_mb:.1f} MB)")
        update_run_status(run_id, "running", progress=0)
        return jsonify({"success": True, "run_id": run_id})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@upgrade_bp.route('/api/upgrade/active', methods=['GET'])
def get_active_upgrade_run():
    """The upgrade run currently in flight, if any -- so the UI can
    reattach after the backend restart signs the operator out mid-upgrade.
    The frontend held the run id only in memory; after signing back in it
    had nothing to poll. Discoverable from the server instead."""
    ACTIVE = ('running', 'pending')
    try:
        runs = get_all_automation_runs() or []
    except Exception as e:
        return jsonify({"success": False, "error": str(e), "active": None}), 200

    best = None
    for run in runs:
        # An import in flight is typed upgrade_package_upload (the browser path
        # continues the upload's own row), so excluding it defeated the very
        # purpose of this endpoint: after the backend restart signed the
        # operator out mid-import, the UI had nothing to reattach to and the
        # upgrade looked stuck with no information, while it was in fact still
        # running through the remaining modules.
        if run.get('automation_type') not in (
                *upgrade_launcher.UPGRADE_AUTOMATION_TYPES, 'prepare_package'):
            continue
        if (run.get('status') or '').lower() not in ACTIVE:
            continue
        if best is None or (run.get('updated_at') or '') > (best.get('updated_at') or ''):
            best = run
    if not best:
        return jsonify({"success": True, "active": None}), 200
    return jsonify({
        "success": True,
        "active": {
            "run_id": best.get('run_id'),
            "status": best.get('status'),
            "progress": best.get('progress'),
            "name": best.get('name'),
            "updated_at": best.get('updated_at'),
        },
    }), 200
