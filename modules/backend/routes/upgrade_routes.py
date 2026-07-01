#!/usr/bin/env python3
"""
Upgrade Routes - System upgrade endpoints (online and offline)
"""

from flask import Blueprint, jsonify, request, send_file
import threading
import os
import time
import json

from services import (
    create_automation_run,
    add_log_to_run,
    update_run_status
)

upgrade_bp = Blueprint('upgrade', __name__)


# Allowlist for operator-supplied `package_path` (Mythos finding #7).
# Both `/api/upgrade/package-info` and `/api/upgrade/offline` accept
# `package_path` from the request body, and `/api/upgrade/offline`
# applies its contents over the running install (Phase 1 copies
# `source/intact/*` over WORKDIR/*) — so a tarball at an attacker-
# controlled path means persistent RCE in one POST. The two allowed
# prefixes are the LEGIT landing points: `/data/uploads/` for files
# the operator uploaded through the Import UI card, and
# `/data/upgrade_packages/` for the prepare-side output of the
# Online Upgrade flow. Any path outside these is by definition not
# a legitimate workflow. `os.path.realpath` strips `..` traversal
# before the prefix check, so an input like
# `/data/uploads/foo/../../tmp/evil.tar.gz` resolves outside the
# allowlist and is rejected.
ALLOWED_PACKAGE_DIRS = ('/data/uploads/', '/data/upgrade_packages/')


def _reject_package_path(package_path):
    """Return a (jsonify_response, 400_status) tuple if `package_path`
    is outside the allowlist; otherwise return None.

    Callers use the idiom:
        err = _reject_package_path(package_path)
        if err: return err
    """
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


# Fixed package path (only keep one package, overwrite each time)
PACKAGE_PATH = "/data/upgrade_packages/intact-upgrade-latest.tar.gz"
# Co-locate the package RECORD on the SAME persistent volume as the package file, so
# it survives a container recreate exactly like the package does. Legacy installs kept
# it in the ephemeral /data/db (wiped on recreate) — read that as a fallback so an
# in-place upgrade doesn't lose track of an already-prepared package.
PACKAGE_INFO_FILE = "/data/upgrade_packages/prepared_package.json"
_LEGACY_PACKAGE_INFO_FILE = "/data/db/prepared_package.json"


def _get_package_info():
    """Get current prepared package info (new volume path, then legacy fallback)."""
    for path in (PACKAGE_INFO_FILE, _LEGACY_PACKAGE_INFO_FILE):
        if os.path.exists(path):
            try:
                with open(path, 'r') as f:
                    return json.load(f)
            except Exception:
                pass
    return None


def _save_package_info(info):
    """Save prepared package info."""
    try:
        os.makedirs(os.path.dirname(PACKAGE_INFO_FILE), exist_ok=True)
        with open(PACKAGE_INFO_FILE, 'w') as f:
            json.dump(info, f, indent=2)
    except Exception as e:
        print(f"[WARN] Failed to save package info: {e}")


def _read_package_manifest(package_path):
    """Read manifest.json from a prepared package to get version info."""
    import tarfile
    try:
        with tarfile.open(package_path, 'r:gz') as tar:
            # Find manifest.json in the archive
            for member in tar.getmembers():
                if member.name.endswith('manifest.json'):
                    f = tar.extractfile(member)
                    if f:
                        return json.load(f)
    except Exception as e:
        print(f"[WARN] Failed to read package manifest: {e}")
    return {}


def _modules_from_track(target: str, opted_in_optional: list):
    """Translate the new ``{target, opted_in_optional}`` request shape
    into the ``{module: version}`` dict the existing prepare/online
    dispatchers consume.

    Returns a 2-tuple ``(modules_dict, warnings)`` — warnings is a list
    of strings the caller should emit into the workflow log AFTER the
    run is created, so the operator sees them in the Workflow UI.
    Today the only warning is the "default credentials" notice, fired
    when ``modules.<name>`` was created from upstream — the upstream
    creds are KNOWN-PUBLIC release defaults (id: tenroot, password:
    123123 in the shipped config.yaml) so the operator MUST change them
    before the new module is exposed.

    Forced rows (modules already installed locally) are ALL included —
    operator can't opt out per principle 1 of the design. Optional rows
    only land in the dict when the operator explicitly ticked them.
    Noop rows (current == target) are dropped to keep the work list
    minimal.

    Side effect — opt-in credential plumbing: when the operator ticks
    an optional module that doesn't yet have a ``modules.<name>`` block
    in their local config.yaml, we splice it in from the upstream
    config.yaml BEFORE dispatching. The install function later reads
    the credentials from the local file as normal.

    Raises :class:`ResolverError` (handled at the route layer) when the
    target is unreachable, rate-limited, or returns garbage.
    """
    from services.upgrade.resolver import compute_plan, fetch_upstream_config
    from services.upgrade.base import set_module_block_in_config

    plan = compute_plan(target, user_action='submit')
    modules: dict = {}
    warnings: list = []
    for row in plan['forced']:
        if row['action'] == 'noop':
            continue
        modules[row['module']] = row['target']

    opted_in_set = set(opted_in_optional or [])
    if opted_in_set:
        # Cache hit ~all the time — compute_plan above already cached
        # this fetch for 30 min. Safe to call again.
        upstream_cfg = fetch_upstream_config(target, user_action='submit')
        upstream_modules = (upstream_cfg.get('modules') or {})
        for row in plan['optional']:
            name = row['module']
            if name not in opted_in_set:
                continue
            modules[name] = row['target']
            # Splice in modules.<name> if local config.yaml is missing
            # it, forcing enabled:true — the operator explicitly opted to
            # add this module, so it must be visible/active rather than
            # inheriting whatever (possibly disabled) default the upstream
            # release ships. No-op if the block already exists (operator's
            # wins). Upstream creds (id/password/...) are preserved.
            block = upstream_modules.get(name)
            if block:
                block = {**block, 'enabled': True}
                wrote = set_module_block_in_config(name, block)
                if wrote:
                    # The upstream block IS the public release default
                    # (whatever TenrootOrg ships in config.yaml). Tell
                    # the operator loud and clear, with the actual
                    # values quoted so they know what to change.
                    cred_summary = ', '.join(
                        f'{k}={v}' for k, v in block.items()
                        if k in ('id', 'password', 'api_id', 'api_password')
                    ) or '(no credential keys)'
                    warnings.append(
                        f"⚠ modules.{name}: created in config.yaml using the "
                        f"RELEASE DEFAULTS ({cred_summary}). CHANGE these in "
                        f"config.yaml before exposing the module to anyone "
                        f"outside this host."
                    )

    return modules, warnings


def _modules_for_prepare(target: str, selected_modules: list) -> dict:
    """Translate the Prepare Package shape ``{target, selected_modules}``
    into the ``{module: version}`` dict the prepare workflow consumes.

    Pure function — does NOT read local machine state. The build-server's
    installed modules are IRRELEVANT to what the operator wants to bundle
    for an air-gap target. See plan: Prepare's semantics are "pick from
    the upstream release's full module list", not "diff against local".

    Cross-references the operator's selected_modules list against the
    upstream release's actual versions block so a typo or stale module
    name in the request doesn't silently slip through — only modules the
    upstream release actually pins land in the result.

    Backend safety net for the intact requirement: a tarball without
    the intact platform itself is useless (every other module needs
    the platform to drive it; air-gap targets need it to receive the
    upgrade). intact is force-added even if the request omitted it
    (UI disables the checkbox, but an external automation might POST
    a list that excludes it).
    """
    from services.upgrade.resolver import list_upstream_modules
    upstream = list_upstream_modules(target, user_action='submit-prepare')
    upstream_map = {row['module']: row['target'] for row in upstream}
    selected_set = set(selected_modules or [])
    selected_set.add('intact')  # ← always bundled, no opt-out
    modules: dict = {}
    for name in selected_set:
        v = upstream_map.get(name)
        if v is not None:
            modules[name] = v
    return modules


@upgrade_bp.route('/api/upgrade/prepare-list', methods=['POST'])
def list_prepare_modules():
    """Operator-triggered (the Prepare modal's "Show Modules" button).

    Body: ``{"target": "<ref>"}`` — the release the operator picked.
    Returns the flat module list for that release, no local-state diff.

    Used by the Prepare Package modal to render its checkbox table.
    Online Upgrade uses ``/api/upgrade/plan`` instead (which DOES read
    local state for the forced/optional split).
    """
    try:
        data = request.json or {}
        target = (data.get('target') or '').strip()
        if not target:
            return jsonify({"success": False, "error": "target required"}), 400

        err = _quota_preflight_or_jsonify(1, "prepare-list (module enumeration)")
        if err: return err

        from services.upgrade.resolver import list_upstream_modules, ResolverError
        try:
            rows = list_upstream_modules(target, user_action='prepare-list')
        except ResolverError as e:
            return jsonify({"success": False, "error": str(e)}), 502
        return jsonify({"success": True, "target": target, "modules": rows})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@upgrade_bp.route('/api/upgrade/peek-manifest', methods=['POST'])
def peek_manifest_from_blob():
    """Extract manifest.json from the FIRST few MB of a tarball blob.

    The operator's browser slices the first ~5 MB of a local file
    (FileReader API) and POSTs the raw bytes here. We decompress
    streaming-style and look for the first ``manifest.json`` entry —
    which lives in the first ~10 KB of any tarball built by the new
    prepare flow (manifest.json is written first via tar --files-from
    so it's at the very start). For older tarballs without that
    ordering, this will fail gracefully and the JS falls back to the
    post-upload review path.

    Body: raw gzip+tar bytes (Content-Type: application/octet-stream).
    Returns: {"success": True, "manifest": {...}} on hit,
             {"success": False, "error": "..."} on miss.
    """
    try:
        blob = request.get_data()
        if not blob:
            return jsonify({"success": False, "error": "empty body"}), 400
        if len(blob) > 25 * 1024 * 1024:
            # 25 MB ceiling — peek is supposed to be the FIRST chunk,
            # not the whole file. Refuse anything larger.
            return jsonify({"success": False, "error": "blob too large for peek"}), 400

        import io as _io
        import tarfile as _tarfile
        # Streaming mode (mode='r|gz') reads entry-by-entry from the
        # bytes object without seeking — perfect for a partial gzip
        # stream that ends mid-entry beyond manifest.json.
        try:
            with _tarfile.open(fileobj=_io.BytesIO(blob), mode='r|gz') as tar:
                for member in tar:
                    if member.name.endswith('manifest.json') and member.isfile():
                        f = tar.extractfile(member)
                        if f is None:
                            continue
                        manifest = json.load(f)
                        return jsonify({
                            "success": True,
                            "manifest": manifest,
                            "versions": manifest.get('versions', {}),
                            "contents": manifest.get('contents', {}),
                            "created": manifest.get('created'),
                        })
        except (EOFError, _tarfile.ReadError):
            # Stream ended before manifest.json was found. Caller
            # should fall back to the post-upload review path.
            pass
        return jsonify({
            "success": False,
            "error": "manifest.json not found in the first chunk (likely an older tarball)",
        }), 200
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@upgrade_bp.route('/api/upgrade/list-packages', methods=['POST'])
def list_pending_packages():
    """Return the inventory of tarballs currently sitting on disk in the
    two allowlisted package dirs (``/data/uploads/`` from operator
    uploads + ``/data/upgrade_packages/`` from the prepare flow).

    Used by the new Apply Uploaded Package card so the operator can see
    what tarballs are available and pick one. POST (not GET) to match
    the other upgrade endpoints' convention and signal "operator
    action, not page chatter".
    """
    try:
        import os as _os
        out = []
        for prefix in ALLOWED_PACKAGE_DIRS:
            if not _os.path.isdir(prefix):
                continue
            try:
                names = _os.listdir(prefix)
            except OSError:
                continue
            for name in sorted(names):
                # tarballs only — silently skip anything else (the
                # upload + prepare flows can leave .info files and
                # subdirectories around that aren't applicable).
                if not (name.endswith('.tar.gz') or name.endswith('.tgz')):
                    continue
                full = _os.path.join(prefix, name)
                try:
                    st = _os.stat(full)
                except OSError:
                    continue
                out.append({
                    'path': full,
                    'name': name,
                    'size_bytes': st.st_size,
                    'mtime': st.st_mtime,
                    'source': 'uploads' if prefix == '/data/uploads/' else 'prepare',
                })
        # Newest first — operators usually want the latest tarball
        out.sort(key=lambda r: r['mtime'], reverse=True)
        return jsonify({"success": True, "packages": out})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


def _quota_preflight_or_jsonify(needed: int, action: str):
    """Pre-flight GitHub quota check used by every github-touching route.

    Returns either (None, None) on pass-through OR (jsonify_response,
    status_code) when the quota is too low. Routes call:

        err = _quota_preflight_or_jsonify(N, "refs fetch")
        if err: return err

    Fail-open: if the rate_limit endpoint itself is unreachable,
    `check_quota_or_raise` logs a warning and returns silently — we
    never block on the check failing.
    """
    from services.upgrade.resolver import check_quota_or_raise, ResolverQuotaError
    try:
        check_quota_or_raise(needed, action)
        return None
    except ResolverQuotaError as e:
        return (jsonify({"success": False, "error": str(e)}), 429)


def _quota_audit_lines(needed: int) -> list:
    """Build the multi-line quota audit + setup-hint emission for the
    workflow log. Returns a list of strings the caller pushes via
    add_log_to_run (one per line) so each lands as its own row in the
    Workflows tab.

    Always emits:
      1. The "needs N / have N/60 remaining" line.
      2. A short setup-hint when NOT authed (no GITHUB_TOKEN set) OR
         when needed > 0 AND quota is uncomfortably low (<= 2 × needed).
         Operators with a token already in place don't see the hint —
         they already know.

    Mirrors the format that `check_quota_or_raise` prints to stdout so
    the wording is consistent between `docker logs intact_backend` AND
    the workflow log tab in the UI.
    """
    from services.upgrade.resolver import get_github_rate_limit
    state = get_github_rate_limit()

    if state is None:
        return [
            "[GH-QUOTA] rate-limit endpoint unreachable; "
            "proceeding without pre-flight check",
        ]

    lines = []
    remaining = state['remaining']
    limit = state['limit'] or 60
    reset_hm = state['reset_hm']
    authed = state['authed']

    # Line 1: state.
    if needed == 0:
        lines.append(
            f"[GH-QUOTA] needs 0 GitHub calls (offline-only); "
            f"current quota: {remaining}/{limit} remaining "
            f"(resets {reset_hm}{' — authed' if authed else ''})"
        )
    else:
        ratio_label = '' if authed else ' — anonymous IP, low cap'
        lines.append(
            f"[GH-QUOTA] needs {needed} GitHub calls; "
            f"have {remaining}/{limit} remaining "
            f"(resets {reset_hm}{ratio_label})"
        )

    # Line 2: setup hint. Only when no token — if they already have
    # one, the 60→5000 jump has happened and the hint is noise.
    if not authed:
        lines.append(
            "[GH-QUOTA-SETUP] To raise cap 60 → 5000/hr:  "
            "echo 'GITHUB_TOKEN=ghp_YOUR_TOKEN' | sudo tee -a "
            "/home/tenroot/intact/modules/backend/.env  &&  "
            "docker restart intact_backend  "
            "(token: github.com/settings/tokens → Generate new (classic), "
            "no scopes needed)"
        )
    return lines


@upgrade_bp.route('/api/upgrade/current-versions', methods=['GET'])
def get_upgrade_current_versions():
    """Return the current installed version of every module + intact.

    Feeds the "current → target" comparison in the Apply Uploaded
    Package modal (and any other UI that needs to show "what would
    this package change"). Same data source the offline upgrade flow
    itself uses, so the UI shows exactly what the apply will see.

    Response:
        {
          "success": true,
          "versions": {
             "intact":       "intact-20260615",
             "elk":          "9.3.3",
             "timesketch":   "20260326",   # or "Not installed"
             ...
          }
        }
    """
    out = {}
    # intact's own version comes from the VERSION file, not from a .env
    workdir = os.environ.get('INTACT_PATH', '/app/workdir')
    try:
        with open(os.path.join(workdir, 'VERSION')) as f:
            v = f.read().strip()
        out['intact'] = v or 'unknown'
    except Exception:
        out['intact'] = 'unknown'

    try:
        from services.upgrade.base import get_current_versions
        modules = get_current_versions() or {}
        for name, info in modules.items():
            cur = (info or {}).get('current')
            out[name] = cur if cur else 'unknown'
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

    return jsonify({"success": True, "versions": out})


@upgrade_bp.route('/api/upgrade/quota', methods=['GET'])
def get_upgrade_quota():
    """Returns the current GitHub rate-limit state for the UI to surface
    BEFORE the operator triggers a quota-spending call. Cheap (cached
    in-process); no GitHub round-trip on most invocations.

    Response shape:
        {
          "success": true,
          "remaining": int,     // calls left in the current window
          "limit":     int,     // window cap (60 anon / 5000 authed)
          "reset_hm":  str,     // "14:23" — when the window resets
          "authed":    bool,    // GITHUB_TOKEN present?
        }
    On rate_limit endpoint failure: success=false (UI proceeds without
    a quota gate — mirrors the server's fail-open posture).
    """
    from services.upgrade.resolver import get_github_rate_limit
    state = get_github_rate_limit()
    if state is None:
        return jsonify({"success": False, "error": "rate-limit endpoint unreachable"}), 200
    return jsonify({
        "success": True,
        "remaining": state['remaining'],
        "limit":     state['limit'] or 60,
        "reset_hm":  state['reset_hm'],
        "authed":    state['authed'],
    })


@upgrade_bp.route('/api/upgrade/refs', methods=['POST'])
def list_upgrade_refs():
    """Operator-triggered (Fetch button). Returns the release/branch list.

    POST not GET on purpose: the call hits the GitHub API, costs anonymous
    rate-limit budget, and MUST stay behind an explicit operator action
    (not page-load chatter). Returns cached results within the 30-minute
    TTL — so a double-click only spends one GitHub call.
    """
    err = _quota_preflight_or_jsonify(1, "refs fetch")
    if err: return err
    try:
        from services.upgrade.resolver import list_github_refs, ResolverError
        try:
            refs = list_github_refs(user_action='fetch')
        except ResolverError as e:
            return jsonify({"success": False, "error": str(e)}), 502
        return jsonify({"success": True, "refs": refs})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@upgrade_bp.route('/api/upgrade/plan', methods=['POST'])
def compute_upgrade_plan():
    """Operator-triggered (Compute Plan button). Returns the work plan.

    Body: ``{"target": "<ref>"}`` where ref is one of the names returned
    by ``/api/upgrade/refs`` (a release tag like ``v1.4.2`` or the
    synthetic ``development``).

    Response (see :func:`services.upgrade.resolver.compute_plan`):
        {
          current_intact_version: ...,
          target: ...,
          chain: [ref, ref, ...],
          forced:   [{module, current, target, action}, ...],
          optional: [{module, current, target, action}, ...],
        }
    """
    try:
        data = request.json or {}
        target = (data.get('target') or '').strip()
        if not target:
            return jsonify({"success": False, "error": "target required"}), 400

        err = _quota_preflight_or_jsonify(1, "plan compute")
        if err: return err

        from services.upgrade.resolver import compute_plan, ResolverError
        try:
            plan = compute_plan(target, user_action='plan')
        except ResolverError as e:
            return jsonify({"success": False, "error": str(e)}), 502
        return jsonify({"success": True, "plan": plan})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@upgrade_bp.route('/api/upgrade/status', methods=['GET'])
def get_upgrade_status():
    """Get latest versions for all modules (used by Prepare Package modal)."""
    try:
        from services.upgrade import get_latest_versions

        latest = get_latest_versions()

        versions = {}
        for module in ['elk', 'timesketch', 'plaso', 'iris', 'velociraptor', 'prowler', 'o365rc', 'volweb', 'intact']:
            versions[module] = {
                'latest': latest.get(module, 'unknown')
            }

        return jsonify({
            "success": True,
            "versions": versions
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 200  # Return 200 so frontend can use fallbacks


@upgrade_bp.route('/api/upgrade/package-info', methods=['POST'])
def get_upgrade_package_info():
    """Get manifest info from an uploaded upgrade package.

    Body: { "package_path": "/data/uploads/..." }
    """
    try:
        data = request.json
        if not data:
            return jsonify({"error": "No data provided"}), 400

        package_path = data.get('package_path')
        if not package_path:
            return jsonify({"error": "No package_path provided"}), 400

        err = _reject_package_path(package_path)
        if err:
            return err

        from services.upgrade import get_package_info
        result = get_package_info(package_path)

        return jsonify(result)

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@upgrade_bp.route('/api/upgrade/offline', methods=['POST'])
def start_offline_upgrade():
    """Start offline upgrade from an uploaded package.

    Body: {
        "package_path": "/data/uploads/...",
        "db_overwrite": {"timesketch": true, "iris": false},  // optional: fresh install per module
        "selected_modules": ["elk", "velociraptor"]  // optional: only apply these modules from the tarball
    }

    ``selected_modules`` is the new Apply Uploaded Package shape — when
    present, the workflow loop skips every module in the manifest that
    isn't in this list. When omitted, the workflow applies everything
    in the manifest (legacy behavior, preserves any external automation).
    """
    try:
        data = request.json
        if not data:
            return jsonify({"error": "No data provided"}), 400

        package_path = data.get('package_path')
        db_overwrite = data.get('db_overwrite', {})  # Per-module fresh install flags
        selected_modules = data.get('selected_modules')  # None = no filter (apply all)

        if not package_path:
            return jsonify({"error": "No package_path provided"}), 400

        err = _reject_package_path(package_path)
        if err:
            return err

        if not os.path.exists(package_path):
            return jsonify({"error": f"Package not found: {package_path}"}), 400

        # Continue the UPLOAD's workflow when this package came from a TUS
        # upload — its run_id was persisted in a `<package>.run` sidecar by
        # the upload hook. Reusing it keeps the import (upload) and the apply
        # in ONE workflow/log instead of two. Prepare-built packages
        # (/data/upgrade_packages/) have no sidecar and get a fresh run.
        run_id = None
        sidecar = f"{package_path}.run"
        if os.path.exists(sidecar):
            try:
                with open(sidecar) as _rf:
                    candidate = (_rf.read() or "").strip()
                from services.file_storage_service import get_workflow as _get_wf
                if candidate and _get_wf(candidate):
                    run_id = candidate
            except Exception:
                run_id = None

        if run_id:
            # Consume the sidecar so a later RE-apply of the same package gets
            # its own run (honest audit trail) instead of re-opening this one.
            try:
                os.remove(sidecar)
            except Exception:
                pass
            add_log_to_run(run_id, "─" * 40, "info")
            add_log_to_run(run_id, "Applying uploaded package — continuing this workflow.", "info")
        else:
            run_id = create_automation_run(
                automation_type="upgrade",
                name="System Upgrade (Offline)",
                details={
                    "trigger": "manual",
                    "mode": "offline",
                    "package_path": package_path
                }
            )
            add_log_to_run(run_id, "Starting offline upgrade from package", "info")
        add_log_to_run(run_id, f"Package: {package_path}", "info")
        for line in _quota_audit_lines(0):
            add_log_to_run(run_id, line, "info")
        update_run_status(run_id, "running", progress=5)

        from services.workflow_service import register_cancel_event, unregister_cancel
        cancel_event = register_cancel_event(run_id)

        # Track completed modules for progress
        completed_modules = [0]

        # Run upgrade in background
        def run_offline_upgrade():
            try:
                from services.upgrade import (run_offline_upgrade_workflow,
                                              sweep_stale_upgrade_staging)

                def logger(msg, level="info"):
                    add_log_to_run(run_id, msg, level)

                    # Track progress based on module completion messages
                    if level == "success" and " upgrade completed" in msg:
                        first_word = msg.split()[0] if msg else ""
                        if first_word.isupper() and first_word in ["ELK", "TIMESKETCH", "PLASO", "IRIS", "VELOCIRAPTOR", "AWS", "AZURE", "Intact.AI"]:
                            completed_modules[0] += 1
                            # Estimate 6 modules max, progress from 5% to 95%
                            progress = 5 + min(completed_modules[0] * 15, 90)
                            update_run_status(run_id, "running", progress=progress)

                # Reclaim any orphaned staging from a prior run that died before
                # Phase 2's cleanup (crash / failed resume / killed by the restart).
                sweep_stale_upgrade_staging(logger=logger)

                result = run_offline_upgrade_workflow(
                    package_path, run_id=run_id, logger=logger,
                    db_overwrite=db_overwrite,
                    selected_modules=selected_modules,
                )

                # Handle two-phase upgrade (backend restart pending)
                if result.get('phase') == 'awaiting_restart':
                    add_log_to_run(run_id, "Phase 1 complete. Backend restarting. Phase 2 will resume automatically.", "info")
                    update_run_status(run_id, "running", progress=50)
                    # Don't mark complete - Phase 2 will continue after restart
                elif result.get('success'):
                    add_log_to_run(run_id, f"Offline upgrade completed: {result.get('completed', 0)}/{result.get('total', 0)} modules", "success")
                    update_run_status(run_id, "completed", progress=100)
                else:
                    failed = [m for m, r in result.get('results', {}).items() if not r.get('success')]
                    if failed:
                        add_log_to_run(run_id, f"Offline upgrade completed with failures: {', '.join(failed)}", "warning")
                    update_run_status(run_id, "completed", progress=100)

            except Exception as e:
                add_log_to_run(run_id, f"Offline upgrade failed: {str(e)}", "error")
                update_run_status(run_id, "failed", progress=0, error=str(e))
                import traceback
                traceback.print_exc()
            finally:
                unregister_cancel(run_id)

        # Start background thread
        thread = threading.Thread(target=run_offline_upgrade, daemon=True)
        thread.start()

        return jsonify({
            "success": True,
            "run_id": run_id,
            "message": "Offline upgrade started"
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@upgrade_bp.route('/api/upgrade/prepare', methods=['POST'])
def prepare_upgrade_package():
    """Prepare an upgrade package for offline/air-gapped transfer.

    Two request shapes are accepted:

    1. NEW track-based shape::

           {"target": "<ref>", "selected_modules": ["elk", "velociraptor", ...]}

       The build-server's installed state is IRRELEVANT to what gets
       bundled — the operator chose a release + a subset of that
       release's modules. We pull versions straight from upstream.

    2. LEGACY SHAPE A (online-style — diff against local state)::

           {"target": "<ref>", "opted_in_optional": ["prowler", ...]}

       Backed by :func:`_modules_from_track`. Was the original Prepare
       behavior but it leaked local state into the bundle decision —
       wrong for air-gap. Kept for any external automation that still
       posts this shape.

    3. LEGACY SHAPE B (explicit dict)::

           {"modules": {"elk": "9.3.1", "velociraptor": "0.75.6", ...}}
    """
    try:
        data = request.json
        if not data:
            return jsonify({"error": "No data provided"}), 400

        # Pre-flight: prepare hits api.github.com a few times (intact
        # branches API + maybe DetectRaptor /latest/ redirect). Refuse
        # early if quota is too low instead of failing mid-run.
        err = _quota_preflight_or_jsonify(2, "prepare package")
        if err: return err

        target = (data.get('target') or '').strip()
        track_warnings: list = []
        selected_modules = data.get('selected_modules')
        if target and selected_modules is not None:
            # New shape: explicit module subset against the picked
            # release's upstream versions. Pure — no local-state read.
            from services.upgrade.resolver import ResolverError
            try:
                modules = _modules_for_prepare(target, selected_modules)
            except ResolverError as e:
                return jsonify({"error": str(e)}), 502
        elif target:
            # Legacy track-flow shape (local-state-aware). Backed by
            # _modules_from_track which reads `current_versions`.
            from services.upgrade.resolver import ResolverError
            try:
                modules, track_warnings = _modules_from_track(
                    target, data.get('opted_in_optional') or []
                )
            except ResolverError as e:
                return jsonify({"error": str(e)}), 502
        else:
            modules = data.get('modules', {})

        if not modules:
            return jsonify({"error": "No modules selected for package"}), 400

        # NOTE: no downgrade check here on purpose. The prepare-side
        # machine is often DIFFERENT from the target — a build server
        # at 0.76.5 may legitimately prepare a 0.75.6 package destined
        # for a customer who's still on 0.74.0. The downgrade guard
        # lives in services/upgrade/velociraptor.py where it checks
        # the TARGET's .env at apply time, which is the only point
        # where "current vs requested" has a meaningful answer.

        # Create workflow run
        run_id = create_automation_run(
            automation_type="prepare_package",
            name="Prepare Upgrade Package",
            details={
                "trigger": "manual",
                "modules": modules
            }
        )
        add_log_to_run(run_id, "Starting package preparation", "info")
        add_log_to_run(run_id, f"Modules: {', '.join(modules.keys())}", "info")
        for line in _quota_audit_lines(2):
            add_log_to_run(run_id, line, "info")
        for w in track_warnings:
            add_log_to_run(run_id, w, "warning")
        update_run_status(run_id, "running", progress=5)

        # Calculate total steps for progress tracking
        # Each module has different number of operations:
        # - ELK: 3 images (elasticsearch, kibana, logstash)
        # - Timesketch: 1 image
        # - Plaso: 1 image
        # - IRIS: 2 images (app, nginx)
        # - Velociraptor: 1 binary download
        # - Prowler (AWS posture): 1 image
        # - DFIR-O365RC (Microsoft 365 UAL): 1 image
        # - Intact.AI: 2 source copies (backend, frontend)
        # Plus: manifest (1) + archive (1)
        steps_per_module = {
            'elk': 3,
            'timesketch': 1,
            'plaso': 1,
            'iris': 2,
            'velociraptor': 1,
            'prowler': 1,
            'o365rc': 1,
            'intact': 2
        }
        total_steps = sum(steps_per_module.get(m, 1) for m in modules.keys()) + 2  # +2 for manifest and archive
        completed_steps = [0]

        from services.workflow_service import register_cancel_event, unregister_cancel
        cancel_event_prep = register_cancel_event(run_id)

        # Run package preparation in background
        def run_prepare():
            try:
                from services.upgrade.package import prepare_upgrade_package as do_prepare
                from services.connectivity import require_internet
                if not require_internet(run_id, "Prepare upgrade package"):
                    return

                def logger(msg, level="info"):
                    add_log_to_run(run_id, msg, level)

                    # Track progress based on completion messages
                    if level == "success":
                        # Image saved or binary downloaded
                        if msg.strip().startswith("Done (") or msg.strip().startswith("Downloaded ("):
                            completed_steps[0] += 1
                        # Intact.AI source copies
                        elif "source copied" in msg:
                            completed_steps[0] += 1
                        # Manifest created
                        elif "Created manifest.json" in msg:
                            completed_steps[0] += 1
                        # Package archive created
                        elif "Package created:" in msg:
                            completed_steps[0] += 1

                        # Calculate progress (5% start, 95% for work, 100% at end)
                        progress = 5 + int((completed_steps[0] / total_steps) * 90)
                        update_run_status(run_id, "running", progress=min(progress, 95))

                result = do_prepare(modules, run_id, logger)

                if result.get('success'):
                    # Store package info (only one package at a time, overwrites previous)
                    _save_package_info({
                        'run_id': run_id,
                        'path': result['package_path'],
                        'name': result['package_name'],
                        'size': result['package_size'],
                        'created_at': time.time()
                    })
                    add_log_to_run(run_id, f"Package ready for download: {result['package_name']}", "success")
                    add_log_to_run(run_id, "Note: Preparing a new package will replace this one", "info")
                    update_run_status(run_id, "completed", progress=100)
                else:
                    add_log_to_run(run_id, f"Package preparation failed: {result.get('error', 'Unknown error')}", "error")
                    update_run_status(run_id, "failed", progress=0, error=result.get('error'))

            except Exception as e:
                # If the user clicked Stop, the killed subprocess raised
                # on its way out — that's not a real failure. Let the
                # 'cancelled' state (already set by request_stop()) stand.
                from services.workflow_service import is_cancelled, get_automation_run
                wf = get_automation_run(run_id) or {}
                if is_cancelled(run_id) or wf.get('status') == 'cancelled':
                    return
                add_log_to_run(run_id, f"Package preparation failed: {str(e)}", "error")
                update_run_status(run_id, "failed", progress=0, error=str(e))
                import traceback
                traceback.print_exc()
            finally:
                unregister_cancel(run_id)

        # Start background thread
        thread = threading.Thread(target=run_prepare, daemon=True)
        thread.start()

        return jsonify({
            "success": True,
            "run_id": run_id,
            "message": f"Package preparation started for {len(modules)} module(s)"
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@upgrade_bp.route('/api/upgrade/online', methods=['POST'])
def start_online_upgrade():
    """Combined prepare + apply in one workflow — no intermediate tar.gz.

    Same dual-shape body as ``/api/upgrade/prepare``:

    1. NEW track-based shape::

           {"target": "<ref>", "opted_in_optional": [...]}

    2. LEGACY explicit shape (still supported)::

           {"modules": {"elk": "9.3.1", "intact": "development", ...}}

    For internet-connected machines. Visible in the same Workflows
    tab as prepare-package and offline-apply.
    """
    try:
        data = request.json
        if not data:
            return jsonify({"error": "No data provided"}), 400

        # Pre-flight: online upgrade prepares + applies in one run, so
        # it hits all the same github endpoints as prepare. Same quota
        # cost — refuse early instead of mid-run.
        err = _quota_preflight_or_jsonify(2, "online upgrade")
        if err: return err

        target = (data.get('target') or '').strip()
        track_warnings: list = []
        if target:
            from services.upgrade.resolver import ResolverError
            try:
                modules, track_warnings = _modules_from_track(
                    target, data.get('opted_in_optional') or []
                )
            except ResolverError as e:
                return jsonify({"error": str(e)}), 502
        else:
            modules = data.get('modules', {})

        if not modules:
            return jsonify({"error": "No modules selected for online upgrade"}), 400

        db_overwrite = data.get('db_overwrite') or {}

        run_id = create_automation_run(
            automation_type="online_upgrade",
            name="Online Upgrade",
            details={
                "trigger": "manual",
                "modules": modules,
                "db_overwrite": db_overwrite,
            },
        )
        add_log_to_run(run_id, "Starting online upgrade (prepare + apply in one run)", "info")
        add_log_to_run(run_id, f"Modules: {', '.join(modules.keys())}", "info")
        for line in _quota_audit_lines(2):
            add_log_to_run(run_id, line, "info")
        for w in track_warnings:
            add_log_to_run(run_id, w, "warning")
        update_run_status(run_id, "running", progress=2)

        # Progress estimation: split the visible 2-95% band between
        # prepare-side image saves + apply-side per-module completions.
        steps_per_module_prepare = {
            'elk': 3, 'timesketch': 1, 'plaso': 1, 'iris': 2,
            'velociraptor': 1, 'prowler': 1, 'o365rc': 1,
            'volweb': 2, 'intact': 2,
        }
        prepare_steps_total = sum(steps_per_module_prepare.get(m, 1) for m in modules) + 1
        apply_steps_total = len(modules)
        total_steps = max(prepare_steps_total + apply_steps_total, 1)
        completed_steps = [0]

        def bump_progress_from_log(msg, level):
            if level == "success":
                if msg.strip().startswith("Done (") or msg.strip().startswith("Downloaded ("):
                    completed_steps[0] += 1
                elif "source copied" in msg:
                    completed_steps[0] += 1
                elif "Created manifest.json" in msg:
                    completed_steps[0] += 1
                elif "upgrade completed" in msg:
                    completed_steps[0] += 1
            elif level == "error" and msg.startswith("MODULE_FAILED:"):
                completed_steps[0] += 1
            progress = 2 + int((completed_steps[0] / total_steps) * 93)
            update_run_status(run_id, "running", progress=min(progress, 95))

        from services.workflow_service import register_cancel_event, unregister_cancel
        register_cancel_event(run_id)

        def run_online():
            try:
                from services.upgrade import (run_online_upgrade_workflow,
                                              sweep_stale_upgrade_staging)
                from services.connectivity import require_internet
                if not require_internet(run_id, "Online upgrade"):
                    return

                def logger(msg, level="info"):
                    add_log_to_run(run_id, msg, level)
                    try:
                        bump_progress_from_log(msg, level)
                    except Exception:
                        pass

                # Reclaim orphaned staging from any prior run before we build a new one.
                sweep_stale_upgrade_staging(logger=logger)

                result = run_online_upgrade_workflow(
                    modules=modules,
                    run_id=run_id,
                    logger=logger,
                    db_overwrite=db_overwrite,
                )

                if result.get('phase') == 'awaiting_restart':
                    add_log_to_run(run_id, "Phase 1 complete. Backend restarting to resume Phase 2.", "info")
                    return

                if result.get('success'):
                    update_run_status(run_id, "completed", progress=100)
                else:
                    from services.workflow_service import get_automation_run
                    wf = get_automation_run(run_id) or {}
                    if wf.get('status') in ('running', None):
                        update_run_status(run_id, "failed", progress=0,
                                          error=result.get('error', 'unknown'))

            except Exception as e:
                from services.workflow_service import is_cancelled, get_automation_run
                wf = get_automation_run(run_id) or {}
                if is_cancelled(run_id) or wf.get('status') == 'cancelled':
                    return
                add_log_to_run(run_id, f"Online upgrade failed: {str(e)}", "error")
                import traceback
                add_log_to_run(run_id, f"Traceback: {traceback.format_exc()[:800]}", "error")
                update_run_status(run_id, "failed", progress=0, error=str(e))
                traceback.print_exc()
            finally:
                unregister_cancel(run_id)

        thread = threading.Thread(target=run_online, daemon=True)
        thread.start()

        return jsonify({
            "success": True,
            "run_id": run_id,
            "message": f"Online upgrade started for {len(modules)} module(s)",
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@upgrade_bp.route('/api/upgrade/prepare/<run_id>/status', methods=['GET'])
def get_prepare_status(run_id):
    """Check if a prepared package is ready for download."""
    try:
        pkg = _get_package_info()

        # Check if package exists and matches this run_id
        if pkg and pkg.get('run_id') == run_id and os.path.exists(pkg.get('path', '')):
            # Read manifest to get versions for user confirmation
            manifest = _read_package_manifest(pkg['path'])
            return jsonify({
                "success": True,
                "ready": True,
                "package_name": pkg['name'],
                "package_size": pkg['size'],
                "versions": manifest.get('versions', {})
            })
        else:
            # Only ONE prepared package exists at a time (fixed filename — each
            # prepare overwrites the last). So an older prepare workflow's package
            # is gone once a newer prepare ran. Tell the operator which newer
            # workflow superseded it + both ways forward.
            newer = (pkg or {}).get('run_id')
            if newer and newer != run_id:
                msg = ("This upgrade package was overwritten by a newer preparation "
                       f"(workflow {newer}). Re-create the package from this workflow, "
                       "or use the newer workflow instead.")
            else:
                msg = ("The prepared package is no longer available on the server. "
                       "Re-create it from this workflow.")
            return jsonify({
                "success": True,
                "ready": False,
                "superseded_by": newer,
                "message": msg,
            })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@upgrade_bp.route('/api/upgrade/prepare/<run_id>/download', methods=['GET'])
def download_prepared_package(run_id):
    """Download a prepared upgrade package."""
    try:
        pkg = _get_package_info()

        # Check if package exists and matches this run_id. Only the LAST prepared
        # package is kept (fixed filename), so an older workflow's package is gone
        # once a newer prepare ran — point the operator to the newer workflow.
        if not pkg or pkg.get('run_id') != run_id:
            newer = (pkg or {}).get('run_id')
            if newer and newer != run_id:
                err = (f"This upgrade package was overwritten by a newer preparation "
                       f"(workflow {newer}). Re-create the package from this workflow, "
                       f"or use the newer workflow instead.")
            else:
                err = ("The prepared package is no longer available on the server. "
                       "Please prepare it again.")
            return jsonify({"error": err, "superseded_by": (pkg or {}).get('run_id')}), 410

        package_path = pkg['path']
        package_name = pkg['name']

        if not os.path.exists(package_path):
            return jsonify({"error": "Package file not found on server"}), 404

        return send_file(
            package_path,
            as_attachment=True,
            download_name=package_name,
            mimetype='application/gzip'
        )

    except Exception as e:
        return jsonify({"error": str(e)}), 500
