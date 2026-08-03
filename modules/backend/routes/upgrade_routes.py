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

# Closes the check→create TOCTOU on a double-click: the DB-based
# check_upgrade_lock is the real (restart-surviving) lock, but two
# simultaneous requests could both pass it before either creates its run.
# Callers hold this across gate + create_automation_run.
_UPGRADE_START_MUTEX = threading.Lock()


def _upgrade_gate(force: bool = False):
    """Single-writer gate for upgrade/prepare entry routes.

    Returns None when clear to start, else a (jsonify, 409) response naming
    the blocking run. Caller must hold _UPGRADE_START_MUTEX across this call
    AND its create_automation_run so a concurrent request can't slip between.
    """
    try:
        from services.upgrade import check_upgrade_lock
        gate = check_upgrade_lock(force=force)
        if gate.get("ok"):
            return None
        return jsonify({
            "error": gate.get("reason", "An upgrade is already in progress"),
            "blocking_run_id": gate.get("blocking_run_id"),
            "stale": gate.get("stale", False),
        }), 409
    except Exception as e:
        # Never brick the upgrade button on a gate bug — fail open, log.
        print(f"[UPGRADE] gate check errored ({e}); allowing", flush=True)
        return None


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


def _modules_from_track(target: str, opted_in_optional: list,
                        opted_in_reinstall: list = None):
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

    from services.upgrade import LEGACY_MODULE_ALIASES
    plan = compute_plan(target, user_action='submit')
    modules: dict = {}
    warnings: list = []
    # Unchanged ("noop") modules the operator explicitly ticked to force a
    # reinstall (bug-recovery — reinstall a module that's already at the target
    # version). Excluded by default; only these get re-added below.
    reinstall_set = {LEGACY_MODULE_ALIASES.get(m, m) for m in (opted_in_reinstall or [])}
    for row in plan['forced']:
        if row['action'] == 'noop':
            if row['module'] in reinstall_set:
                modules[row['module']] = row['target']
            continue
        modules[row['module']] = row['target']

    opted_in_set = {LEGACY_MODULE_ALIASES.get(m, m) for m in (opted_in_optional or [])}
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


def _close_orphan_upload_run(package_path: str) -> None:
    """Close an upload run for ``package_path`` that is still `running`.

    The tus hook leaves the upload's run open (progress=10) on purpose, because
    the apply is meant to adopt it via the `<package>.run` sidecar and continue
    it as ONE workflow. When adoption doesn't happen the row is orphaned: it
    reports `running` indefinitely until cleanup_orphan_workflows reaps it, so
    the UI shows a stalled-looking upload beside a perfectly healthy upgrade.

    Adoption legitimately fails in two cases, and both leave the same wreckage:
      * re-applying a package whose sidecar the FIRST apply consumed
        (consume-once is deliberate — a second apply deserves its own run);
      * an apply that raced the post-finish hook.

    Best-effort and never raises: failing to tidy a status row must not block
    an upgrade.
    """
    try:
        # tus stores the package at /data/uploads/<upload_id>, and the upload
        # run records that id in details.upload_id — so the basename IS the key.
        # (details has no package_path: the row is created before tus assigns a
        # path, carrying only filename/purpose/size. Matching on package_path
        # would silently never fire.) _resolve_upload_run also recovers the
        # mapping from storage when the in-memory map was lost to a restart.
        upload_id = os.path.basename(package_path or '')
        if not upload_id:
            return
        from routes.upload_routes import _resolve_upload_run
        from services.file_storage_service import get_workflow
        rid = _resolve_upload_run(upload_id)
        if not rid:
            return
        wf = get_workflow(rid) or {}
        # Anything not already finished is fair game. Gating on == 'running'
        # missed the real case: the apply can arrive in the few milliseconds
        # before the tus post-finish hook flips the row to running/10%, so this
        # saw a still-`pending` row, returned, and the hook then set `running`
        # on a row nothing would ever close again (observed 2026-07-23: apply
        # at .849, hook at .843).
        if wf.get('status') in ('completed', 'failed', 'cancelled'):
            return          # already closed — nothing to tidy
        add_log_to_run(rid, "Upload complete. This package was applied in a "
                            "separate workflow — closing this row so it does "
                            "not read as still-running.", "info")
        update_run_status(rid, "completed", progress=100)
    except Exception as e:                                    # pragma: no cover
        print(f"[UPGRADE] could not close orphan upload run for "
              f"{package_path}: {e}", flush=True)


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
    # Everything — including intact, whose version now falls back
    # VERSION-file -> BACKEND_VERSION (.env) -> container image tag -> 'unknown'
    # — comes from get_current_versions() so the modal shows exactly what the
    # apply will compare against (and never a bare "?" for a box that's actually
    # installed, incl. older releases with an empty/gitignored VERSION file).
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
    # force=true is the operator explicitly asking GitHub again (opening the
    # modal, or the refresh button). Costs 2 calls: /releases plus
    # /releases/latest for the (latest) badge.
    force = bool((request.get_json(silent=True) or {}).get('force'))

    # Distinguish "no internet" from "GitHub said no" BEFORE spending the
    # quota preflight — offline is the common case on an air-gapped or
    # firewalled box, and "rate limit" or a bare socket error reads as a
    # product fault rather than a missing link. Only probe on a forced
    # fetch; a cached answer is still perfectly serviceable offline.
    if force:
        try:
            from services.connectivity import has_internet
            if not has_internet():
                return jsonify({
                    "success": False,
                    "offline": True,
                    "error": "No internet connection — cannot reach GitHub to "
                             "list releases. Showing nothing rather than a "
                             "stale list; reconnect and press refresh.",
                }), 503
        except Exception:
            pass          # probe itself failed — fall through and let the real call decide

    from services.upgrade.resolver import (
        list_github_refs, ResolverError, _cache_get_stale)

    def _stale_or(err_msg, status):
        """Serve the last known list rather than an empty dropdown.

        Every failure below -- quota exhausted, GitHub unreachable, a 5xx that
        survived the retries -- used to return nothing, so the operator saw an
        empty picker with no way forward. Releases are cut weekly at most, so a
        list from an hour ago is very nearly as good as a live one and is
        enormously better than none. Marked `stale` with its age so the UI says
        where it came from instead of implying it is current.
        """
        cached, age = _cache_get_stale('refs')
        if cached and any(i.get('kind') == 'tag' for i in cached):
            return jsonify({
                "success": True, "refs": cached, "stale": True,
                "stale_age_s": age, "error": err_msg,
            }), 200
        return jsonify({"success": False, "error": err_msg}), status

    err = _quota_preflight_or_jsonify(2 if force else 1, "refs fetch")
    if err:
        # The quota gate is the single most common reason this comes back
        # empty: 2 calls per modal open against an anonymous 60/hr cap.
        return _stale_or(
            "GitHub API quota is spent, so the release list could not be "
            "refreshed. It resets within the hour; setting GITHUB_TOKEN in "
            "modules/backend/.env raises the cap from 60/hr to 5000/hr.", 429)
    try:
        try:
            refs = list_github_refs(user_action='fetch', force=force)
        except ResolverError as e:
            return _stale_or(str(e), 502)

        # An empty list is a real answer, but a useless one on its own. Say
        # WHICH empty it is: GitHub had no releases at all, or it had releases
        # and none of them carries a package asset yet because CI is still
        # building. The second is the common case right after a tag is pushed,
        # and looks identical to a broken dialog without this.
        if not any(r.get('kind') == 'tag' for r in refs):
            return _stale_or(
                "GitHub returned no installable releases. A release only "
                "appears once CI has attached its upgrade package, which takes "
                "a few minutes after the tag is pushed.", 200)

        return jsonify({"success": True, "refs": refs})
    except Exception as e:
        return _stale_or(f"Unexpected error listing releases: {e}", 500)


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

        err = _quota_preflight_or_jsonify(2, "plan compute")
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
        for module in ['elk', 'timesketch', 'plaso', 'iris', 'velociraptor', 'aws_sigma', 'o365rc', 'volweb', 'intact', 'portainer']:
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


@upgrade_bp.route('/api/upgrade/upload-run', methods=['POST'])
def create_upgrade_upload_run():
    """Pre-create the UPGRADE_PACKAGE_UPLOAD workflow row so the UI shows it the
    instant the operator clicks Apply — instead of waiting for tusd's post-create
    hook. The browser passes the returned run_id back in the tus upload metadata
    as `upload_run_id`; the hook reuses it (see routes/upload_routes.py) rather
    than opening a second run. As an `upgrade_package_upload` type it is forced to
    the System workspace (services/workflow_service.SYSTEM_TYPES), the SAME place
    the apply lands, so the whole import is one row in one workspace."""
    try:
        data = request.get_json(silent=True) or {}
        filename = (data.get('filename') or 'upgrade package').strip()
        size_bytes = int(data.get('size_bytes') or 0)
        size_mb = size_bytes / (1024 * 1024) if size_bytes else 0
        run_id = create_automation_run(
            'upgrade_package_upload',
            f"Upload: {filename}",
            {
                "filename": filename,
                "purpose": "upgrade_package",
                "size_bytes": size_bytes,
                "size_mb": round(size_mb, 2),
            },
        )
        add_log_to_run(run_id, f"Preparing upload: {filename} ({size_mb:.1f} MB)")
        update_run_status(run_id, "running", progress=0)
        return jsonify({"success": True, "run_id": run_id})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@upgrade_bp.route('/api/upgrade/preflight', methods=['POST'])
def preflight_upgrade_package():
    """Would this package apply cleanly on this box? Changes NOTHING.

    Body: ``{"package_path": "/data/uploads/<id>"}``

    Runs the same checks the real apply runs — archive integrity, module
    ordering (downgrade refusal), disk sized from the package's own manifest,
    docker reachability, and whether the backend image this target resolves is
    actually bundled. Answering "will this work?" previously required running
    it, which is a poor question to have to answer destructively.

    Read-only by construction: it extracts to a scratch dir and deletes it, and
    never mirrors source, loads an image, writes config.yaml, or touches a
    container. Returns 200 with ``ok: false`` for a package that would fail —
    the CHECK succeeded, the package is what is bad — and 4xx only for a bad
    request.
    """
    try:
        data = request.json or {}
        package_path = (data.get('package_path') or '').strip()
        if not package_path:
            return jsonify({"error": "package_path required"}), 400
        err = _reject_package_path(package_path)
        if err:
            return err

        from services.upgrade import preflight_package
        lines = []
        result = preflight_package(
            package_path, logger=lambda m, l="info": lines.append(f"[{l}] {m}"))
        result["log"] = lines
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
        # Optional operator-supplied digest for the uploaded archive. The
        # package's own manifest can only prove it is INTACT — the hashes
        # travel inside the archive they validate. This is the one value
        # that comes from outside it: the .sha256 published alongside the
        # release. When absent the apply proceeds exactly as before, with
        # the computed digest logged so it can be compared by eye.
        expected_sha256 = (data.get('expected_sha256') or '').strip() or None
        if selected_modules:
            # Accept legacy module ids from external automation (e.g. 'cloudtrail')
            from services.upgrade import LEGACY_MODULE_ALIASES
            selected_modules = [LEGACY_MODULE_ALIASES.get(m, m) for m in selected_modules]

        if not package_path:
            return jsonify({"error": "No package_path provided"}), 400

        err = _reject_package_path(package_path)
        if err:
            return err

        if not os.path.exists(package_path):
            return jsonify({"error": f"Package not found: {package_path}"}), 400

        # Single-writer gate + run acquisition under one mutex: refuse when
        # another upgrade/prepare owns the system (concurrent upgrades mirror
        # the same live source tree — install corruption). The mutex closes
        # the double-click TOCTOU between the DB check and run creation.
        with _UPGRADE_START_MUTEX:
            blocked = _upgrade_gate(force=bool(data.get('force')))
            if blocked:
                return blocked

            # Continue the UPLOAD's workflow when this package came from a TUS
            # upload, so the import and the apply are ONE workflow row instead
            # of two. Prepare-built packages (/data/upgrade_packages/) have no
            # upload run at all and get a fresh one.
            #
            # This used to depend solely on a `<package>.run` sidecar written by
            # the post-finish hook — and lost a race to it. The frontend POSTs
            # this apply from its tus onSuccess handler while the server-side
            # hook runs concurrently, so the check landed BEFORE the file
            # existed: observed 2026-07-23 with the sidecar written at
            # .843 and this handler creating a second run at .849, 6 ms later.
            # A wider sleep would just be a bigger guess.
            #
            # So identity no longer comes from the sidecar. tus stores the
            # package at /data/uploads/<upload_id>, and the upload run recorded
            # that id in details.upload_id when the row was CREATED — minutes
            # earlier, entirely outside the contested window. The basename is
            # therefore a durable join key that cannot be raced. The sidecar is
            # kept only as a fast path.
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

            if not run_id:
                # Durable fallback: find the upload's run by upload_id.
                try:
                    from routes.upload_routes import _resolve_upload_run
                    from services.file_storage_service import get_workflow as _get_wf
                    _uid = os.path.basename(package_path or '')
                    _rid = _resolve_upload_run(_uid) if _uid else None
                    if _rid:
                        _wf = _get_wf(_rid) or {}
                        # Only adopt a row that is still open. An upload run
                        # that already finished belongs to a previous apply.
                        if _wf.get('status') not in ('completed', 'failed',
                                                     'cancelled'):
                            run_id = _rid
                except Exception as _ae:
                    print(f"[UPGRADE] upload-run adoption lookup failed: {_ae}",
                          flush=True)

            if run_id:
                # Consume-once, so a genuine RE-apply of the same package gets
                # its own row (honest audit trail) instead of re-opening this
                # one. Deleting the sidecar is no longer sufficient for that —
                # the upload_id fallback above would happily find the row again
                # — so the claim is recorded IN the run. mutate_run_details does
                # read-modify-write under the per-run lock, making this a real
                # test-and-set rather than a check-then-write.
                _claimed = {"ok": False}

                def _claim(d, _c=_claimed):
                    if not d.get("applied"):
                        d["applied"] = True
                        _c["ok"] = True

                try:
                    from services.workflow_service import mutate_run_details
                    mutate_run_details(run_id, _claim)
                except Exception as _ce:
                    print(f"[UPGRADE] could not claim upload run {run_id}: {_ce}",
                          flush=True)
                    _claimed["ok"] = True   # fail open: adopt rather than split

                if not _claimed["ok"]:
                    # Someone already applied this package — give this attempt
                    # its own row instead of writing into the finished one.
                    run_id = None

            if run_id:
                try:
                    os.remove(sidecar)
                except Exception:
                    pass
                add_log_to_run(run_id, "─" * 40, "info")
                add_log_to_run(run_id, "Applying uploaded package — continuing this workflow.", "info")
            else:
                # No sidecar to adopt, so this apply gets its own row. Before
                # opening it, CLOSE any upload run for this same package that is
                # still sitting `running`.
                #
                # The upload hook deliberately leaves its run open at progress=10
                # (see upload_routes.py) because the apply is expected to re-open
                # it. When adoption doesn't happen — a re-apply, whose sidecar was
                # consumed by the first apply, or an apply that raced the hook —
                # nothing ever closes that row, so it reads "running" forever until
                # cleanup_orphan_workflows reaps it hours later. An operator then
                # sees a permanently-in-progress upload next to a finished upgrade
                # and reasonably concludes something hung (reported 2026-07-23).
                # Same class as the Stop-button bug in 654799a: the status lied.
                _close_orphan_upload_run(package_path)

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
                    expected_sha256=expected_sha256,
                )

                # Handle two-phase upgrade (backend restart pending)
                if result.get('phase') == 'awaiting_restart':
                    add_log_to_run(run_id, "Phase 1 complete. Backend restarting. Phase 2 will resume automatically.", "info")
                    update_run_status(run_id, "running", progress=50)
                    # Don't mark complete - Phase 2 will continue after restart
                elif result.get('success'):
                    # force=True: the per-module results are the authoritative
                    # success signal for an upgrade. Without it, any error-level
                    # log line during the run (e.g. a step that failed and was
                    # retried/rolled back inside a module that ultimately
                    # SUCCEEDED) auto-demotes the whole run to 'failed' (G8).
                    add_log_to_run(run_id, f"Offline upgrade completed: {result.get('completed', 0)}/{result.get('total', 0)} modules", "success")
                    # See app.py's twin: the browser may still be running the
                    # pre-upgrade JS bundle, so say so rather than letting the
                    # operator conclude nothing changed.
                    add_log_to_run(run_id,
                        "Refresh your browser with Ctrl+Shift+R (Cmd+Shift+R on Mac) "
                        "to load the new interface — until you do, you are still "
                        "viewing the previous version's UI.", "info")
                    add_log_to_run(run_id,
                        "This run is kept under Workflows → System workspace, "
                        "so you can reopen these logs at any time.", "info")
                    update_run_status(run_id, "completed", progress=100, force=True)
                elif result.get('error') and not result.get('results'):
                    # Workflow aborted BEFORE any module ran (config.yaml
                    # validation, package verification, ...). Previously this
                    # fell into the branch below and was mislabeled
                    # "completed, 100%" — the operator saw a successful run
                    # that did nothing. Surface it as the failure it is.
                    add_log_to_run(run_id, f"Offline upgrade aborted: {result['error']}", "error")
                    update_run_status(run_id, "failed", progress=0, error=result['error'])
                else:
                    # Partial success: some modules failed, others upgraded
                    # fine. Mark 'completed' WITH the failure list in the
                    # error field (visible in the UI) instead of letting the
                    # error-count auto-flip label a 5/6 success as a flat
                    # 'failed' — which read as "the upgrade did nothing" and
                    # caused unnecessary full re-runs (G8). Failed modules'
                    # version pins were already reverted per-module, so a
                    # re-run retries exactly the right thing.
                    # Skip underscore METADATA keys (_health, _workflow_error):
                    # they are not modules and carry no `success` field, so
                    # counting them turned a healthy run into "completed with
                    # failed module(s): _health".
                    failed = [m for m, r in result.get('results', {}).items()
                              if isinstance(r, dict) and not r.get('success')
                              and not m.startswith('_')]
                    if failed:
                        add_log_to_run(run_id, f"Offline upgrade completed with failures: {', '.join(failed)}", "warning")
                        update_run_status(run_id, "completed", progress=100, force=True,
                                          error=f"completed with failed module(s): {', '.join(failed)}")
                    else:
                        update_run_status(run_id, "completed", progress=100, force=True)

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

           {"target": "<ref>", "opted_in_optional": ["aws_sigma", ...]} (legacy "cloudtrail" accepted)

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
        err = _quota_preflight_or_jsonify(3, "prepare package")
        if err: return err

        target = (data.get('target') or '').strip()
        if not target:
            # Legacy shapes posted a module dict; download-only needs the ref.
            target = ((data.get('modules') or {}).get('intact') or '').strip()
        if not target:
            return jsonify({"error": "target (release tag) required"}), 400

        # Create workflow run — behind the single-writer gate (prepare writes
        # into the package staging dir, so it serializes with upgrades). The
        # mutex closes the double-click TOCTOU.
        with _UPGRADE_START_MUTEX:
            blocked = _upgrade_gate(force=bool((data or {}).get('force')))
            if blocked:
                return blocked
            run_id = create_automation_run(
                automation_type="prepare_package",
                name="Prepare Upgrade Package",
                details={"trigger": "manual", "target": target},
            )
        add_log_to_run(run_id, f"Fetching the prebuilt release package for {target}", "info")
        for line in _quota_audit_lines(2):
            add_log_to_run(run_id, line, "info")
        update_run_status(run_id, "running", progress=5)

        from services.workflow_service import register_cancel_event, unregister_cancel
        register_cancel_event(run_id)

        # Download the package in the background
        def run_prepare():
            # Imported first so the except clause below can always name it.
            from services.upgrade.download import (
                download_release_package, PackageDownloadCancelled)
            try:
                from services.connectivity import require_internet
                if not require_internet(run_id, "Prepare upgrade package"):
                    return

                def logger(msg, level="info"):
                    add_log_to_run(run_id, msg, level)

                # DOWNLOAD-ONLY: the package is the CI-built artifact attached
                # to the GitHub Release, produced from that release's OWN code.
                # Nothing is built on this machine — building on-box is what
                # produced the factor-5 / "Unknown module" bug class.
                # /api/upgrade/refs only offers releases that ship a package, so
                # a miss here means the release was retargeted, or its CI build
                # has not run yet.
                _dl_pct = [5]

                def _dl_progress(frac):
                    p = min(95, 5 + int(frac * 90))
                    if p > _dl_pct[0]:
                        _dl_pct[0] = p
                        update_run_status(run_id, "running", progress=p)

                pkg_path = download_release_package(
                    target, dest_dir="/data/upgrade_packages",
                    run_id=run_id, logger=logger, progress_cb=_dl_progress)

                if not pkg_path:
                    msg = (f"Release '{target}' ships no downloadable upgrade "
                           f"package, and nothing is built on this machine. "
                           f"Run the build-release-package workflow for this "
                           f"tag, then retry.")
                    add_log_to_run(run_id, msg, "error")
                    update_run_status(run_id, "failed", progress=0, error=msg)
                    return

                _save_package_info({
                    'run_id': run_id,
                    'path': pkg_path,
                    'name': os.path.basename(pkg_path),
                    'size': os.path.getsize(pkg_path),
                    'created_at': time.time(),
                })
                add_log_to_run(run_id, f"Package ready for download: "
                                       f"{os.path.basename(pkg_path)}", "success")
                add_log_to_run(run_id, "Note: Preparing a new package will "
                                       "replace this one", "info")
                update_run_status(run_id, "completed", progress=100)

            except PackageDownloadCancelled:
                return  # 'cancelled' already set by request_stop()
            except Exception as e:
                # If the operator clicked Stop, the aborted download raised on
                # its way out — that's not a real failure. Let the 'cancelled'
                # state stand.
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

        # NB: no `modules` in scope here — this route is download-only and takes
        # a single `target` ref. A leftover f"{len(modules)}" raised NameError
        # AFTER the run was created and the thread started, so the outer except
        # returned a 500 and the UI reported "Upgrade request failed" for a
        # preparation that was in fact running (and which then blocked the
        # retry via the single-writer gate).
        return jsonify({
            "success": True,
            "run_id": run_id,
            "message": f"Package preparation started for {target}"
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
        err = _quota_preflight_or_jsonify(3, "online upgrade")
        if err: return err

        target = (data.get('target') or '').strip()
        track_warnings: list = []
        if target:
            from services.upgrade.resolver import ResolverError
            try:
                modules, track_warnings = _modules_from_track(
                    target, data.get('opted_in_optional') or [],
                    data.get('opted_in_reinstall') or [],
                )
            except ResolverError as e:
                return jsonify({"error": str(e)}), 502
        else:
            from services.upgrade import _normalize_legacy_module_keys
            modules = _normalize_legacy_module_keys(data.get('modules', {}))

        if not modules:
            return jsonify({"error": "No modules selected for online upgrade"}), 400

        db_overwrite = data.get('db_overwrite') or {}

        # Single-writer gate + run creation under one mutex (see offline route).
        with _UPGRADE_START_MUTEX:
            blocked = _upgrade_gate(force=bool(data.get('force')))
            if blocked:
                return blocked
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

        # Progress estimation over the visible 2-95% band. DOWNLOAD-ONLY: there
        # are no prepare-side image saves to count any more (nothing is built
        # here), so the band belongs entirely to apply-side per-module
        # completions. The download phase reports its own MB/percentage lines
        # into the run log via download_release_package().
        total_steps = max(len(modules), 1)
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
