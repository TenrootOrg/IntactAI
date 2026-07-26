#!/usr/bin/env python3
"""Endpoints backing Settings → Agentic for subscription (CLI) providers.

Install / Configure / Test are long-running and can fail in a dozen ways (no
internet, blocked proxy, expired code, vendor rejection), so each one is
created as a `settings` automation run and executed on a background thread.
The route returns immediately with the run id; the UI jumps to Settings →
Actions where the operator watches the same live log modal every other system
operation uses. Nothing bespoke to learn, and a failed attempt leaves a
permanent, inspectable record.

/status is the cheap poll the panel uses (no tokens, no network) and never
returns anything token-shaped — booleans plus a human-readable detail string.
"""

import threading

from flask import Blueprint, jsonify, request

from services.agentic import subscription_cli as sub
from services.workflow_service import create_automation_run, add_log_to_run

agentic_cli_bp = Blueprint('agentic_cli', __name__)


def _provider_from_request(default="codex-subscription"):
    p = (request.args.get('provider')
         or (request.get_json(silent=True) or {}).get('provider')
         or default)
    if not sub.is_subscription_provider(p):
        return None, (jsonify({"error": f"not a subscription provider: {p}"}), 400)
    return p, None


def _close_orphaned_runs(provider):
    """Close out any earlier run of ours still marked pending/running.

    Two different situations end up looking identical in the table, and each
    gets its own explanation below: a backend restart (upgrade, crash, compose
    recreate) kills the daemon worker while the row stays 'pending' forever, and
    a second click supersedes a run that is legitimately still waiting (a device
    login can sit for 15 minutes awaiting approval).
    """
    try:
        from services import workflow_service as ws
        sid = ws._system_case_id()
        runs = ws.get_automation_runs_by_case(sid) if sid else []
    except Exception:  # noqa: BLE001
        return
    ours = set(sub.WORKFLOW_NAMES.values())
    for r in runs:
        if r.get("name") not in ours or r.get("status") not in ("pending", "running"):
            continue
        # A run whose worker is still alive here is being superseded by the
        # action the operator just started (e.g. clicking Connect twice while
        # the first code was still awaiting approval). One with no worker was
        # orphaned by a restart. Saying "restarted" for both is a lie the
        # operator cannot debug.
        superseded = sub.is_run_active(r["run_id"])
        msg = ("Superseded: a newer attempt was started from Settings, so this "
               "one was cancelled." if superseded else
               "Interrupted: the backend restarted while this workflow was "
               "running, so it could not finish. Start it again.")
        try:
            ws.add_log_to_run(r["run_id"], msg, "warning" if superseded else "error")
            ws.update_run_status(
                r["run_id"], "failed",
                error="superseded by a newer attempt" if superseded
                      else "interrupted by a backend restart")
        except Exception:  # noqa: BLE001
            pass


def _start_action(provider, kind, target, *args):
    """Create the Actions run, kick off the worker, hand back the run id."""
    _close_orphaned_runs(provider)
    name = sub.WORKFLOW_NAMES[kind]
    run_id = create_automation_run(
        automation_type="settings",
        name=name,
        details={"provider": provider, "action": kind},
    )
    add_log_to_run(run_id, f"Starting: {name}")
    add_log_to_run(run_id, f"Workflow ID: {run_id}")
    t = threading.Thread(target=target, args=(run_id, provider) + args)
    t.daemon = True
    t.start()
    return jsonify({"success": True, "run_id": run_id, "name": name,
                    "message": "Workflow started — follow it in Settings → Actions."})


@agentic_cli_bp.route('/api/agentic/cli/status', methods=['GET'])
def cli_status():
    """Cheap detect: is the CLI installed, is it connected. No tokens spent."""
    provider, err = _provider_from_request()
    if err:
        return err
    try:
        d = sub.detect(provider)
        # surface a pending device login so the panel can show the URL/code
        # even after a page reload
        d["login"] = sub.pending_login(provider)
        return jsonify(d)
    except Exception as e:  # noqa: BLE001
        return jsonify({"provider": provider, "installed": False,
                        "authenticated": False, "detail": f"status failed: {e}"}), 200


@agentic_cli_bp.route('/api/agentic/cli/install', methods=['POST'])
def cli_install():
    """Install the vendor CLI as an Actions workflow. Needs internet."""
    provider, err = _provider_from_request()
    if err:
        return err
    return _start_action(provider, "install", sub.run_install_workflow)


@agentic_cli_bp.route('/api/agentic/cli/login', methods=['POST'])
def cli_login_start():
    """Sign in with the subscription, as an Actions workflow.

    The device URL + one-time code appear both in the run log and in
    /status.login so the panel can render clickable/copyable buttons.
    """
    provider, err = _provider_from_request()
    if err:
        return err
    # A device code stays valid for ~15 minutes, so a second click while one is
    # already awaiting approval must NOT kill it — that would invalidate the code
    # the operator is part-way through entering. Hand back the run that is
    # already waiting instead, along with its still-valid URL and code.
    live = sub.pending_login(provider)
    if live.get("url"):
        return jsonify({
            "success": True, "run_id": live.get("run_id"),
            "name": sub.WORKFLOW_NAMES["configure"],
            "url": live.get("url"), "code": live.get("code"),
            "message": "A sign-in is already waiting for approval — use the "
                       "code already shown, or Cancel it first to start over.",
        })
    return _start_action(provider, "configure", sub.run_configure_workflow)


@agentic_cli_bp.route('/api/agentic/cli/login', methods=['GET'])
def cli_login_poll():
    """Poll the pending login; persists the token once approved."""
    provider, err = _provider_from_request()
    if err:
        return err
    return jsonify(sub.login_poll(provider))


@agentic_cli_bp.route('/api/agentic/cli/login/cancel', methods=['POST'])
def cli_login_cancel():
    provider, err = _provider_from_request()
    if err:
        return err
    return jsonify({"cancelled": sub.login_cancel(provider)})


@agentic_cli_bp.route('/api/agentic/cli/disconnect', methods=['POST'])
def cli_disconnect():
    """Forget the stored credential. Leaves the binary installed."""
    provider, err = _provider_from_request()
    if err:
        return err
    sub.login_cancel(provider)
    return jsonify({"success": sub.forget_credentials(provider)})


@agentic_cli_bp.route('/api/agentic/cli/import-credential', methods=['POST'])
def cli_import_credential():
    """Adopt a login the operator created manually on the host."""
    provider, err = _provider_from_request()
    if err:
        return err
    result = sub.import_manual_credential(provider)
    return jsonify(result), (200 if result.get('success') else 400)


@agentic_cli_bp.route('/api/agentic/cli/test', methods=['POST'])
def cli_test():
    """Round-trip a trivial prompt, as an Actions workflow."""
    provider, err = _provider_from_request()
    if err:
        return err
    return _start_action(provider, "test", sub.run_test_workflow)
