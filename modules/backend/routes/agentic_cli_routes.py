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
    """Fail any earlier run of ours still marked pending/running.

    These workflows execute on a daemon thread, so a backend restart (upgrade,
    crash, compose recreate) kills the worker while the row stays 'pending'
    forever — an operator sees a spinner that will never resolve. There is no
    worker left to recover, so mark them failed with the reason when the next
    action starts.
    """
    try:
        from services import workflow_service as ws
        sid = ws._system_case_id()
        runs = ws.get_automation_runs_by_case(sid) if sid else []
    except Exception:  # noqa: BLE001
        return
    ours = set(sub.WORKFLOW_NAMES.values())
    for r in runs:
        if r.get("name") in ours and r.get("status") in ("pending", "running"):
            try:
                ws.add_log_to_run(
                    r["run_id"],
                    "Interrupted: the backend restarted while this workflow was "
                    "running, so it could not finish. Start it again.", "error")
                ws.update_run_status(r["run_id"], "failed",
                                     error="interrupted by a backend restart")
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


@agentic_cli_bp.route('/api/agentic/cli/test', methods=['POST'])
def cli_test():
    """Round-trip a trivial prompt, as an Actions workflow."""
    provider, err = _provider_from_request()
    if err:
        return err
    return _start_action(provider, "test", sub.run_test_workflow)
