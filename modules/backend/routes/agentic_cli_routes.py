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
    """Close out earlier runs of ours whose worker died with a restart.

    A backend restart (upgrade, crash, compose recreate) kills the daemon
    worker while the row stays 'pending' forever.
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
        # A run whose worker is still alive is left to finish itself. Marking
        # it "superseded" never stopped it: its _finish later overwrote the
        # failed row with 'completed', so the log said cancelled and the
        # status said green.
        if sub.is_run_active(r["run_id"]):
            continue
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
    # Marked before the thread starts, so a second click in that gap does not
    # see a pending row with no worker and close it as interrupted.
    sub._mark_active(run_id)
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
        # Everything the panel needs, and nothing it can act on: installed,
        # version, signed-in, which binary, whose credential. There is no
        # pending-login to report any more — signing in happens on the host.
        return jsonify(sub.detect(provider))
    except Exception as e:  # noqa: BLE001
        return jsonify({"provider": provider, "installed": False,
                        "authenticated": False, "detail": f"status failed: {e}"}), 200



# INSTALL AND SIGN-IN WERE REMOVED, deliberately.
#
# This blueprint used to carry /install, /login (start, poll, cancel),
# /disconnect and /import-credential: the appliance ran the vendor's installer
# into a directory of its own, drove a device-code sign-in, and kept the
# resulting credential in its database.
#
# None of that was the appliance's business. Installing third-party software on
# the host behind a button in a web panel, and holding somebody's ChatGPT
# credential, are both things an operator can do better and more visibly
# themselves — and the "install" half only ever worked when the box had
# outbound internet, which a DFIR appliance frequently does not.
#
# So codex is now the operator's: they install it on the host and run
# `codex login`, and the backend finds and uses it (services/agentic/
# subscription_cli.py resolves the binary, and reads their ~/.codex credential
# through a read-only bind mount). What is left here is a read (/status) and a
# proof (/test).
#
# Appliances that signed in through the old flow keep working untouched — the
# credential in the secret store is still checked first, and is still refreshed
# on use. Nobody has to re-do anything.

@agentic_cli_bp.route('/api/agentic/cli/test', methods=['POST'])
def cli_test():
    """Round-trip a trivial prompt, as an Actions workflow."""
    provider, err = _provider_from_request()
    if err:
        return err
    return _start_action(provider, "test", sub.run_test_workflow)
