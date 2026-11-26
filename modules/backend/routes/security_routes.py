"""Dashboard banner: which modules still run on a publicly known password, and
which had a password changed for them that the operator has not seen yet.

An install or upgrade keeps every tool login as it is, even a public default,
and lists it here until the operator changes it with scripts/apply-passwords.sh
(2026-11-22). "rotated" is what an OLDER release replaced on its own and the
operator has not looked up yet. lib/credentials_apply.sh records both in
data/state/default-passwords.json,
{"modules": [...], "rotated": [...], "since": "<iso>"}; this only reports it.
A missing file means none.

Authenticated like every other /api route (app.py's _auth_gate): the list tells
an attacker which default to try.

Also Settings -> Security: audit forwarding to the customer's syslog server
(services/audit_forward.py) and the security alerts (services/security_alerts.py).
Roles are in services/access_policy.POLICY like every other route.
"""
import json
import os

from flask import Blueprint, jsonify, request, session

from services import audit_forward, auth_service, security_alerts, users
from services.storage.base import STORAGE_BASE

security_bp = Blueprint('security', __name__)


def marker_path():
    return os.path.join(STORAGE_BASE, 'state', 'default-passwords.json')


def default_passwords_in_use(path=None):
    """{'modules': [names], 'rotated': [names], 'since': iso or None}. Never raises."""
    empty = {'modules': [], 'rotated': [], 'since': None}
    try:
        with open(path or marker_path()) as f:
            data = json.load(f)
    except FileNotFoundError:
        return empty
    except (OSError, ValueError):
        # Unreadable or half-written: say so rather than claim "none".
        return dict(empty, error='marker unreadable')
    if not isinstance(data, dict):
        return dict(empty, error='marker unreadable')

    def names(key):
        v = data.get(key)
        return [m for m in v if isinstance(m, str) and m] if isinstance(v, list) else []
    return {'modules': names('modules'), 'rotated': names('rotated'), 'since': data.get('since')}


@security_bp.route('/api/security/default-passwords', methods=['GET'])
def get_default_passwords():
    return jsonify(default_passwords_in_use())


@security_bp.route('/api/security/audit-forward', methods=['GET'])
def get_audit_forward():
    return jsonify({'config': audit_forward.get_config(), 'status': audit_forward.status()})


@security_bp.route('/api/security/audit-forward', methods=['PUT'])
def save_audit_forward():
    old = audit_forward.get_config()
    cfg, problem = audit_forward.save_config(request.get_json(silent=True))
    if problem:
        return jsonify({'success': False, 'message': problem}), 400
    keys = ('enabled', 'protocol', 'host', 'port')
    if any(old[k] != cfg[k] for k in keys):
        # Its own event (security_alerts raises a high alert when the feed is
        # turned off or moved), not just app.py's generic `action` line.
        auth_service.audit('audit_forward_changed', request, username_value=users.caller_name(session),
                           old={k: old[k] for k in keys}, new={k: cfg[k] for k in keys})
    return jsonify({'success': True, 'config': cfg, 'status': audit_forward.status()})


@security_bp.route('/api/security/audit-forward/test', methods=['POST'])
def test_audit_forward():
    # The form's values, so an Admin can test before saving.
    result = audit_forward.send_test(request.get_json(silent=True) or {})
    return jsonify(dict(result, success=result['ok'])), (200 if result['ok'] else 400)


@security_bp.route('/api/security/alerts', methods=['GET'])
def list_security_alerts():
    unacked = request.args.get('unacked') in ('1', 'true')
    return jsonify({'alerts': security_alerts.list_alerts(unacked=unacked)})


@security_bp.route('/api/security/alerts/count', methods=['GET'])
def security_alert_count():
    return jsonify({'unacknowledged': security_alerts.unacked_count()})


@security_bp.route('/api/security/alerts/<int:alert_id>/ack', methods=['POST'])
def ack_security_alert(alert_id):
    who = users.caller_name(session)
    alert = security_alerts.get(alert_id)
    if alert is None:
        return jsonify({'success': False, 'message': 'No such alert.'}), 404
    if alert.get('user') == who and not users.caller_has(session, users.SUPERADMIN):
        # Otherwise an Admin could clear the alert their own action raised
        # before anyone else saw it.
        return jsonify({'success': False,
                        'message': 'An alert about your own action is for someone else to acknowledge.'}), 403
    alert = security_alerts.acknowledge(alert_id, who or '-')
    auth_service.audit('security_alert_acknowledged', request, username_value=who,
                       alert_id=alert_id, kind=alert['kind'], alert_user=alert.get('user'))
    return jsonify({'success': True, 'alert': alert})
