#!/usr/bin/env python3
"""Auth Routes — single-user dashboard login.

Endpoints here are the ONLY ones reachable without a session (see the allowlist
in app.py:_auth_gate). Keep that in mind before adding anything: whatever lands
in this blueprint is exposed to anyone who can route to the appliance.

See services/auth_service.py for the policy and the three security-critical
invariants it documents.
"""

from flask import Blueprint, jsonify, request, session

from services import auth_service as auth

auth_bp = Blueprint('auth', __name__)


def _client_ip():
    return request.headers.get('X-Real-IP') or request.remote_addr


@auth_bp.route('/api/auth/status', methods=['GET'])
def auth_status():
    """Drives both login.html and setup.html, and the frontend's decision to
    redirect. Unauthenticated by necessity — so it must not leak anything an
    attacker could use. The username is only returned once authenticated."""
    mode = auth.auth_mode()
    state = auth.evaluate_session(session)
    locked = auth.lock_remaining_seconds()

    body = {
        'mode': mode,                       # setup | login | error
        'authenticated': state == auth.SESSION_OK,
        'session_state': state,             # ok | none | expired | credentials_changed
        'locked': locked > 0,
        'lock_remaining_seconds': locked,
        'recovery_hint': auth.recovery_hint(),
    }
    if mode == auth.MODE_ERROR:
        body['message'] = ('config.yaml could not be read, so the appliance '
                           'cannot tell whether it has been set up. Fix the '
                           'file on the host, then reload.')
    if state == auth.SESSION_OK:
        body['user'] = session.get('user')
    return jsonify(body)


@auth_bp.route('/api/auth/setup', methods=['POST'])
def auth_setup():
    """Claim the appliance: set the single user's id + password.

    Only available while config.yaml has first_login: true. That flag is the
    operator's deliberate "I am standing at this box" signal — it requires host
    access to set, which is what stops this endpoint being an open account
    takeover.
    """
    if auth.auth_mode() != auth.MODE_SETUP:
        auth.audit('setup_rejected', request, reason='not_in_setup_mode')
        return jsonify({
            'success': False,
            'error': 'setup_closed',
            'message': 'This appliance is already set up. Use the login page.',
        }), 403

    data = request.get_json(silent=True) or {}
    user = (data.get('username') or '').strip()
    password = data.get('password') or ''
    confirm = data.get('confirm') or ''

    if not user or not password:
        return jsonify({'success': False, 'error': 'missing_fields',
                        'message': 'Username and password are both required.'}), 400
    if password != confirm:
        return jsonify({'success': False, 'error': 'mismatch',
                        'message': 'The two passwords do not match.'}), 400
    # No minimum length. Removed deliberately at the operator's request so the
    # shipped default (123123) can be used, matching the module passwords in
    # config.yaml. The appliance's real protection against a guessed dashboard
    # password is the lockout in evaluate_login() -- ten wrong attempts and the
    # account is locked -- not length. Operators who want a strong password can
    # still set one; this only stops the appliance refusing a short one.

    # ORDER IS SECURITY-CRITICAL: close setup FIRST, then store the credential.
    # The reverse order means a failed config write leaves the setup page still
    # being served WITH a credential set — permanently claimable by the next
    # visitor. This order fails closed instead: worst case the credential is
    # absent and login refuses everything, which the recovery hint covers.
    if not auth.write_first_login(False):
        auth.audit('setup_failed', request, username_value=user,
                   reason='config_write_failed')
        return jsonify({
            'success': False,
            'error': 'config_write_failed',
            'message': ('Could not update config.yaml, so setup was not '
                        'completed. Check the backend logs and the file '
                        'permissions on config.yaml.'),
        }), 500

    if not auth.set_credential(user, password):
        auth.audit('setup_failed', request, username_value=user,
                   reason='credential_store_failed')
        return jsonify({
            'success': False,
            'error': 'store_failed',
            'message': ('Could not store the credential. Set first_login: true '
                        'in config.yaml on the host and try again.'),
        }), 500

    auth.bump_generation_cache()
    auth.start_session(session, user)
    auth.audit('setup', request, username_value=user)
    return jsonify({'success': True, 'user': user})


@auth_bp.route('/api/auth/login', methods=['POST'])
def auth_login():
    if auth.auth_mode() == auth.MODE_ERROR:
        return jsonify({'success': False, 'error': 'config_error',
                        'message': 'config.yaml could not be read.'}), 503

    locked = auth.lock_remaining_seconds()
    if locked > 0:
        auth.audit('login_blocked', request, reason='locked',
                   lock_remaining_seconds=locked)
        return jsonify({
            'success': False,
            'error': 'locked',
            'lock_remaining_seconds': locked,
            'message': f'Too many failed attempts. Try again in '
                       f'{_humanize(locked)}.',
            'recovery_hint': auth.recovery_hint(),
        }), 429

    # Independent of the strike counter — otherwise ten failures burn in
    # milliseconds and the lockout is decorative against a script.
    if not auth.throttle_ok():
        return jsonify({'success': False, 'error': 'too_fast',
                        'message': 'Slow down and try again.'}), 429

    data = request.get_json(silent=True) or {}
    user = (data.get('username') or '').strip()
    password = data.get('password') or ''

    if not auth.has_credential():
        # Reachable after a DB export/import: secret_store is deliberately
        # excluded from export_db(), so the flag can say "set up" while no
        # credential exists. Fail closed, but say what to do about it.
        auth.audit('login_failed', request, username_value=user,
                   reason='no_credential_configured')
        return jsonify({
            'success': False,
            'error': 'no_credential',
            'message': 'No credential is configured on this appliance.',
            'recovery_hint': auth.recovery_hint(),
        }), 403

    if not auth.verify_password(user, password):
        lock_seconds = auth.register_failure()
        remaining = auth.failures_before_lock()
        auth.audit('login_failed', request, username_value=user,
                   locked_for_seconds=lock_seconds or None)
        if lock_seconds:
            auth.audit('locked', request, username_value=user,
                       locked_for_seconds=lock_seconds)
            return jsonify({
                'success': False,
                'error': 'locked',
                'lock_remaining_seconds': lock_seconds,
                'message': f'Too many failed attempts. Locked for '
                           f'{_humanize(lock_seconds)}.',
                'recovery_hint': auth.recovery_hint(),
            }), 429
        return jsonify({
            'success': False,
            'error': 'invalid_credentials',
            'attempts_before_lock': remaining,
            'message': 'Incorrect username or password.',
            'recovery_hint': auth.recovery_hint(),
        }), 401

    auth.reset_lockout()
    auth.bump_generation_cache()
    auth.start_session(session, user)
    auth.audit('login_ok', request, username_value=user)
    return jsonify({'success': True, 'user': user})


@auth_bp.route('/api/auth/logout', methods=['POST'])
def auth_logout():
    user = session.get('user')
    session.clear()
    auth.audit('logout', request, username_value=user)
    return jsonify({'success': True})


@auth_bp.route('/api/auth/change-password', methods=['POST'])
def auth_change_password():
    """Requires the current password even though the caller already holds a
    session — a stolen cookie should not be enough to lock the real operator
    out of their own appliance."""
    if auth.evaluate_session(session) != auth.SESSION_OK:
        return jsonify({'success': False, 'error': 'unauthenticated'}), 401

    data = request.get_json(silent=True) or {}
    current = data.get('current_password') or ''
    new_password = data.get('new_password') or ''
    confirm = data.get('confirm') or ''
    user = session.get('user')

    if not auth.verify_password(user, current):
        auth.audit('password_change_failed', request, username_value=user,
                   reason='wrong_current_password')
        return jsonify({'success': False, 'error': 'invalid_credentials',
                        'message': 'Current password is incorrect.'}), 401
    if new_password != confirm:
        return jsonify({'success': False, 'error': 'mismatch',
                        'message': 'The two passwords do not match.'}), 400
    # No minimum length here either. Removing it only from /api/auth/setup was
    # a half-measure: an appliance claimed with a short password could not then
    # CHANGE it back to one, so any rotation was a one-way door out of the
    # documented default. Same reasoning as setup — the lockout in
    # evaluate_login() is the control, not length.

    if not auth.set_credential(user, new_password):
        return jsonify({'success': False, 'error': 'store_failed',
                        'message': 'Could not store the new password.'}), 500

    # Bumping the generation invalidates every OTHER session; re-issue this one
    # so the operator who just changed their own password isn't logged out.
    auth.bump_generation_cache()
    auth.start_session(session, user)
    auth.audit('password_changed', request, username_value=user)
    return jsonify({'success': True})


@auth_bp.route('/api/auth/verify', methods=['GET'])
def auth_verify():
    """Target of nginx's `auth_request` for /velociraptor/ and /api/uploads/ —
    the two protected paths that proxy to non-Flask upstreams and so can only be
    gated in nginx.

    Deliberately a PURE signed-cookie check with no SQLite access: nginx fires
    one subrequest per tus PATCH, which is ~2000 of them for a 10 GB upload
    against a single-process threaded server. 200 or 401, no body.
    """
    if auth.evaluate_session(session) == auth.SESSION_OK:
        return '', 200
    return '', 401


def _humanize(seconds: int) -> str:
    minutes = max(1, int(round(seconds / 60.0)))
    if minutes < 60:
        return f'{minutes} minute{"s" if minutes != 1 else ""}'
    hours = minutes / 60.0
    if hours < 24:
        rounded = int(hours) if hours == int(hours) else round(hours, 1)
        return f'{rounded} hour{"s" if rounded != 1 else ""}'
    return f'{round(hours / 24.0, 1)} days'
