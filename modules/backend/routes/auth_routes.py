#!/usr/bin/env python3
"""Auth Routes — dashboard login, setup, password changes, the nginx check.

Endpoints here are the ONLY ones reachable without a session (see the allowlist
in app.py:_auth_gate). Keep that in mind before adding anything: whatever lands
in this blueprint is exposed to anyone who can route to the appliance.

See services/auth_service.py for the policy and the three security-critical
invariants it documents.
"""

import re

from flask import Blueprint, jsonify, request, session

from services import auth_service as auth
from services import users

auth_bp = Blueprint('auth', __name__)


# Timesketch keeps its own session after its header SSO signs a user in
# (Phase 0, docs/PLAN_multi_user_accounts.md): left alone, the next person to
# sign in to the dashboard in the same browser would land in Timesketch as the
# previous one. Cookies are not isolated by port, so the dashboard expires them.
# Kibana's `sid` too: with no injected credential (an account not made yet)
# Kibana would fall back to a form login left in this browser by someone else.
TOOL_SESSION_COOKIES = ("timesketch_session", "remember_token", "sid")


def _expire_tool_sessions(resp):
    for name in TOOL_SESSION_COOKIES:
        if hasattr(resp, "delete_cookie"):
            resp.delete_cookie(name, path="/")
    return resp


def _client_ip():
    # X-Real-IP only when nginx sent it; a direct caller is its own address.
    return auth.client_address(request)


@auth_bp.route('/api/auth/status', methods=['GET'])
def auth_status():
    """Drives both login.html and setup.html, and the frontend's decision to
    redirect. Unauthenticated by necessity — so it must not leak anything an
    attacker could use. The username is only returned once authenticated."""
    mode = auth.auth_mode()
    state = auth.evaluate_session(session)
    locked = auth.lock_remaining_seconds(_client_ip())

    body = {
        'mode': mode,                       # setup | login | error
        'authenticated': state == auth.SESSION_OK,
        'session_state': state,             # ok | none | expired | credentials_changed
        'locked': locked > 0,
        'lock_remaining_seconds': locked,
        'recovery_hint': auth.recovery_hint(),
        'password_rule': auth.PASSWORD_RULE,    # not secret: the setup page shows it
    }
    if mode == auth.MODE_ERROR:
        body['message'] = ('config.yaml could not be read, so the appliance '
                           'cannot tell whether it has been set up. Fix the '
                           'file on the host, then reload.')
    row = auth.session_user(session)
    if row:
        body['user'] = row['username']
        body['role'] = row['role']
        body['role_label'] = users.ROLE_LABELS.get(row['role'], row['role'])
        body['must_change'] = auth.must_change(session)
        # What the UI may show. The server enforces each one regardless.
        rank = users.rank(row['role'])
        body['can'] = {
            'write': rank >= users.rank(users.OPERATOR),
            'settings': rank >= users.rank(users.ADMIN),
            'users': rank >= users.rank(users.ADMIN),
            'host': row['role'] == users.SUPERADMIN,
            'tools': sorted(t for t, need in auth.access_policy.TOOLS.items()
                            if rank >= users.rank(need)),
        }
    return jsonify(body)


@auth_bp.route('/api/auth/setup', methods=['POST'])
def auth_setup():
    """Claim the appliance: set the Super-admin's name + password. On a box
    that already has users this is the recovery path: it resets the
    Super-admin only and leaves every other account as it is.

    Needs BOTH config.yaml first_login: true AND the one-time setup token from
    data/state/backend/setup_token (printed by install.sh and by
    `sudo scripts/reset-login.sh`). The flag alone used to be enough, so the
    first visitor from the network could claim the box (QA): reaching the page
    is not proof of standing at the host, reading a root-only file is.
    """
    if auth.auth_mode() != auth.MODE_SETUP:
        auth.audit('setup_rejected', request, reason='not_in_setup_mode')
        return jsonify({
            'success': False,
            'error': 'setup_closed',
            'message': 'This appliance is already set up. Use the login page.',
        }), 403

    client = _client_ip()
    auth.forgive_lockouts_on_new_token()
    locked = auth.lock_remaining_seconds(client)
    if locked > 0:
        auth.audit('setup_rejected', request, reason='locked',
                   lock_remaining_seconds=locked)
        return jsonify({
            'success': False,
            'error': 'locked',
            'lock_remaining_seconds': locked,
            'message': f'Too many failed attempts. Try again in '
                       f'{_humanize(locked)}.',
        }), 429
    # The token is a guessable-in-theory secret behind an unauthenticated
    # endpoint, so it gets the same per-client throttle and strikes as login.
    if not auth.throttle_ok(client):
        return jsonify({'success': False, 'error': 'too_fast',
                        'message': 'Slow down and try again.'}), 429

    if auth.read_setup_token() is None:
        # Spent by an earlier setup, or a box that reached setup mode without
        # one (hand-edited first_login, upgrade migration). Fail closed.
        auth.audit('setup_rejected', request, reason='no_setup_token')
        return jsonify({
            'success': False,
            'error': 'setup_token_missing',
            'message': ('No setup token exists on this appliance. On the '
                        'appliance, run sudo scripts/reset-login.sh and enter '
                        'the token it prints.'),
        }), 403

    data = request.get_json(silent=True) or {}
    user = (data.get('username') or '').strip()
    password = data.get('password') or ''
    confirm = data.get('confirm') or ''

    if not auth.setup_token_matches(data.get('setup_token')):
        lock_seconds = auth.register_failure(client)
        auth.audit('setup_rejected', request, username_value=user,
                   reason='bad_setup_token',
                   locked_for_seconds=lock_seconds or None)
        return jsonify({
            'success': False,
            'error': 'bad_setup_token',
            'attempts_before_lock': auth.failures_before_lock(client),
            'message': ('The setup token is missing or wrong. It was printed at '
                        'the end of the install; to get a new one, run sudo '
                        'scripts/reset-login.sh on the appliance.'),
        }), 403

    if not user or not password:
        return jsonify({'success': False, 'error': 'missing_fields',
                        'message': 'Username and password are both required.'}), 400
    if password != confirm:
        return jsonify({'success': False, 'error': 'mismatch',
                        'message': 'The two passwords do not match.'}), 400
    problem = auth.password_problem(password, user)
    if problem:
        return jsonify({'success': False, 'error': 'weak_password',
                        'message': f'Password rejected: {problem}. '
                                   f'Rule: {auth.PASSWORD_RULE}.'}), 400
    existing = users.by_name(user)
    name_problem = None if existing else users.name_problem(user)
    if name_problem or (existing and existing['role'] != users.SUPERADMIN):
        return jsonify({'success': False, 'error': 'bad_username',
                        'message': (f'User name rejected: {name_problem}.' if name_problem else
                                    'That name belongs to another user. Choose another '
                                    'name for the Super-admin.')}), 400

    # ORDER IS SECURITY-CRITICAL: spend the token, close setup, THEN store the
    # credential. Spending first makes the token single-use even for two
    # concurrent requests (only one unlink succeeds). Closing before storing
    # means a failed config write never leaves the setup page served WITH a
    # credential set. Every failure here fails closed: no token left, setup
    # refused, and reset-login.sh is the way back.
    if not auth.consume_setup_token():
        auth.audit('setup_rejected', request, username_value=user,
                   reason='setup_token_already_used')
        return jsonify({
            'success': False,
            'error': 'setup_token_missing',
            'message': ('The setup token was already used. Run sudo '
                        'scripts/reset-login.sh on the appliance for a new one.'),
        }), 403

    if not auth.write_first_login(False):
        auth.audit('setup_failed', request, username_value=user,
                   reason='config_write_failed')
        return jsonify({
            'success': False,
            'error': 'config_write_failed',
            'message': ('Could not update config.yaml, so setup was not '
                        'completed. Check the backend logs and the file '
                        'permissions on config.yaml, then run sudo '
                        'scripts/reset-login.sh for a new setup token.'),
        }), 500

    if not auth.set_credential(user, password):
        auth.audit('setup_failed', request, username_value=user,
                   reason='credential_store_failed')
        return jsonify({
            'success': False,
            'error': 'store_failed',
            'message': ('Could not store the credential. Run sudo '
                        'scripts/reset-login.sh on the appliance and try again.'),
        }), 500

    row = users.superadmin()
    auth.start_session(session, row)
    auth.audit('setup', request, username_value=row['username'], role=row['role'])
    return _expire_tool_sessions(jsonify({'success': True, 'user': row['username']}))


@auth_bp.route('/api/auth/login', methods=['POST'])
def auth_login():
    if auth.auth_mode() == auth.MODE_ERROR:
        return jsonify({'success': False, 'error': 'config_error',
                        'message': 'config.yaml could not be read.'}), 503

    client = _client_ip()
    locked = auth.lock_remaining_seconds(client)
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
    if not auth.throttle_ok(client):
        return jsonify({'success': False, 'error': 'too_fast',
                        'message': 'Slow down and try again.'}), 429

    # No password_problem() here on purpose: boxes set up before the rule
    # existed (some with 123123) must keep signing in.
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

    row = auth.authenticate(user, password)
    if row is None:
        lock_seconds = auth.register_failure(client)
        remaining = auth.failures_before_lock(client)
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

    auth.reset_lockout(client)
    auth.start_session(session, row)
    users.touch_login(row['id'])
    # A publicly known password still gets in -- old boxes must -- and so does a
    # one-time password from an Admin, but either session can do nothing except
    # choose a new password (gate_decision).
    temp = bool(row.get('temp_expires'))
    must_change = temp or auth.needs_change(password)
    if must_change:
        session['must_change'] = auth.MUST_CHANGE_TEMP if temp else True
    auth.audit('login_ok', request, username_value=row['username'], role=row['role'],
               must_change=must_change or None)
    return _expire_tool_sessions(jsonify({'success': True, 'user': row['username'],
                                          'role': row['role'], 'must_change': must_change}))


@auth_bp.route('/api/auth/logout', methods=['POST'])
def auth_logout():
    user = session.get('user')
    session.clear()
    auth.audit('logout', request, username_value=user)
    return _expire_tool_sessions(jsonify({'success': True}))


@auth_bp.route('/api/auth/change-password', methods=['POST'])
def auth_change_password():
    """Requires the current password even though the caller already holds a
    session — a stolen cookie should not be enough to lock the real operator
    out of their own appliance."""
    row = auth.session_user(session)
    if row is None:
        return jsonify({'success': False, 'error': 'unauthenticated'}), 401

    data = request.get_json(silent=True) or {}
    current = data.get('current_password') or ''
    new_password = data.get('new_password') or ''
    confirm = data.get('confirm') or ''
    user = row['username']

    refused = password_guess_guard()
    if refused:
        return refused
    ok = auth.verify_password(user, current)
    password_guess_result(ok)
    if not ok:
        auth.audit('password_change_failed', request, username_value=user,
                   reason='wrong_current_password')
        return jsonify({'success': False, 'error': 'invalid_credentials',
                        'message': 'Current password is incorrect.'}), 401
    if new_password != confirm:
        return jsonify({'success': False, 'error': 'mismatch',
                        'message': 'The two passwords do not match.'}), 400
    # Same rule as setup (auth.password_problem): a known or weak dashboard
    # password on a tool that controls every endpoint was a QA finding. A box
    # still on an old short password keeps logging in; it just cannot change
    # TO one.
    problem = auth.password_problem(new_password, user)
    if not problem and new_password == current:
        problem = 'it is the same as the current one'
    if problem:
        return jsonify({'success': False, 'error': 'weak_password',
                        'message': f'Password rejected: {problem}. '
                                   f'Rule: {auth.PASSWORD_RULE}.'}), 400

    try:
        auth.set_user_password(row, new_password)
    except Exception:
        return jsonify({'success': False, 'error': 'store_failed',
                        'message': 'Could not store the new password.'}), 500

    # The new generation ends every OTHER session of this user; re-issue this
    # one so the person who just changed their own password stays signed in.
    auth.start_session(session, users.get(row['id']))
    auth.audit('password_changed', request, username_value=user, role=row['role'])
    return jsonify({'success': True})


def password_guess_guard():
    refused = auth.password_guess_refusal(_client_ip())
    return (jsonify(refused[0]), refused[1]) if refused else None


def password_guess_result(ok: bool) -> None:
    auth.password_guess_result(_client_ip(), ok)


@auth_bp.route('/api/auth/reauth', methods=['POST'])
def auth_reauth():
    """Step-up: re-enter the password before user management (ASVS 7.5.3).
    Wrong answers count toward the same per-address lockout as login."""
    row = auth.session_user(session)
    if row is None:
        return jsonify({'success': False, 'error': 'unauthenticated'}), 401
    refused = password_guess_guard()
    if refused:
        return refused
    data = request.get_json(silent=True) or {}
    ok = auth.verify_password(row['username'], data.get('password') or '')
    password_guess_result(ok)
    if not ok:
        auth.audit('reauth_failed', request, username_value=row['username'])
        return jsonify({'success': False, 'error': 'invalid_credentials',
                        'message': 'Password is incorrect.'}), 401
    auth.mark_reauthenticated(session)
    auth.audit('reauth', request, username_value=row['username'])
    return jsonify({'success': True})


@auth_bp.route('/api/auth/verify', methods=['GET'])
def auth_verify():
    """Target of nginx's `auth_request` for every bundled tool, /velociraptor/
    and /api/uploads/ — paths that proxy to non-Flask upstreams and so can only
    be gated in nginx. `?tool=<name>` (access_policy.TOOLS) also checks the
    role: 401 means sign in, 403 means this role may not open that tool.

    No SQLite on this path: nginx fires one subrequest per tus PATCH, which is
    ~2000 of them for a 10 GB upload against a single-process threaded server.
    The user row comes from users' in-process snapshot. The X-Intact-User
    response header is for nginx's access log (auth_request_set); nginx never
    passes it to the browser.
    """
    # No default: an auth_request location that forgets ?tool= is refused,
    # never quietly given some role's access.
    tool = request.args.get('tool') or ''
    if auth.evaluate_session(session) != auth.SESSION_OK or auth.must_change(session):
        return '', 401
    # The access log and VolWeb's /__intact_sso page print it. New names are
    # [a-z0-9._-] (users.name_problem); a name migrated from the single-user
    # login was never checked, so it is cleaned here, once, for every reader.
    who = {'X-Intact-User': re.sub(r'[^a-z0-9._-]', '_', (session.get('user') or '-').lower()) or '-'}
    if not auth.tool_allowed(session, tool):
        return '', 403, who         # logged too: who tried a tool above their role
    # nginx injects this user's own credential into the tool request, so a
    # state change from another origin (a script on another port of the box,
    # which is "same-site") would run as them. The tool's own pages are its own
    # origin and pass (Sec-Fetch-Site: same-origin).
    if auth.csrf_problem(request.headers.get('X-Original-Method') or 'GET', request.headers):
        auth.audit('denied', request, username_value=session.get('user'), reason='csrf_rejected',
                   endpoint=f'tool:{tool}')
        return '', 403, who
    # The user's own credential for this tool, for nginx to inject
    # (services/tool_accounts). Absent: the tool shows its own login.
    from services import tool_accounts
    value = tool_accounts.auth_value(users.get(session.get('uid')), tool)
    if value:
        who['X-Intact-Auth'] = value
    return '', 200, who


def _humanize(seconds: int) -> str:
    minutes = max(1, int(round(seconds / 60.0)))
    if minutes < 60:
        return f'{minutes} minute{"s" if minutes != 1 else ""}'
    hours = minutes / 60.0
    if hours < 24:
        rounded = int(hours) if hours == int(hours) else round(hours, 1)
        return f'{rounded} hour{"s" if rounded != 1 else ""}'
    return f'{round(hours / 24.0, 1)} days'
