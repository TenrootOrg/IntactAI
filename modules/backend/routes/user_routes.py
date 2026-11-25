#!/usr/bin/env python3
"""User management: list, create, change role, enable/disable, one-time
password reset, Super-admin transfer.

Who may call each route is services/access_policy.POLICY (Admin and up, with
a recent password for every change). The RANK rule is enforced here, per
target: services/users.may_manage / may_grant. Users are disabled, never
deleted: their name stays on every run and audit line they left.
"""

from flask import Blueprint, jsonify, request, session

from services import auth_service as auth
from services import users

users_bp = Blueprint('users', __name__)


def _actor():
    return auth.session_user(session)


def _refuse(message, status=403):
    return jsonify({'success': False, 'error': 'forbidden', 'message': message}), status


@users_bp.route('/api/users', methods=['GET'])
def list_users():
    actor = _actor()
    return jsonify({'users': users.list_all(), 'me': actor['username'],
                    'roles': [{'role': r, 'label': users.ROLE_LABELS[r],
                               'grantable': users.may_grant(actor, r)} for r in users.ROLES]})


@users_bp.route('/api/users', methods=['POST'])
def create_user():
    actor = _actor()
    data = request.get_json(silent=True) or {}
    name = (data.get('username') or '').strip().lower()
    role = data.get('role') or ''
    problem = users.name_problem(name)
    if problem:
        return _refuse(f'User name rejected: {problem}.', 400)
    if users.by_name(name):
        return _refuse('A user with that name already exists. Names are never reused.', 409)
    if not users.may_grant(actor, role):
        return _refuse('You can only create users with a role below your own.')
    temp = auth.create_user(name, role, actor['username'])
    auth.audit('user_created', request, username_value=actor['username'],
               target=name, role=role)
    # Shown once. Only its hash is stored, and it works only to choose a password.
    return jsonify({'success': True, 'username': name, 'temporary_password': temp,
                    'expires_hours': users.TEMP_PASSWORD_HOURS})


@users_bp.route('/api/users/<username>', methods=['PATCH'])
def update_user(username):
    actor = _actor()
    target = users.by_name(username)
    if target is None:
        return _refuse('No such user.', 404)
    if not users.may_manage(actor, target):
        return _refuse('You can only change users with a role below your own.')
    data = request.get_json(silent=True) or {}
    if 'role' in data:
        role = data.get('role') or ''
        if not users.may_grant(actor, role):
            return _refuse('You can only give a role below your own.')
        if role != target['role']:
            users.set_role(target['id'], role)
            auth.audit('user_role_changed', request, username_value=actor['username'],
                       target=target['username'], old_role=target['role'], role=role)
    if 'enabled' in data:
        enabled = bool(data.get('enabled'))
        if enabled != bool(target['enabled']):
            users.set_enabled(target['id'], enabled)
            auth.audit('user_enabled' if enabled else 'user_disabled', request,
                       username_value=actor['username'], target=target['username'])
    return jsonify({'success': True, 'user': users.public(users.by_name(username))})


@users_bp.route('/api/users/<username>/reset-password', methods=['POST'])
def reset_password(username):
    actor = _actor()
    target = users.by_name(username)
    if target is None:
        return _refuse('No such user.', 404)
    if not users.may_manage(actor, target):
        return _refuse('You can only reset users with a role below your own.')
    temp = auth.reset_user_password(target)
    auth.audit('user_password_reset', request, username_value=actor['username'],
               target=target['username'])
    return jsonify({'success': True, 'username': target['username'],
                    'temporary_password': temp, 'expires_hours': users.TEMP_PASSWORD_HOURS})


@users_bp.route('/api/users/transfer-superadmin', methods=['POST'])
def transfer_superadmin():
    """The Super-admin hands the role to an enabled Admin and becomes an Admin.
    Only from the Super-admin's own session, with the password typed again."""
    actor = _actor()
    client = auth.client_address(request)
    refused = auth.password_guess_refusal(client)
    if refused:
        return jsonify(refused[0]), refused[1]
    data = request.get_json(silent=True) or {}
    ok = auth.verify_password(actor['username'], data.get('current_password') or '')
    auth.password_guess_result(client, ok)
    if not ok:
        auth.audit('superadmin_transfer_failed', request, username_value=actor['username'],
                   reason='wrong_current_password')
        return _refuse('Current password is incorrect.', 401)
    target = users.by_name(data.get('to') or '')
    if target is None or target['role'] != users.ADMIN or not target['enabled']:
        return _refuse('The new Super-admin must be an enabled Admin.', 400)
    auth.transfer_superadmin(actor, target)
    auth.audit('superadmin_transferred', request, username_value=actor['username'],
               target=target['username'])
    # Our own generation moved too: re-issue this session as the Admin we now are.
    auth.start_session(session, users.get(actor['id']))
    return jsonify({'success': True, 'superadmin': target['username']})
