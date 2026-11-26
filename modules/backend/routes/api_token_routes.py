#!/usr/bin/env python3
"""API tokens: list, create, revoke (services/api_tokens.py).

Session only: auth_service refuses every api_tokens.* endpoint to a token, so
a leaked token cannot mint another. Creating one needs a recent password
(step_up in access_policy.POLICY). Everyone manages their own; an Admin may
also list and revoke the tokens of users below them (users.may_manage), the
Super-admin everyone's.
"""

from flask import Blueprint, jsonify, request, session

from services import api_tokens
from services import auth_service as auth
from services import users

api_tokens_bp = Blueprint('api_tokens', __name__)


def _refuse(message, status=403):
    return jsonify({'success': False, 'error': 'forbidden', 'message': message}), status


def _actor():
    """The signed-in user. None on a loopback request: the box has no tokens."""
    return auth.session_user(session)


@api_tokens_bp.route('/api/tokens', methods=['GET'])
def list_tokens():
    actor = _actor()
    if actor is None:
        return _refuse('Sign in to manage API tokens.', 401)
    name = (request.args.get('user') or '').strip().lower()
    target = users.by_name(name) if name else actor
    if target is None and users.rank(actor['role']) >= users.rank(users.ADMIN):
        return _refuse('No such user.', 404)
    # Below Admin, a missing name answers like a forbidden one: no probing
    # which user names exist (only Admins may list users).
    if target is None or (target['id'] != actor['id'] and not users.may_manage(actor, target)):
        return _refuse('You can only see the tokens of users with a role below your own.')
    return jsonify({'user': target['username'], 'tokens': api_tokens.list_for(target['id']),
                    'max_days': api_tokens.MAX_DAYS})


@api_tokens_bp.route('/api/tokens', methods=['POST'])
def create_token():
    actor = _actor()
    if actor is None:
        return _refuse('Sign in to manage API tokens.', 401)
    if auth.must_enroll(actor):
        # The gate already stops such a session; kept here so the rule is visible.
        return _refuse('Set up two-step login before you create a token.')
    data = request.get_json(silent=True) or {}
    name = str(data.get('name') or '').strip()
    scope = data.get('scope') or ''
    days = data.get('days')
    problem = api_tokens.problem(name, scope, days)
    if problem:
        return _refuse(f'Token not created: {problem}.', 400)
    raw, tok = api_tokens.create(actor, name, scope, days, actor['username'])
    auth.audit('token_created', request, username_value=actor['username'],
               token=tok['prefix'], scope=scope, days=days, name=name)
    # Shown once. Only its hash is stored.
    return jsonify({'success': True, 'token': raw, 'prefix': tok['prefix'],
                    'expires_at': tok['expires_at'], 'item': tok})


@api_tokens_bp.route('/api/tokens/<int:token_id>', methods=['DELETE'])
def revoke_token(token_id):
    actor = _actor()
    if actor is None:
        return _refuse('Sign in to manage API tokens.', 401)
    tok = api_tokens.get(token_id)
    owner = users.get(tok['user_id']) if tok else None
    # One answer for "no such token" and "not yours": ids must not be probeable.
    if tok is None or (tok['user_id'] != actor['id'] and not users.may_manage(actor, owner)):
        return _refuse('No such token.', 404)
    api_tokens.delete(token_id)
    auth.audit('token_revoked', request, username_value=actor['username'],
               token=tok['prefix'], owner=owner['username'] if owner else None)
    return jsonify({'success': True})
