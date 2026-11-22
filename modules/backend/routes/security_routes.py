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
"""
import json
import os

from flask import Blueprint, jsonify

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
