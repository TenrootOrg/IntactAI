"""Dashboard banner: which modules still run on a publicly known password, and
which had a password changed for them that the operator has not seen yet.

An upgraded old box keeps the passwords that machines log in with (Elasticsearch
`elastic`, the Timesketch user, VolWeb admin) even when they are a public
default -- changing them under a running tool locks the backend out of the
evidence; the operator changes them with scripts/apply-passwords.sh. Human-only
defaults ARE rotated by the upgrade, and the operator needs to know to look them
up. lib/credentials_apply.sh records both in data/state/default-passwords.json,
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
