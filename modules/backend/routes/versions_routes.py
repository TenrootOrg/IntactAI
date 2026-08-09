"""Read-only "what is installed" endpoint.

All that remains of routes/upgrade_routes.py. Upgrading is a host-side
operation now (`sudo bash upgrade.sh`), so there is nothing here that
applies, prepares, uploads or plans anything -- the dashboard shows the
operator what is running and tells them the command to change it.

The pins are read straight from the per-module .env files, which are what
compose actually interpolates, rather than from config.yaml's `versions:`
block -- that is the operator's *intent*, and the two differ whenever an
upgrade has been requested but not applied. A module whose primary container
does not exist reports "Not installed" no matter what its .env says: a
release package seeds pins for every module, including the ones this box has
switched off.
"""

import os

from flask import Blueprint, jsonify

versions_bp = Blueprint('versions', __name__)

WORKDIR = os.environ.get('INTACT_PATH', '/app/workdir')

# module -> (env file relative to WORKDIR, key, primary container)
# Mirrors _PIN_SOURCE in lib/upgrade/plan.sh; keep the two in step.
_PINS = {
    'elk':          ('modules/elk/.env',          'ELASTIC_VERSION',        'intact_elasticsearch'),
    'iris':         ('modules/iris/.env',         'IRIS_VERSION',           'intact_iris_app'),
    'timesketch':   ('modules/timesketch/.env',   'TIMESKETCH_VERSION',     'intact_timesketch_web'),
    'velociraptor': ('modules/velociraptor/.env', 'VELOCIRAPTOR_VERSION',   'intact_velociraptor'),
    'volweb':       ('modules/volweb/.env',       'VOLWEB_BACKEND_VERSION', 'intact_volweb_backend'),
    'portainer':    ('modules/portainer/.env',    'PORTAINER_VERSION',      'intact_portainer'),
    'plaso':        ('modules/backend/.env',      'PLASO_VERSION',          None),
    'aws_sigma':    ('modules/backend/.env',      'CLOUDTRAIL_VERSION',     None),
    'o365rc':       ('modules/backend/.env',      'DFIR_O365RC_VERSION',    None),
}


def _read_env_var(rel_path, key):
    path = os.path.join(WORKDIR, rel_path)
    try:
        with open(path, encoding='utf-8') as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith('#') or '=' not in line:
                    continue
                name, _, value = line.partition('=')
                if name.strip() == key:
                    return value.strip().strip('"').strip("'")
    except OSError:
        pass
    return None


def _container_exists(name):
    if not name:
        return True          # nothing to check; the pin is the truth
    try:
        import subprocess
        return subprocess.run(['docker', 'inspect', name],
                              capture_output=True, timeout=10).returncode == 0
    except Exception:        # noqa: BLE001 -- never fail the page over this
        return False


@versions_bp.route('/api/upgrade/current-versions', methods=['GET'])
def get_current_versions_route():
    """Every module's installed version, plus the platform's release tag."""
    versions = {}

    for module, (rel, key, container) in _PINS.items():
        pin = _read_env_var(rel, key)
        if not pin or not _container_exists(container):
            versions[module] = 'Not installed'
        else:
            versions[module] = pin

    # The platform's own version: the VERSION file is the release tag and is
    # what upgrade.sh stamps; BACKEND_VERSION is the image tag and is the
    # fallback for older boxes whose VERSION file was never written.
    intact = None
    try:
        with open(os.path.join(WORKDIR, 'VERSION'), encoding='utf-8') as fh:
            intact = fh.read().strip()
    except OSError:
        pass
    versions['intact'] = intact or _read_env_var('modules/backend/.env',
                                                 'BACKEND_VERSION') or 'unknown'

    return jsonify({
        'success': True,
        'versions': versions,
        # Told to the UI rather than hardcoded there, so the two cannot drift.
        'upgrade_command': 'sudo bash upgrade.sh <release-tag>',
        'list_command': 'sudo bash upgrade.sh --list',
    })
