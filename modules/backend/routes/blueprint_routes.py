#!/usr/bin/env python3
"""
Blueprint Routes - Manage artifact blueprints for hunt configurations
Separated into Velociraptor and Agentic blueprint stores.

Blueprint definitions are loaded from YAML files:
- /app/config/default_blueprints.yaml - Bundled defaults (in container)
- /app/data/blueprints/*.yaml - User overrides (optional, persists)
"""

import time
from flask import Blueprint, jsonify, request

from services.file_storage_service import (
    save_velociraptor_blueprint,
    load_velociraptor_blueprints,
    get_velociraptor_blueprint,
    delete_velociraptor_blueprint,
    save_agentic_blueprint,
    load_agentic_blueprints,
    get_agentic_blueprint,
    delete_agentic_blueprint,
    save_timesketch_blueprint,
    load_timesketch_blueprints,
    get_timesketch_blueprint,
    delete_timesketch_blueprint,
)
from services.blueprint_loader_service import get_all_blueprints, get_artifact_lists

blueprint_bp = Blueprint('blueprints', __name__)


# ============================================================================
# Seeding - Load from YAML files
# ============================================================================

def seed_default_blueprints():
    """Seed default blueprints from YAML configuration files.

    Loads blueprints from:
    - /app/config/default_blueprints.yaml (bundled defaults)
    - /app/data/blueprints/*.yaml (user overrides, optional)

    Seeds to SQLite if not already present.
    """
    # Load all blueprints from YAML files
    blueprints = get_all_blueprints()

    # Velociraptor blueprints
    velo_defaults = blueprints.get('velociraptor', [])
    existing_velo = load_velociraptor_blueprints()

    if not existing_velo:
        for bp in velo_defaults:
            save_velociraptor_blueprint(bp)
        print(f"[BLUEPRINTS] Seeded {len(velo_defaults)} velociraptor blueprints from YAML", flush=True)
    else:
        existing_map = {bp.get('id'): bp for bp in existing_velo}
        for default_bp in velo_defaults:
            existing = existing_map.get(default_bp['id'])
            if not existing:
                save_velociraptor_blueprint(default_bp)
                print(f"[BLUEPRINTS] Re-seeded missing velociraptor default: {default_bp['id']}", flush=True)
            elif existing.get('is_default') and not existing.get('name', '').startswith('[Velociraptor]'):
                existing['name'] = default_bp['name']
                save_velociraptor_blueprint(existing)
                print(f"[BLUEPRINTS] Updated velociraptor blueprint name: {default_bp['id']}", flush=True)

    # Agentic blueprints
    agentic_defaults = blueprints.get('agentic', [])
    existing_agentic = load_agentic_blueprints()

    if not existing_agentic:
        for bp in agentic_defaults:
            save_agentic_blueprint(bp)
        print(f"[BLUEPRINTS] Seeded {len(agentic_defaults)} agentic blueprints from YAML", flush=True)
    else:
        existing_map = {bp.get('id'): bp for bp in existing_agentic}
        for default_bp in agentic_defaults:
            existing = existing_map.get(default_bp['id'])
            if not existing:
                save_agentic_blueprint(default_bp)
                print(f"[BLUEPRINTS] Re-seeded missing agentic default: {default_bp['id']}", flush=True)
            elif existing.get('is_default') and not existing.get('name', '').startswith('[Agentic]'):
                existing['name'] = default_bp['name']
                save_agentic_blueprint(existing)
                print(f"[BLUEPRINTS] Updated agentic blueprint name: {default_bp['id']}", flush=True)

    # Timesketch blueprints
    ts_defaults = blueprints.get('timesketch', [])
    existing_ts = load_timesketch_blueprints()

    if not existing_ts:
        for bp in ts_defaults:
            save_timesketch_blueprint(bp)
        print(f"[BLUEPRINTS] Seeded {len(ts_defaults)} timesketch blueprints from YAML", flush=True)
    else:
        existing_map = {bp.get('id'): bp for bp in existing_ts}
        for bp in ts_defaults:
            existing = existing_map.get(bp['id'])
            if not existing:
                save_timesketch_blueprint(bp)
                print(f"[BLUEPRINTS] Re-seeded missing timesketch default: {bp['id']}", flush=True)
            elif existing.get('is_default') and not existing.get('settings', {}).get('collection_timeout'):
                existing['settings'] = existing.get('settings', {})
                existing['settings']['collection_timeout'] = 10000
                save_timesketch_blueprint(existing)
                print(f"[BLUEPRINTS] Updated timesketch default: {bp['id']}", flush=True)


# Seed on module load
seed_default_blueprints()


# ============================================================================
# Unified Forensics Blueprint API Route (combines velociraptor + agentic)
# ============================================================================

@blueprint_bp.route('/api/blueprints/forensics', methods=['GET'])
def list_forensics_blueprints():
    """Get all forensics blueprints (velociraptor + agentic combined)

    Returns blueprints from both tables with [Velociraptor] and [Agentic] prefixes.
    All forensics modules should use this unified endpoint.
    """
    try:
        all_blueprints = []

        # Load velociraptor blueprints with [Velociraptor] prefix
        velo_blueprints = load_velociraptor_blueprints()
        for bp in velo_blueprints:
            name = bp.get('name', '')
            # Add prefix if not already present
            if not name.startswith('[Velociraptor]'):
                bp['name'] = f"[Velociraptor] {name}"
            bp['blueprint_type'] = 'velociraptor'
            all_blueprints.append(bp)

        # Load agentic blueprints with [Agentic] prefix
        agentic_blueprints = load_agentic_blueprints()
        for bp in agentic_blueprints:
            name = bp.get('name', '')
            # Add prefix if not already present
            if not name.startswith('[Agentic]'):
                bp['name'] = f"[Agentic] {name}"
            bp['blueprint_type'] = 'agentic'
            all_blueprints.append(bp)

        # Sort: Velociraptor first, then Agentic, alphabetically within each group
        all_blueprints.sort(key=lambda x: (0 if x.get('blueprint_type') == 'velociraptor' else 1, x.get('name', '')))

        return jsonify({"blueprints": all_blueprints})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ============================================================================
# Velociraptor Blueprint API Routes
# ============================================================================

@blueprint_bp.route('/api/blueprints/velociraptor', methods=['GET'])
def list_velociraptor_blueprints():
    """Get all velociraptor blueprints"""
    try:
        blueprints = load_velociraptor_blueprints()
        return jsonify({"blueprints": blueprints})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@blueprint_bp.route('/api/blueprints/velociraptor', methods=['POST'])
def create_velociraptor_blueprint():
    """Create a new velociraptor blueprint"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400
        if not data.get('name'):
            return jsonify({"error": "Blueprint name is required"}), 400
        if not data.get('artifacts') or len(data['artifacts']) == 0:
            return jsonify({"error": "At least one artifact is required"}), 400

        blueprint_id = data.get('id') or f"custom_{int(time.time() * 1000)}"
        blueprint = {
            "id": blueprint_id,
            "name": data['name'],
            "description": data.get('description', ''),
            "is_default": False,
            "artifacts": data['artifacts'],
            "settings": data.get('settings', {"hunt_expiry": 120, "timeout": 3600, "cpu_limit": 50})
        }

        result = save_velociraptor_blueprint(blueprint)
        if result:
            return jsonify({"success": True, "blueprint": blueprint}), 201
        else:
            return jsonify({"error": "Failed to save blueprint"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@blueprint_bp.route('/api/blueprints/velociraptor/<blueprint_id>', methods=['GET'])
def get_velociraptor_blueprint_by_id(blueprint_id):
    """Get a specific velociraptor blueprint"""
    try:
        bp = get_velociraptor_blueprint(blueprint_id)
        if bp:
            return jsonify(bp)
        return jsonify({"error": "Blueprint not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@blueprint_bp.route('/api/blueprints/velociraptor/<blueprint_id>', methods=['PUT'])
def update_velociraptor_blueprint_route(blueprint_id):
    """Update a velociraptor blueprint"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400

        existing = get_velociraptor_blueprint(blueprint_id)
        if not existing:
            return jsonify({"error": "Blueprint not found"}), 404

        data['id'] = blueprint_id
        data['is_default'] = existing.get('is_default', False)
        data['created_at'] = existing.get('created_at')

        result = save_velociraptor_blueprint(data)
        if result:
            return jsonify({"success": True, "blueprint": data})
        else:
            return jsonify({"error": "Failed to update blueprint"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@blueprint_bp.route('/api/blueprints/velociraptor/<blueprint_id>', methods=['DELETE'])
def delete_velociraptor_blueprint_route(blueprint_id):
    """Delete a velociraptor blueprint (defaults cannot be deleted)"""
    try:
        bp = get_velociraptor_blueprint(blueprint_id)
        if not bp:
            return jsonify({"error": "Blueprint not found"}), 404
        if bp.get('is_default'):
            return jsonify({"error": "Cannot delete default blueprints"}), 400

        result = delete_velociraptor_blueprint(blueprint_id)
        if result:
            return jsonify({"success": True})
        else:
            return jsonify({"error": "Failed to delete blueprint"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ============================================================================
# Agentic Blueprint API Routes
# ============================================================================

@blueprint_bp.route('/api/blueprints/agentic', methods=['GET'])
def list_agentic_blueprints():
    """Get all agentic blueprints"""
    try:
        blueprints = load_agentic_blueprints()
        return jsonify({"blueprints": blueprints})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@blueprint_bp.route('/api/blueprints/agentic', methods=['POST'])
def create_agentic_blueprint():
    """Create a new agentic blueprint"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400
        if not data.get('name'):
            return jsonify({"error": "Blueprint name is required"}), 400
        if not data.get('artifacts') or len(data['artifacts']) == 0:
            return jsonify({"error": "At least one artifact is required"}), 400

        blueprint_id = data.get('id') or f"custom_{int(time.time() * 1000)}"
        blueprint = {
            "id": blueprint_id,
            "name": data['name'],
            "description": data.get('description', ''),
            "is_default": False,
            "artifacts": data['artifacts'],
            "settings": data.get('settings', {"hunt_expiry": 120, "timeout": 3600, "cpu_limit": 50})
        }

        result = save_agentic_blueprint(blueprint)
        if result:
            return jsonify({"success": True, "blueprint": blueprint}), 201
        else:
            return jsonify({"error": "Failed to save blueprint"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@blueprint_bp.route('/api/blueprints/agentic/<blueprint_id>', methods=['GET'])
def get_agentic_blueprint_by_id(blueprint_id):
    """Get a specific agentic blueprint"""
    try:
        bp = get_agentic_blueprint(blueprint_id)
        if bp:
            return jsonify(bp)
        return jsonify({"error": "Blueprint not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@blueprint_bp.route('/api/blueprints/agentic/<blueprint_id>', methods=['PUT'])
def update_agentic_blueprint_route(blueprint_id):
    """Update an agentic blueprint"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400

        existing = get_agentic_blueprint(blueprint_id)
        if not existing:
            return jsonify({"error": "Blueprint not found"}), 404

        data['id'] = blueprint_id
        data['is_default'] = existing.get('is_default', False)
        data['created_at'] = existing.get('created_at')

        result = save_agentic_blueprint(data)
        if result:
            return jsonify({"success": True, "blueprint": data})
        else:
            return jsonify({"error": "Failed to update blueprint"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@blueprint_bp.route('/api/blueprints/agentic/<blueprint_id>', methods=['DELETE'])
def delete_agentic_blueprint_route(blueprint_id):
    """Delete an agentic blueprint (defaults cannot be deleted)"""
    try:
        bp = get_agentic_blueprint(blueprint_id)
        if not bp:
            return jsonify({"error": "Blueprint not found"}), 404
        if bp.get('is_default'):
            return jsonify({"error": "Cannot delete default blueprints"}), 400

        result = delete_agentic_blueprint(blueprint_id)
        if result:
            return jsonify({"success": True})
        else:
            return jsonify({"error": "Failed to delete blueprint"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ============================================================================
# Timesketch Blueprint API Routes
# ============================================================================

@blueprint_bp.route('/api/blueprints/timesketch', methods=['GET'])
def list_timesketch_blueprints():
    """Get all timesketch blueprints"""
    try:
        blueprints = load_timesketch_blueprints()
        return jsonify({"blueprints": blueprints})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@blueprint_bp.route('/api/blueprints/timesketch', methods=['POST'])
def create_timesketch_blueprint():
    """Create a new timesketch blueprint"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400
        if not data.get('name'):
            return jsonify({"error": "Blueprint name is required"}), 400

        blueprint_id = data.get('id') or f"custom_{int(time.time() * 1000)}"
        # Ensure settings has collection_timeout with default
        settings = data.get('settings', {})
        if 'collection_timeout' not in settings:
            settings['collection_timeout'] = 10000

        blueprint = {
            "id": blueprint_id,
            "name": data['name'],
            "description": data.get('description', ''),
            "is_default": False,
            "settings": settings if settings else {
                "kape_target": "_KapeTriage",
                "plaso_parser": "win7",
                "plaso_workers": 2,
                "plaso_hasher": "none",
                "plaso_hasher_size": 100,
                "collection_timeout": 10000
            }
        }

        result = save_timesketch_blueprint(blueprint)
        if result:
            return jsonify({"success": True, "blueprint": blueprint}), 201
        else:
            return jsonify({"error": "Failed to save blueprint"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@blueprint_bp.route('/api/blueprints/timesketch/<blueprint_id>', methods=['GET'])
def get_timesketch_blueprint_by_id(blueprint_id):
    """Get a specific timesketch blueprint"""
    try:
        bp = get_timesketch_blueprint(blueprint_id)
        if bp:
            return jsonify(bp)
        return jsonify({"error": "Blueprint not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@blueprint_bp.route('/api/blueprints/timesketch/<blueprint_id>', methods=['PUT'])
def update_timesketch_blueprint_route(blueprint_id):
    """Update a timesketch blueprint"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400

        existing = get_timesketch_blueprint(blueprint_id)
        if not existing:
            return jsonify({"error": "Blueprint not found"}), 404

        data['id'] = blueprint_id
        data['is_default'] = existing.get('is_default', False)
        data['created_at'] = existing.get('created_at')

        result = save_timesketch_blueprint(data)
        if result:
            return jsonify({"success": True, "blueprint": data})
        else:
            return jsonify({"error": "Failed to update blueprint"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@blueprint_bp.route('/api/blueprints/timesketch/<blueprint_id>', methods=['DELETE'])
def delete_timesketch_blueprint_route(blueprint_id):
    """Delete a timesketch blueprint (defaults cannot be deleted)"""
    try:
        bp = get_timesketch_blueprint(blueprint_id)
        if not bp:
            return jsonify({"error": "Blueprint not found"}), 404
        if bp.get('is_default'):
            return jsonify({"error": "Cannot delete default blueprints"}), 400

        result = delete_timesketch_blueprint(blueprint_id)
        if result:
            return jsonify({"success": True})
        else:
            return jsonify({"error": "Failed to delete blueprint"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500
