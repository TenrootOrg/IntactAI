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
    # Agentic functions are aliases to velociraptor (same storage)
    save_agentic_blueprint,
    load_agentic_blueprints,
    save_timesketch_blueprint,
    load_timesketch_blueprints,
    get_timesketch_blueprint,
    delete_timesketch_blueprint,
    save_memory_blueprint,
    load_memory_blueprints,
    get_memory_blueprint,
    delete_memory_blueprint,
)
from services.blueprint_loader_service import get_all_blueprints, get_artifact_lists

blueprint_bp = Blueprint('blueprints', __name__)


# ============================================================================
# Seeding - Load from YAML files
# ============================================================================

def _prune_orphaned_defaults(bp_type, yaml_defaults, load_fn, delete_fn):
    """Remove default (is_default) blueprint rows whose id is no longer shipped
    in default_blueprints.yaml — i.e. a default that was RENAMED or REMOVED in a
    new release. Without this, upgrading leaves the OLD default in the DB
    alongside the NEW one ("both new and old"). User-created blueprints
    (is_default=false) are NEVER touched.

    Guard: if the YAML produced no defaults for this type (a load failure),
    prune NOTHING — a broken/empty YAML must never nuke every default.
    """
    yaml_ids = {b.get('id') for b in (yaml_defaults or []) if b.get('id')}
    if not yaml_ids:
        return
    for row in load_fn():
        if row.get('is_default') and row.get('id') not in yaml_ids:
            delete_fn(row['id'])
            print(f"[BLUEPRINTS] Pruned orphaned {bp_type} default "
                  f"(renamed/removed this release): {row['id']}", flush=True)


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
            elif existing.get('is_default'):
                # Always sync default blueprints from YAML (artifacts, name, description)
                existing['name'] = default_bp['name']
                existing['description'] = default_bp.get('description', '')
                existing['artifacts'] = default_bp['artifacts']
                existing['settings'] = default_bp.get('settings', existing.get('settings', {}))
                save_velociraptor_blueprint(existing)
                print(f"[BLUEPRINTS] Synced velociraptor default from YAML: {default_bp['id']} ({len(default_bp['artifacts'])} artifacts)", flush=True)

    # Agentic blueprints - always sync defaults from YAML
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
            elif existing.get('is_default'):
                # Always sync default blueprints from YAML (artifacts, name, description)
                existing['name'] = default_bp['name']
                existing['description'] = default_bp.get('description', '')
                existing['artifacts'] = default_bp['artifacts']
                existing['settings'] = default_bp.get('settings', existing.get('settings', {}))
                save_agentic_blueprint(existing)
                print(f"[BLUEPRINTS] Synced agentic default from YAML: {default_bp['id']} ({len(default_bp['artifacts'])} artifacts)", flush=True)

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
                continue
            if not existing.get('is_default'):
                continue
            # Sync name + description from YAML for default blueprints —
            # mirrors the velociraptor branch above. Lets us copy-edit the
            # default labels in default_blueprints.yaml and have them land
            # on the next backend restart without a manual DB update.
            changed = False
            if existing.get('name') != bp.get('name'):
                existing['name'] = bp.get('name')
                changed = True
            if existing.get('description') != bp.get('description', ''):
                existing['description'] = bp.get('description', '')
                changed = True
            # Backfill any missing keys we've added to default TS blueprints
            # over time. Only touches defaults; user-customised blueprints stay
            # untouched.
            settings = existing.get('settings') or {}
            # Default jumped from 10000 → 100000 (~28h); the old value was
            # killing legitimate long KAPE collections. Only bump rows that
            # are still at the old default — anything else is user choice.
            if not settings.get('collection_timeout') or settings.get('collection_timeout') == 10000:
                settings['collection_timeout'] = 100000
                changed = True
            if not settings.get('timesketch_processing_timeout'):
                # 3 days. The old 10000s default killed long uploads while
                # Timesketch was still happily indexing — see
                # services/timesketch_service.py wait_timeout flow.
                settings['timesketch_processing_timeout'] = 259200
                changed = True
            if changed:
                existing['settings'] = settings
                save_timesketch_blueprint(existing)
                print(f"[BLUEPRINTS] Updated timesketch default: {bp['id']}", flush=True)

    # Memory-forensics blueprints
    from services.storage.blueprint_store import (
        load_memory_blueprints,
        save_memory_blueprint,
        delete_memory_blueprint,
    )

    # Memory blueprints that previously shipped as defaults and have
    # since been removed from default_blueprints.yaml. Listed explicitly
    # (rather than computed as "in DB but not YAML") so a YAML mistake
    # never silently nukes a real default. Each entry is deleted on
    # startup if the DB row is still flagged is_default — an operator
    # who customized the name or settings (is_default=false) is left
    # alone.
    DEPRECATED_MEMORY_BLUEPRINT_IDS = {
        # Removed when YARA became a memory-page checkbox: was just
        # the curated 12-plugin set with `mode: plugin`, redundant
        # with the renamed memory_layered_default ("Curated standard").
        'memory_plugin_only',
        # The four "fast" scenario blueprints were collapsed into their
        # "deep" counterparts (renamed to plain scenario names — Process
        # Anomalies / Persistence / Network / Credentials). Operators
        # who want a faster variant can clone a default and prune the
        # plugin checkboxes.
        'memory_process_fast',
        'memory_persistence_fast',
        'memory_network_fast',
        'memory_credentials_fast',
    }

    mem_defaults = blueprints.get('memory', [])
    existing_mem = load_memory_blueprints()

    if not existing_mem:
        for bp in mem_defaults:
            save_memory_blueprint(bp)
        print(f"[BLUEPRINTS] Seeded {len(mem_defaults)} memory blueprints from YAML", flush=True)
    else:
        existing_map = {bp.get('id'): bp for bp in existing_mem}
        for default_bp in mem_defaults:
            existing = existing_map.get(default_bp['id'])
            if not existing:
                save_memory_blueprint(default_bp)
                print(f"[BLUEPRINTS] Re-seeded missing memory default: {default_bp['id']}", flush=True)
            elif existing.get('is_default'):
                # Sync defaults from YAML — operator's custom blueprints stay untouched.
                existing['name'] = default_bp['name']
                existing['description'] = default_bp.get('description', '')
                existing['settings'] = default_bp.get('settings', existing.get('settings', {}))
                save_memory_blueprint(existing)
                print(f"[BLUEPRINTS] Synced memory default from YAML: {default_bp['id']}", flush=True)

        # Cleanup pass — remove deprecated defaults that linger in DB
        # from older seeds. Skip rows the operator already customized.
        for bp_id in DEPRECATED_MEMORY_BLUEPRINT_IDS:
            existing = existing_map.get(bp_id)
            if existing and existing.get('is_default'):
                delete_memory_blueprint(bp_id)
                print(f"[BLUEPRINTS] Removed deprecated memory default: {bp_id}", flush=True)

    # Generic orphan prune: drop default (is_default) rows no longer shipped in
    # the YAML, so upgrading a release that renamed/removed a default doesn't
    # leave the old copy sitting alongside the new one. The velociraptor table
    # holds both velociraptor + agentic defaults (agentic saves there too), so
    # pruning it against the velociraptor YAML ids covers both. Memory is handled
    # by the explicit list above. Custom (is_default=false) blueprints are never
    # touched; a broken YAML (no defaults) prunes nothing.
    _prune_orphaned_defaults('velociraptor', velo_defaults,
                             load_velociraptor_blueprints, delete_velociraptor_blueprint)
    _prune_orphaned_defaults('timesketch', ts_defaults,
                             load_timesketch_blueprints, delete_timesketch_blueprint)


# Seed on module load
seed_default_blueprints()


# ============================================================================
# Unified Forensics Blueprint API Route (combines velociraptor + agentic)
# ============================================================================

# Which blueprints lead the list, and in what order. Everything else follows
# alphabetically. Keyed by id so a rename cannot reshuffle the defaults.
PREFERRED_FIRST_BLUEPRINTS = {
    'agentic_quick_wins': 0,     # Velociraptor Agentic QuickWins Windows
    'agentic_linux_triage': 1,   # …then the Linux twin
}


@blueprint_bp.route('/api/blueprints/forensics', methods=['GET'])
def list_forensics_blueprints():
    """Get all forensics blueprints (velociraptor table contains both types)

    Velociraptor blueprints have [Velociraptor] prefix in name.
    Agentic blueprints have [Agentic] prefix in name.
    Both are stored in the same velociraptor table.
    """
    try:
        # All blueprints are now in velociraptor table
        all_blueprints = load_velociraptor_blueprints()

        # Set blueprint_type based on name prefix
        for bp in all_blueprints:
            name = bp.get('name', '')
            if '[Agentic]' in name:
                bp['blueprint_type'] = 'agentic'
            else:
                bp['blueprint_type'] = 'velociraptor'

        # Sort: Velociraptor first, then Agentic, alphabetically within each group
        # Velociraptor first, then the PREFERRED default, then by name.
        #
        # The middle term is the whole point. Every one of these dropdowns —
        # Collection, Hunt and the offline collector — reads this one endpoint
        # and shows entry [0] as the pre-selected option, so whatever sorts
        # first IS the default an operator gets. Sorting on the name alone made
        # that an accident of the alphabet: "…QuickWins Linux" beats
        # "…QuickWins Windows" on the L, and a Windows-first estate opened on a
        # Linux triage every time.
        #
        # Ordered by id, not by name, so renaming a blueprint cannot silently
        # move it. Reordering default_blueprints.yaml would NOT have worked:
        # nothing preserves file order — the store has a fixed column set, and
        # this sort is what the UI actually sees.
        all_blueprints.sort(key=lambda x: (
            0 if x.get('blueprint_type') == 'velociraptor' else 1,
            0 if x.get('id') in PREFERRED_FIRST_BLUEPRINTS else 1,
            PREFERRED_FIRST_BLUEPRINTS.get(x.get('id'), 0),
            x.get('name', '')))

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
# Agentic Blueprint API Routes (delegates to velociraptor - same storage)
# ============================================================================
# Note: Agentic and Velociraptor blueprints share the same storage.
# The only distinction is the [Agentic] prefix in the name.
# These routes are kept for backwards compatibility.

@blueprint_bp.route('/api/blueprints/agentic', methods=['GET'])
def list_agentic_blueprints():
    """Get agentic (Velociraptor Collector) blueprints — the client-targeted
    collection blueprints, filtered from the shared velociraptor storage. Matches
    the current naming ("Velociraptor Agentic: …" / id agentic_*); the old
    "[Agentic]" bracket marker is no longer used, which silently returned 0."""
    try:
        all_bp = load_velociraptor_blueprints()
        agentic = [bp for bp in all_bp
                   if 'agentic' in (bp.get('name', '') + ' ' + bp.get('id', '')).lower()]
        return jsonify({"blueprints": agentic})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@blueprint_bp.route('/api/blueprints/agentic', methods=['POST'])
def create_agentic_blueprint():
    """Create agentic blueprint (stored in velociraptor table)"""
    return create_velociraptor_blueprint()


@blueprint_bp.route('/api/blueprints/agentic/<blueprint_id>', methods=['GET'])
def get_agentic_blueprint_by_id(blueprint_id):
    """Get agentic blueprint by ID (from velociraptor storage)"""
    return get_velociraptor_blueprint_by_id(blueprint_id)


@blueprint_bp.route('/api/blueprints/agentic/<blueprint_id>', methods=['PUT'])
def update_agentic_blueprint_route(blueprint_id):
    """Update agentic blueprint (in velociraptor storage)"""
    return update_velociraptor_blueprint_route(blueprint_id)


@blueprint_bp.route('/api/blueprints/agentic/<blueprint_id>', methods=['DELETE'])
def delete_agentic_blueprint_route(blueprint_id):
    """Delete agentic blueprint (from velociraptor storage)"""
    return delete_velociraptor_blueprint_route(blueprint_id)


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


# ============================================================================
# Memory Forensics Blueprints — VolWeb plugin sets
# ============================================================================
# Same shape as timesketch CRUD but the settings payload is the Vol3
# plugin_set + acquisition knobs (cpu_limit, max_bytes). The Memory page
# also reads these via /api/memory/blueprints (memory_routes.py) — both
# endpoints hit the same blueprints_memory SQLite table, so changes
# made in the blueprints UI flow through to the Memory dropdown
# immediately.

@blueprint_bp.route('/api/blueprints/memory', methods=['GET'])
def list_memory_blueprints_route():
    """Get all memory blueprints"""
    try:
        blueprints = load_memory_blueprints()
        return jsonify({"blueprints": blueprints})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@blueprint_bp.route('/api/blueprints/memory', methods=['POST'])
def create_memory_blueprint():
    """Create a new memory blueprint"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400
        if not data.get('name'):
            return jsonify({"error": "Blueprint name is required"}), 400

        blueprint_id = data.get('id') or f"custom_{int(time.time() * 1000)}"
        settings = data.get('settings') or {}

        blueprint = {
            "id": blueprint_id,
            "name": data['name'],
            "description": data.get('description', ''),
            "is_default": False,
            "settings": settings,
        }

        result = save_memory_blueprint(blueprint)
        if result:
            return jsonify({"success": True, "blueprint": blueprint}), 201
        return jsonify({"error": "Failed to save blueprint"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@blueprint_bp.route('/api/blueprints/memory/<blueprint_id>', methods=['GET'])
def get_memory_blueprint_by_id(blueprint_id):
    """Get a specific memory blueprint"""
    try:
        bp = get_memory_blueprint(blueprint_id)
        if bp:
            return jsonify(bp)
        return jsonify({"error": "Blueprint not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@blueprint_bp.route('/api/blueprints/memory/<blueprint_id>', methods=['PUT'])
def update_memory_blueprint_route(blueprint_id):
    """Update a memory blueprint"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400

        existing = get_memory_blueprint(blueprint_id)
        if not existing:
            return jsonify({"error": "Blueprint not found"}), 404

        data['id'] = blueprint_id
        data['is_default'] = existing.get('is_default', False)
        data['created_at'] = existing.get('created_at')

        result = save_memory_blueprint(data)
        if result:
            return jsonify({"success": True, "blueprint": data})
        return jsonify({"error": "Failed to update blueprint"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@blueprint_bp.route('/api/blueprints/memory/<blueprint_id>', methods=['DELETE'])
def delete_memory_blueprint_route(blueprint_id):
    """Delete a memory blueprint (defaults cannot be deleted)"""
    try:
        bp = get_memory_blueprint(blueprint_id)
        if not bp:
            return jsonify({"error": "Blueprint not found"}), 404
        if bp.get('is_default'):
            return jsonify({"error": "Cannot delete default blueprints"}), 400

        result = delete_memory_blueprint(blueprint_id)
        if result:
            return jsonify({"success": True})
        return jsonify({"error": "Failed to delete blueprint"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500
