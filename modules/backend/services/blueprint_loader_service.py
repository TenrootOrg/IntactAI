#!/usr/bin/env python3
"""
Blueprint Loader Service - Loads blueprints from YAML files

This service:
1. Loads bundled default blueprints from /app/config/default_blueprints.yaml
2. Optionally loads user overrides from /app/data/blueprints/*.yaml
3. Merges overrides with defaults

Directory structure:
- /app/config/default_blueprints.yaml - Bundled defaults (in container)
- /app/data/blueprints/*.yaml - User overrides (volume-mounted)
"""

import os
import yaml
from typing import Dict, List, Any, Optional
from copy import deepcopy

# Paths
BUNDLED_DEFAULTS_PATH = '/app/config/default_blueprints.yaml'
USER_OVERRIDES_DIR = '/app/data/blueprints'

# Fallback paths for local development
DEV_DEFAULTS_PATH = os.path.join(
    os.path.dirname(__file__), '..', 'config', 'default_blueprints.yaml'
)


def _load_yaml_file(path: str) -> Optional[Dict]:
    """Load a YAML file and return its contents."""
    try:
        if os.path.exists(path):
            with open(path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f)
    except Exception as e:
        print(f"[BLUEPRINT-LOADER] Error loading {path}: {e}", flush=True)
    return None


def load_bundled_defaults() -> Dict:
    """Load bundled default blueprints from the shipped YAML file."""
    for path in [BUNDLED_DEFAULTS_PATH, DEV_DEFAULTS_PATH]:
        data = _load_yaml_file(path)
        if data:
            print(f"[BLUEPRINT-LOADER] Loaded defaults from {path}", flush=True)
            return data

    print("[BLUEPRINT-LOADER] Warning: No default blueprints file found", flush=True)
    return {}


def load_user_overrides() -> Dict[str, List[Dict]]:
    """Load user override blueprints from /data/blueprints/ directory."""
    overrides = {
        'velociraptor': [],
        'timesketch': [],
        'memory': [],
    }

    if not os.path.exists(USER_OVERRIDES_DIR):
        return overrides

    for filename in ['velociraptor.yaml', 'timesketch.yaml', 'memory.yaml']:
        path = os.path.join(USER_OVERRIDES_DIR, filename)
        data = _load_yaml_file(path)
        if data and isinstance(data, list):
            key = filename.replace('.yaml', '')
            overrides[key] = data
            print(f"[BLUEPRINT-LOADER] Loaded {len(data)} user overrides from {filename}",
                  flush=True)

    return overrides


def get_all_blueprints() -> Dict[str, List[Dict]]:
    """Load and merge all blueprints.

    Returns:
        Dict with keys: 'velociraptor', 'agentic', 'timesketch'
        (agentic returns same as velociraptor for backwards compatibility)
    """
    defaults = load_bundled_defaults()

    # Build result directly from YAML (no more $references)
    result = {
        'velociraptor': [],
        'timesketch': [],
        'memory': [],
    }

    for bp_type in ['velociraptor', 'timesketch', 'memory']:
        for bp in defaults.get(bp_type, []):
            result[bp_type].append(deepcopy(bp))

    # Load and merge user overrides
    overrides = load_user_overrides()

    for bp_type in ['velociraptor', 'timesketch', 'memory']:
        override_list = overrides.get(bp_type, [])
        if not override_list:
            continue

        existing_ids = {bp['id']: idx for idx, bp in enumerate(result[bp_type])}

        for override_bp in override_list:
            bp_id = override_bp.get('id')
            if not bp_id:
                continue

            if bp_id in existing_ids:
                result[bp_type][existing_ids[bp_id]] = deepcopy(override_bp)
                print(f"[BLUEPRINT-LOADER] Override replaced: {bp_type}/{bp_id}", flush=True)
            else:
                result[bp_type].append(deepcopy(override_bp))
                print(f"[BLUEPRINT-LOADER] Override added: {bp_type}/{bp_id}", flush=True)

    # Backwards compatibility: agentic returns the velociraptor-stored collection
    # blueprints. Match the current naming ("Velociraptor Agentic: …" / id
    # agentic_*) — the old "[Agentic]" bracket marker is no longer used.
    result['agentic'] = [bp for bp in result['velociraptor']
                         if 'agentic' in (bp.get('name', '') + ' ' + bp.get('id', '')).lower()]

    # Log summary
    for bp_type in result:
        print(f"[BLUEPRINT-LOADER] {bp_type}: {len(result[bp_type])} blueprints loaded", flush=True)

    return result


def get_artifact_lists() -> Dict[str, List[str]]:
    """Get unique artifacts from all blueprints (for reference/validation)."""
    blueprints = get_all_blueprints()
    artifacts = set()
    for bp_list in blueprints.values():
        for bp in bp_list:
            artifacts.update(bp.get('artifacts', []))
    return {'all_artifacts': sorted(list(artifacts))}


# For testing
if __name__ == "__main__":
    import json
    blueprints = get_all_blueprints()
    print(json.dumps(blueprints, indent=2))
