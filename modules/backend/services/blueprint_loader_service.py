#!/usr/bin/env python3
"""
Blueprint Loader Service - Loads blueprints from YAML files

This service:
1. Loads bundled default blueprints from /app/config/default_blueprints.yaml
2. Optionally loads user overrides from /app/data/blueprints/*.yaml
3. Merges and resolves references ($artifact_list_name -> actual list)
4. Provides clean API for seeding

Directory structure:
- /app/config/default_blueprints.yaml - Bundled defaults (in container, NOT volume-mounted)
- /app/data/blueprints/*.yaml - User overrides (volume-mounted, persists)
"""

import os
import yaml
from typing import Dict, List, Any, Optional
from copy import deepcopy

# Paths - bundled defaults are in /app/config (NOT volume-mounted)
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


def _resolve_reference(value: Any, artifact_lists: Dict, settings: Dict) -> Any:
    """Resolve $reference strings to actual values.

    Args:
        value: The value to resolve (may be a $reference string)
        artifact_lists: Dict of artifact list names to artifact arrays
        settings: Dict of settings template names to settings objects

    Returns:
        Resolved value (deep copy of referenced list/settings, or original value)
    """
    if isinstance(value, str) and value.startswith('$'):
        ref_name = value[1:]  # Remove $ prefix
        # Check artifact_lists first
        if ref_name in artifact_lists:
            return deepcopy(artifact_lists[ref_name])
        # Then check settings
        if ref_name in settings:
            return deepcopy(settings[ref_name])
        print(f"[BLUEPRINT-LOADER] Warning: Unresolved reference: {value}", flush=True)
    return value


def _resolve_blueprint(bp: Dict, artifact_lists: Dict, settings: Dict) -> Dict:
    """Resolve all references in a blueprint.

    Args:
        bp: Blueprint dict with potential $references
        artifact_lists: Dict of artifact list names to artifact arrays
        settings: Dict of settings template names to settings objects

    Returns:
        Blueprint dict with all references resolved to actual values
    """
    resolved = deepcopy(bp)

    # Resolve artifacts reference
    if 'artifacts' in resolved:
        resolved['artifacts'] = _resolve_reference(
            resolved['artifacts'], artifact_lists, settings
        )

    # Resolve settings reference
    if 'settings' in resolved:
        resolved['settings'] = _resolve_reference(
            resolved['settings'], artifact_lists, settings
        )

    return resolved


def load_bundled_defaults() -> Dict:
    """Load bundled default blueprints from the shipped YAML file.

    Returns:
        Dict containing version, artifact_lists, default_settings, and blueprints
    """
    # Try container path first, then dev path
    for path in [BUNDLED_DEFAULTS_PATH, DEV_DEFAULTS_PATH]:
        data = _load_yaml_file(path)
        if data:
            print(f"[BLUEPRINT-LOADER] Loaded defaults from {path}", flush=True)
            return data

    print("[BLUEPRINT-LOADER] Warning: No default blueprints file found", flush=True)
    return {}


def load_user_overrides() -> Dict[str, List[Dict]]:
    """Load user override blueprints from /data/blueprints/ directory.

    User can create YAML files to override or add to default blueprints:
    - velociraptor.yaml - Override/add velociraptor blueprints
    - agentic.yaml - Override/add agentic blueprints
    - timesketch.yaml - Override/add timesketch blueprints

    Returns:
        Dict with keys 'velociraptor', 'agentic', 'timesketch', each containing list of blueprints
    """
    overrides = {
        'velociraptor': [],
        'agentic': [],
        'timesketch': []
    }

    if not os.path.exists(USER_OVERRIDES_DIR):
        return overrides

    for filename in ['velociraptor.yaml', 'agentic.yaml', 'timesketch.yaml']:
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

    This is the main API function. It:
    1. Loads bundled defaults from /app/config/default_blueprints.yaml
    2. Resolves all $references to actual artifact lists and settings
    3. Loads user overrides from /app/data/blueprints/*.yaml (if any)
    4. Merges overrides with defaults (matching IDs replace, new IDs add)

    Returns:
        Dict with keys: 'velociraptor', 'agentic', 'timesketch'
        Each value is a list of fully resolved blueprint dicts.

    Example:
        blueprints = get_all_blueprints()
        for bp in blueprints['velociraptor']:
            print(bp['name'], len(bp['artifacts']))
    """
    # Load bundled defaults
    defaults = load_bundled_defaults()

    # Extract reference tables
    artifact_lists = defaults.get('artifact_lists', {})
    default_settings = defaults.get('default_settings', {})

    # Build result from defaults, resolving references
    result = {
        'velociraptor': [],
        'agentic': [],
        'timesketch': []
    }

    for bp_type in ['velociraptor', 'agentic', 'timesketch']:
        for bp in defaults.get(bp_type, []):
            resolved = _resolve_blueprint(bp, artifact_lists, default_settings)
            result[bp_type].append(resolved)

    # Load and merge user overrides
    overrides = load_user_overrides()

    for bp_type in ['velociraptor', 'agentic', 'timesketch']:
        override_list = overrides.get(bp_type, [])
        if not override_list:
            continue

        # Build map of existing IDs
        existing_ids = {bp['id']: idx for idx, bp in enumerate(result[bp_type])}

        for override_bp in override_list:
            bp_id = override_bp.get('id')
            if not bp_id:
                continue

            # Resolve any references in override (user can use $references too)
            resolved = _resolve_blueprint(override_bp, artifact_lists, default_settings)

            if bp_id in existing_ids:
                # Replace existing
                result[bp_type][existing_ids[bp_id]] = resolved
                print(f"[BLUEPRINT-LOADER] Override replaced: {bp_type}/{bp_id}", flush=True)
            else:
                # Add new
                result[bp_type].append(resolved)
                print(f"[BLUEPRINT-LOADER] Override added: {bp_type}/{bp_id}", flush=True)

    # Log summary
    for bp_type in result:
        print(f"[BLUEPRINT-LOADER] {bp_type}: {len(result[bp_type])} blueprints loaded", flush=True)

    return result


def get_artifact_lists() -> Dict[str, List[str]]:
    """Get all defined artifact lists for reference.

    Returns:
        Dict of artifact list names to artifact arrays
    """
    defaults = load_bundled_defaults()
    return defaults.get('artifact_lists', {})


# For testing
if __name__ == "__main__":
    import json
    blueprints = get_all_blueprints()
    print(json.dumps(blueprints, indent=2))
