#!/usr/bin/env python3
"""
Configuration settings for Intact.AI Dashboard Backend
"""

import os
import yaml


def load_main_config():
    """Load the main config.yaml from the project root."""
    config_paths = [
        '/app/config.yaml',  # Mounted in Docker
        os.path.join(os.path.dirname(__file__), '../../config.yaml'),  # Development
        '/home/tenroot/intact/config.yaml'  # Fallback
    ]

    for path in config_paths:
        if os.path.exists(path):
            try:
                with open(path, 'r') as f:
                    return yaml.safe_load(f)
            except Exception as e:
                print(f"[CONFIG] Error loading {path}: {e}", flush=True)

    return {}


def get_installation_options():
    """Get installation options from config.yaml."""
    config = load_main_config()
    return config.get('options', {})


def is_module_enabled(module_name):
    """Check if a module is enabled in config.yaml."""
    config = load_main_config()
    mod = config.get('modules', {}).get(module_name, {})
    if isinstance(mod, dict):
        return mod.get('enabled', True)
    return True

# Artifact name mapping - keeping only essential automations
ARTIFACT_MAPPING = {
    'kape': 'Windows.KapeFiles.Targets'
}

# Artifact definitions
ARTIFACTS = {
    "kape": {
        "name": "Windows.KapeFiles.Targets",
        "display_name": "KAPE Collection",
        "parameters": {
            "Device": "C:",
            "VSSAnalysis": "Y",
            "_KapeTriage": "Y"
        },
        "timeout": 7200,
        "cpu_limit": 30
    }
}

# Velociraptor configuration
VELOCIRAPTOR_CONTAINER = "intact_velociraptor"
VELOCIRAPTOR_API_CONFIG_PATH = "/velociraptor/api.config.yaml"
VELOCIRAPTOR_SNAPSHOT_PATH = "/var./client_info/snapshot.json"

# Timesketch configuration (from environment variables)
# Note: intact_timesketch_web is the container name in Docker network
TIMESKETCH_CONFIG = {
    'host': os.environ.get('TIMESKETCH_HOST', 'http://intact_timesketch_web:5000'),
    'username': os.environ.get('TIMESKETCH_USER', 'nof'),
    'password': os.environ.get('TIMESKETCH_PASS', '123123')
}

# Plaso configuration
PLASO_OUTPUT_DIR = "/tmp/plaso"
PLASO_VERSION = os.environ.get('PLASO_VERSION', '20260119')
PLASO_IMAGE = f"log2timeline/plaso:{PLASO_VERSION}"
PLASO_CPUS = "2"
PLASO_MEMORY = "4g"


def get_plaso_image():
    """Get Plaso image, reading fresh from .env if available.

    This allows upgrades to take effect without restarting the backend.
    """
    # Try workdir path first (inside container), then local path
    env_paths = [
        '/app/workdir/modules/backend/.env',
        os.path.join(os.path.dirname(__file__), '.env')
    ]
    for env_file in env_paths:
        if os.path.exists(env_file):
            with open(env_file) as f:
                for line in f:
                    if line.startswith('PLASO_VERSION='):
                        version = line.strip().split('=', 1)[1]
                        return f"log2timeline/plaso:{version}"
    return PLASO_IMAGE  # fallback to static value


def _fresh_image_from_env(var_name: str, image_fmt: str, fallback: str) -> str:
    """Read a version var fresh from the backend .env and format the image
    ref, so an upgrade takes effect without restarting the backend (same
    trick as get_plaso_image). `image_fmt` is e.g. 'anssi/dfir-o365rc:{}'."""
    env_paths = [
        '/app/workdir/modules/backend/.env',
        os.path.join(os.path.dirname(__file__), '.env'),
    ]
    for env_file in env_paths:
        if os.path.exists(env_file):
            with open(env_file) as f:
                for line in f:
                    if line.startswith(f'{var_name}='):
                        return image_fmt.format(line.strip().split('=', 1)[1])
    return fallback


# Azure DFIR-O365RC configuration (Unified Audit Log collection on demand).
# Upstream publishes only ':latest', so DFIR_O365RC_VERSION is normally 'latest'.
DFIR_O365RC_VERSION = os.environ.get('DFIR_O365RC_VERSION', 'latest')
DFIR_O365RC_IMAGE = f"anssi/dfir-o365rc:{DFIR_O365RC_VERSION}"


def get_dfir_o365rc_image():
    """DFIR-O365RC image, read fresh from .env so upgrades apply without restart."""
    return _fresh_image_from_env('DFIR_O365RC_VERSION', 'anssi/dfir-o365rc:{}', DFIR_O365RC_IMAGE)

# Velociraptor data path inside container (where collections are stored)
VELOCIRAPTOR_DATA_PATH = "/var."

# Elasticsearch configuration
ELASTICSEARCH_CONFIG = {
    'host': os.environ.get('ELASTICSEARCH_HOST', 'elasticsearch'),
    'port': int(os.environ.get('ELASTICSEARCH_PORT', '9200'))
}

