#!/usr/bin/env python3
"""
Configuration settings for MSSP Dashboard Backend
"""

import os
import yaml


def load_main_config():
    """Load the main config.yaml from the project root."""
    config_paths = [
        '/app/config.yaml',  # Mounted in Docker
        os.path.join(os.path.dirname(__file__), '../../config.yaml'),  # Development
        '/home/tenroot/new-mssp/config.yaml'  # Fallback
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
VELOCIRAPTOR_CONTAINER = "mssp_velociraptor"
VELOCIRAPTOR_API_CONFIG_PATH = "/velociraptor/api.config.yaml"
VELOCIRAPTOR_SNAPSHOT_PATH = "/var./client_info/snapshot.json"

# Timesketch configuration (from environment variables)
# Note: mssp_timesketch_web is the container name in Docker network
TIMESKETCH_CONFIG = {
    'host': os.environ.get('TIMESKETCH_HOST', 'http://mssp_timesketch_web:5000'),
    'username': os.environ.get('TIMESKETCH_USER', 'nof'),
    'password': os.environ.get('TIMESKETCH_PASS', '123123')
}

# Plaso configuration
PLASO_OUTPUT_DIR = "/tmp/plaso"
PLASO_VERSION = os.environ.get('PLASO_VERSION', '20260119')
PLASO_IMAGE = f"log2timeline/plaso:{PLASO_VERSION}"
PLASO_CPUS = "2"
PLASO_MEMORY = "4g"

# Velociraptor data path inside container (where collections are stored)
VELOCIRAPTOR_DATA_PATH = "/var."

# Elasticsearch configuration
ELASTICSEARCH_CONFIG = {
    'host': os.environ.get('ELASTICSEARCH_HOST', 'elasticsearch'),
    'port': int(os.environ.get('ELASTICSEARCH_PORT', '9200'))
}

# IRIS configuration (DFIR-IRIS case management)
# Note: mssp_iris_app is the container name in Docker network
IRIS_CONFIG = {
    'host': os.environ.get('IRIS_HOST', 'https://mssp_iris_app:8000'),
    'external_host': os.environ.get('IRIS_EXTERNAL_HOST', 'https://localhost:8443'),
    'username': os.environ.get('IRIS_USER', 'administrator'),
    'password': os.environ.get('IRIS_PASS', '123123')
}
