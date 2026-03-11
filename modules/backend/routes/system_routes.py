#!/usr/bin/env python3
"""
System Routes - System endpoints (config, health, maintenance)
"""

from flask import Blueprint, jsonify, request
import threading
import time

from services import (
    create_automation_run,
    add_log_to_run,
    update_run_status
)
from services.velociraptor_init_service import initialize_velociraptor_artifacts
from services.file_storage_service import load_frontend_config, save_frontend_config

system_bp = Blueprint('system', __name__)

# Default configuration (agentic settings only - velociraptor uses container's api.config.yaml)
DEFAULT_CONFIG = {
    "agentic": {
        "llm_mode": "online",
        "offline_llm": {
            "provider": "ollama",
            "model": "llama3.3:70b",
            "url": "http://localhost:11434",
            "batch_size": 100
        },
        "online_llm": {
            "provider": "claude",
            "api_key": "",
            "model": "claude-sonnet-4-6",
            "batch_size": 100
        }
    }
}


def _deep_merge(base, update):
    """Deep merge update into base dict."""
    for key, value in update.items():
        if key in base and isinstance(base[key], dict) and isinstance(value, dict):
            _deep_merge(base[key], value)
        else:
            base[key] = value


def _load_config():
    """Load configuration from database or return defaults."""
    try:
        saved_config = load_frontend_config()
        if saved_config:
            config = DEFAULT_CONFIG.copy()
            _deep_merge(config, saved_config)
            return config
    except Exception as e:
        print(f"Error loading config: {e}")
    return DEFAULT_CONFIG.copy()


def _save_config(config):
    """Save configuration to database."""
    save_frontend_config(config)

@system_bp.route('/api/test', methods=['GET', 'POST'])
def test_endpoint():
    """Simple test endpoint"""
    return jsonify({"status": "ok", "method": request.method})

@system_bp.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({"status": "healthy", "service": "mssp-backend"})


# =============================================================================
# Configuration Endpoints (persistent storage)
# =============================================================================

@system_bp.route('/api/config', methods=['GET'])
def get_config():
    """Get frontend configuration."""
    try:
        config = _load_config()
        return jsonify(config)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@system_bp.route('/api/config', methods=['PUT', 'POST'])
def save_config():
    """Save frontend configuration."""
    try:
        config = request.json
        if not config:
            return jsonify({"error": "No configuration provided"}), 400

        _save_config(config)
        return jsonify({"status": "saved", "message": "Configuration saved successfully"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# =============================================================================
# Cloud Configuration Endpoints
# =============================================================================

# Default cloud configuration
DEFAULT_CLOUD_CONFIG = {
    "provider": "aws",
    "aws": {
        "access_key_id": "",
        "secret_access_key": "",
        "region": "us-east-1",
        "session_token": ""
    },
    "azure": {
        "tenant_id": "",
        "client_id": "",
        "client_secret": "",
        "subscription_id": ""
    }
}


def _load_cloud_config():
    """Load cloud configuration from database."""
    from services.file_storage_service import load_cloud_config
    try:
        saved = load_cloud_config()
        if saved:
            config = DEFAULT_CLOUD_CONFIG.copy()
            _deep_merge(config, saved)
            return config
    except Exception as e:
        print(f"Error loading cloud config: {e}")
    return DEFAULT_CLOUD_CONFIG.copy()


def _save_cloud_config(config):
    """Save cloud configuration to database."""
    from services.file_storage_service import save_cloud_config
    save_cloud_config(config)


@system_bp.route('/api/config/cloud', methods=['GET'])
def get_cloud_config():
    """Get cloud provider configuration."""
    try:
        config = _load_cloud_config()
        # Mask sensitive fields for GET requests
        masked = config.copy()
        if masked.get('aws', {}).get('secret_access_key'):
            masked['aws']['secret_access_key'] = '••••••••' + masked['aws']['secret_access_key'][-4:]
        if masked.get('aws', {}).get('session_token'):
            masked['aws']['session_token'] = '••••••••'
        if masked.get('azure', {}).get('client_secret'):
            masked['azure']['client_secret'] = '••••••••'
        return jsonify(masked)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@system_bp.route('/api/config/cloud', methods=['PUT', 'POST'])
def save_cloud_config_endpoint():
    """Save cloud provider configuration."""
    try:
        config = request.json
        if not config:
            return jsonify({"error": "No configuration provided"}), 400

        # Load existing config to preserve masked fields
        existing = _load_cloud_config()

        # Don't overwrite with masked values
        if config.get('aws', {}).get('secret_access_key', '').startswith('••••'):
            config['aws']['secret_access_key'] = existing.get('aws', {}).get('secret_access_key', '')
        if config.get('aws', {}).get('session_token') == '••••••••':
            config['aws']['session_token'] = existing.get('aws', {}).get('session_token', '')
        if config.get('azure', {}).get('client_secret') == '••••••••':
            config['azure']['client_secret'] = existing.get('azure', {}).get('client_secret', '')

        _save_cloud_config(config)
        print(f"[CLOUD] Saved cloud config for provider: {config.get('provider', 'unknown')}", flush=True)
        return jsonify({"status": "saved", "message": "Cloud configuration saved successfully"})
    except Exception as e:
        print(f"[CLOUD] Error saving config: {e}", flush=True)
        return jsonify({"error": str(e)}), 500


@system_bp.route('/api/maintenance/run', methods=['POST'])
def run_system_maintenance():
    """Run system maintenance tasks (artifact import, config refresh, etc.)"""
    try:
        # Create workflow run
        run_id = create_automation_run(
            automation_type="maintenance",
            name="System Maintenance",
            details={"trigger": "manual", "tasks": ["artifact_import", "tool_download", "health_check"]}
        )
        add_log_to_run(run_id, "Starting system maintenance", "info")
        add_log_to_run(run_id, "Tasks: Artifact Import (Exchange + DetectRaptor + TenRoot) → Tool Download → Health Check", "info")
        update_run_status(run_id, "running", progress=5)

        # Run maintenance in background
        def run_maintenance():
            try:
                # =========================================================
                # Task 1: Import Velociraptor artifacts (20%)
                # =========================================================
                add_log_to_run(run_id, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", "info")
                add_log_to_run(run_id, "TASK 1/3: Velociraptor Artifact Import", "info")
                add_log_to_run(run_id, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", "info")
                update_run_status(run_id, "running", progress=10)

                add_log_to_run(run_id, "Importing artifacts (Exchange, DetectRaptor, TenRoot custom)...", "info")
                import_results = initialize_velociraptor_artifacts()

                if import_results:
                    success_count = len(import_results.get('success', []))
                    failed_count = len(import_results.get('failed', []))

                    for artifact in import_results.get('success', []):
                        add_log_to_run(run_id, f"  ✓ {artifact}", "success")

                    for artifact in import_results.get('failed', []):
                        add_log_to_run(run_id, f"  ✗ {artifact}", "warning")

                    if success_count > 0:
                        add_log_to_run(run_id, f"Artifact import complete: {success_count} succeeded, {failed_count} failed", "success")
                    else:
                        add_log_to_run(run_id, "No new artifacts to import (already up to date)", "info")
                else:
                    add_log_to_run(run_id, "Artifact import returned no results", "warning")

                update_run_status(run_id, "running", progress=25)

                # =========================================================
                # Task 2: Download tools and configure inventory (60%)
                # =========================================================
                add_log_to_run(run_id, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", "info")
                add_log_to_run(run_id, "TASK 2/3: Download & Configure Tools", "info")
                add_log_to_run(run_id, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", "info")
                update_run_status(run_id, "running", progress=30)

                try:
                    from services.tools_download_service import download_and_configure_tools

                    tool_results = download_and_configure_tools(
                        logger=lambda msg, level="info": add_log_to_run(run_id, msg, level)
                    )

                    if tool_results.get('success'):
                        # Download results
                        dl_results = tool_results.get('download_results', {})
                        downloaded = len(dl_results.get('downloaded', []))
                        existed = len(dl_results.get('already_exists', []))
                        dl_failed = len(dl_results.get('failed', []))

                        # Inventory results
                        inv_results = tool_results.get('inventory_results', {})
                        configured = len(inv_results.get('configured', []))
                        already_served = len(inv_results.get('already_served', []))
                        not_found = len(inv_results.get('file_not_found', []))

                        add_log_to_run(run_id, f"Tool download: {downloaded} new, {existed} existed, {dl_failed} failed", "success" if downloaded > 0 or existed > 0 else "info")
                        add_log_to_run(run_id, f"Inventory config: {configured} configured, {already_served} already served, {not_found} not found", "success" if configured > 0 else "info")
                    else:
                        add_log_to_run(run_id, f"Tool download had issues: {tool_results.get('error', 'unknown')}", "warning")

                except Exception as e:
                    add_log_to_run(run_id, f"Tool download error: {str(e)}", "warning")
                    import traceback
                    traceback.print_exc()

                update_run_status(run_id, "running", progress=70)

                # =========================================================
                # Task 3: System health check (20%)
                # =========================================================
                add_log_to_run(run_id, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", "info")
                add_log_to_run(run_id, "TASK 3/3: System Health Check", "info")
                add_log_to_run(run_id, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", "info")
                update_run_status(run_id, "running", progress=75)

                health_issues = []

                # Check Velociraptor connection
                try:
                    from services.velociraptor_service import setup_velociraptor_connection
                    channel = setup_velociraptor_connection()
                    if channel:
                        add_log_to_run(run_id, "  ✓ Velociraptor: Connected", "success")
                        channel.close()
                    else:
                        add_log_to_run(run_id, "  ✗ Velociraptor: Connection failed", "error")
                        health_issues.append("Velociraptor")
                except Exception as e:
                    add_log_to_run(run_id, f"  ✗ Velociraptor: {str(e)[:50]}", "error")
                    health_issues.append("Velociraptor")

                update_run_status(run_id, "running", progress=85)

                # Check Elasticsearch
                try:
                    import requests
                    es_response = requests.get("http://mssp_elasticsearch:9200/_cluster/health", timeout=5)
                    if es_response.status_code == 200:
                        es_health = es_response.json()
                        status = es_health.get('status', 'unknown')
                        add_log_to_run(run_id, f"  ✓ Elasticsearch: {status}", "success" if status in ['green', 'yellow'] else "warning")
                    else:
                        add_log_to_run(run_id, "  ✗ Elasticsearch: Unhealthy", "warning")
                        health_issues.append("Elasticsearch")
                except Exception as e:
                    add_log_to_run(run_id, f"  ⚠ Elasticsearch: Not reachable", "warning")

                update_run_status(run_id, "running", progress=95)

                # Check database
                try:
                    from services.file_storage_service import load_workflows
                    workflows = load_workflows()
                    add_log_to_run(run_id, f"  ✓ Database: OK ({len(workflows)} workflows stored)", "success")
                except Exception as e:
                    add_log_to_run(run_id, f"  ⚠ Database: {str(e)[:30]}", "warning")

                # Final summary
                add_log_to_run(run_id, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", "info")
                if health_issues:
                    add_log_to_run(run_id, f"Maintenance completed with issues: {', '.join(health_issues)}", "warning")
                else:
                    add_log_to_run(run_id, "System maintenance completed successfully", "success")

                update_run_status(run_id, "completed", progress=100)

            except Exception as e:
                add_log_to_run(run_id, f"✗ Maintenance failed: {str(e)}", "error")
                update_run_status(run_id, "failed", progress=0, error=str(e))

        # Start background thread
        thread = threading.Thread(target=run_maintenance, daemon=True)
        thread.start()

        return jsonify({
            "success": True,
            "run_id": run_id,
            "message": "System maintenance started"
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@system_bp.route('/api/maintenance/download-tools', methods=['POST'])
def download_velociraptor_tools():
    """Download third-party tools and configure Velociraptor server inventory.
    Downloads tools from GitHub/URLs and configures them to be served locally."""
    try:
        from services.tools_download_service import download_and_configure_tools

        # Create workflow run for tracking
        run_id = create_automation_run(
            automation_type="maintenance",
            name="Tool Download",
            details={"trigger": "manual", "tasks": ["tool_download"]}
        )
        add_log_to_run(run_id, "Starting tool download and inventory configuration", "info")
        update_run_status(run_id, "running", progress=10)

        def run_download():
            try:
                result = download_and_configure_tools(
                    logger=lambda msg, level="info": add_log_to_run(run_id, msg, level)
                )
                if result.get('success'):
                    add_log_to_run(run_id, f"Tool download completed: {result.get('summary', '')}", "success")
                    update_run_status(run_id, "completed", progress=100)
                else:
                    add_log_to_run(run_id, f"Tool download failed: {result.get('error', 'Unknown')}", "error")
                    update_run_status(run_id, "failed", progress=0, error=result.get('error'))
            except Exception as e:
                add_log_to_run(run_id, f"Tool download error: {str(e)}", "error")
                update_run_status(run_id, "failed", progress=0, error=str(e))
                import traceback
                traceback.print_exc()

        thread = threading.Thread(target=run_download, daemon=True)
        thread.start()

        return jsonify({
            "success": True,
            "run_id": run_id,
            "message": "Tool download started"
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@system_bp.route('/api/maintenance/tools-config', methods=['GET'])
def get_tools_config():
    """Get the tools inventory configuration summary."""
    try:
        from services.tools_download_service import load_tools_config
        config = load_tools_config()
        if config:
            # Count tools by section
            summary = {"sections": {}, "total_enabled": 0, "total_disabled": 0}
            download_sections = [
                'velociraptor_core', 'event_log_tools', 'persistence_tools',
                'yara_tools', 'velociraptor_artifacts', 'memory_tools',
                'nirsoft_tools', 'zimmerman_tools', 'sysinternals_tools',
                'imaging_tools', 'audit_tools', 'threat_intel', 'linux_tools'
            ]
            for section in download_sections:
                tools = config.get(section, [])
                if tools:
                    enabled = sum(1 for t in tools if t.get('enabled', True))
                    disabled = len(tools) - enabled
                    summary["sections"][section] = {"enabled": enabled, "disabled": disabled}
                    summary["total_enabled"] += enabled
                    summary["total_disabled"] += disabled
            return jsonify({"success": True, "config": summary})
        return jsonify({"error": "Could not load tools config"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@system_bp.route('/api/maintenance/tools-inventory', methods=['GET'])
def get_velociraptor_tools_inventory():
    """Get the current Velociraptor server tool inventory status."""
    try:
        from services.velociraptor_service import setup_velociraptor_connection
        from pyvelociraptor import api_pb2, api_pb2_grpc
        import json

        channel = setup_velociraptor_connection()
        if not channel:
            return jsonify({"error": "Could not connect to Velociraptor"}), 500

        stub = api_pb2_grpc.APIStub(channel)

        vql = "SELECT name, artifact, serve_locally, github_project, url FROM inventory()"
        request = api_pb2.VQLCollectorArgs(
            max_wait=30,
            max_row=200,
            Query=[api_pb2.VQLRequest(VQL=vql)]
        )

        tools = []
        for response in stub.Query(request, timeout=35):
            if response.Response:
                data = json.loads(response.Response)
                tools.extend(data)

        channel.close()

        # Categorize
        served = [t for t in tools if t.get('serve_locally')]
        not_served = [t for t in tools if not t.get('serve_locally')]

        return jsonify({
            "success": True,
            "total": len(tools),
            "served_locally": len(served),
            "not_served": len(not_served),
            "tools": {
                "served": sorted([{"name": t.get('name'), "artifact": t.get('artifact')} for t in served], key=lambda x: x['name']),
                "not_served": sorted([{"name": t.get('name'), "artifact": t.get('artifact')} for t in not_served], key=lambda x: x['name'])
            }
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500
