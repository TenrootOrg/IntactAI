#!/usr/bin/env python3
"""
Simple backend API for MSSP Dashboard
Main Flask application with modular structure
"""

import threading
import time
import os
import sys
from flask import Flask, jsonify
from flask_cors import CORS

# Import blueprints
from routes import (
    client_bp,
    velociraptor_bp,
    timesketch_bp,
    dashboard_bp,
    system_bp,
    blueprint_bp,
    agentic_bp,
    db_bp,
    scheduler_bp
)

# Import initialization services
from services.elasticsearch_service import init_elasticsearch
from services.velociraptor_init_service import initialize_velociraptor_artifacts
from services.offline_collector import init_offline_collector_index
from services.msi_generator_service import generate_all_client_installers
from config import ELASTICSEARCH_CONFIG

# Create Flask app
app = Flask(__name__)
CORS(app)

# Register blueprints
app.register_blueprint(client_bp)
app.register_blueprint(velociraptor_bp)
app.register_blueprint(timesketch_bp)
app.register_blueprint(dashboard_bp)
app.register_blueprint(system_bp)
app.register_blueprint(blueprint_bp)
app.register_blueprint(agentic_bp)
app.register_blueprint(db_bp)
app.register_blueprint(scheduler_bp)

# Global flag to track initialization status
initialization_status = {
    "elasticsearch": False,
    "velociraptor_artifacts": False,
    "msi_generation": False,
    "offline_collectors": False,
    "in_progress": False
}


def run_startup_initialization():
    """Run initialization tasks in background thread"""
    global initialization_status
    initialization_status["in_progress"] = True

    print("[STARTUP] Starting background initialization...", flush=True)

    # Initialize Elasticsearch
    try:
        print("[STARTUP] Initializing Elasticsearch...", flush=True)
        es_result = init_elasticsearch(
            host=ELASTICSEARCH_CONFIG['host'],
            port=ELASTICSEARCH_CONFIG['port']
        )
        initialization_status["elasticsearch"] = es_result
        if es_result:
            print("[WORKFLOW] Elasticsearch initialized successfully", flush=True)
    except Exception as e:
        print(f"[STARTUP] Elasticsearch initialization failed: {e}", flush=True)

    # Wait for Velociraptor to be ready (smart check instead of hardcoded wait)
    print("[STARTUP] Waiting for Velociraptor to be ready...", flush=True)
    velo_ready = False
    max_wait = 60  # Maximum 60 seconds
    wait_interval = 5
    waited = 0

    while waited < max_wait:
        try:
            from services.velociraptor_service import get_grpc_channel
            channel = get_grpc_channel()
            if channel:
                print(f"[STARTUP] Velociraptor ready after {waited}s", flush=True)
                velo_ready = True
                break
        except Exception:
            pass
        time.sleep(wait_interval)
        waited += wait_interval
        print(f"[STARTUP] Waiting for Velociraptor... ({waited}s)", flush=True)

    if not velo_ready:
        print("[STARTUP] Velociraptor not responding after 60s, continuing anyway...", flush=True)

    # Download tools FIRST (needed for TenRoot artifact import)
    try:
        from config import get_installation_options
        options = get_installation_options()
        download_tools_enabled = options.get('download_forensic_tools', True)

        if download_tools_enabled:
            print("[STARTUP] Downloading tools (includes TenRoot artifacts zip)...", flush=True)
            from services.tools_download_service import download_and_configure_tools
            tool_results = download_and_configure_tools()
            if tool_results.get('success'):
                dl = tool_results.get('download_results', {})
                print(f"[STARTUP] ✓ Tools: {len(dl.get('downloaded', []))} new, {len(dl.get('already_exists', []))} cached", flush=True)
                initialization_status["tools_download"] = True
            else:
                print(f"[STARTUP] Tool download had issues: {tool_results.get('error', 'unknown')}", flush=True)
                initialization_status["tools_download"] = False
        else:
            print("[STARTUP] Tool download SKIPPED (download_forensic_tools: false in config.yaml)", flush=True)
            print("[STARTUP] Tools can be downloaded later via Dashboard > Settings > Maintenance", flush=True)
            initialization_status["tools_download"] = "skipped"
    except Exception as e:
        print(f"[STARTUP] Tool download failed: {e}", flush=True)
        initialization_status["tools_download"] = False

    # Initialize Velociraptor artifacts (Exchange + DetectRaptor + TenRoot custom)
    # Runs AFTER tool download so TenRoot zip exists
    try:
        print("[STARTUP] Initializing Velociraptor artifacts...", flush=True)
        results = initialize_velociraptor_artifacts()
        initialization_status["velociraptor_artifacts"] = len(results.get("success", [])) > 0
        print(f"[STARTUP] Velociraptor artifacts: {len(results.get('success', []))} imported", flush=True)
    except Exception as e:
        print(f"[STARTUP] Velociraptor artifact initialization failed: {e}", flush=True)

    # Generate client installers for all platforms (Windows EXE/MSI, Linux, Mac)
    # This runs AFTER artifact import to ensure Server.Utils artifacts are available
    try:
        print("[STARTUP] Generating properly configured client installers for all platforms...", flush=True)
        print("[STARTUP] (This fixes the known CLI repacking bug in Velociraptor 0.75.x)", flush=True)
        time.sleep(5)  # Brief pause to ensure artifacts are fully loaded
        client_result = generate_all_client_installers()
        if client_result.get("success"):
            print("[STARTUP] ✓ Client generation successful", flush=True)
            print(f"[STARTUP] {client_result.get('message', '')}", flush=True)
            initialization_status["msi_generation"] = True
        else:
            print(f"[STARTUP] Client generation failed: {client_result.get('error', 'unknown')}", flush=True)
            initialization_status["msi_generation"] = False
    except Exception as e:
        print(f"[STARTUP] Client generation error: {e}", flush=True)
        initialization_status["msi_generation"] = False

    # Initialize offline collector configurations (runs AFTER client generation)
    try:
        print("[STARTUP] Initializing offline collector configurations...", flush=True)
        init_result = init_offline_collector_index()
        if init_result:
            print("[STARTUP] ✓ Offline collector configurations initialized", flush=True)
            initialization_status["offline_collectors"] = True
        else:
            print("[STARTUP] Offline collector initialization failed", flush=True)
            initialization_status["offline_collectors"] = False
    except Exception as e:
        print(f"[STARTUP] Offline collector initialization error: {e}", flush=True)
        initialization_status["offline_collectors"] = False

    initialization_status["in_progress"] = False
    print("[STARTUP] Background initialization complete", flush=True)


@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({"status": "ok"})


@app.route('/api/init/status')
def init_status():
    """Get initialization status"""
    return jsonify(initialization_status)


@app.route('/api/init/artifacts', methods=['POST'])
def reinit_artifacts():
    """Manually trigger artifact initialization"""
    if initialization_status["in_progress"]:
        return jsonify({"error": "Initialization already in progress"}), 400

    # Run in background
    thread = threading.Thread(target=lambda: initialize_velociraptor_artifacts())
    thread.daemon = True
    thread.start()

    return jsonify({"message": "Artifact initialization started"})


@app.route('/api/init/msi', methods=['POST'])
def reinit_msi():
    """Manually trigger MSI/client generation"""
    if initialization_status["in_progress"]:
        return jsonify({"error": "Initialization already in progress"}), 400

    # Run MSI generation
    def run_msi_gen():
        result = generate_all_client_installers()
        print(f"[MSI-GEN] Manual trigger result: {result}", flush=True)

    thread = threading.Thread(target=run_msi_gen)
    thread.daemon = True
    thread.start()

    return jsonify({"message": "Client generation started"})


if __name__ == '__main__':
    # Always run without hot-reload for stability
    print("[STARTUP] Starting backend API (production mode)", flush=True)

    # Start initialization in background thread
    init_thread = threading.Thread(target=run_startup_initialization)
    init_thread.daemon = True
    init_thread.start()

    # Run Flask without debug/reloader
    app.run(host='0.0.0.0', port=5001, debug=False, use_reloader=False, threaded=True)
