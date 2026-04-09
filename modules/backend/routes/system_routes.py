#!/usr/bin/env python3
"""
System Routes - Core system endpoints (health, test)

Other system endpoints have been split into:
- config_routes.py - Configuration endpoints
- maintenance_routes.py - Maintenance and tool management
- upgrade_routes.py - System upgrade endpoints
"""

from flask import Blueprint, jsonify, request

system_bp = Blueprint('system', __name__)


import subprocess

# Service ID to Container Name mapping
SERVICE_CONTAINERS = {
    'velociraptor': 'mssp_velociraptor',
    'timesketch': 'mssp_timesketch_web',
    'kibana': 'mssp_kibana',
    'iris': 'mssp_iris_app',
    'portainer': 'mssp_portainer'
}

@system_bp.route('/api/test', methods=['GET', 'POST'])
def test_endpoint():
    """Simple test endpoint"""
    return jsonify({"status": "ok", "method": request.method})


@system_bp.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({"status": "healthy", "service": "mssp-backend"})

@system_bp.route('/api/system/containers', methods=['GET'])
def get_container_status():
    """Get status of core system containers from Docker interface"""
    results = {}
    try:
        # Run docker ps to get running container names
        # Note: mssp_backend has /var/run/docker.sock mounted
        cmd = ["docker", "ps", "--format", "{{.Names}}"]
        output = subprocess.check_output(cmd, text=True)
        running_containers = [n.strip() for n in output.strip().split('\n') if n.strip()]
        
        for service_id, container_name in SERVICE_CONTAINERS.items():
            if container_name in running_containers:
                results[service_id] = 'online'
            else:
                # Optional: check if container exists but is stopped
                results[service_id] = 'offline'
                
    except Exception as e:
        return jsonify({"error": f"Failed to query Docker: {str(e)}"}), 500

    return jsonify(results)
