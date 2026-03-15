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


@system_bp.route('/api/test', methods=['GET', 'POST'])
def test_endpoint():
    """Simple test endpoint"""
    return jsonify({"status": "ok", "method": request.method})


@system_bp.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({"status": "healthy", "service": "mssp-backend"})
