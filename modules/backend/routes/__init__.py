"""
Routes package for MSSP Dashboard Backend
"""

from routes.client_routes import client_bp
from routes.velociraptor_routes import velociraptor_bp
from routes.velociraptor_offline_routes import velociraptor_offline_bp
from routes.timesketch_routes import timesketch_bp
from routes.timesketch_llm_routes import timesketch_llm_bp
from routes.dashboard_routes import dashboard_bp
from routes.system_routes import system_bp
from routes.config_routes import config_bp
from routes.maintenance_routes import maintenance_bp
from routes.upgrade_routes import upgrade_bp
from routes.blueprint_routes import blueprint_bp
from routes.agentic_routes import agentic_bp
from routes.db_routes import db_bp
from routes.scheduler_routes import scheduler_bp
from routes.upload_routes import upload_bp
from routes.azure_routes import azure_bp

__all__ = [
    'client_bp',
    'velociraptor_bp',
    'velociraptor_offline_bp',
    'timesketch_bp',
    'timesketch_llm_bp',
    'dashboard_bp',
    'system_bp',
    'config_bp',
    'maintenance_bp',
    'upgrade_bp',
    'blueprint_bp',
    'agentic_bp',
    'db_bp',
    'scheduler_bp',
    'upload_bp',
    'azure_bp'
]
