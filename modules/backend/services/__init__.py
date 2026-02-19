"""
Services package for MSSP Dashboard Backend
"""

from services.workflow_service import (
    create_automation_run,
    add_log_to_run,
    update_run_status,
    get_all_automation_runs,
    get_automation_run,
    get_jobs,
    add_job,
    get_job,
    update_job
)

from services.velociraptor_service import (
    get_clients_from_snapshot,
    load_velociraptor_api_config,
    setup_velociraptor_connection,
    create_velociraptor_hunt
)

from services.kape_service import (
    run_kape_collection_grpc,
    monitor_flow_completion
)

from services.plaso_service import (
    process_with_plaso,
    run_pinfo
)

from services.timesketch_service import (
    import_to_timesketch
)

from services.velociraptor_init_service import (
    initialize_velociraptor_artifacts,
    run_server_artifact,
    check_artifact_exists
)

from services.vql_utils import (
    execute_vql,
    execute_vql_single,
    execute_vql_raw,
    safe_json_parse
)

from services.workflow_logger import (
    WorkflowLogger,
    create_logger
)

__all__ = [
    'create_automation_run',
    'add_log_to_run',
    'update_run_status',
    'get_all_automation_runs',
    'get_automation_run',
    'get_jobs',
    'add_job',
    'get_job',
    'update_job',
    'get_clients_from_snapshot',
    'load_velociraptor_api_config',
    'setup_velociraptor_connection',
    'create_velociraptor_hunt',
    'run_kape_collection_grpc',
    'monitor_flow_completion',
    'process_with_plaso',
    'run_pinfo',
    'import_to_timesketch',
    'initialize_velociraptor_artifacts',
    'run_server_artifact',
    'check_artifact_exists',
    'execute_vql',
    'execute_vql_single',
    'execute_vql_raw',
    'safe_json_parse',
    'WorkflowLogger',
    'create_logger'
]
