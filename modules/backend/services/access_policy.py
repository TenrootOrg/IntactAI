#!/usr/bin/env python3
"""Who may call which API route, and who may open which bundled tool.

One table for the whole backend, keyed by Flask endpoint name
("blueprint.function", what request.endpoint holds), so the 24 route files
carry no role code and a reviewer reads every decision in one place.
auth_service.gate_decision() enforces it on every request; the server is the
only place a role is enforced (the UI only hides what a role cannot use).

    readonly    view existing cases, workflows, reports
    operator    everything an Admin does except the Settings page and users:
                cases, runs, uploads, chat, blueprints, collector configs
    admin       the Settings page (LLM, cloud, tools, network...), users below
    superadmin  host-level power: upgrade, restore, data move, Docker, Portainer

A route that is not in POLICY needs SUPERADMIN (fail closed), and
tests/test_access_policy.py fails the build for any route left out, so a new
route cannot quietly become readable by everyone.

A value is either one role for every method, or a {method: role} dict for a
view function that serves several methods (anything not listed needs
SUPERADMIN). Wrap it in step_up(...) when the call also needs a password typed
in the last 15 minutes (user management).
"""

from typing import NamedTuple, Optional, Union

from services.users import ADMIN, OPERATOR, READONLY, SUPERADMIN


class Rule(NamedTuple):
    role: str
    step_up: bool = False


def step_up(role: str) -> Rule:
    return Rule(role, True)


# Which role may pass nginx's per-tool auth_request (/api/auth/verify?tool=).
# Read-only users get no tool at all: the dashboard is their whole view, and
# Kibana's and Velociraptor's read roles would show every case, not one.
TOOLS = {
    "velociraptor": OPERATOR,
    "timesketch": OPERATOR,
    "kibana": OPERATOR,
    "volweb": OPERATOR,
    "uploads": OPERATOR,
    "iris": OPERATOR,
    # Portainer drives Docker: root on the host, so above every role below it.
    "portainer": SUPERADMIN,
}

_Value = Union[str, Rule, dict]

POLICY = {
    # --- auth and users: routes/auth_routes.py, routes/user_routes.py --------
    # (the unauthenticated ones are in auth_service.EXEMPT_PATHS and never
    # reach this table)
    "auth.auth_change_password": READONLY,
    "auth.auth_reauth": READONLY,
    "users.list_users": ADMIN,
    "users.create_user": step_up(ADMIN),
    "users.update_user": step_up(ADMIN),
    "users.reset_password": step_up(ADMIN),
    "users.transfer_superadmin": step_up(SUPERADMIN),

    # --- cases and Case Analysis: routes/case_routes.py ----------------------
    # Reading a case, its report and its chat history is READONLY; anything
    # that writes to the case, fuses, or spends model tokens is OPERATOR.
    "case.list_cases": READONLY,
    "case.get_case": READONLY,
    "case.attachable_runs": READONLY,
    "case.case_log": READONLY,
    "case.get_case_risk": READONLY,
    "case.case_file_facts": READONLY,
    "case.get_zoom_targets": READONLY,
    # The rows behind one finding: part of reading the finding.
    "case.finding_evidence": READONLY,
    "case.finding_detail": READONLY,
    "case.get_relevance": READONLY,
    "case.members": READONLY,
    "case.hosts": READONLY,
    "case.get_checklist": READONLY,
    "case.ai_cost": READONLY,
    "case.identities": READONLY,
    "case.report": READONLY,
    "case.report_download": READONLY,
    "case.report_download_html": READONLY,
    "case.report_download_pdf": READONLY,
    "case.kept_report": READONLY,
    "case.kept_report_download": READONLY,
    "case.graph": READONLY,
    "case.timeline": READONLY,
    "case.chat_history": READONLY,
    "case.dispositions": READONLY,
    "case.metrics": READONLY,
    "case.create_case": OPERATOR,
    "case.update_case": OPERATOR,
    "case.upload_case_file": OPERATOR,
    # Uploaded evidence: raw files are not for Read-only (the report's own
    # pictures come with the HTML/PDF download instead).
    "case.download_case_file": OPERATOR,
    "case.update_case_file": OPERATOR,
    "case.delete_case_file": OPERATOR,
    "case.set_host_status": OPERATOR,
    # Scope selection is stored on the case, not per user: it changes what
    # every viewer of the case sees, so it is a write.
    "case.apply_zoom": OPERATOR,
    "case.create_case_scope": OPERATOR,
    "case.switch_case_scope": OPERATOR,
    "case.set_scope_hosts": OPERATOR,
    "case.delete_case_scope": OPERATOR,
    "case.investigate_case": OPERATOR,
    "case.download_case_bundle": OPERATOR,
    "case.attach": OPERATOR,
    "case.quick_case": OPERATOR,
    "case.fuse": OPERATOR,
    "case.rescan": OPERATOR,
    "case.save_config": OPERATOR,
    "case.decide_checklist": OPERATOR,
    "case.decide_identity": OPERATOR,
    "case.decide_identity_grp": OPERATOR,
    "case.identity_verdict": OPERATOR,
    "case.split_identity_account": OPERATOR,
    "case.exclude_identity_host": OPERATOR,
    "case.undo_identity": OPERATOR,
    "case.manual_identity_link": OPERATOR,
    "case.timeline_validate": OPERATOR,
    "case.timeline_seen": OPERATOR,
    "case.timeline_add_event": OPERATOR,
    "case.timeline_delete_event": OPERATOR,
    "case.set_branding": OPERATOR,
    "case.regenerate_report": OPERATOR,
    "case.synthesize": OPERATOR,
    "case.delete_kept_report": OPERATOR,
    "case.chat": OPERATOR,
    "case.chat_clear": OPERATOR,
    "case.disposition": OPERATOR,
    # Destroying a case or its activity log: an Operator may (decided
    # 2026-11-25: Operator = Admin minus the Settings page and users). The
    # audit log still records who did it.
    "case.delete_case": OPERATOR,
    # Their runs are System runs (Settings -> Actions shows progress and the
    # download; stopping one is there too), so they go with that audience.
    # shortcut: Operators cannot export a case yet; show those runs on the
    # Workflows page first if Operators need it.
    "case.export_case": ADMIN,
    "case.import_case": ADMIN,
    "case.start_relevance": ADMIN,
    "case.case_log_clear": OPERATOR,

    # --- workflows: routes/dashboard_routes.py --------------------------------
    "dashboard.get_all_automations": READONLY,
    "dashboard.get_automation_details": READONLY,
    "dashboard.get_automation_logs": READONLY,
    # Only the Rerun button reads it.
    "dashboard.rerun_spec": OPERATOR,
    "dashboard.recollect": OPERATOR,
    "dashboard.stop_automation": OPERATOR,

    # --- Velociraptor: routes/velociraptor_routes.py, client_routes.py,
    #     velociraptor_offline_routes.py, agentic_routes.py -------------------
    "client.get_clients": READONLY,
    "client.get_clients_summary": READONLY,
    "client.get_client": READONLY,
    # The top-bar org dropdown on every page.
    "velociraptor.list_orgs": READONLY,
    # An installer carries the enrolment config: whoever has it adds clients.
    "client.download_client": OPERATOR,
    "client.legacy_client_status": OPERATOR,
    "velociraptor.get_artifacts": OPERATOR,
    "velociraptor.get_client_labels": OPERATOR,
    # Every hunt on the server, not one case's: what the Velociraptor tool
    # itself would show, and Read-only has no tool.
    "velociraptor.get_hunts_status": OPERATOR,
    "velociraptor.run_timesketch_collection": OPERATOR,
    "velociraptor.run_bestpractice_hunts": OPERATOR,
    "velociraptor.adopt_velociraptor_collection": OPERATOR,
    "agentic.start_agentic_run": OPERATOR,
    "velociraptor_offline.list_offline_configs": OPERATOR,
    "velociraptor_offline.get_offline_config": OPERATOR,
    "velociraptor_offline.generate_offline_collector": OPERATOR,
    "velociraptor_offline.download_offline_collector": OPERATOR,
    "velociraptor_offline.import_offline_results": OPERATOR,
    # A collector config is a stored artifact set, like a blueprint: Operators
    # write and run them.
    "velociraptor_offline.create_offline_config": OPERATOR,
    "velociraptor_offline.update_offline_config": OPERATOR,
    "velociraptor_offline.delete_offline_config": OPERATOR,
    # Settings -> Velociraptor clients: pushes a new binary to every endpoint.
    "velociraptor.velociraptor_client_versions": ADMIN,
    "velociraptor.velociraptor_pilot_candidates": ADMIN,
    "velociraptor.velociraptor_refresh_client_info": ADMIN,
    "velociraptor.velociraptor_upgrade_state": ADMIN,
    "velociraptor.velociraptor_upgrade_clients": ADMIN,
    # Pushes custom artifacts into Velociraptor / builds client installers.
    "init_status": ADMIN,
    "reinit_artifacts": ADMIN,
    "reinit_msi": ADMIN,

    # --- blueprints: routes/blueprint_routes.py, memory_routes.py ------------
    # Operators write and run them. Writing one is authoring VQL, which is
    # admin power in Velociraptor -- decided: Operators are trusted with it,
    # and every hunt they start is audited under their name.
    "blueprints.list_forensics_blueprints": OPERATOR,
    "blueprints.list_velociraptor_blueprints": OPERATOR,
    "blueprints.get_velociraptor_blueprint_by_id": OPERATOR,
    "blueprints.list_agentic_blueprints": OPERATOR,
    "blueprints.get_agentic_blueprint_by_id": OPERATOR,
    "blueprints.list_timesketch_blueprints": OPERATOR,
    "blueprints.get_timesketch_blueprint_by_id": OPERATOR,
    "blueprints.list_memory_blueprints_route": OPERATOR,
    "blueprints.get_memory_blueprint_by_id": OPERATOR,
    "memory.list_memory_blueprints": OPERATOR,
    "memory.list_available_memory_plugins": OPERATOR,
    "blueprints.create_velociraptor_blueprint": OPERATOR,
    "blueprints.update_velociraptor_blueprint_route": OPERATOR,
    "blueprints.delete_velociraptor_blueprint_route": OPERATOR,
    "blueprints.create_agentic_blueprint": OPERATOR,
    "blueprints.update_agentic_blueprint_route": OPERATOR,
    "blueprints.delete_agentic_blueprint_route": OPERATOR,
    "blueprints.create_timesketch_blueprint": OPERATOR,
    "blueprints.update_timesketch_blueprint_route": OPERATOR,
    "blueprints.delete_timesketch_blueprint_route": OPERATOR,
    "blueprints.create_memory_blueprint": OPERATOR,
    "blueprints.update_memory_blueprint_route": OPERATOR,
    "blueprints.delete_memory_blueprint_route": OPERATOR,
    "memory.create_memory_blueprint": OPERATOR,
    "memory.update_memory_blueprint": OPERATOR,
    "memory.delete_memory_blueprint": OPERATOR,

    # --- memory: routes/memory_routes.py --------------------------------------
    "memory.get_memory_status": READONLY,
    "memory.start_memory_run": OPERATOR,
    "memory.upload_memory_dump": OPERATOR,
    "memory.adopt_memory_run": OPERATOR,
    "memory.list_memory_dumps": OPERATOR,
    "memory.memory_symbol_library": OPERATOR,
    "memory.upload_memory_symbol": OPERATOR,
    "memory.remove_memory_dump": OPERATOR,
    "memory.stop_memory_run": OPERATOR,

    # --- Timesketch: routes/timesketch_routes.py, timesketch_llm_routes.py ---
    "timesketch.get_timesketch_status": READONLY,
    # Listed with Timesketch's admin login: every sketch on the server.
    "timesketch.get_timesketch_sketches": OPERATOR,
    "timesketch.run_timesketch_import": OPERATOR,
    "timesketch.start_multi_client_timesketch": OPERATOR,
    "timesketch_llm.get_timesketch_llm_config": ADMIN,
    # An LLM setting, but saving it restarts the Timesketch containers.
    "timesketch_llm.update_timesketch_llm_config": SUPERADMIN,

    # --- AWS and Azure: routes/aws_routes.py, azure_routes.py ----------------
    # Run results and findings are READONLY; the page's launch catalogue,
    # the paged raw collection and the raw ZIP are OPERATOR.
    "aws.get_run_status": READONLY,
    "aws.get_run_findings": READONLY,
    "aws.get_run_analysis": READONLY,
    "aws.list_runs": READONLY,
    "azure.get_run_status": READONLY,
    "azure.get_run_findings": READONLY,
    "azure.get_run_analysis": READONLY,
    "azure.list_runs": READONLY,
    "aws.get_run_results": OPERATOR,
    "aws.download_aws_raw_data": OPERATOR,
    "azure.get_run_results": OPERATOR,
    "azure.download_azure_raw_data": OPERATOR,
    # Shows the start of the access key id.
    "aws.get_aws_status": OPERATOR,
    "aws.get_blueprints": OPERATOR,
    "aws.get_sources": OPERATOR,
    "aws.get_rules_info": OPERATOR,
    # The AWS page saves its pickers on every change; no credential in them.
    "aws.save_aws_regions": OPERATOR,
    "aws.save_aws_time_window": OPERATOR,
    "aws.start_scan": OPERATOR,
    "aws.upload_logs": OPERATOR,
    "aws.analyze_offline": OPERATOR,
    "aws.delete_run": OPERATOR,
    "azure.get_azure_status": OPERATOR,
    "azure.get_blueprints": OPERATOR,
    "azure.get_sources": OPERATOR,
    "azure.get_rules_info": OPERATOR,
    "azure.list_custom_azure_rules": OPERATOR,
    "azure.start_scan": OPERATOR,
    "azure.upload_logs": OPERATOR,
    "azure.analyze_offline": OPERATOR,
    "azure.delete_run": OPERATOR,
    # Detection content for every later scan, managed on the Azure page.
    "azure.upload_custom_azure_rule": OPERATOR,
    "azure.delete_custom_azure_rule": OPERATOR,

    # --- scheduler and uploads: routes/scheduler_routes.py, upload_routes.py -
    "scheduler.get_jobs": READONLY,
    "scheduler.get_job": READONLY,
    "scheduler.create_job": OPERATOR,
    "scheduler.update_job": OPERATOR,
    "scheduler.delete_job": OPERATOR,
    "scheduler.toggle_job": OPERATOR,
    "scheduler.trigger_job": OPERATOR,
    "uploads.get_upload_status": OPERATOR,

    # --- settings: routes/config_routes.py, agentic_cli_routes.py,
    #     maintenance_routes.py ------------------------------------------------
    # Reads too: they show masked keys, endpoints and which credential is in
    # force, which is the Settings page's business only.
    "config.get_config": ADMIN,
    "config.save_config": ADMIN,
    "config.get_cloud_config": ADMIN,
    "config.save_cloud_config_endpoint": ADMIN,
    "config.get_azure_certificate": ADMIN,
    "config.download_azure_certificate": ADMIN,
    "config.get_available_models": ADMIN,
    "config.get_openrouter_models": ADMIN,
    "config.get_codex_models": ADMIN,
    "config.get_anthropic_models": ADMIN,
    "config.get_openai_models": ADMIN,
    "config.get_gemini_models": ADMIN,
    "config.get_ollama_models": ADMIN,
    "config.get_ollama_cloud_models": ADMIN,
    "config.test_llm_connection": ADMIN,
    "config.decision_models": ADMIN,
    "config.refresh_decision_models": ADMIN,
    "config.test_decision_model": ADMIN,
    # Polled by Case Analysis on every tab: a reachable/not answer, no key.
    "config.llm_reachability": READONLY,
    "agentic_cli.cli_status": ADMIN,
    "agentic_cli.cli_test": ADMIN,
    "maintenance.openrouter_catalog_status": ADMIN,
    "maintenance.refresh_openrouter_models": ADMIN,
    "maintenance.test_openrouter_models": ADMIN,
    "maintenance.refresh_anthropic_models": ADMIN,
    "maintenance.refresh_openai_models": ADMIN,
    "maintenance.refresh_codex_models": ADMIN,
    "maintenance.refresh_gemini_models": ADMIN,
    "maintenance.download_velociraptor_tools": ADMIN,
    "maintenance.get_tools_config": ADMIN,
    "maintenance.get_velociraptor_tools_inventory": ADMIN,
    "maintenance.refresh_yara_rulesets": ADMIN,
    "maintenance.yara_rulesets_status": ADMIN,
    # The purge empties Velociraptor, Elasticsearch and Timesketch through
    # docker exec; its section sizes exist only for that screen.
    "maintenance.run_system_purge": SUPERADMIN,
    "maintenance.list_purge_sections": SUPERADMIN,
    "maintenance.purge_selected_sections": SUPERADMIN,

    # --- system: routes/system_routes.py, versions_routes.py,
    #     security_routes.py -------------------------------------------------
    "system.test_endpoint": READONLY,
    "system.get_intact_version": READONLY,
    # The sidebar hides modules that are not installed; states only.
    "system.get_container_status": READONLY,
    # Tool tiles: Read-only opens no tool.
    "system.get_service_ports": OPERATOR,
    # Tells whoever reads it which public default password still works.
    "security.get_default_passwords": ADMIN,
    "system.get_system_actions": ADMIN,
    "system.network_get": ADMIN,
    "versions.get_current_versions_route": ADMIN,
    # Runs scripts/change_ip.sh on the host with systemd-run, which restarts
    # every stack: host power, not a setting.
    "system.network_change": SUPERADMIN,
    "system.data_location_get": SUPERADMIN,
    "system.data_location_disks": SUPERADMIN,
    "system.data_location_check": SUPERADMIN,
    "system.data_location_move": SUPERADMIN,
    "system.data_location_undo": SUPERADMIN,
    "system.data_location_cleanup": SUPERADMIN,

    # --- host level: routes/upgrade_routes.py, db_routes.py,
    #     support_bundle_routes.py -------------------------------------------
    "upgrade.list_upgrade_refs": SUPERADMIN,
    "upgrade.compute_upgrade_plan": SUPERADMIN,
    "upgrade.get_upgrade_quota": SUPERADMIN,
    "upgrade.start_online_upgrade": SUPERADMIN,
    "upgrade.start_offline_upgrade": SUPERADMIN,
    "upgrade.prepare_upgrade_package": SUPERADMIN,
    "upgrade.download_prepared_package": SUPERADMIN,
    "upgrade.get_upgrade_package_info": SUPERADMIN,
    "upgrade.preflight_upgrade_package": SUPERADMIN,
    "upgrade.upload_preflight": SUPERADMIN,
    "upgrade.list_pending_packages": SUPERADMIN,
    "upgrade.peek_manifest_from_blob": SUPERADMIN,
    "upgrade.create_upgrade_upload_run": SUPERADMIN,
    "upgrade.get_active_upgrade_run": SUPERADMIN,
    # Export and backup are every case and setting in one file; import
    # overwrites them.
    "db.export_database": SUPERADMIN,
    "db.backup_database": SUPERADMIN,
    "db.import_database": SUPERADMIN,
    # The bundle carries config.yaml, compose files, the auth audit log, host
    # facts, every case's log and the container logs; the log viewer is the
    # same docker logs. Redaction there is best effort.
    "support_bundle.prepare_support_bundle_endpoint": SUPERADMIN,
    "support_bundle.download_support_bundle": SUPERADMIN,
    "support_bundle.system_logs_list": SUPERADMIN,
    "support_bundle.system_log_read": SUPERADMIN,
    "support_bundle.system_log_download": SUPERADMIN,
}


def rule_for(endpoint: Optional[str], method: str) -> Rule:
    value: _Value = POLICY.get(endpoint or "", SUPERADMIN)
    if isinstance(value, dict):
        value = value.get((method or "").upper(), SUPERADMIN)
    return value if isinstance(value, Rule) else Rule(value)
