#!/usr/bin/env python3
"""
Maintenance Routes - System maintenance and tool management endpoints
"""

from flask import Blueprint, jsonify, request
import threading

from services import (
    create_automation_run,
    add_log_to_run,
    update_run_status
)
from services.velociraptor_init_service import initialize_velociraptor_artifacts

maintenance_bp = Blueprint('maintenance', __name__)


@maintenance_bp.route('/api/maintenance/run', methods=['POST'])
def run_system_maintenance():
    """Run system maintenance tasks (artifact import, config refresh, etc.)"""
    try:
        # Create workflow run
        run_id = create_automation_run(
            automation_type="maintenance",
            name="System Maintenance",
            details={"trigger": "manual", "tasks": ["artifact_import", "tool_download", "skills_refresh", "health_check"]}
        )
        add_log_to_run(run_id, "Starting system maintenance", "info")
        add_log_to_run(run_id, "Tasks: Artifact Import (Exchange + DetectRaptor + TenRoot) → Tool Download → Refresh Skills → Health Check", "info")
        update_run_status(run_id, "running", progress=5)

        from services.workflow_service import register_cancel_event, unregister_cancel
        cancel_event = register_cancel_event(run_id)

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

                # =========================================================
                # Task 2.5: Refresh LLM model catalogs (5%)
                # =========================================================
                # Persisted catalogs at /app/data/{openrouter,anthropic,
                # openai,gemini}_models.json drive the dashboard's model
                # selector. OpenRouter goes first because the three
                # direct-provider refreshes enrich their entries against
                # it. Each is best-effort — if a provider is unreachable
                # or its API key isn't configured, the existing on-disk
                # file keeps serving the UI and the others still run.
                add_log_to_run(run_id, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", "info")
                add_log_to_run(run_id, "TASK 2.5: Refresh LLM Model Catalogs", "info")
                add_log_to_run(run_id, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", "info")

                from services.llm_catalogs import openrouter as _or_cat
                from services.llm_catalogs import anthropic as _ant_cat
                from services.llm_catalogs import openai as _oai_cat
                from services.llm_catalogs import gemini as _gem_cat

                # OpenRouter first — it's the enrichment source for the
                # other three. Enrichment failures degrade gracefully but
                # quality is much better when this finishes first.
                _CATALOG_TASKS = [
                    ("OpenRouter", _or_cat),
                    ("Anthropic", _ant_cat),
                    ("OpenAI", _oai_cat),
                    ("Gemini", _gem_cat),
                ]
                for label, mod in _CATALOG_TASKS:
                    try:
                        cat_result = mod.refresh_catalog(
                            logger=lambda msg, level="info": add_log_to_run(run_id, f"  [{label}] {msg}", level)
                        )
                        if cat_result.get('success'):
                            unenriched = cat_result.get('unenriched_count', 0)
                            extra = f" ({unenriched} un-enriched)" if unenriched else ""
                            add_log_to_run(
                                run_id,
                                f"{label} catalog: {cat_result['model_count']} models cached{extra}",
                                "success",
                            )
                        else:
                            add_log_to_run(
                                run_id,
                                f"{label} catalog skipped: {cat_result.get('error', 'unknown')} "
                                "(existing on-disk catalog still serves the UI)",
                                "warning",
                            )
                    except Exception as e:
                        add_log_to_run(run_id, f"{label} catalog error: {e}", "warning")

                update_run_status(run_id, "running", progress=60)

                # =========================================================
                # Task 3: Refresh DFIR/agentic skills (10%)
                # =========================================================
                add_log_to_run(run_id, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", "info")
                add_log_to_run(run_id, "TASK 3/4: Refresh DFIR Skills", "info")
                add_log_to_run(run_id, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", "info")
                update_run_status(run_id, "running", progress=62)

                try:
                    from services.skills_download_service import refresh_skills
                    skills_result = refresh_skills(
                        logger_fn=lambda msg, level="info": add_log_to_run(run_id, msg, level),
                    )
                    if skills_result.get("success"):
                        add_log_to_run(
                            run_id,
                            f"Skills refresh: {len(skills_result['updated'])} updated, "
                            f"{len(skills_result['unchanged'])} unchanged, "
                            f"{len(skills_result['failed'])} failed",
                            "success" if not skills_result['failed'] else "warning",
                        )
                    else:
                        add_log_to_run(
                            run_id,
                            f"Skills refresh had issues: {skills_result.get('error', 'unknown')}",
                            "warning",
                        )
                except Exception as e:
                    add_log_to_run(run_id, f"Skills refresh error: {str(e)}", "warning")
                    import traceback
                    traceback.print_exc()

                update_run_status(run_id, "running", progress=68)

                # =========================================================
                # Task 3.5: Refresh CVE Scan databases (CPE dict + local
                # CVE mirror) (~3%)
                # =========================================================
                # Two refreshes back-to-back, both best-effort:
                #   a) CPE dictionary CSV from tiiuae/cpedict — drives
                #      the product → CPE resolver.
                #   b) Local CVE mirror from fkie-cad/nvd-json-data-feeds
                #      — eliminates per-product NVD REST calls at scan
                #      time. Initial run takes ~10-30 min; subsequent
                #      runs are incremental (skip unchanged year-files).
                add_log_to_run(run_id, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", "info")
                add_log_to_run(run_id, "TASK 3.5/4: Refresh CVE Scan databases (CPE dict + local CVE mirror)", "info")
                add_log_to_run(run_id, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", "info")

                # --- 3.5a: CPE dictionary ---
                try:
                    from services.cve_scan.cpe_dict import refresh_dictionary_from_upstream
                    cpe_dict_result = refresh_dictionary_from_upstream(
                        logger=lambda msg, level="info": add_log_to_run(run_id, msg, level)
                    )
                    if cpe_dict_result.get("ok"):
                        add_log_to_run(
                            run_id,
                            f"CPE dictionary refresh: {cpe_dict_result.get('message')}",
                            "success",
                        )
                    else:
                        add_log_to_run(
                            run_id,
                            f"CPE dictionary refresh had issues: {cpe_dict_result.get('message')}",
                            "warning",
                        )
                except Exception as e:
                    add_log_to_run(run_id, f"CPE dictionary refresh error: {str(e)}", "warning")
                    import traceback
                    traceback.print_exc()

                # --- 3.5b: local CVE mirror ---
                try:
                    from services.cve_scan import local_db as _local_db
                    add_log_to_run(
                        run_id,
                        "[LOCAL_DB] Refreshing local CVE mirror "
                        "(initial run ~10-30 min, incremental ~minutes)…",
                        "info",
                    )
                    bulk_result = _local_db.bulk_load(
                        logger=lambda msg, level="info": add_log_to_run(run_id, msg, level)
                    )
                    if bulk_result.get("ok"):
                        add_log_to_run(
                            run_id,
                            f"Local CVE mirror: {bulk_result.get('cve_count')} CVEs indexed, "
                            f"{bulk_result.get('db_size_mb', 0):.0f} MB on disk, "
                            f"{bulk_result.get('elapsed_seconds', 0):.0f}s elapsed",
                            "success",
                        )
                    else:
                        add_log_to_run(
                            run_id,
                            "Local CVE mirror refresh had issues — scans will fall back to REST",
                            "warning",
                        )
                except Exception as e:
                    add_log_to_run(run_id, f"Local CVE mirror refresh error: {str(e)}", "warning")
                    import traceback
                    traceback.print_exc()

                update_run_status(run_id, "running", progress=70)

                # =========================================================
                # Task 4: System health check (20%)
                # =========================================================
                add_log_to_run(run_id, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", "info")
                add_log_to_run(run_id, "TASK 4/4: System Health Check", "info")
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
                    es_response = requests.get("http://intact_elasticsearch:9200/_cluster/health", timeout=5)
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
            finally:
                unregister_cancel(run_id)

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


@maintenance_bp.route('/api/maintenance/openrouter-catalog', methods=['GET'])
def openrouter_catalog_status():
    """Return on-disk OpenRouter catalog summary (model count, fetch
    time, file presence). UI shows this so the operator knows when
    the dashboard's model selector list was last refreshed."""
    from services.llm_catalogs.openrouter import catalog_status
    return jsonify(catalog_status())


def _refresh_one_catalog(catalog_module):
    """Standalone synchronous refresh wrapper used by the four per-provider
    refresh endpoints. Returns (json_dict, http_status)."""
    try:
        result = catalog_module.refresh_catalog()
        if result.get('success'):
            return result, 200
        return result, 502  # upstream fetch problem, not our bug
    except Exception as e:
        return {"success": False, "error": str(e)}, 500


@maintenance_bp.route('/api/maintenance/refresh-openrouter-models', methods=['POST'])
def refresh_openrouter_models():
    """Refresh `data/openrouter_models.json` from
    https://openrouter.ai/api/v1/models. Standalone counterpart to the
    catalog refresh that runs as Task 2.5 of `/api/maintenance/run`.

    Synchronous — the fetch is small (~few hundred KB) and finishes in
    a second or two. No workflow row needed for that timescale.
    """
    from services.llm_catalogs import openrouter as catalog_module
    body, status = _refresh_one_catalog(catalog_module)
    return jsonify(body), status


@maintenance_bp.route('/api/maintenance/refresh-anthropic-models', methods=['POST'])
def refresh_anthropic_models():
    """Refresh `data/anthropic_models.json` from Anthropic's `/v1/models`
    endpoint, then enrich each entry against the OpenRouter catalog."""
    from services.llm_catalogs import anthropic as catalog_module
    body, status = _refresh_one_catalog(catalog_module)
    return jsonify(body), status


@maintenance_bp.route('/api/maintenance/refresh-openai-models', methods=['POST'])
def refresh_openai_models():
    """Refresh `data/openai_models.json` from OpenAI's `/v1/models`
    endpoint, filter to chat-capable, enrich from OpenRouter."""
    from services.llm_catalogs import openai as catalog_module
    body, status = _refresh_one_catalog(catalog_module)
    return jsonify(body), status


@maintenance_bp.route('/api/maintenance/refresh-gemini-models', methods=['POST'])
def refresh_gemini_models():
    """Refresh `data/gemini_models.json` from Google's `/v1beta/models`
    endpoint. Native max_output_tokens / context_length come from the
    response; pricing is enriched from OpenRouter."""
    from services.llm_catalogs import gemini as catalog_module
    body, status = _refresh_one_catalog(catalog_module)
    return jsonify(body), status


@maintenance_bp.route('/api/maintenance/refresh-skills', methods=['POST'])
def refresh_dfir_skills():
    """Re-download DFIR / agentic skill markdown files from the upstream
    Anthropic Cybersecurity Skills repository. Skill files are bundled with
    the install but improve over time upstream — this endpoint pulls the
    latest versions atomically and reloads the in-memory skill index.
    """
    try:
        from services.skills_download_service import refresh_skills

        run_id = create_automation_run(
            automation_type="maintenance",
            name="Refresh DFIR skills",
            details={"trigger": "manual", "tasks": ["skills_refresh"]},
        )
        add_log_to_run(run_id, "Starting DFIR skill refresh from upstream", "info")
        update_run_status(run_id, "running", progress=10)

        def run_refresh():
            try:
                result = refresh_skills(
                    logger_fn=lambda msg, level="info": add_log_to_run(run_id, msg, level),
                )
                if result.get("success"):
                    summary = (
                        f"Skills refreshed: {len(result['updated'])} updated, "
                        f"{len(result['unchanged'])} unchanged, "
                        f"{len(result['failed'])} failed of {result['total']}"
                    )
                    add_log_to_run(run_id, summary, "success")
                    update_run_status(run_id, "completed", progress=100)
                else:
                    err = result.get("error", "unknown")
                    add_log_to_run(run_id, f"Skills refresh failed: {err}", "error")
                    update_run_status(run_id, "failed", progress=0, error=err)
            except Exception as e:
                add_log_to_run(run_id, f"Skills refresh error: {str(e)}", "error")
                update_run_status(run_id, "failed", progress=0, error=str(e))
                import traceback
                traceback.print_exc()

        thread = threading.Thread(target=run_refresh, daemon=True)
        thread.start()

        return jsonify({
            "success": True,
            "run_id": run_id,
            "message": "Skills refresh started",
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@maintenance_bp.route('/api/maintenance/download-tools', methods=['POST'])
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


@maintenance_bp.route('/api/maintenance/tools-config', methods=['GET'])
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


@maintenance_bp.route('/api/maintenance/tools-inventory', methods=['GET'])
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


@maintenance_bp.route('/api/maintenance/purge', methods=['POST'])
def run_system_purge():
    """Purge all accumulated data: workflows, reports, uploads, temp files, Velociraptor hunt data."""
    run_id = create_automation_run(
        automation_type="system_purge",
        name="System Purge",
        details={"trigger": "manual"}
    )
    update_run_status(run_id, "running", progress=5)
    add_log_to_run(run_id, "Starting system purge...", "info")

    from services.workflow_service import register_cancel_event, unregister_cancel
    cancel_event = register_cancel_event(run_id)

    def run_purge():
        import os
        import shutil
        import glob
        import sqlite3

        total_freed = 0

        def get_dir_size(path):
            total = 0
            if os.path.isfile(path):
                return os.path.getsize(path)
            if not os.path.exists(path):
                return 0
            for dirpath, _, filenames in os.walk(path):
                for f in filenames:
                    try:
                        total += os.path.getsize(os.path.join(dirpath, f))
                    except (OSError, FileNotFoundError):
                        pass
            return total

        def fmt(size_bytes):
            if size_bytes >= 1024**3:
                return f"{size_bytes / 1024**3:.1f} GB"
            elif size_bytes >= 1024**2:
                return f"{size_bytes / 1024**2:.1f} MB"
            elif size_bytes >= 1024:
                return f"{size_bytes / 1024:.1f} KB"
            return f"{size_bytes} B"

        def purge_dir(path):
            if not os.path.exists(path):
                return 0, 0
            size = get_dir_size(path)
            count = 0
            for item in os.listdir(path):
                item_path = os.path.join(path, item)
                try:
                    if os.path.isdir(item_path):
                        shutil.rmtree(item_path)
                    else:
                        os.remove(item_path)
                    count += 1
                except Exception as e:
                    add_log_to_run(run_id, f"  Warning: Could not remove {item}: {e}", "warning")
            return size, count

        try:
            # === 1. Workflows & Reports ===
            add_log_to_run(run_id, "=" * 50, "info")
            add_log_to_run(run_id, "PURGE: Workflows & Reports", "info")
            add_log_to_run(run_id, "=" * 50, "info")
            update_run_status(run_id, "running", progress=10)

            try:
                db_path = "/app/data/intact.db"
                db_size_before = os.path.getsize(db_path) if os.path.exists(db_path) else 0
                conn = sqlite3.connect(db_path)
                c = conn.cursor()
                c.execute("SELECT COUNT(*) FROM workflows")
                wf_count = c.fetchone()[0]
                c.execute("SELECT COUNT(*) FROM reports")
                rpt_count = c.fetchone()[0]
                c.execute("DELETE FROM workflows WHERE run_id != ?", (run_id,))
                c.execute("DELETE FROM reports")
                conn.commit()
                c.execute("VACUUM")
                conn.commit()
                conn.close()
                db_size_after = os.path.getsize(db_path) if os.path.exists(db_path) else 0
                freed = max(0, db_size_before - db_size_after)
                total_freed += freed
                add_log_to_run(run_id, f"  Deleted {wf_count - 1} workflows, {rpt_count} reports", "info")
                add_log_to_run(run_id, f"  Freed: {fmt(freed)}", "success")
            except Exception as e:
                add_log_to_run(run_id, f"  Error: {e}", "error")

            # === 2. Azure Scan Data ===
            add_log_to_run(run_id, "=" * 50, "info")
            add_log_to_run(run_id, "PURGE: Azure Scan Data", "info")
            add_log_to_run(run_id, "=" * 50, "info")
            update_run_status(run_id, "running", progress=20)
            freed, count = purge_dir("/data/db/azure_runs")
            total_freed += freed
            add_log_to_run(run_id, f"  Removed {count} scan files | Freed: {fmt(freed)}", "success")

            # === 3. Upload Data ===
            add_log_to_run(run_id, "=" * 50, "info")
            add_log_to_run(run_id, "PURGE: Upload Data (KAPE, packages, logs)", "info")
            add_log_to_run(run_id, "=" * 50, "info")
            update_run_status(run_id, "running", progress=30)
            freed, count = purge_dir("/data/uploads")
            total_freed += freed
            add_log_to_run(run_id, f"  Removed {count} uploads | Freed: {fmt(freed)}", "success")

            # === 4. Upgrade Packages ===
            add_log_to_run(run_id, "=" * 50, "info")
            add_log_to_run(run_id, "PURGE: Upgrade Packages", "info")
            add_log_to_run(run_id, "=" * 50, "info")
            update_run_status(run_id, "running", progress=40)
            freed, count = purge_dir("/data/upgrade_packages")
            for f in ["/data/db/prepared_package.json", "/data/db/prepared_packages.json"]:
                if os.path.exists(f):
                    freed += os.path.getsize(f)
                    os.remove(f)
                    count += 1
            total_freed += freed
            add_log_to_run(run_id, f"  Removed {count} items | Freed: {fmt(freed)}", "success")

            # === 5. Temp Files ===
            add_log_to_run(run_id, "=" * 50, "info")
            add_log_to_run(run_id, "PURGE: Temp Files", "info")
            add_log_to_run(run_id, "=" * 50, "info")
            update_run_status(run_id, "running", progress=50)
            freed = 0
            for temp_dir in ["/app/data/tmp", "/data/tmp", "/tmp/plaso", "/tmp/azure_uploads"]:
                d_freed, _ = purge_dir(temp_dir)
                freed += d_freed
            for d in glob.glob("/app/data/tmp/intact-upgrade-*") + glob.glob("/tmp/intact-upgrade-*"):
                freed += get_dir_size(d)
                shutil.rmtree(d, ignore_errors=True)
            total_freed += freed
            add_log_to_run(run_id, f"  Freed: {fmt(freed)}", "success")

            # === 6. Report Downloads ===
            add_log_to_run(run_id, "=" * 50, "info")
            add_log_to_run(run_id, "PURGE: Report Downloads", "info")
            add_log_to_run(run_id, "=" * 50, "info")
            update_run_status(run_id, "running", progress=60)
            freed, count = purge_dir("/app/downloads")
            total_freed += freed
            add_log_to_run(run_id, f"  Removed {count} items | Freed: {fmt(freed)}", "success")

            # === 7. Velociraptor Hunt Data ===
            add_log_to_run(run_id, "=" * 50, "info")
            add_log_to_run(run_id, "PURGE: Velociraptor Hunts & Collections", "info")
            add_log_to_run(run_id, "=" * 50, "info")
            update_run_status(run_id, "running", progress=70)

            try:
                from services.upgrade.base import run_command
                import json as json_mod

                # Velociraptor datastore is at /var./ (configured in server.config.yaml)
                # Measure before (exclude /var./public/ which contains forensic tools)
                du_before = run_command("docker exec intact_velociraptor sh -c 'du -sb --exclude=public /var./ 2>/dev/null || echo 0'", logger=None)
                size_before = int(du_before.get('stdout', '0').split()[0]) if du_before.get('success') else 0
                add_log_to_run(run_id, f"  Datastore size: {fmt(size_before)}", "info")

                # Delete all hunts via VQL
                add_log_to_run(run_id, "  Deleting hunts...", "info")
                list_result = run_command(
                    'docker exec intact_velociraptor /velociraptor/velociraptor --config /velociraptor/server.config.yaml query '
                    '"SELECT hunt_id, state FROM hunts()"',
                    logger=None
                )
                hunt_count = 0
                if list_result.get('success') and list_result.get('stdout', '').strip():
                    try:
                        hunts = json_mod.loads(list_result['stdout'])
                        for hunt in (hunts if isinstance(hunts, list) else []):
                            hunt_id = hunt.get('hunt_id', '')
                            if hunt_id:
                                run_command(
                                    f'docker exec intact_velociraptor /velociraptor/velociraptor --config /velociraptor/server.config.yaml query '
                                    f'"SELECT * FROM hunt_delete(hunt_id=\'{hunt_id}\', really_do_it=true)"',
                                    logger=None
                                )
                                hunt_count += 1
                    except (json_mod.JSONDecodeError, ValueError):
                        pass
                add_log_to_run(run_id, f"  Deleted {hunt_count} hunts", "info")

                # Clean client collection data (flows/uploads)
                add_log_to_run(run_id, "  Cleaning client collections & uploads...", "info")
                run_command("docker exec intact_velociraptor sh -c 'rm -rf /var./clients/*/collections/ /var./clients/*/uploads/ 2>/dev/null; true'", logger=None)

                # Clean downloads
                add_log_to_run(run_id, "  Cleaning downloads...", "info")
                run_command("docker exec intact_velociraptor sh -c 'rm -rf /var./downloads/* 2>/dev/null; true'", logger=None)

                # Clean notebooks
                add_log_to_run(run_id, "  Cleaning notebooks...", "info")
                run_command("docker exec intact_velociraptor sh -c 'rm -rf /var./notebooks/* 2>/dev/null; true'", logger=None)

                # Clean server artifact logs and server artifacts
                run_command("docker exec intact_velociraptor sh -c 'rm -rf /var./server_artifact_logs/* /var./server_artifacts/* 2>/dev/null; true'", logger=None)

                # Measure after (exclude /var./public/ which contains forensic tools)
                du_after = run_command("docker exec intact_velociraptor sh -c 'du -sb --exclude=public /var./ 2>/dev/null || echo 0'", logger=None)
                size_after = int(du_after.get('stdout', '0').split()[0]) if du_after.get('success') else 0
                freed = max(0, size_before - size_after)
                total_freed += freed
                add_log_to_run(run_id, f"  Freed: {fmt(freed)}", "success")
            except Exception as e:
                add_log_to_run(run_id, f"  Velociraptor cleanup error: {e}", "warning")

            # === 8. ELK (Velociraptor Artifacts) ===
            add_log_to_run(run_id, "=" * 50, "info")
            add_log_to_run(run_id, "PURGE: ELK (Velociraptor Artifact Indices)", "info")
            add_log_to_run(run_id, "=" * 50, "info")
            update_run_status(run_id, "running", progress=80)

            try:
                import requests as req
                # Get size before
                es_resp = req.get("http://intact_elasticsearch:9200/_cat/indices?h=index,store.size&bytes=b", timeout=5)
                es_size_before = 0
                es_index_count = 0
                if es_resp.status_code == 200:
                    for line in es_resp.text.strip().split('\n'):
                        parts = line.split()
                        if len(parts) >= 2 and parts[0].startswith('artifact_'):
                            es_size_before += int(parts[1])
                            es_index_count += 1

                add_log_to_run(run_id, f"  Found {es_index_count} artifact indices ({fmt(es_size_before)})", "info")

                if es_index_count > 0:
                    # Delete each index individually (wildcard delete is disabled by default)
                    deleted = 0
                    for line in es_resp.text.strip().split('\n'):
                        parts = line.split()
                        if len(parts) >= 2 and parts[0].startswith('artifact_'):
                            del_resp = req.delete(f"http://intact_elasticsearch:9200/{parts[0]}", timeout=10)
                            if del_resp.status_code == 200:
                                deleted += 1
                    add_log_to_run(run_id, f"  Deleted {deleted}/{es_index_count} indices", "info")
                    total_freed += es_size_before

                add_log_to_run(run_id, f"  Freed: {fmt(es_size_before)}", "success")
            except Exception as e:
                add_log_to_run(run_id, f"  ELK cleanup error: {e}", "warning")

            # === 9. Timesketch (Timelines & Events) ===
            add_log_to_run(run_id, "=" * 50, "info")
            add_log_to_run(run_id, "PURGE: Timesketch (Timelines & Events)", "info")
            add_log_to_run(run_id, "=" * 50, "info")
            update_run_status(run_id, "running", progress=85)

            try:
                # Get OpenSearch size before (exclude system indices starting with .)
                os_resp = run_command(
                    "docker exec intact_timesketch_opensearch curl -s 'http://localhost:9200/_cat/indices?h=index,store.size&bytes=b'",
                    logger=None
                )
                os_size_before = 0
                os_index_count = 0
                if os_resp.get('success'):
                    for line in os_resp.get('stdout', '').strip().split('\n'):
                        parts = line.split()
                        if len(parts) >= 2 and not parts[0].startswith('.'):
                            try:
                                os_size_before += int(parts[1])
                                os_index_count += 1
                            except ValueError:
                                pass

                add_log_to_run(run_id, f"  Found {os_index_count} timeline indices ({fmt(os_size_before)})", "info")

                if os_index_count > 0:
                    # Delete timeline indices from OpenSearch
                    run_command(
                        "docker exec intact_timesketch_opensearch curl -s -X DELETE 'http://localhost:9200/*,-.*'",
                        logger=None
                    )
                    # Clear PostgreSQL timeline data
                    run_command(
                        "docker exec intact_timesketch_postgres psql -U timesketch -d timesketch -c 'DELETE FROM timeline; DELETE FROM searchindex;'",
                        logger=None
                    )
                    add_log_to_run(run_id, f"  Deleted {os_index_count} indices and cleared timeline database", "info")
                    total_freed += os_size_before

                add_log_to_run(run_id, f"  Freed: {fmt(os_size_before)}", "success")
            except Exception as e:
                add_log_to_run(run_id, f"  Timesketch cleanup error: {e}", "warning")

            # === SUMMARY ===
            add_log_to_run(run_id, "=" * 50, "info")
            add_log_to_run(run_id, f"PURGE COMPLETE - Total freed: {fmt(total_freed)}", "success")
            add_log_to_run(run_id, "=" * 50, "info")
            update_run_status(run_id, "completed", progress=100)

        except Exception as e:
            add_log_to_run(run_id, f"Purge failed: {str(e)}", "error")
            update_run_status(run_id, "failed", error=str(e))
        finally:
            unregister_cancel(run_id)

    thread = threading.Thread(target=run_purge, daemon=True)
    thread.start()

    return jsonify({"success": True, "run_id": run_id, "message": "System purge started"})
