#!/usr/bin/env python3
"""
Maintenance Routes - System maintenance and tool management endpoints
"""

from flask import Blueprint, jsonify, request
import subprocess
import threading

from services import (
    create_automation_run,
    add_log_to_run,
    update_run_status
)
from services.velociraptor_init_service import initialize_velociraptor_artifacts
from config import is_module_enabled

maintenance_bp = Blueprint('maintenance', __name__)


def container_running(name):
    """Return True when an optional module container is currently running."""
    try:
        result = subprocess.run(
            [
                "docker", "ps",
                "--filter", f"name=^{name}$",
                "--filter", "status=running",
                "--format", "{{.Names}}",
            ],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except Exception:
        return False
    return name in {line.strip() for line in result.stdout.splitlines()}


@maintenance_bp.route('/api/maintenance/run', methods=['POST'])
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

        from services.workflow_service import register_cancel_event, unregister_cancel
        cancel_event = register_cancel_event(run_id)

        # Run maintenance in background
        def run_maintenance():
            try:
                # =========================================================
                # Velociraptor artifacts: NO import step in maintenance.
                # The curated artifact bundle (ArtifactExchange / DetectRaptor
                # / Sigma / Rapid7 / TenRoot, ~400 definitions) is baked into
                # the velociraptor image and loaded on boot via --definitions
                # (see modules/velociraptor/{Dockerfile,entrypoint.sh,
                # bundled_artifacts/}). Event monitoring + operator custom
                # artifacts are (re)ensured on backend startup. So there is
                # nothing to import here — this used to be the slow step.
                # =========================================================
                add_log_to_run(run_id, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", "info")
                add_log_to_run(run_id, "Velociraptor artifacts: loaded from the image on boot "
                                       "(--definitions) — no maintenance import needed.", "info")
                add_log_to_run(run_id, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", "info")
                update_run_status(run_id, "running", progress=25)

                # =========================================================
                # Task 2: Download tools and configure inventory (60%)
                # =========================================================
                add_log_to_run(run_id, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", "info")
                add_log_to_run(run_id, "TASK 2/3: Download & Configure Tools", "info")
                add_log_to_run(run_id, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", "info")
                update_run_status(run_id, "running", progress=30)

                if not container_running('intact_velociraptor'):
                    add_log_to_run(run_id, "Tool download skipped: intact_velociraptor is not running", "info")
                else:
                    try:
                        from services.tools_download_service import download_and_configure_tools

                        tool_results = download_and_configure_tools(
                            logger=lambda msg, level="info": add_log_to_run(run_id, msg, level),
                            run_id=run_id,
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

                # NOTE: DFIR/agentic skills are NOT refreshed here. The
                # fusion analyst's macro skills ship as STATIC files baked
                # into the backend image (services/agentic/skills/macros/) —
                # there is no runtime download. (The old per-artifact skill
                # corpus + its GitHub downloader were removed.)

                # =========================================================
                # Task 3: Refresh CVE Scan databases (CPE dict + local
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
                add_log_to_run(run_id, "TASK 3/4: Refresh CVE Scan databases (CPE dict + local CVE mirror)", "info")
                add_log_to_run(run_id, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", "info")

                # Gate on modules.cve_scan.enabled — a DISABLED CVE module must not
                # download/refresh the CVE feed during maintenance (same rule as
                # every other module: disabled => no data, no pages).
                from config import is_module_enabled as _is_mod_enabled
                if not _is_mod_enabled('cve_scan'):
                    add_log_to_run(
                        run_id,
                        "CVE Scan disabled (modules.cve_scan.enabled=false) — "
                        "skipping CVE database refresh/download.",
                        "info",
                    )
                else:
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
                if not container_running('intact_velociraptor'):
                    add_log_to_run(run_id, "  Velociraptor: skipped (container not running)", "info")
                else:
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
                if not container_running('intact_elasticsearch'):
                    add_log_to_run(run_id, "  Elasticsearch: skipped (container not running)", "info")
                else:
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


# NOTE: the /api/maintenance/refresh-skills endpoint was removed. The fusion
# analyst's macro skills are STATIC files baked into the backend image
# (services/agentic/skills/macros/) — they are never downloaded at runtime, so
# there is nothing to "refresh". The old per-artifact skill corpus and its
# GitHub downloader (services/skills_download_service.py) were deleted.


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
                if not container_running('intact_velociraptor'):
                    msg = "Tool download skipped: intact_velociraptor is not running"
                    add_log_to_run(run_id, msg, "info")
                    update_run_status(run_id, "completed", progress=100)
                    return

                result = download_and_configure_tools(
                    logger=lambda msg, level="info": add_log_to_run(run_id, msg, level),
                    run_id=run_id,
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


def _delete_runs_preserve_cases(c, run_id, include_system=False):
    """Delete investigation run rows, preserving:

      (a) the purge run itself,
      (b) every case workspace — a case is an organizational container, not
          accumulated data; a *data* purge empties the workspaces, it does not
          destroy the workspace structure. The builtin Default/System
          workspaces in particular must always survive (they're undeletable
          through the normal case-delete path too). Without this guard the raw
          `DELETE FROM workflows` wiped every case, the active workspace the UI
          was scoped to vanished mid-run, and the purge log appeared to "stop
          in the middle."
      (c) system/admin run history (SYSTEM_TYPES: upgrade/maintenance/purge/
          support-bundle/settings/…) UNLESS ``include_system=True``. This is an
          audit trail, not investigation data — a normal purge keeps it; only
          the explicit "System Operation History" section removes it.

    Surviving cases now reference deleted member runs, so their cached fusion
    graph is stale — strip it so the UI doesn't render a graph built from
    purged evidence. Returns (runs_deleted, cases_kept).
    """
    import json as _json
    from services.workflow_service import SYSTEM_TYPES
    keep = {"case"} | (set() if include_system else set(SYSTEM_TYPES))
    placeholders = ",".join("?" * len(keep))
    before = c.execute("SELECT COUNT(*) FROM workflows").fetchone()[0]
    cases = c.execute(
        "SELECT COUNT(*) FROM workflows WHERE automation_type = 'case'"
    ).fetchone()[0]
    c.execute(
        f"DELETE FROM workflows WHERE run_id != ? "
        f"AND automation_type NOT IN ({placeholders})",
        (run_id, *sorted(keep)),
    )
    after = c.execute("SELECT COUNT(*) FROM workflows").fetchone()[0]
    rows = c.execute(
        "SELECT run_id, details FROM workflows WHERE automation_type = 'case'"
    ).fetchall()
    for cid, det in rows:
        try:
            d = _json.loads(det) if det else {}
        except (TypeError, ValueError):
            d = {}
        if not isinstance(d, dict):
            continue
        changed = False
        for k in ("fusion_graph", "fused_run_ids", "report_md", "report_html",
                  "stale_run_ids"):
            if k in d:
                d.pop(k, None)
                changed = True
        if changed:
            c.execute("UPDATE workflows SET details = ? WHERE run_id = ?",
                      (_json.dumps(d), cid))
    return max(0, before - after), cases


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
        # Sections that couldn't run because their module isn't
        # deployed (e.g. Velociraptor purge skipped on a
        # backend-only install). Surfaced in the end-of-run summary
        # so operators see why a section freed 0 bytes — was there
        # nothing to clean, or could it not even attempt to?
        skipped_sections: list[str] = []

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
                c.execute("SELECT COUNT(*) FROM reports")
                rpt_count = c.fetchone()[0]
                runs_deleted, cases_kept = _delete_runs_preserve_cases(c, run_id)
                c.execute("DELETE FROM reports")
                conn.commit()
                c.execute("VACUUM")
                conn.commit()
                conn.close()
                db_size_after = os.path.getsize(db_path) if os.path.exists(db_path) else 0
                freed = max(0, db_size_before - db_size_after)
                total_freed += freed
                add_log_to_run(run_id, f"  Deleted {runs_deleted} investigation runs, {rpt_count} reports (kept {cases_kept} case workspaces + system operation history)", "info")
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
            # /data/downloads = report exports. NOT /app/downloads (install
            # artifacts: client installers + collector + tools).
            freed, count = purge_dir("/data/downloads")
            total_freed += freed
            add_log_to_run(run_id, f"  Removed {count} items | Freed: {fmt(freed)}", "success")

            # === 7. Velociraptor Hunt Data ===
            add_log_to_run(run_id, "=" * 50, "info")
            add_log_to_run(run_id, "PURGE: Velociraptor Hunts & Collections", "info")
            add_log_to_run(run_id, "=" * 50, "info")
            update_run_status(run_id, "running", progress=70)

            # Skip the whole section cleanly when Velociraptor isn't
            # deployed. Without this guard, every docker-exec below
            # fails with "No such container: intact_velociraptor",
            # the section reports 0 bytes freed, the workflow ends
            # as `completed`, and the operator can't tell whether
            # there was nothing to clean or whether the section
            # couldn't even attempt it. Track in skipped_sections so
            # the end-of-run summary surfaces what didn't run.
            if not container_running('intact_velociraptor'):
                add_log_to_run(run_id, "  Skipped: intact_velociraptor not deployed (nothing to purge)", "info")
                skipped_sections.append("velociraptor")
            else:
                try:
                    from services.velociraptor_service import purge_velociraptor_data
                    from services.upgrade.base import run_command

                    # Measure before (exclude /var./public/ which holds forensic tools)
                    du_before = run_command("docker exec intact_velociraptor sh -c 'du -sb --exclude=public /var./ 2>/dev/null || echo 0'", logger=None)
                    size_before = int(du_before.get('stdout', '0').split()[0]) if du_before.get('success') else 0
                    add_log_to_run(run_id, f"  Datastore size: {fmt(size_before)}", "info")

                    # Delete hunts/flows/monitoring + sweep orphaned result files
                    # via the gRPC API (proper server context + index-safe
                    # file_store_delete — keeps every client enrolled). The old
                    # `docker exec … query` CLI saw 0 hunts/clients and only
                    # rm -rf'd collections/+uploads/, orphaning the bulk of the
                    # data under clients/*/artifacts/ — which is why purges here
                    # historically freed almost nothing.
                    def _vlog(msg, level="info"):
                        add_log_to_run(run_id, f"  {msg}", level)

                    res = purge_velociraptor_data(logger=_vlog)
                    add_log_to_run(
                        run_id,
                        f"  Deleted {res.get('hunts', 0)} hunts, {res.get('flows', 0)} flows, "
                        f"{res.get('data_files', 0)} result files, "
                        f"{res.get('monitoring', 0)} monitoring files",
                        "info",
                    )

                    # Measure after (exclude /var./public/ which holds forensic tools)
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

            if not container_running('intact_elasticsearch'):
                add_log_to_run(run_id, "  Skipped: intact_elasticsearch not deployed (nothing to purge)", "info")
                skipped_sections.append("elk")
            else:
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

            # Timesketch purge spans TWO containers (opensearch +
            # postgres). Skip the whole section unless the opensearch
            # container is up — the postgres-only cleanup without
            # the index delete leaves the stack in an inconsistent
            # state, so all-or-nothing is the right policy.
            if not container_running('intact_timesketch_opensearch'):
                add_log_to_run(run_id, "  Skipped: intact_timesketch_opensearch not deployed (nothing to purge)", "info")
                skipped_sections.append("timesketch")
            else:
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
            if skipped_sections:
                add_log_to_run(
                    run_id,
                    f"Sections skipped (module not deployed): {', '.join(skipped_sections)}",
                    "info",
                )
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


# ============================================================================
# Section-aware purge — operator picks which sections to clear after seeing
# how much each one is currently consuming. Keeps the "purge all" endpoint
# above for backwards compatibility; new UI uses these two endpoints.
# ============================================================================
#
# Section definitions: one entry per purgeable area, each declaring:
#   - id:       stable identifier (used in the API)
#   - label:    human-readable name shown in the UI
#   - scan:     callable() → (size_bytes, detail_str) — non-destructive
#   - purge:    callable() → (size_bytes_freed, detail_str) — destructive
#
# `scan` MUST be cheap (filesystem stat + small DB count). `purge` runs
# in the background worker, never on the request thread.

def _fmt_size(b: int) -> str:
    if b >= 1024 ** 3:
        return f"{b / 1024 ** 3:.1f} GB"
    if b >= 1024 ** 2:
        return f"{b / 1024 ** 2:.1f} MB"
    if b >= 1024:
        return f"{b / 1024:.1f} KB"
    return f"{b} B"


def _scan_dir(path: str) -> int:
    import os
    if not os.path.exists(path):
        return 0
    if os.path.isfile(path):
        return os.path.getsize(path)
    total = 0
    for dirpath, _, filenames in os.walk(path):
        for f in filenames:
            try:
                total += os.path.getsize(os.path.join(dirpath, f))
            except (OSError, FileNotFoundError):
                pass
    return total


def _purge_dir(path: str) -> tuple[int, int]:
    """Delete contents of a directory (not the dir itself). Returns
    ``(bytes_freed, items_removed)``."""
    import os
    import shutil
    if not os.path.exists(path):
        return 0, 0
    size = _scan_dir(path)
    count = 0
    for item in os.listdir(path):
        ip = os.path.join(path, item)
        try:
            if os.path.isdir(ip):
                shutil.rmtree(ip)
            else:
                os.remove(ip)
            count += 1
        except Exception:
            pass
    return size, count


# ---- scan functions ----------------------------------------------------

def _scan_workflows():
    import os, sqlite3
    from services.workflow_service import SYSTEM_TYPES
    p = "/app/data/intact.db"
    db_size = os.path.getsize(p) if os.path.exists(p) else 0
    wf_count = rp_count = 0
    # Count INVESTIGATION runs only — case workspaces and system/admin history
    # are preserved by this section's purge, so don't advertise them as
    # reclaimable here.
    exclude = ["case", *sorted(SYSTEM_TYPES)]
    ph = ",".join("?" * len(exclude))
    try:
        conn = sqlite3.connect(p)
        wf_count = conn.execute(
            f"SELECT COUNT(*) FROM workflows WHERE automation_type NOT IN ({ph})",
            tuple(exclude),
        ).fetchone()[0]
        try:
            rp_count = conn.execute("SELECT COUNT(*) FROM reports").fetchone()[0]
        except sqlite3.OperationalError:
            rp_count = 0
        conn.close()
    except Exception:
        pass
    # The DB file holds workflows + reports + blueprints etc.; we can't
    # cleanly attribute size to the wf+report rows alone, but a workflow
    # row averages ~5-50 KB (logs as JSON). Estimate: 25 KB × wf_count.
    estimated = wf_count * 25 * 1024 + rp_count * 50 * 1024
    return min(estimated, db_size), f"{wf_count} investigation runs, {rp_count} reports"


def _scan_system_workflows():
    import os, sqlite3
    from services.workflow_service import SYSTEM_TYPES
    p = "/app/data/intact.db"
    cnt = 0
    ph = ",".join("?" * len(SYSTEM_TYPES))
    try:
        conn = sqlite3.connect(p)
        cnt = conn.execute(
            f"SELECT COUNT(*) FROM workflows WHERE automation_type IN ({ph})",
            tuple(sorted(SYSTEM_TYPES)),
        ).fetchone()[0]
        conn.close()
    except Exception:
        pass
    return cnt * 25 * 1024, f"{cnt} system operation run(s)"


def _scan_azure_runs():
    p = "/data/db/azure_runs"
    return _scan_dir(p), ""


def _scan_uploads():
    p = "/data/uploads"
    return _scan_dir(p), ""


def _scan_upgrade_packages():
    import os
    s = _scan_dir("/data/upgrade_packages")
    for f in ("/data/db/prepared_package.json", "/data/db/prepared_packages.json"):
        if os.path.exists(f):
            s += os.path.getsize(f)
    return s, ""


def _scan_temp_files():
    import glob
    s = 0
    for d in ("/app/data/tmp", "/data/tmp", "/tmp/plaso", "/tmp/azure_uploads"):
        s += _scan_dir(d)
    for d in glob.glob("/app/data/tmp/intact-upgrade-*") + glob.glob("/tmp/intact-upgrade-*"):
        s += _scan_dir(d)
    return s, ""


def _scan_report_downloads():
    # Report EXPORTS live in /data/downloads/<run_id>/. NOT /app/downloads —
    # that's the nginx-mounted install-artifact dir (Velociraptor legacy/musl
    # client installers + offline collector + tools, fetched by install.sh).
    # Purging it deletes the client downloads and greys out the Downloads page.
    return _scan_dir("/data/downloads"), ""


def _scan_velociraptor():
    from services.upgrade.base import run_command
    r = run_command(
        "docker exec intact_velociraptor sh -c 'du -sb --exclude=public /var./ 2>/dev/null || echo 0'",
        logger=None,
    )
    try:
        size = int((r.get("stdout") or "0").split()[0])
    except Exception:
        size = 0
    return size, "hunts + flows + uploads + notebooks (excludes /var./public tools)"


def _scan_elk_artifacts():
    import requests as req
    try:
        r = req.get(
            "http://intact_elasticsearch:9200/_cat/indices?h=index,store.size&bytes=b",
            timeout=5,
        )
        if r.status_code != 200:
            return 0, "elasticsearch unreachable"
        size = 0
        n = 0
        for line in r.text.strip().split("\n"):
            parts = line.split()
            if len(parts) >= 2 and parts[0].startswith("artifact_"):
                size += int(parts[1])
                n += 1
        return size, f"{n} artifact_* indices"
    except Exception:
        return 0, "elasticsearch unreachable"


def _scan_timesketch():
    from services.upgrade.base import run_command
    r = run_command(
        "docker exec intact_timesketch_opensearch curl -s 'http://localhost:9200/_cat/indices?h=index,store.size&bytes=b'",
        logger=None,
    )
    if not r.get("success"):
        return 0, "opensearch unreachable"
    size = 0
    n = 0
    for line in (r.get("stdout") or "").strip().split("\n"):
        parts = line.split()
        if len(parts) >= 2 and not parts[0].startswith("."):
            try:
                size += int(parts[1])
                n += 1
            except ValueError:
                pass
    return size, f"{n} timeline indices"


def _scan_memory_dumps():
    """Memory module residue — host .raw + VolWeb media + Velociraptor
    flow uploads. All three are independent of the normal purge sweep."""
    import os
    sizes = {
        "host_raw": _scan_dir("/data/memory_dumps"),
        "volweb_media": 0,
    }
    # VolWeb media .raw lives in a docker volume; size via du from the
    # container. Skipped if VolWeb isn't deployed.
    try:
        from services.upgrade.base import run_command
        r = run_command(
            "docker exec intact_volweb_backend sh -c 'du -sb /home/app/web/media/evidences 2>/dev/null || echo 0'",
            logger=None,
        )
        if r.get("success"):
            try:
                sizes["volweb_media"] = int((r.get("stdout") or "0").split()[0])
            except Exception:
                pass
    except Exception:
        pass
    total = sum(sizes.values())
    detail_parts = [f"{k.replace('_', ' ')}: {_fmt_size(v)}" for k, v in sizes.items() if v]
    return total, ", ".join(detail_parts) if detail_parts else "(no residue)"


# ---- Docker storage scanners --------------------------------------------
#
# The IntactAI working-tree scanners cover < 3 GB on a typical box. The
# real disk hog is Docker itself (~20 GB on a mature install: 12 GB
# images + 7 GB volumes + build cache). Without these three sections the
# operator can run the Purge UI to 0% and the disk is still full because
# the dashboard can't see /var/lib/docker.
#
# `docker system df --format '{{json .}}'` returns one JSON line per
# resource type with `Reclaimable` parsed as a string ("619.1MB (9%)").
# We parse that into bytes so the scan can mirror the other sections'
# return shape.

def _parse_size_string(s: str) -> int:
    """Turn '12.91GB' / '619.1MB' / '0B' into a byte int.

    Docker's `--format '{{json .}}'` emits Reclaimable like
    `"619.1MB (9%)"` — strip the `( … )` suffix first.
    """
    if not s:
        return 0
    s = s.split("(")[0].strip()
    units = {"B": 1, "KB": 1024, "MB": 1024**2, "GB": 1024**3, "TB": 1024**4,
             "K": 1024, "M": 1024**2, "G": 1024**3, "T": 1024**4}
    for unit_len in (2, 1):
        if len(s) > unit_len and s[-unit_len:].upper() in units:
            try:
                return int(float(s[:-unit_len]) * units[s[-unit_len:].upper()])
            except ValueError:
                return 0
    try:
        return int(float(s))
    except ValueError:
        return 0


def _docker_system_df():
    """Return parsed `docker system df` rows keyed by `Type`.

    Result e.g.:
      {'Images': {'TotalCount': '22', 'Active': '21',
                  'Size': '12.91GB', 'Reclaimable': '480.3MB (3%)'},
       'Containers': {...}, 'Local Volumes': {...}, 'Build Cache': {...}}
    """
    import json
    from services.upgrade.base import run_command
    r = run_command(
        "docker system df --format '{{json .}}'",
        logger=None,
    )
    out = (r.get("stdout") or "").strip()
    rows = {}
    for line in out.split("\n"):
        if not line.strip():
            continue
        try:
            j = json.loads(line)
            rows[j.get("Type", "?")] = j
        except Exception:
            continue
    return rows


def _scan_docker_images():
    """Reclaimable image bytes (= unused images = what `image prune -a`
    would drop). The dashboard already shows in-use containers and their
    images stay tied to running services; only orphans are touched."""
    rows = _docker_system_df()
    row = rows.get("Images") or {}
    bytes_ = _parse_size_string(row.get("Reclaimable", "0B"))
    total_count = row.get("TotalCount", "?")
    active = row.get("Active", "?")
    detail = f"{active}/{total_count} active; rest reclaimable on next deploy"
    return bytes_, detail


def _scan_docker_volumes():
    rows = _docker_system_df()
    row = rows.get("Local Volumes") or {}
    bytes_ = _parse_size_string(row.get("Reclaimable", "0B"))
    total_count = row.get("TotalCount", "?")
    active = row.get("Active", "?")
    detail = f"{active}/{total_count} active; orphan volumes only"
    return bytes_, detail


def _scan_docker_build_cache():
    rows = _docker_system_df()
    # Docker's row label is "Build Cache" — fall back if Docker renames it.
    row = rows.get("Build Cache") or rows.get("Build cache") or {}
    bytes_ = _parse_size_string(row.get("Reclaimable", "0B"))
    total_count = row.get("TotalCount", "?")
    detail = f"{total_count} layer cache entries"
    return bytes_, detail


def _scan_docker_deep():
    """Deep prune estimate — `docker system prune -a --volumes -f`.

    This is a strict superset of the 3 individual docker_* sections
    above (images, volumes, build cache). It also drops stopped
    containers' writable layers, which the per-resource scans don't
    cover. On boxes where image upgrades have orphaned overlay layers
    (`/var/lib/docker/overlay2` much larger than what `docker system
    df` reports), this is the section that actually recovers the
    "missing" disk.

    Scan returns the sum of all reclaimable across image / volume /
    build-cache layers as a conservative LOWER bound — actual freed
    may be 2-10× higher because the per-resource API undercounts
    orphan overlay layers.
    """
    rows = _docker_system_df()
    bytes_ = 0
    for type_key in ("Images", "Build Cache"):
        row = rows.get(type_key) or {}
        bytes_ += _parse_size_string(row.get("Reclaimable", "0B"))
    detail = (
        "All unused images + build cache + stopped-container layers. Does NOT "
        "touch volumes (data is preserved — use the Docker Volumes section for "
        "that). Active services keep running; images re-pull on next "
        "`docker compose up`. Often frees more than the individual rows report."
    )
    return bytes_, detail


def _scan_system_journal():
    """systemd journal disk usage — `/var/log/journal` accumulation.

    Probed by a one-shot Ubuntu container with /var/log/journal
    mounted, since the IntactAI backend container doesn't ship
    journalctl. Returns 0 (and a benign note) on hosts without
    systemd journal storage.
    """
    from services.upgrade.base import run_command
    r = run_command(
        "docker run --rm -v /var/log/journal:/var/log/journal:ro "
        "ubuntu:22.04 sh -c 'journalctl --disk-usage 2>/dev/null | "
        "grep -oE \"[0-9.]+[KMGT]?B\" | head -1' 2>/dev/null",
        logger=None,
    )
    raw = (r.get("stdout") or "").strip()
    if not raw:
        return 0, "no systemd journal storage (or backend can't access it)"
    bytes_ = _parse_size_string(raw)
    # Vacuum target is 200 MB — anything above that is reclaimable.
    target = 200 * 1024 * 1024
    reclaimable = max(0, bytes_ - target)
    return reclaimable, f"current {raw}; vacuum to 200 MB"


# ---- purge functions ---------------------------------------------------

def _purge_workflows(run_id):
    import os
    import sqlite3
    db_path = "/app/data/intact.db"
    before = os.path.getsize(db_path) if os.path.exists(db_path) else 0
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    rp = 0
    try:
        rp = c.execute("SELECT COUNT(*) FROM reports").fetchone()[0]
    except sqlite3.OperationalError:
        pass
    runs_deleted, cases_kept = _delete_runs_preserve_cases(c, run_id)
    try:
        c.execute("DELETE FROM reports")
    except sqlite3.OperationalError:
        pass
    conn.commit()
    c.execute("VACUUM")
    conn.commit()
    conn.close()
    after = os.path.getsize(db_path) if os.path.exists(db_path) else 0
    return max(0, before - after), f"{runs_deleted} investigation runs, {rp} reports (kept {cases_kept} workspaces + system history)"


def _purge_system_workflows(run_id):
    """Delete system/admin run history (upgrades, prepares, online upgrades,
    maintenance, purges, support bundles, settings ops, case import/export).

    Deliberately kept OUT of the default "Workflows & Reports" section — this
    is an audit trail, not investigation data, and is only removed when the
    operator explicitly marks this section. Never touches cases or
    investigation runs. The currently-running purge row is preserved so its
    own log survives."""
    import os, sqlite3
    from services.workflow_service import SYSTEM_TYPES
    db_path = "/app/data/intact.db"
    before = os.path.getsize(db_path) if os.path.exists(db_path) else 0
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    ph = ",".join("?" * len(SYSTEM_TYPES))
    params = (*sorted(SYSTEM_TYPES), run_id)
    cnt = c.execute(
        f"SELECT COUNT(*) FROM workflows "
        f"WHERE automation_type IN ({ph}) AND run_id != ?",
        params,
    ).fetchone()[0]
    c.execute(
        f"DELETE FROM workflows WHERE automation_type IN ({ph}) AND run_id != ?",
        params,
    )
    conn.commit()
    c.execute("VACUUM")
    conn.commit()
    conn.close()
    after = os.path.getsize(db_path) if os.path.exists(db_path) else 0
    return max(0, before - after), f"{cnt} system operation run(s)"


def _purge_azure_runs(_):
    f, c = _purge_dir("/data/db/azure_runs")
    return f, f"{c} files"


def _purge_uploads(_):
    f, c = _purge_dir("/data/uploads")
    return f, f"{c} items"


def _purge_upgrade_packages(_):
    import os
    freed, count = _purge_dir("/data/upgrade_packages")
    for fp in ("/data/db/prepared_package.json", "/data/db/prepared_packages.json"):
        if os.path.exists(fp):
            freed += os.path.getsize(fp)
            try:
                os.remove(fp)
                count += 1
            except Exception:
                pass
    return freed, f"{count} items"


def _purge_temp_files(_):
    import glob
    import shutil
    freed = 0
    for d in ("/app/data/tmp", "/data/tmp", "/tmp/plaso", "/tmp/azure_uploads"):
        df, _c = _purge_dir(d)
        freed += df
    for d in glob.glob("/app/data/tmp/intact-upgrade-*") + glob.glob("/tmp/intact-upgrade-*"):
        freed += _scan_dir(d)
        shutil.rmtree(d, ignore_errors=True)
    return freed, ""


def _purge_report_downloads(_):
    # /data/downloads = generated report exports (per run_id). NOT /app/downloads
    # — that's the install-artifact dir (client installers + collector); purging
    # it broke the Downloads page.
    f, c = _purge_dir("/data/downloads")
    return f, f"{c} items"


def _purge_velociraptor(run_id):
    """Remove collected hunt/flow/monitoring DATA while keeping every client
    enrolled. Delegates to the gRPC-API purge in velociraptor_service — that
    runs in the proper server context (the old `docker exec … query` CLI saw 0
    hunts and 0 clients, so it silently freed nothing) and uses Velociraptor's
    own flow_delete/hunt_delete/file_store_delete primitives instead of an
    index-corrupting `rm -rf`."""
    from services.velociraptor_service import purge_velociraptor_data

    def _log(msg, level="info"):
        try:
            add_log_to_run(run_id, f"  {msg}", level)
        except Exception:
            pass

    before = _scan_velociraptor()[0]
    res = purge_velociraptor_data(logger=_log)
    after = _scan_velociraptor()[0]
    detail = (
        f"{res.get('hunts', 0)} hunts, {res.get('flows', 0)} flows, "
        f"{res.get('data_files', 0)} result files, "
        f"{res.get('monitoring', 0)} monitoring files"
    )
    if res.get("errors"):
        detail += f" (errors: {'; '.join(res['errors'])})"
    return max(0, before - after), detail


def _purge_elk_artifacts(_):
    import requests as req
    try:
        r = req.get(
            "http://intact_elasticsearch:9200/_cat/indices?h=index,store.size&bytes=b",
            timeout=5,
        )
        if r.status_code != 200:
            return 0, "elasticsearch unreachable"
        size = 0
        deleted = 0
        for line in r.text.strip().split("\n"):
            parts = line.split()
            if len(parts) >= 2 and parts[0].startswith("artifact_"):
                size += int(parts[1])
                d = req.delete(f"http://intact_elasticsearch:9200/{parts[0]}", timeout=10)
                if d.status_code == 200:
                    deleted += 1
        return size, f"{deleted} indices"
    except Exception as e:
        return 0, f"error: {e}"


def _purge_timesketch(_):
    """Purge Timesketch sketches + timelines + all dependent state.

    Three layers to wipe so the UI shows a true clean slate:

    1. OpenSearch indices — the actual event data (timeline_*)
    2. Postgres `sketch` table (TRUNCATE CASCADE)
       Every per-sketch child table in Timesketch's schema has
       `ON DELETE NO ACTION`, so plain DELETE would error on FK
       violations. TRUNCATE CASCADE bypasses that and clears every
       table that references `sketch` transitively (timeline,
       searchindex, view, story, aggregation, event, graph,
       analysis, scenario, investigativequestion, facet, attribute,
       searchhistory, plus their *_comment / *_label / *_status /
       *_accesscontrolentry siblings).
    3. searchindex + timeline get cleared anyway via the CASCADE
       from #2 — listed explicitly for clarity.

    User accounts, groups, and YARA rule rows are intentionally NOT
    touched — the operator's login + customization survives the
    purge. Only investigation state is dropped.
    """
    from services.upgrade.base import run_command
    before = _scan_timesketch()[0]

    # 1) OpenSearch indices
    run_command(
        "docker exec intact_timesketch_opensearch curl -s -X DELETE 'http://localhost:9200/*,-.*'",
        logger=None,
    )

    # 2) Postgres sketch tree — TRUNCATE CASCADE from the roots.
    #    RESTART IDENTITY resets auto-increment so new sketches start
    #    from id=1 again (matches the visible "fresh install" feel).
    #
    #    Both `sketch` AND `searchindex` are roots — searchindex is
    #    NOT a child of sketch (it stores OpenSearch index pointers
    #    that timelines reference). Without TRUNCATEing it separately,
    #    9-ish orphan rows survive and accumulate every purge cycle.
    #    `datasource` cascades automatically (FK to searchindex).
    truncate_sql = (
        "TRUNCATE TABLE sketch, searchindex RESTART IDENTITY CASCADE;"
    )
    run_command(
        f"docker exec intact_timesketch_postgres psql -U timesketch -d timesketch -c \"{truncate_sql}\"",
        logger=None,
    )

    after = _scan_timesketch()[0]
    return max(0, before - after), ""


def _purge_memory_dumps(_):
    """Memory module residue across all three places dumps land."""
    import os
    import shutil
    freed = 0
    detail = []
    # Host .raw files
    host_dir = "/data/memory_dumps"
    if os.path.isdir(host_dir):
        s = _scan_dir(host_dir)
        for f in os.listdir(host_dir):
            try:
                fp = os.path.join(host_dir, f)
                if os.path.isfile(fp):
                    os.remove(fp)
                elif os.path.isdir(fp):
                    shutil.rmtree(fp)
            except Exception:
                pass
        freed += s
        detail.append(f"host .raw {_fmt_size(s)}")
    # VolWeb media — best-effort; skipped silently if VolWeb isn't up.
    try:
        from services.upgrade.base import run_command
        before = 0
        r = run_command(
            "docker exec intact_volweb_backend sh -c 'du -sb /home/app/web/media/evidences 2>/dev/null || echo 0'",
            logger=None,
        )
        if r.get("success"):
            try:
                before = int((r.get("stdout") or "0").split()[0])
            except Exception:
                pass
        if before > 0:
            run_command(
                "docker exec intact_volweb_backend sh -c 'rm -f /home/app/web/media/evidences/*.raw'",
                logger=None,
            )
            freed += before
            detail.append(f"VolWeb media {_fmt_size(before)}")
    except Exception:
        pass
    return freed, ", ".join(detail) if detail else "no dumps found"


# ---- Docker storage purgers ---------------------------------------------

def _purge_docker_images(_):
    """`docker image prune -a -f` — drop every image no running container
    depends on. The next `docker compose up` will re-pull anything still
    referenced by a compose file, which is the expected operator path
    after a disk-pressure cleanup."""
    from services.upgrade.base import run_command
    before, _ = _scan_docker_images()
    run_command("docker image prune -a -f", logger=None)
    after, _ = _scan_docker_images()
    return max(0, before - after), ""


def _purge_docker_volumes(_):
    """Reclaim unused docker volumes WITHOUT destroying service data.

    Modern Docker's `volume prune` (no -a) only removes anonymous volumes, so
    named leftovers never get reclaimed — e.g. a 647 MB stale `*_timesketch_venv`
    persists forever (the 'doesn't free anything' bug). But a blanket
    `volume prune -af` would also delete a STOPPED service's data volume
    (e.g. `iris_iris_db_data`) — destroying real data. So:
      1. `volume prune -f` — anonymous unused volumes (always safe).
      2. remove unused NAMED volumes ONLY when the name is clearly rebuildable
         throwaway state (venv / cache / tmp / build). Anything that looks like
         a database / evidence / media / data store is left untouched.
    """
    from services.upgrade.base import run_command
    import re
    before, _ = _scan_docker_volumes()

    # 1. Anonymous unused volumes — Docker's own safe default.
    run_command("docker volume prune -f", logger=None)

    # 2. Named unused volumes that are safe to rebuild. Allow-list (not a
    #    data-volume deny-list) so an unrecognised name is KEPT, never deleted.
    #    Match on whole underscore/dash/dot-delimited SEGMENTS, not substrings —
    #    otherwise "temp" would wrongly match "iris_iris_templates" (real data).
    SAFE_TOKENS = {"venv", "cache", "tmp", "temp", "build", "buildcache",
                   "node_modules", "pip", "wheels"}

    def _is_rebuildable(vol_name):
        segs = re.split(r"[_\-.]", vol_name.lower())
        return any(seg in SAFE_TOKENS for seg in segs)

    listing = run_command(
        "docker volume ls --filter dangling=true --format '{{.Name}}'",
        logger=None,
    )
    removed = []
    for name in [x.strip() for x in (listing.get("stdout") or "").splitlines() if x.strip()]:
        if _is_rebuildable(name):
            if run_command(f"docker volume rm {name}", logger=None).get("success"):
                removed.append(name)

    after, _ = _scan_docker_volumes()
    detail = (f"{len(removed)} rebuildable named volume(s) + anonymous"
              if removed else "anonymous only (named data volumes preserved)")
    return max(0, before - after), detail


def _purge_docker_build_cache(_):
    from services.upgrade.base import run_command
    before, _ = _scan_docker_build_cache()
    # `-a` includes inactive cache entries; `-f` skips the prompt.
    run_command("docker builder prune -af", logger=None)
    after, _ = _scan_docker_build_cache()
    return max(0, before - after), ""


def _purge_docker_deep(_):
    """`docker system prune -a --volumes -f` — single-shot deep clean.

    Drops every unused image (not just dangling), every orphan volume,
    every stopped container's layer, and the entire build cache. The
    canonical recipe for clawing back overlay2 space that's leaked
    over time via failed builds, image upgrades, container churn.

    To measure actual savings we compare the host's total docker
    storage footprint via `docker system df` (sum of in-use + reclaimable
    across all types) before and after. That captures the orphan
    overlay layers the per-type API undercounts.
    """
    from services.upgrade.base import run_command

    def _docker_total_bytes():
        rows = _docker_system_df()
        n = 0
        for row in rows.values():
            n += _parse_size_string(row.get("Size", "0B"))
        return n

    before = _docker_total_bytes()
    # NOTE: intentionally NO `--volumes`. `docker system prune --volumes` would
    # delete every unused NAMED volume too — including a stopped service's data
    # store (e.g. iris_iris_db_data) — which destroys real data. Volume cleanup
    # is handled safely (allow-listed) by the dedicated docker_volumes section.
    run_command("docker system prune -a -f", logger=None)
    after = _docker_total_bytes()
    return max(0, before - after), ""


def _purge_system_journal(_):
    """`journalctl --vacuum-size=200M` via a one-shot Ubuntu container
    with /var/log/journal mounted read-write. Trims old archived
    journals; keeps the active journal + the most recent ~200 MB."""
    from services.upgrade.base import run_command
    before, _ = _scan_system_journal()
    run_command(
        "docker run --rm -v /var/log/journal:/var/log/journal:rw "
        "ubuntu:22.04 journalctl --vacuum-size=200M 2>&1 | tail -1",
        logger=None,
    )
    after, _ = _scan_system_journal()
    return max(0, before - after), ""


# ---- registry -----------------------------------------------------------

# Sections deliberately EXCLUDED from the "Select all" button — the operator
# must tick them individually. System operation history is an audit trail, so a
# blanket "purge everything" must never sweep it away by accident.
_EXCLUDE_FROM_ALL = {"system_workflows"}

_PURGE_SECTIONS = (
    # System operation history first — but excluded from "Select all" (above).
    ("system_workflows",   "System Operation History (upgrades, purges, …)", _scan_system_workflows, _purge_system_workflows),
    ("workflows",          "Investigation Runs & Reports",        _scan_workflows,         _purge_workflows),
    ("azure_runs",         "Azure Scan Data",                     _scan_azure_runs,        _purge_azure_runs),
    ("uploads",            "Upload Data (KAPE, packages, logs)",  _scan_uploads,           _purge_uploads),
    ("upgrade_packages",   "Upgrade Packages",                    _scan_upgrade_packages,  _purge_upgrade_packages),
    ("temp_files",         "Temp Files",                          _scan_temp_files,        _purge_temp_files),
    ("report_downloads",   "Report Downloads",                    _scan_report_downloads,  _purge_report_downloads),
    ("velociraptor",       "Velociraptor Hunts & Collections",    _scan_velociraptor,      _purge_velociraptor),
    ("elk",                "ELK Artifact Indices",                _scan_elk_artifacts,     _purge_elk_artifacts),
    ("timesketch",         "Timesketch Timelines & Events",       _scan_timesketch,        _purge_timesketch),
    ("memory_dumps",       "Memory dumps (.raw files)",           _scan_memory_dumps,      _purge_memory_dumps),
    # Docker-side disk hogs — typically dwarf everything above on a
    # mature install (12 GB+ of unused images is common). The
    # registry's UI is auto-discovered so no frontend changes needed.
    ("docker_images",      "Docker Images (unused)",              _scan_docker_images,     _purge_docker_images),
    ("docker_volumes",     "Docker Volumes (orphan)",             _scan_docker_volumes,    _purge_docker_volumes),
    ("docker_build_cache", "Docker Build Cache",                  _scan_docker_build_cache, _purge_docker_build_cache),
    # Deep clean — strict superset of the 3 docker_* rows. Use when
    # `/var/lib/docker/overlay2` is much larger than `docker system df`
    # reports (orphan layers from image upgrades, failed builds,
    # crashed containers). Safe for running services.
    ("docker_deep",        "Docker Deep Prune (recover orphan layers)", _scan_docker_deep, _purge_docker_deep),
    # Systemd journal — accumulates over time on long-running boxes.
    ("system_journal",     "System Journal (archived)",           _scan_system_journal,    _purge_system_journal),
)


@maintenance_bp.route('/api/maintenance/purge/sections', methods=['GET'])
def list_purge_sections():
    """Return per-section size + count snapshot.

    Used by the Maintenance UI to populate the section-picker so the
    operator sees how much each one is using before selecting.
    """
    out = []
    total = 0
    for sid, label, scan_fn, _purge in _PURGE_SECTIONS:
        try:
            size, detail = scan_fn()
        except Exception as e:
            size, detail = 0, f"scan error: {e}"
        out.append({
            "id": sid,
            "label": label,
            "size_bytes": int(size or 0),
            "size_label": _fmt_size(int(size or 0)),
            "detail": detail,
            "exclude_from_all": sid in _EXCLUDE_FROM_ALL,
        })
        total += int(size or 0)
    return jsonify({
        "sections": out,
        "total_bytes": total,
        "total_label": _fmt_size(total),
    })


@maintenance_bp.route('/api/maintenance/purge/sections', methods=['POST'])
def purge_selected_sections():
    """Purge only the operator-selected sections.

    Body: ``{"sections": ["workflows", "temp_files", ...]}``

    Returns the workflow ``run_id`` so the UI can poll progress via
    ``/api/dashboard/automation/<run_id>``.
    """
    from services.workflow_service import (
        register_cancel_event, unregister_cancel,
    )

    data = request.get_json(silent=True) or {}
    requested = [s for s in (data.get("sections") or []) if isinstance(s, str)]
    if not requested:
        return jsonify({"error": "no sections provided"}), 400

    known = {sid: (label, scan, purge) for sid, label, scan, purge in _PURGE_SECTIONS}
    unknown = [s for s in requested if s not in known]
    if unknown:
        return jsonify({"error": f"unknown sections: {unknown}"}), 400

    run_id = create_automation_run(
        automation_type="system_purge",
        name="System Purge (selected sections)",
        details={"trigger": "manual", "sections": requested},
    )
    update_run_status(run_id, "running", progress=2)
    add_log_to_run(run_id, f"Purging {len(requested)} section(s): {', '.join(requested)}", "info")
    register_cancel_event(run_id)

    def _runner():
        total_freed = 0
        try:
            n = len(requested)
            for idx, sid in enumerate(requested, start=1):
                label, _scan, purge_fn = known[sid]
                add_log_to_run(run_id, "=" * 50, "info")
                add_log_to_run(run_id, f"[{idx}/{n}] PURGE: {label}", "info")
                add_log_to_run(run_id, "=" * 50, "info")
                try:
                    freed, detail = purge_fn(run_id)
                except Exception as e:
                    add_log_to_run(run_id, f"  Error: {e}", "error")
                    continue
                total_freed += int(freed or 0)
                msg = f"  Freed {_fmt_size(int(freed or 0))}"
                if detail:
                    msg += f" — {detail}"
                add_log_to_run(run_id, msg, "success")
                update_run_status(run_id, "running", progress=2 + int(idx / n * 95))

            add_log_to_run(run_id, "=" * 50, "info")
            add_log_to_run(run_id, f"PURGE COMPLETE — Total freed: {_fmt_size(total_freed)}", "success")
            add_log_to_run(run_id, "=" * 50, "info")
            update_run_status(run_id, "completed", progress=100)
        except Exception as e:
            add_log_to_run(run_id, f"Purge failed: {e}", "error")
            update_run_status(run_id, "failed", error=str(e))
        finally:
            unregister_cancel(run_id)

    threading.Thread(target=_runner, daemon=True).start()
    return jsonify({
        "success": True,
        "run_id": run_id,
        "sections": requested,
        "message": "Section purge started",
    })


# ============================================================================
# YARA Ruleset Refresh (VolWeb backing store)
# ============================================================================
#
# Refresh the curated YARA corpus VolWeb scans against. Re-imports the
# two seeded sources from GitHub — Neo23x0/signature-base and
# elastic/protections-artifacts — via VolWeb's existing
# `POST /api/yararulesets/import/github/` endpoint, which downloads each
# repo's source archive and globs its .yar files. Idempotent on
# (name, source) so running it weekly is safe.
#
# YARA-Forge was intentionally dropped: it publishes rules ONLY as
# release assets (its repo has zero .yar files), so this repo-archive
# importer seeded a single useless rule. Both sources here are
# native-importable repos that ship .yar files in-tree.
#
# Tracked as a workflow row (`automation_type='maintenance'`) so the
# operator sees progress in the Workflows tab and can Stop mid-flight.

_YARA_RULESETS = [
    {
        "name": "Neo23x0 signature-base",
        "github_url": "https://github.com/Neo23x0/signature-base",
        "description": "Florian Roth's curated YARA rules (~749 active)",
    },
    {
        "name": "Elastic protections",
        "github_url": "https://github.com/elastic/protections-artifacts",
        "description": "Elastic security YARA detection rules (~695 active)",
    },
]


@maintenance_bp.route('/api/maintenance/yara-rulesets/refresh', methods=['POST'])
def refresh_yara_rulesets():
    """Trigger a refresh of all three seeded YARA rulesets in VolWeb.

    Spawns a background worker so the route returns quickly; the
    operator polls the resulting run_id via the dashboard's
    standard workflow polling.
    """
    import subprocess
    import requests
    from services.workflow_service import (
        create_automation_run, update_run_status, add_log_to_run,
        register_cancel_event, unregister_cancel, is_cancelled,
    )

    run_id = create_automation_run(
        automation_type='maintenance',
        name='YARA Rulesets — Refresh from GitHub',
        details={'trigger': 'manual', 'rulesets': [r['name'] for r in _YARA_RULESETS]},
    )
    add_log_to_run(run_id, f"Refreshing {len(_YARA_RULESETS)} YARA rulesets from GitHub", "info")
    update_run_status(run_id, "running", progress=5)
    register_cancel_event(run_id)

    def _refresh() -> None:
        try:
            # 1. Auth against VolWeb. The platform's tenroot credentials
            #    are seeded into VolWeb by lib/modules.sh:seed_volweb_admin
            #    at install time; we use them here too.
            # Use VolWebClient — it handles the JWT, the Host header
            # override (Django rejects underscored hostnames), the
            # 4-attempt retry-with-backoff, and reads credentials from
            # frontend_config.memory.volweb (same auth path the pipeline
            # uses). No duplicated config-resolution logic.
            from services.memory.volweb_client import VolWebClient
            client = VolWebClient(
                logger=lambda m, level="info": add_log_to_run(run_id, m, level),
            )

            n_total = len(_YARA_RULESETS)
            for idx, rs in enumerate(_YARA_RULESETS, start=1):
                if is_cancelled(run_id):
                    raise RuntimeError("cancelled by operator")
                add_log_to_run(run_id, f"[{idx}/{n_total}] importing {rs['name']}...", "info")
                try:
                    resp = client._post_json(
                        "/api/yararulesets/import/github/",
                        rs,
                        timeout=600,
                    )
                    add_log_to_run(
                        run_id,
                        f"  imported: {str(resp)[:200]}",
                        "info",
                    )
                except Exception as e:
                    add_log_to_run(run_id, f"  failed: {e}", "warning")
                update_run_status(run_id, "running", progress=5 + int(idx / n_total * 90))

            update_run_status(run_id, "completed", progress=100)
            add_log_to_run(
                run_id,
                "YARA refresh dispatched — rule validation runs async in workers-yarascan",
                "success",
            )
        except Exception as e:
            add_log_to_run(run_id, f"YARA refresh failed: {e}", "error")
            update_run_status(run_id, "failed", error=str(e))
        finally:
            unregister_cancel(run_id)

    threading.Thread(target=_refresh, daemon=True).start()
    return jsonify({"success": True, "run_id": run_id})


@maintenance_bp.route('/api/maintenance/yara-rulesets/status', methods=['GET'])
def yara_rulesets_status():
    """Return the seeded rulesets + active-rule counts.

    Read directly from VolWeb so the panel reflects whatever rule
    population actually exists (rather than what we tried to seed).
    """
    try:
        from services.memory.volweb_client import VolWebClient
        client = VolWebClient()
        rulesets = client._get_json("/api/yararulesets/")
        return jsonify({"available": True, "rulesets": rulesets})
    except Exception as e:
        return jsonify({"available": False, "reason": str(e)}), 200
