#!/usr/bin/env python3
"""
Run maintenance tasks directly (no workflow creation).
Used by install.sh to run maintenance during installation.
"""
import sys
sys.path.insert(0, '/app')


def log(msg, level="info"):
    """Print log message with level prefix."""
    prefix = {
        "info": "[INFO]",
        "success": "[SUCCESS]",
        "warning": "[WARN]",
        "error": "[ERROR]"
    }
    print(f"{prefix.get(level, '[INFO]')} {msg}", flush=True)


def main():
    """Run maintenance tasks."""
    log("Starting maintenance tasks...")
    print("", flush=True)

    # =========================================================================
    # Task 1: Import Velociraptor artifacts
    # =========================================================================
    log("Task 1/4: Importing Velociraptor artifacts...")
    try:
        from services.velociraptor_init_service import initialize_velociraptor_artifacts
        results = initialize_velociraptor_artifacts()
        if results:
            success_list = results.get('success', [])
            failed_list = results.get('failed', [])
            success = len(success_list)
            failed = len(failed_list)

            # Show imported artifacts
            for artifact in success_list[:5]:  # Show first 5
                log(f"  + {artifact}", "success")
            if success > 5:
                log(f"  ... and {success - 5} more", "info")

            if failed > 0:
                for artifact in failed_list[:3]:
                    log(f"  - {artifact}", "warning")

            log(f"Artifacts: {success} imported, {failed} failed",
                "success" if success > 0 else "info")
        else:
            log("No new artifacts to import (already up to date)", "info")
    except Exception as e:
        log(f"Artifact import error: {e}", "warning")

    print("", flush=True)

    # =========================================================================
    # Task 2: Download tools and configure inventory
    # =========================================================================
    log("Task 2/4: Downloading tools...")
    try:
        from services.tools_download_service import download_and_configure_tools

        def tool_logger(msg, level="info"):
            # Indent tool download messages
            log(f"  {msg}", level)

        results = download_and_configure_tools(logger=tool_logger)

        if results.get('success'):
            dl = results.get('download_results', {})
            downloaded = len(dl.get('downloaded', []))
            existed = len(dl.get('already_exists', []))
            dl_failed = len(dl.get('failed', []))

            inv = results.get('inventory_results', {})
            configured = len(inv.get('configured', []))

            log(f"Tools: {downloaded} downloaded, {existed} existed, {dl_failed} failed",
                "success" if downloaded > 0 or existed > 0 else "info")
            if configured > 0:
                log(f"Inventory: {configured} tools configured", "success")
        else:
            log(f"Tool download issue: {results.get('error', 'unknown')}", "warning")
    except Exception as e:
        log(f"Tool download error: {e}", "warning")

    print("", flush=True)

    # =========================================================================
    # Task 3: Create Kibana data view for Velociraptor artifacts
    # =========================================================================
    log("Task 3/4: Setting up Kibana data view...")
    try:
        import requests

        kibana_url = "http://intact_kibana:5601"
        headers = {"kbn-xsrf": "true", "Content-Type": "application/json"}

        # Check if Kibana is reachable
        kibana_health = requests.get(f"{kibana_url}/api/status", timeout=10)

        if kibana_health.status_code == 200:
            # First check if data view already exists
            existing = requests.get(
                f"{kibana_url}/api/data_views",
                headers=headers,
                timeout=10
            )

            if existing.status_code == 200:
                data_views = existing.json().get('data_view', [])
                already_exists = any(dv.get('title') == 'artifact_*' for dv in data_views)

                if already_exists:
                    log("  Kibana: Data view 'Velociraptor Artifacts' already exists", "info")
                else:
                    # Create data view for Velociraptor artifacts
                    data_view_payload = {
                        "data_view": {
                            "title": "artifact_*",
                            "name": "Velociraptor Artifacts",
                            "timeFieldName": "@timestamp"
                        }
                    }

                    response = requests.post(
                        f"{kibana_url}/api/data_views/data_view",
                        json=data_view_payload,
                        headers=headers,
                        timeout=10
                    )

                    if response.status_code in [200, 201]:
                        log("  Kibana: Created 'Velociraptor Artifacts' data view", "success")
                    elif response.status_code == 409:
                        log("  Kibana: Data view already exists", "info")
                    else:
                        log(f"  Kibana: Could not create data view ({response.status_code})", "warning")
            else:
                log("  Kibana: Could not check existing data views", "warning")
        else:
            log("  Kibana: Not ready yet", "info")
    except Exception as e:
        log(f"  Kibana: {str(e)[:50]}", "info")

    print("", flush=True)

    # =========================================================================
    # Task 4: Health check
    # =========================================================================
    log("Task 4/4: Health check...")
    health_ok = True

    # Check Velociraptor connection
    try:
        from services.velociraptor_service import setup_velociraptor_connection
        channel = setup_velociraptor_connection()
        if channel:
            log("  Velociraptor: Connected", "success")
            channel.close()
        else:
            log("  Velociraptor: Connection failed", "warning")
            health_ok = False
    except Exception as e:
        log(f"  Velociraptor: {str(e)[:50]}", "warning")
        health_ok = False

    # Check Elasticsearch
    try:
        import requests
        es_response = requests.get("http://intact_elasticsearch:9200/_cluster/health", timeout=5)
        if es_response.status_code == 200:
            status = es_response.json().get('status', 'unknown')
            log(f"  Elasticsearch: {status}",
                "success" if status in ['green', 'yellow'] else "warning")
        else:
            log("  Elasticsearch: Unhealthy", "warning")
    except Exception:
        log("  Elasticsearch: Not reachable (may be disabled)", "info")

    # Check database
    try:
        from services.file_storage_service import load_workflows
        workflows = load_workflows()
        log(f"  Database: OK ({len(workflows)} workflows)", "success")
    except Exception as e:
        log(f"  Database: {str(e)[:30]}", "warning")

    print("", flush=True)
    log("Maintenance complete!", "success")

    return 0 if health_ok else 1


if __name__ == "__main__":
    sys.exit(main())
