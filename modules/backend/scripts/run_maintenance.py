#!/usr/bin/env python3
"""
Run maintenance tasks directly (no workflow creation).
Used by install.sh to run maintenance during installation.
"""
import subprocess
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


def main():
    """Run maintenance tasks."""
    log("Starting maintenance tasks...")
    print("", flush=True)

    velociraptor_available = container_running('intact_velociraptor')
    elk_available = container_running('intact_kibana')

    # =========================================================================
    # Task 1: Ensure runtime artifact state — event monitoring + operator
    # custom artifacts. The curated bundle (ArtifactExchange / DetectRaptor /
    # Sigma / Rapid7 / TenRoot, ~400 defs) is baked into the velociraptor
    # image and loaded on boot via --definitions; it is NOT imported here
    # anymore (that was the slow step). This step only (re)starts the Elastic
    # event-upload monitoring and imports any operator custom_artifacts/.
    # =========================================================================
    log("Task 1/4: Ensuring Velociraptor event monitoring + operator custom artifacts...")
    if not velociraptor_available:
        log("Velociraptor not running — curated artifacts still load from the "
            "image on boot; skipping the runtime ensure step.", "info")
    else:
        try:
            from services.velociraptor_init_service import initialize_velociraptor_artifacts
            results = initialize_velociraptor_artifacts()
            if results:
                ok = len(results.get('success', []))
                failed = len(results.get('failed', []))
                log(f"Event monitoring + custom artifacts: {ok} ensured, {failed} failed "
                    "(curated bundle loads from the image via --definitions)",
                    "success" if failed == 0 else "warning")
            else:
                log("Nothing to ensure (curated bundle loads from the image)", "info")
        except Exception as e:
            log(f"Artifact ensure error: {e}", "warning")

    print("", flush=True)

    # =========================================================================
    # Task 2: Download tools and configure inventory
    # =========================================================================
    log("Task 2/4: Downloading tools...")
    if not velociraptor_available:
        log("Tools: skipped (Velociraptor inventory target not installed/running)", "info")
    else:
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
    if not elk_available:
        log("Kibana data view: skipped (ELK/Kibana module not installed/running)", "info")
    else:
        try:
            # Kibana serves HTTPS (self-signed); the shared helper handles the
            # scheme + idempotent create. Same helper the ELK upgrade calls so the
            # data view is re-ensured after an upgrade.
            from services.kibana_init import ensure_kibana_data_view
            ensure_kibana_data_view(log, wait=False)
        except Exception as e:
            log(f"  Kibana: {str(e)[:50]}", "info")

    print("", flush=True)

    # =========================================================================
    # Task 4: Health check
    # =========================================================================
    log("Task 4/4: Health check...")
    health_ok = True

    # Check Velociraptor connection
    if not velociraptor_available:
        log("  Velociraptor: skipped (module not installed/running)", "info")
    else:
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
    if not elk_available:
        log("  Elasticsearch: skipped (ELK module not installed/running)", "info")
    else:
        try:
            import requests
            from config import ELASTICSEARCH_CONFIG
            es_auth = (ELASTICSEARCH_CONFIG.get('user'), ELASTICSEARCH_CONFIG.get('password'))
            es_response = requests.get(
                "http://intact_elasticsearch:9200/_cluster/health",
                auth=es_auth, timeout=5)
            if es_response.status_code == 200:
                status = es_response.json().get('status', 'unknown')
                log(f"  Elasticsearch: {status}",
                    "success" if status in ['green', 'yellow'] else "warning")
            else:
                log("  Elasticsearch: Unhealthy", "warning")
        except Exception:
            log("  Elasticsearch: Not reachable", "warning")
            health_ok = False

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
