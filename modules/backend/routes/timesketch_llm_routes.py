#!/usr/bin/env python3
"""
Timesketch LLM Routes - LLM configuration and settings for Timesketch
"""

from flask import Blueprint, jsonify, request
import re
import subprocess
import time
import threading
import traceback

from services import (
    create_automation_run,
    add_log_to_run,
    update_run_status
)

timesketch_llm_bp = Blueprint('timesketch_llm', __name__)

TIMESKETCH_CONFIG_PATH = '/app/config/timesketch/timesketch.conf'


@timesketch_llm_bp.route('/api/timesketch/config/llm', methods=['GET'])
def get_timesketch_llm_config():
    """Get current Timesketch LLM configuration"""
    try:
        config = {
            'google_ai_key': '',
            'google_ai_model': 'gemini-2.5-flash',
            'ollama_url': '',
            'ollama_model': ''
        }

        # Read config file and extract LLM settings
        try:
            with open(TIMESKETCH_CONFIG_PATH, 'r') as f:
                content = f.read()

            # Extract Google AI API key from aistudio section
            match = re.search(r"'aistudio':\s*\{[^}]*'api_key':\s*'([^']*)'", content)
            if match:
                config['google_ai_key'] = match.group(1)

            # Extract Google AI model
            match = re.search(r"'aistudio':\s*\{[^}]*'model':\s*'([^']*)'", content)
            if match:
                config['google_ai_model'] = match.group(1)

            # Extract Ollama URL
            match = re.search(r"'ollama':\s*\{[^}]*'server_url':\s*'([^']*)'", content)
            if match:
                config['ollama_url'] = match.group(1)

            # Extract Ollama model
            match = re.search(r"'ollama':\s*\{[^}]*'model':\s*'([^']*)'", content)
            if match:
                config['ollama_model'] = match.group(1)

        except FileNotFoundError:
            print(f"[TIMESKETCH] Config file not found: {TIMESKETCH_CONFIG_PATH}", flush=True)

        return jsonify(config)

    except Exception as e:
        print(f"[TIMESKETCH] Error reading LLM config: {e}", flush=True)
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


def _run_timesketch_settings_workflow(run_id, config_data):
    """Background worker for Timesketch settings update workflow"""
    google_ai_key = config_data.get('google_ai_key', '')
    google_ai_model = config_data.get('google_ai_model', 'gemini-2.5-flash')
    ollama_url = config_data.get('ollama_url', '')
    ollama_model = config_data.get('ollama_model', '')

    try:
        # Phase 1: Read existing config
        update_run_status(run_id, "running", progress=10)
        add_log_to_run(run_id, "Reading existing Timesketch configuration...")

        with open(TIMESKETCH_CONFIG_PATH, 'r') as f:
            content = f.read()

        add_log_to_run(run_id, f"Successfully read config file: {TIMESKETCH_CONFIG_PATH}")

        # Phase 2: Update configuration
        update_run_status(run_id, "running", progress=20)
        add_log_to_run(run_id, "Building new LLM configuration...")

        # Build new LLM_PROVIDER_CONFIGS section
        new_llm_config = f'''LLM_PROVIDER_CONFIGS = {{
    'nl2q': {{
        'vertexai': {{
            'model': 'gemini-2.5-flash',
            'project_id': '',
        }},
    }},
    'llm_summarize': {{
        'aistudio': {{
            'model': '{google_ai_model}',
            'api_key': '{google_ai_key}',
        }},
    }},
    'llm_synthesize': {{
        'aistudio': {{
            'model': '{google_ai_model}',
            'api_key': '{google_ai_key}',
        }},
    }},
    'log_analyzer': {{
        'secgemini_log_analyzer_agent': {{
            'logs_processor_api_url': '',
            'api_key': '',
            'model': 'logs_analysis_agent-1.1',
            'base_url': '',
            'wss_url': '',
            'agents_config': {{}},
        }}
    }},
    'default': {{
        'ollama': {{
            'server_url': '{ollama_url}',
            'model': '{ollama_model}',
        }},
    }}
}}'''

        # Replace existing LLM_PROVIDER_CONFIGS section
        pattern = r"LLM_PROVIDER_CONFIGS\s*=\s*\{[\s\S]*?\n\}"
        if re.search(pattern, content):
            content = re.sub(pattern, new_llm_config, content)
            add_log_to_run(run_id, "Updated existing LLM_PROVIDER_CONFIGS section")
        else:
            content += '\n\n' + new_llm_config
            add_log_to_run(run_id, "Added new LLM_PROVIDER_CONFIGS section")

        # Phase 3: Write config file
        update_run_status(run_id, "running", progress=30)
        add_log_to_run(run_id, "Writing updated configuration to file...")

        with open(TIMESKETCH_CONFIG_PATH, 'w') as f:
            f.write(content)

        add_log_to_run(run_id, "Configuration file saved successfully", "success")

        # Log what was configured
        if google_ai_key:
            add_log_to_run(run_id, f"Configured Google AI Studio with model: {google_ai_model}")
        if ollama_url:
            add_log_to_run(run_id, f"Configured Ollama at {ollama_url} with model: {ollama_model}")

        # Phase 4: Restart containers
        update_run_status(run_id, "running", progress=40)
        containers = ['intact_timesketch_web', 'intact_timesketch_worker']

        for i, container in enumerate(containers):
            add_log_to_run(run_id, f"Restarting container: {container}...")

            result = subprocess.run(
                ['docker', 'restart', container],
                capture_output=True,
                text=True,
                timeout=60
            )

            if result.returncode != 0:
                add_log_to_run(run_id, f"Failed to restart {container}: {result.stderr}", "error")
                update_run_status(run_id, "failed", error=f"Container restart failed: {container}")
                return

            add_log_to_run(run_id, f"Container {container} restart initiated", "success")
            update_run_status(run_id, "running", progress=50 + (i * 10))

        # Phase 5: Wait for containers to be healthy
        update_run_status(run_id, "running", progress=70)
        add_log_to_run(run_id, "Waiting for Timesketch containers to become healthy...")

        max_wait = 120  # 2 minutes max
        check_interval = 5
        elapsed = 0

        while elapsed < max_wait:
            time.sleep(check_interval)
            elapsed += check_interval

            # Check container health
            all_healthy = True
            for container in containers:
                result = subprocess.run(
                    ['docker', 'inspect', '--format', '{{.State.Health.Status}}', container],
                    capture_output=True,
                    text=True,
                    timeout=10
                )

                status = result.stdout.strip()
                if status != 'healthy':
                    # Also check if container is just running (no healthcheck defined)
                    result2 = subprocess.run(
                        ['docker', 'inspect', '--format', '{{.State.Status}}', container],
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                    if result2.stdout.strip() != 'running':
                        all_healthy = False
                        break

            progress = 70 + int((elapsed / max_wait) * 25)
            update_run_status(run_id, "running", progress=min(progress, 95))

            if all_healthy:
                # Verify Timesketch is responding
                try:
                    import urllib.request
                    req = urllib.request.urlopen('http://intact_timesketch_web:5000/', timeout=5)
                    if req.status in [200, 302]:
                        add_log_to_run(run_id, "Timesketch web interface is responding", "success")
                        break
                except:
                    pass

            add_log_to_run(run_id, f"Waiting for containers... ({elapsed}s elapsed)")

        # Final status check - verify containers are actually running
        containers_ok = True
        for container in containers:
            result = subprocess.run(
                ['docker', 'ps', '--filter', f'name={container}', '--format', '{{.Status}}'],
                capture_output=True,
                text=True,
                timeout=10
            )
            status = result.stdout.strip()
            add_log_to_run(run_id, f"Container {container}: {status}")

            # Check if container is running
            if not status or 'Up' not in status:
                containers_ok = False
                add_log_to_run(run_id, f"Container {container} is not running!", "error")

        # Verify Timesketch web is accessible
        ts_accessible = False
        try:
            import urllib.request
            req = urllib.request.urlopen('http://intact_timesketch_web:5000/', timeout=10)
            if req.status in [200, 302]:
                ts_accessible = True
                add_log_to_run(run_id, "Timesketch web interface verified accessible", "success")
        except Exception as e:
            add_log_to_run(run_id, f"Timesketch web interface not accessible: {e}", "warning")

        # Determine final status
        if containers_ok and ts_accessible:
            update_run_status(run_id, "completed", progress=100)
            add_log_to_run(run_id, "Timesketch settings update completed successfully", "success")
        elif containers_ok:
            # Containers running but web not accessible yet - might still be starting
            update_run_status(run_id, "completed", progress=100)
            add_log_to_run(run_id, "Settings saved. Containers running but web interface may still be initializing.", "warning")
        else:
            update_run_status(run_id, "failed", error="Containers failed to start properly")
            add_log_to_run(run_id, "Settings workflow failed - containers not running", "error")

    except Exception as e:
        add_log_to_run(run_id, f"Error: {str(e)}", "error")
        update_run_status(run_id, "failed", error=str(e))
        traceback.print_exc()


@timesketch_llm_bp.route('/api/timesketch/config/llm', methods=['PUT'])
def update_timesketch_llm_config():
    """Update Timesketch LLM configuration and restart containers (runs as workflow)"""
    try:
        data = request.get_json()

        # Create workflow run
        run_id = create_automation_run(
            automation_type="settings",
            name="Timesketch LLM Configuration",
            details={
                "google_ai_model": data.get('google_ai_model', 'gemini-2.5-flash'),
                "ollama_url": data.get('ollama_url', ''),
                "ollama_model": data.get('ollama_model', '')
            }
        )

        add_log_to_run(run_id, "Starting Timesketch settings update workflow...")
        add_log_to_run(run_id, f"Workflow ID: {run_id}")

        # Run in background thread
        thread = threading.Thread(
            target=_run_timesketch_settings_workflow,
            args=(run_id, data)
        )
        thread.daemon = True
        thread.start()

        return jsonify({
            "success": True,
            "message": "Settings workflow started",
            "run_id": run_id
        })

    except Exception as e:
        print(f"[TIMESKETCH] Error starting settings workflow: {e}", flush=True)
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500
