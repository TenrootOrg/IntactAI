#!/usr/bin/env python3
"""
Timesketch LLM Routes - LLM configuration and settings for Timesketch
"""

from flask import Blueprint, jsonify, request
import io
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
import traceback
import urllib.request
import zipfile

from services import (
    create_automation_run,
    add_log_to_run,
    update_run_status
)

timesketch_llm_bp = Blueprint('timesketch_llm', __name__)

TIMESKETCH_CONFIG_PATH = '/app/config/timesketch/timesketch.conf'
TIMESKETCH_CONFIG_DIR = os.path.dirname(TIMESKETCH_CONFIG_PATH)
DFIQ_DATA_DIR = os.path.join(TIMESKETCH_CONFIG_DIR, 'dfiq')
DFIQ_ZIP_URL = 'https://github.com/google/dfiq/archive/refs/heads/main.zip'
DFIQ_SUBDIRS = ('scenarios', 'facets', 'questions')

# Same bullet mask GET /api/config and GET /api/config/cloud use for secrets.
_API_KEY_MASK = '••••'

# The providers this UI can configure, and how each maps onto the keys
# Timesketch expects inside LLM_PROVIDER_CONFIGS.
#
#   ui mode -> (timesketch provider NAME, ((conf_key, ui_key, is_secret), ...))
#
# `openrouter` and `litellm_proxy` are not upstream providers — they are the
# two contrib modules modules/timesketch/llm_providers/apply.sh installs into
# the vendor image at container start. Naming one here that the container has
# not registered yields a config Timesketch cannot resolve, so this table and
# that payload have to move together.
_TS_PROVIDERS = {
    'google': ('aistudio', (
        ('model',      'google_ai_model',  False),
        ('api_key',    'google_ai_key',    True),
    )),
    'ollama': ('ollama', (
        ('server_url', 'ollama_url',       False),
        ('model',      'ollama_model',     False),
    )),
    'openrouter': ('openrouter', (
        ('api_key',    'openrouter_key',   True),
        ('model',      'openrouter_model', False),
    )),
    'litellm': ('litellm_proxy', (
        ('server_url', 'litellm_url',      False),
        ('model',      'litellm_model',    False),
        ('api_key',    'litellm_key',      True),
    )),
}

DEFAULT_LLM_MODE = 'google'


def _read_conf_value(content, ts_provider, conf_key):
    """Pull one provider field out of timesketch.conf, '' if absent.

    Same shape as the aistudio/ollama scrapes this file has always used:
    find the provider dict, then the key inside it. `[^}]*` keeps the match
    from wandering past the end of that provider's block.
    """
    match = re.search(
        r"'" + re.escape(ts_provider) + r"':\s*\{[^}]*'"
        + re.escape(conf_key) + r"':\s*'([^']*)'",
        content)
    return match.group(1) if match else ''


def _mask_secret(value):
    if not value:
        return ''
    return (_API_KEY_MASK * 2) + value[-4:] if len(value) > 4 else (_API_KEY_MASK * 2)


def _detect_llm_mode(content):
    """Which provider currently occupies the nl2q slot.

    GET has to return this or the UI cannot show what is actually configured:
    settings.js falls back to 'google' whenever llm_mode is missing, so before
    this the selector always read "Google AI Studio" no matter what was in the
    file. Harmless while the mode was decorative; wrong now that it selects
    the provider.
    """
    match = re.search(r"'nl2q':\s*\{\s*'([A-Za-z0-9_]+)'", content)
    if match:
        for mode, (ts_provider, _fields) in _TS_PROVIDERS.items():
            if ts_provider == match.group(1):
                return mode
    return DEFAULT_LLM_MODE


def _provider_block(mode, data, content, indent='        '):
    """Render one provider's dict for LLM_PROVIDER_CONFIGS.

    repr() — not raw '{var}' interpolation — for every operator-supplied
    value: this gets written verbatim into a .py file Timesketch imports as
    code. A value containing a single quote would break the generated syntax,
    and a deliberately crafted one could inject arbitrary Python that executes
    on import. repr() always produces a correctly-escaped string literal.

    Every brace below is indented, which the LLM_PROVIDER_CONFIGS replacement
    regex depends on — it is non-greedy and stops at the first `}` in column 0.
    """
    ts_provider, fields = _TS_PROVIDERS[mode]
    lines = ["%s%r: {" % (indent, ts_provider)]
    for conf_key, ui_key, is_secret in fields:
        value = data.get(ui_key, '') or ''
        # A masked key means "keep what is already there" — the operator never
        # retyped it, they just saved the form GET handed them. Writing the
        # bullets through would silently destroy a working key.
        if is_secret and isinstance(value, str) and value.startswith(_API_KEY_MASK):
            value = _read_conf_value(content, ts_provider, conf_key)
        lines.append("%s    %r: %r," % (indent, conf_key, value))
    lines.append("%s}," % indent)
    return "\n".join(lines)


def _dfiq_data_present():
    """True if every expected subdir exists and has at least one YAML."""
    for sub in DFIQ_SUBDIRS:
        d = os.path.join(DFIQ_DATA_DIR, sub)
        if not os.path.isdir(d):
            return False
        if not any(f.endswith(('.yaml', '.yml')) for f in os.listdir(d)):
            return False
    return True


def _ensure_dfiq_data(run_id):
    """Self-heal: download google/dfiq YAML data if any subdir is missing.

    Non-fatal — if the download fails the LLM key save still completes; the
    DFIQ sidebar will just be empty until the operator populates it or retries.
    """
    if _dfiq_data_present():
        add_log_to_run(run_id, 'DFIQ data already present — skipping fetch')
        return True

    add_log_to_run(run_id, f'DFIQ data missing — fetching from {DFIQ_ZIP_URL}')
    try:
        req = urllib.request.Request(DFIQ_ZIP_URL, headers={'User-Agent': 'intactai-installer/1.0'})
        with urllib.request.urlopen(req, timeout=60) as resp:
            zip_bytes = resp.read()
        with tempfile.TemporaryDirectory() as tmp:
            with zipfile.ZipFile(io.BytesIO(zip_bytes)) as z:
                z.extractall(tmp)
            # Archive shape: dfiq-main/dfiq/data/{scenarios,facets,questions}/*.yaml
            src_data = None
            for entry in os.listdir(tmp):
                cand = os.path.join(tmp, entry, 'dfiq', 'data')
                if os.path.isdir(cand):
                    src_data = cand
                    break
            if not src_data:
                add_log_to_run(run_id, 'DFIQ archive layout unexpected — skipping', 'warning')
                return False
            os.makedirs(DFIQ_DATA_DIR, exist_ok=True)
            copied = {}
            for sub in DFIQ_SUBDIRS:
                src = os.path.join(src_data, sub)
                dst = os.path.join(DFIQ_DATA_DIR, sub)
                if not os.path.isdir(src):
                    continue
                if os.path.isdir(dst):
                    shutil.rmtree(dst)
                shutil.copytree(src, dst)
                copied[sub] = len([f for f in os.listdir(dst) if f.endswith(('.yaml', '.yml'))])
            add_log_to_run(
                run_id,
                f'DFIQ data populated: {copied}',
                'success'
            )
            return True
    except Exception as e:
        add_log_to_run(
            run_id,
            f'DFIQ fetch failed (non-fatal — sidebar will be empty until retried): {e}',
            'warning'
        )
        return False


def _ensure_conf_from_template(run_id):
    """Self-heal: if timesketch.conf is missing, recreate from template."""
    if os.path.isfile(TIMESKETCH_CONFIG_PATH):
        return True
    template = TIMESKETCH_CONFIG_PATH + '.template'
    if not os.path.isfile(template):
        add_log_to_run(run_id, f'Config missing and no template found at {template}', 'error')
        return False
    add_log_to_run(run_id, 'timesketch.conf missing — recreating from template')
    shutil.copyfile(template, TIMESKETCH_CONFIG_PATH)
    return True


@timesketch_llm_bp.route('/api/timesketch/config/llm', methods=['GET'])
def get_timesketch_llm_config():
    """Get current Timesketch LLM configuration"""
    try:
        config = {
            'llm_mode': DEFAULT_LLM_MODE,
            'google_ai_key': '',
            'google_ai_model': 'gemini-2.5-flash',
            'ollama_url': '',
            'ollama_model': '',
            'openrouter_key': '',
            'openrouter_model': '',
            'litellm_url': '',
            'litellm_model': '',
            'litellm_key': '',
        }

        # Read config file and extract LLM settings
        try:
            with open(TIMESKETCH_CONFIG_PATH, 'r') as f:
                content = f.read()

            # Every provider's fields, not just the selected one, so switching
            # the selector in the UI does not lose what the others had.
            # Secrets are masked the same way GET /api/config and
            # GET /api/config/cloud mask theirs — this endpoint previously
            # returned the key in full plaintext to any unauthenticated caller.
            for _mode, (ts_provider, fields) in _TS_PROVIDERS.items():
                for conf_key, ui_key, is_secret in fields:
                    value = _read_conf_value(content, ts_provider, conf_key)
                    if value:
                        config[ui_key] = _mask_secret(value) if is_secret else value

            config['llm_mode'] = _detect_llm_mode(content)

        except FileNotFoundError:
            print(f"[TIMESKETCH] Config file not found: {TIMESKETCH_CONFIG_PATH}", flush=True)

        return jsonify(config)

    except Exception as e:
        print(f"[TIMESKETCH] Error reading LLM config: {e}", flush=True)
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


def _run_timesketch_settings_workflow(run_id, config_data):
    """Background worker for Timesketch settings update workflow"""
    llm_mode = config_data.get('llm_mode') or DEFAULT_LLM_MODE

    try:
        # Phase 0: Self-heal — make sure the conf file and DFIQ data exist
        # before we try to read/edit. Covers the fresh-install edge case
        # where the operator hit Settings before install.sh finished, or
        # where network was down during install (DFIQ clone skipped).
        update_run_status(run_id, "running", progress=5)
        if not _ensure_conf_from_template(run_id):
            update_run_status(run_id, "failed", error="timesketch.conf and template both missing")
            return
        _ensure_dfiq_data(run_id)

        # Phase 1: Read existing config
        update_run_status(run_id, "running", progress=10)
        add_log_to_run(run_id, "Reading existing Timesketch configuration...")

        with open(TIMESKETCH_CONFIG_PATH, 'r') as f:
            content = f.read()

        add_log_to_run(run_id, f"Successfully read config file: {TIMESKETCH_CONFIG_PATH}")

        # Phase 2: Update configuration
        update_run_status(run_id, "running", progress=20)
        add_log_to_run(run_id, "Building new LLM configuration...")

        # Build the new LLM_PROVIDER_CONFIGS section from the SELECTED
        # provider. This used to be a fixed block — aistudio in the three
        # feature slots, ollama in 'default' — regardless of what the operator
        # picked, so llm_mode only ever changed which form fields the UI
        # showed. Choosing Ollama still left every actual feature calling
        # Google. The mode now decides.
        #
        # All four slots get the same provider: nl2q, llm_summarize and
        # llm_synthesize because those are the features this page configures,
        # and 'default' because it is the fallback for anything else and
        # pointing it somewhere the operator did not choose is how you get a
        # feature quietly talking to the wrong endpoint.
        #
        # log_analyzer keeps secgemini_log_analyzer_agent: it is a different
        # kind of provider (an agent service, not a chat completion endpoint)
        # and none of the four selectable providers can serve it.
        #
        # _provider_block() handles repr()-escaping and masked-key
        # passthrough; see its docstring.
        provider_block = _provider_block(llm_mode, config_data, content)
        new_llm_config = f'''LLM_PROVIDER_CONFIGS = {{
    'nl2q': {{
{provider_block}
    }},
    'llm_summarize': {{
{provider_block}
    }},
    'llm_synthesize': {{
{provider_block}
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
{provider_block}
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

        # Defensively force the feature flags this UI controls to True. If a
        # prior install / hand-edit left any of these False, the customer's
        # key would land but the feature still wouldn't show up. Settings →
        # Timesketch is the single source of truth, so it normalizes them.
        feature_flags = {
            'DFIQ_ENABLED': 'True',
            'YETI_DFIQ_ENABLED': 'True',
            'ENABLE_EXPERIMENTAL_UI': 'True',
            'ENABLE_V3_INVESTIGATION_VIEW': 'True',
        }
        for flag, target in feature_flags.items():
            flag_pattern = rf"^{flag}\s*=\s*\S+"
            replacement = f"{flag} = {target}"
            if re.search(flag_pattern, content, flags=re.MULTILINE):
                content = re.sub(flag_pattern, replacement, content, flags=re.MULTILINE)
            else:
                content += f"\n{replacement}\n"
        add_log_to_run(run_id, f"Forced feature flags ON: {', '.join(feature_flags)}")

        # Phase 3: Write config file
        update_run_status(run_id, "running", progress=30)
        add_log_to_run(run_id, "Writing updated configuration to file...")

        with open(TIMESKETCH_CONFIG_PATH, 'w') as f:
            f.write(content)

        add_log_to_run(run_id, "Configuration file saved successfully", "success")

        # Log what was configured — never the secret, only its presence.
        _ts_provider, _fields = _TS_PROVIDERS[llm_mode]
        _shown = ', '.join(
            f"{conf_key}={config_data.get(ui_key) or '<empty>'}"
            for conf_key, ui_key, is_secret in _fields if not is_secret)
        add_log_to_run(
            run_id,
            f"Configured provider '{_ts_provider}' for nl2q, llm_summarize, "
            f"llm_synthesize and default ({_shown})")
        if _ts_provider in ('openrouter', 'litellm_proxy'):
            add_log_to_run(
                run_id,
                f"'{_ts_provider}' is an IntactAI contrib provider installed into the "
                f"Timesketch container at start-up. If it does not appear, check "
                f"/var/log/timesketch/intact_llm_providers.log inside the container.")

        # Phase 4: Restart containers.
        # web_v3 is included: it mounts the same ./config with no
        # TIMESKETCH_SETTINGS override, so it reads the same timesketch.conf
        # as the others and was silently never picking up changes.
        containers = ['intact_timesketch_web', 'intact_timesketch_worker',
                      'intact_timesketch_web_legacy', 'intact_timesketch_web_v3']
        update_run_status(run_id, "running", progress=40)

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
        data = request.get_json() or {}

        # Reject an unknown provider rather than silently defaulting to one.
        # llm_mode now decides what gets written into a file Timesketch
        # imports as code, so guessing here means configuring a provider the
        # operator did not ask for.
        llm_mode = data.get('llm_mode') or DEFAULT_LLM_MODE
        if llm_mode not in _TS_PROVIDERS:
            return jsonify({
                "error": f"Unknown LLM provider '{llm_mode}'. "
                         f"Expected one of: {', '.join(sorted(_TS_PROVIDERS))}."
            }), 400
        data['llm_mode'] = llm_mode

        _ts_provider, _fields = _TS_PROVIDERS[llm_mode]

        # Create workflow run. Non-secret fields only — `details` is stored
        # with the run and rendered in the Workflows UI.
        run_id = create_automation_run(
            automation_type="settings",
            name="Timesketch LLM Configuration",
            details=dict(
                {"llm_mode": llm_mode, "provider": _ts_provider},
                **{ui_key: data.get(ui_key, '')
                   for _c, ui_key, is_secret in _fields if not is_secret}
            )
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
