"""
AWS Automation API Routes

Endpoints mirror `azure_routes.py`. Online mode goes through
`services.aws.pipeline.run_aws_pipeline`; offline mode parses uploaded
log files and calls `run_aws_on_existing`. Currently the online path
relies on stub collectors that return fixture data — real boto3 /
Prowler integration lands in a follow-up mission.
"""

from __future__ import annotations

import io
import json
import os
import traceback
import uuid
import zipfile
from datetime import datetime

from flask import Blueprint, Response, jsonify, request
from werkzeug.utils import secure_filename

from config import is_module_enabled
from routes.config_routes import _load_cloud_config
from services.aws.pipeline import (
    get_available_sources,
    get_aws_blueprints,
    run_aws_on_existing,
    run_aws_pipeline,
)
from services.aws.collectors import parse_uploaded_logs
from services.aws.sigma_runner import validate_rules_directory
from services.workflow_logger import add_log_to_run
from services.workflow_service import update_run_status, get_automation_run
import threading


aws_bp = Blueprint('aws', __name__)

# In-memory storage for run results (mirrors `_azure_runs` in azure_routes.py).
_aws_runs: dict = {}

UPLOAD_FOLDER = '/tmp/aws_uploads'
ALLOWED_EXTENSIONS = {'json', 'jsonl', 'csv', 'zip'}
PARSEABLE_EXTENSIONS = {'json', 'jsonl', 'csv'}
PERSIST_DIR = '/app/data/aws_runs'


def _allowed_file(filename: str) -> bool:
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def _parseable(filename: str) -> bool:
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in PARSEABLE_EXTENSIONS


# =============================================================================
# Status & Configuration
# =============================================================================


@aws_bp.route('/api/aws/status', methods=['GET'])
def get_aws_status():
    """Status of the AWS automation service."""
    try:
        rules_valid, rules_msg = validate_rules_directory()
        cloud_config = _load_cloud_config()
        aws_config = cloud_config.get('aws', {})
        has_credentials = bool(
            aws_config.get('access_key_id') and aws_config.get('secret_access_key')
        )
        return jsonify({
            'status': 'ready' if rules_valid else 'partial',
            'sigma_rules': {'available': rules_valid, 'message': rules_msg},
            'aws_credentials': {
                'configured': has_credentials,
                'region': aws_config.get('region') or 'us-east-1',
                'access_key_id': (aws_config.get('access_key_id', '')[:6] + '...') if aws_config.get('access_key_id') else None,
            },
            'capabilities': {
                'online_mode': has_credentials,
                'offline_mode': True,
            },
            'note': 'Collectors are currently stub fixtures — real boto3/Prowler integration is a follow-up mission.',
        })
    except Exception as e:
        return jsonify({'status': 'error', 'error': str(e)}), 500


@aws_bp.route('/api/aws/blueprints', methods=['GET'])
def get_blueprints():
    try:
        return jsonify({'blueprints': get_aws_blueprints()})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@aws_bp.route('/api/aws/sources', methods=['GET'])
def get_sources():
    try:
        return jsonify({'sources': get_available_sources()})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@aws_bp.route('/api/aws/rules', methods=['GET'])
def get_rules_info():
    try:
        rules_valid, rules_msg = validate_rules_directory()
        # Count rules under the cloud/aws subtree without loading them all.
        rule_dir = '/opt/sigma-rules/rules/cloud/aws'
        count = 0
        if os.path.isdir(rule_dir):
            for root, _, files in os.walk(rule_dir):
                for fn in files:
                    if fn.endswith(('.yml', '.yaml')):
                        count += 1
        return jsonify({
            'available': rules_valid,
            'message': rules_msg,
            'aws_rules_count': count,
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# =============================================================================
# Online Mode — POST /api/aws/scan
# =============================================================================


@aws_bp.route('/api/aws/scan', methods=['POST'])
def start_scan():
    """Start an online AWS security scan.

    Request body:
        {
            "blueprint": "aws_quick_triage" | {custom dict},
            "regions": ["us-east-1", ...],
            "time_filter": {"type":"relative","value":"24h"} | {"type":"between","start":"...","end":"..."},
            "scope_mode": "targeted" | "account_wide",
            "target_principals": ["arn:aws:iam::...:user/X"],
            "cloudtrail_mode": "light" | "full",
            "enable_llm": true,
            "min_severity": "medium",
            "iris_config": {...}
        }
    """
    from services.workflow_service import (
        create_automation_run,
        is_cancelled,
        register_cancel_event,
        unregister_cancel,
        update_run_status,
    )

    data = request.json or {}
    blueprint_id = data.get('blueprint', 'aws_quick_triage')

    if isinstance(blueprint_id, dict):
        blueprint_display = blueprint_id.get('name') or blueprint_id.get('id') or 'Custom'
    else:
        blueprint_display = str(blueprint_id)

    target_principals = data.get('target_principals', []) or []
    scope_mode = (data.get('scope_mode') or 'targeted').lower()
    if scope_mode not in ('targeted', 'account_wide'):
        return jsonify({"error": f"Invalid scope_mode: {scope_mode!r}. Use 'targeted' or 'account_wide'."}), 400
    if scope_mode == 'targeted' and not target_principals:
        # In scaffold mode this is just a warning, not an error — we still
        # have fixture data to run against. Once real boto3 lands this
        # becomes a 400 like Azure.
        pass

    cloudtrail_mode = (data.get('cloudtrail_mode') or 'light').lower()
    if cloudtrail_mode not in ('light', 'full'):
        return jsonify({"error": f"Invalid cloudtrail_mode: {cloudtrail_mode!r}. Use 'light' or 'full'."}), 400

    run_id = create_automation_run(
        automation_type='aws_scan',
        name=f"AWS Scan: {blueprint_display}",
        details={
            'trigger': 'manual',
            'blueprint': blueprint_id,
            'mode': 'online',
            'scope_mode': scope_mode,
            'target_principals': target_principals,
            'cloudtrail_mode': cloudtrail_mode,
            'regions': data.get('regions') or [],
            # Persisted so /rerun can re-apply the same scope on the
            # cached findings instead of regenerating reports over
            # informational/low + out-of-window noise.
            'min_severity': data.get('min_severity', 'medium'),
            'time_filter': data.get('time_filter'),
        },
    )
    update_run_status(run_id, 'running', progress=5)
    register_cancel_event(run_id)

    import threading

    def run_scan():
        try:
            if not is_module_enabled('prowler'):
                # AWS module isn't gated by a config.yaml flag the way Azure
                # is; treat it as always-on for the scaffold. Keep the check
                # for symmetry — when the config gate is added it'll come on
                # automatically.
                pass

            cloud_config = _load_cloud_config()
            aws_config = cloud_config.get('aws', {})
            if not aws_config:
                # In scaffold mode the stubs don't actually need creds, but
                # the workflow row should still tell the operator the
                # credentials are missing so the UI can surface the warning.
                add_log_to_run(run_id, "[AWS] No AWS credentials configured — running stub collectors with fixture data.", "warning")
                aws_config = {'region': 'us-east-1'}

            if isinstance(blueprint_id, str):
                blueprints = get_aws_blueprints()
                blueprint = next((b for b in blueprints if b['id'] == blueprint_id), None)
                if not blueprint:
                    add_log_to_run(run_id, f"Blueprint not found: {blueprint_id}", "error")
                    update_run_status(run_id, 'failed', error=f"Blueprint not found: {blueprint_id}")
                    return
            else:
                blueprint = blueprint_id

            add_log_to_run(run_id, f"[AWS] Starting scan with blueprint: {blueprint.get('name', 'Custom')}", "info")

            from services.file_storage_service import load_frontend_config
            llm_config = load_frontend_config() or {}

            # Age-based DFIR filters — null disables; the defaults
            # below approximate "what looks suspicious right now":
            #   30 days for users  (any admin user created in last month)
            #    7 days for keys   (any access key minted in last week)
            # Callers can pass explicit nulls to disable, or larger
            # numbers for retrospective sweeps.
            # CloudTrail per-region cap: null/0 means use blueprint default.
            # See pipeline.collect_aws_logs → cloudtrail_runner for resolution.
            mepr_raw = data.get('max_events_per_region')
            try:
                mepr = int(mepr_raw) if mepr_raw not in (None, '', 0, '0') else None
                if mepr is not None and mepr < 1:
                    mepr = None
            except (TypeError, ValueError):
                mepr = None

            options = {
                'llm_config': llm_config,
                'time_filter': data.get('time_filter'),
                'min_severity': data.get('min_severity', 'medium'),
                'iris_config': data.get('iris_config'),
                'scope_mode': scope_mode,
                'target_principals': target_principals,
                'regions': data.get('regions'),
                'cloudtrail_mode': cloudtrail_mode,
                'max_events_per_region': mepr,
                # DFIR fresh-admin / fresh-key flagging used to take two
                # separate knobs (max_principal_age_days, max_access_key_age_days)
                # — operators didn't understand them and they duplicated the
                # generic `time_range_days` already on the blueprint. The IAM
                # runner now derives the freshness window from the scan's
                # time range, so a 1-day Quick Triage flags admins/keys
                # created in that 1 day, and a 30-day Full Investigation
                # flags anything created in those 30 days. One concept,
                # scales automatically with investigation scope.
                'anonymizer': None,
            }
            add_log_to_run(
                run_id,
                f"[AWS] Scope: {scope_mode}"
                + (f" (principals={','.join(target_principals)})" if target_principals else ""),
                "info",
            )

            result = run_aws_pipeline(
                run_id=run_id,
                aws_config=aws_config,
                blueprint=blueprint,
                options=options,
            )

            if is_cancelled(run_id):
                return

            _aws_runs[run_id] = result

            try:
                os.makedirs(PERSIST_DIR, exist_ok=True)
                with open(f"{PERSIST_DIR}/{run_id}.json", 'w') as f:
                    json.dump(result, f, default=str)
            except Exception as persist_err:
                print(f"[AWS] Warning: Could not persist raw data: {persist_err}", flush=True)

            if result.get('status') == 'failed' or result.get('status') == 'error':
                update_run_status(run_id, 'failed', error=result.get('error', 'Unknown error'))
            else:
                if not is_cancelled(run_id):
                    update_run_status(run_id, 'completed', progress=100)
        except Exception as e:
            if is_cancelled(run_id):
                return
            add_log_to_run(run_id, f"[AWS] Scan failed: {e}", "error")
            update_run_status(run_id, 'failed', error=str(e))
            traceback.print_exc()
        finally:
            unregister_cancel(run_id)

    thread = threading.Thread(target=run_scan, daemon=True)
    thread.start()
    return jsonify({'run_id': run_id, 'status': 'running', 'message': 'AWS scan started'})


# =============================================================================
# Offline Mode — POST /api/aws/upload and /api/aws/analyze-offline
# =============================================================================


@aws_bp.route('/api/aws/upload', methods=['POST'])
def upload_logs():
    """Upload AWS log files (CloudTrail JSON, GuardDuty exports, …) for offline analysis."""
    try:
        if 'files' not in request.files and 'file' not in request.files:
            return jsonify({'error': 'No files provided'}), 400
        os.makedirs(UPLOAD_FOLDER, exist_ok=True)
        run_id = f"aws_offline_{uuid.uuid4().hex[:12]}"
        run_dir = os.path.join(UPLOAD_FOLDER, run_id)
        os.makedirs(run_dir, exist_ok=True)
        files = request.files.getlist('files') or request.files.getlist('file')

        uploaded_files = []
        saved_paths = []
        for file in files:
            if not (file and file.filename and _allowed_file(file.filename)):
                continue
            filename = secure_filename(file.filename)
            file_path = os.path.join(run_dir, filename)
            file.save(file_path)
            ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
            if ext == 'zip':
                extracted = os.path.join(run_dir, 'extracted')
                os.makedirs(extracted, exist_ok=True)
                try:
                    with zipfile.ZipFile(file_path, 'r') as zf:
                        for member in zf.namelist():
                            base = os.path.basename(member)
                            if not base or member.endswith('/'):
                                continue
                            if not _parseable(base):
                                continue
                            target = os.path.join(extracted, base)
                            with zf.open(member) as src, open(target, 'wb') as dst:
                                dst.write(src.read())
                            saved_paths.append(target)
                            uploaded_files.append({'filename': f"{filename}:{base}"})
                except zipfile.BadZipFile as ex:
                    uploaded_files.append({'filename': filename, 'error': f"Invalid ZIP: {ex}"})
            else:
                saved_paths.append(file_path)
                uploaded_files.append({'filename': filename})

        parsed_data = parse_uploaded_logs(saved_paths)
        total_records = sum(len(v) for v in parsed_data.values())

        _aws_runs[run_id] = {
            'status': 'uploaded',
            'mode': 'offline',
            'uploaded_files': uploaded_files,
            'collected_data': parsed_data,
            'total_records': total_records,
            'upload_time': datetime.utcnow().isoformat(),
        }

        # Register workflow row at upload time
        try:
            from services.file_storage_service import save_workflow
            from services.workflow_service import update_run_status
            save_workflow({
                'run_id': run_id,
                'automation_type': 'aws_scan',
                'name': f"AWS Offline Analysis ({len(parsed_data)} sources, {total_records} records)",
                'details': {
                    'trigger': 'upload',
                    'mode': 'offline',
                    'sources': list(parsed_data.keys()),
                    'uploaded_files': [f.get('filename') for f in uploaded_files],
                },
                'status': 'pending',
                'progress': 0,
                'logs': [],
                'created_at': datetime.utcnow().isoformat(),
                'updated_at': datetime.utcnow().isoformat(),
            })
            update_run_status(run_id, 'uploaded', progress=10)
            add_log_to_run(run_id, f"[AWS] Uploaded {total_records} records across {len(parsed_data)} sources", "info")
        except Exception as ex:
            print(f"[AWS] workflow row create failed: {ex}", flush=True)

        return jsonify({
            'run_id': run_id,
            'status': 'uploaded',
            'files': uploaded_files,
            'total_records': total_records,
            'sources': list(parsed_data.keys()),
            'message': 'Files uploaded. POST /api/aws/analyze-offline with this run_id to run the pipeline.',
        })
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@aws_bp.route('/api/aws/analyze-offline', methods=['POST'])
def analyze_offline():
    """Run the post-collection pipeline against already-uploaded data."""
    from services.workflow_service import update_run_status
    try:
        data = request.json or {}
        run_id = data.get('run_id')
        if not run_id or run_id not in _aws_runs:
            return jsonify({'error': 'Invalid or missing run_id'}), 400
        run_data = _aws_runs[run_id]
        if run_data.get('mode') != 'offline':
            return jsonify({'error': 'This endpoint is for offline mode only'}), 400
        uploaded_data = run_data.get('collected_data', {})
        if not uploaded_data:
            return jsonify({'error': 'No data found for this run_id'}), 400

        llm_config = data.get('llm_config') or {}
        if not llm_config:
            try:
                from services.file_storage_service import load_frontend_config
                llm_config = load_frontend_config() or {}
            except Exception:
                llm_config = {}

        blueprint_id = data.get('blueprint', 'aws_quick_triage')
        blueprints = get_aws_blueprints()
        blueprint = next((b for b in blueprints if b['id'] == blueprint_id), blueprints[0])

        options = {
            'llm_config': llm_config,
            'time_filter': data.get('time_filter'),
            'min_severity': data.get('min_severity', 'medium'),
            'iris_config': data.get('iris_config'),
            'blueprint': blueprint,
            'aws_config': data.get('aws_config') or {},
        }

        import threading

        def run_offline():
            try:
                update_run_status(run_id, 'running', progress=15)
                result = run_aws_on_existing(run_id=run_id, uploaded_data=uploaded_data, options=options)
                _aws_runs[run_id].update(result)
                try:
                    os.makedirs(PERSIST_DIR, exist_ok=True)
                    with open(f"{PERSIST_DIR}/{run_id}.json", 'w') as f:
                        json.dump(_aws_runs[run_id], f, default=str)
                except Exception as persist_err:
                    print(f"[AWS] persist failed: {persist_err}", flush=True)
                if result.get('status') == 'error':
                    update_run_status(run_id, 'failed', error=result.get('error', 'Unknown'))
                else:
                    update_run_status(run_id, 'completed', progress=100)
            except Exception as e:
                add_log_to_run(run_id, f"[AWS] Offline analysis failed: {e}", "error")
                update_run_status(run_id, 'failed', error=str(e))
                traceback.print_exc()

        threading.Thread(target=run_offline, daemon=True).start()
        return jsonify({'run_id': run_id, 'status': 'running', 'message': 'Offline analysis started'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# =============================================================================
# Read-only result endpoints
# =============================================================================


def _load_run(run_id: str) -> dict | None:
    """In-memory first, persisted JSON fallback."""
    run_data = _aws_runs.get(run_id)
    if run_data:
        return run_data
    data_path = f"{PERSIST_DIR}/{run_id}.json"
    if os.path.exists(data_path):
        try:
            with open(data_path, 'r') as f:
                return json.load(f)
        except Exception:
            return None
    return None


@aws_bp.route('/api/aws/status/<run_id>', methods=['GET'])
def get_run_status(run_id):
    try:
        run_data = _load_run(run_id)
        if not run_data:
            return jsonify({'error': 'Run not found'}), 404
        phase_timings = llm_metrics = sigma_rule_tally = None
        try:
            from services import get_automation_run as _get_workflow
            wf = _get_workflow(run_id)
            if wf:
                phase_timings = wf.get('phase_timings')
                llm_metrics = wf.get('llm_metrics')
                sigma_rule_tally = wf.get('sigma_rule_tally')
        except Exception:
            pass
        return jsonify({
            'run_id': run_id,
            'status': run_data.get('status'),
            'mode': run_data.get('mode'),
            'phases': run_data.get('phases', {}),
            'start_time': run_data.get('start_time'),
            'end_time': run_data.get('end_time'),
            'error': run_data.get('error'),
            'phase_timings': phase_timings,
            'llm_metrics': llm_metrics,
            'sigma_rule_tally': sigma_rule_tally,
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@aws_bp.route('/api/aws/results/<run_id>', methods=['GET'])
def get_run_results(run_id):
    try:
        run_data = _load_run(run_id)
        if not run_data:
            return jsonify({'error': 'Run not found'}), 404
        collected = run_data.get('collected_data', {})
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 100, type=int)
        source = request.args.get('source')
        data_to_return = {source: collected[source]} if source and source in collected else collected
        total_records = sum(len(v) for v in data_to_return.values())
        start_idx = (page - 1) * per_page
        end_idx = start_idx + per_page
        paginated: dict = {}
        cur = 0
        for src, records in data_to_return.items():
            chunk = []
            for record in records:
                if cur >= start_idx and cur < end_idx:
                    chunk.append(record)
                cur += 1
                if cur >= end_idx:
                    break
            if chunk:
                paginated[src] = chunk
            if cur >= end_idx:
                break
        return jsonify({
            'run_id': run_id,
            'sources': list(collected.keys()),
            'total_records': total_records,
            'page': page,
            'per_page': per_page,
            'data': paginated,
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@aws_bp.route('/api/aws/findings/<run_id>', methods=['GET'])
def get_run_findings(run_id):
    try:
        run_data = _load_run(run_id)
        if not run_data:
            return jsonify({'error': 'Run not found'}), 404
        findings = run_data.get('findings', {})
        min_severity = request.args.get('min_severity', 'informational')
        order = ['informational', 'low', 'medium', 'high', 'critical']
        min_idx = order.index(min_severity.lower()) if min_severity.lower() in order else 0
        filtered: dict = {}
        for source, source_findings in findings.items():
            kept = [
                f for f in source_findings
                if order.index((f.get('severity') or 'medium').lower()) >= min_idx
            ]
            if kept:
                filtered[source] = kept
        return jsonify({
            'run_id': run_id,
            'total_findings': sum(len(v) for v in filtered.values()),
            'findings_by_source': {k: len(v) for k, v in filtered.items()},
            'findings': filtered,
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@aws_bp.route('/api/aws/analysis/<run_id>', methods=['GET'])
def get_run_analysis(run_id):
    try:
        run_data = _load_run(run_id)
        if not run_data:
            return jsonify({'error': 'Run not found'}), 404
        return jsonify({
            'run_id': run_id,
            'analysis': run_data.get('analysis', {}),
            'reports': run_data.get('reports', {}),
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@aws_bp.route('/api/aws/runs', methods=['GET'])
def list_runs():
    try:
        from flask import g
        from services.file_storage_service import get_workflow
        case_id = getattr(g, 'case_id', None)
        runs = []
        for run_id, run_data in _aws_runs.items():
            if case_id:                       # workspace isolation
                wf = get_workflow(run_id)
                if wf and wf.get('case_id') and wf.get('case_id') != case_id:
                    continue
            runs.append({
                'run_id': run_id,
                'status': run_data.get('status'),
                'mode': run_data.get('mode'),
                'start_time': run_data.get('start_time'),
                'end_time': run_data.get('end_time'),
                'findings_count': run_data.get('phases', {}).get('detection', {}).get('total_findings', 0),
            })
        runs.sort(key=lambda x: x.get('start_time', ''), reverse=True)
        return jsonify({'runs': runs})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@aws_bp.route('/api/aws/data/<run_id>/download', methods=['GET'])
def download_aws_raw_data(run_id):
    """Bundle collected data + findings + analysis as a ZIP."""
    try:
        run_data = _load_run(run_id)
        if not run_data:
            return jsonify({'error': 'Raw data not found'}), 404
        collected = run_data.get('collected_data', {})
        findings = run_data.get('findings', {})
        analysis = run_data.get('analysis', {})

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
            for source, records in collected.items():
                clean_records = [r.get('_original', r) for r in records]
                zf.writestr(f"collected/{source}.json", json.dumps(clean_records, indent=2, default=str))
            for rule_name, matches in findings.items():
                zf.writestr(f"findings/{rule_name}.json", json.dumps(matches, indent=2, default=str))
            if analysis:
                for artifact, summary in analysis.items():
                    zf.writestr(
                        f"analysis/{artifact}.md",
                        summary if isinstance(summary, str) else json.dumps(summary, indent=2),
                    )
            metadata = {
                'run_id': run_id,
                'mode': run_data.get('mode'),
                'start_time': run_data.get('start_time'),
                'sources_collected': list(collected.keys()),
                'total_records': sum(len(v) for v in collected.values()),
                'sigma_rules_fired': len(findings),
                'total_findings': sum(len(v) for v in findings.values()),
            }
            zf.writestr('metadata.json', json.dumps(metadata, indent=2))
        zip_buffer.seek(0)
        return Response(
            zip_buffer.getvalue(),
            mimetype='application/zip',
            headers={'Content-Disposition': f'attachment; filename="aws_scan_{run_id}.zip"'},
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@aws_bp.route('/api/aws/runs/<run_id>', methods=['DELETE'])
def delete_run(run_id):
    try:
        if run_id in _aws_runs:
            del _aws_runs[run_id]
        run_dir = os.path.join(UPLOAD_FOLDER, run_id)
        if os.path.exists(run_dir):
            import shutil
            shutil.rmtree(run_dir)
        return jsonify({'status': 'deleted', 'run_id': run_id})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

