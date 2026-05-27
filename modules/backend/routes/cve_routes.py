"""Routes for the CVE Scan tab.

  POST /api/cve/scan/upload     multipart — 1-4 CSV files
                                 → creates a cve_scan workflow row,
                                   dispatches run_cve_scan in a thread
  POST /api/cve/scan/from-flow  body {flow_id|hunt_id, name}
                                 → creates a cve_scan workflow row,
                                   dispatches pull_from_velociraptor + run
  POST /api/cve/scan/run-hunt    body {chain_cve_scan: bool, name}
                                 → dispatches a Velociraptor hunt using the
                                   default `cve_management` blueprint's 4
                                   artifacts. If chain_cve_scan=true,
                                   polls until the hunt finishes then
                                   pulls CSVs + runs the scan in one
                                   workflow row; otherwise drops a
                                   `velociraptor_hunt` row that the
                                   operator can later pull from via the
                                   from-flow mode.
  GET  /api/cve/run/<id>/download
                                 → streams combined_cves.csv
  GET  /api/cve/run/<id>/download/findings
                                 → streams findings.json (machine-friendly)
  GET  /api/cve/sources          → list eligible Velociraptor flows / hunts
                                   for the from-flow picker (lightweight
                                   passthrough — UI text-field for now)
"""
from __future__ import annotations

import csv
import io
import os
import threading
import uuid
import zipfile
from datetime import datetime
from pathlib import Path
from flask import Blueprint, Response, jsonify, request
from werkzeug.utils import secure_filename

from services.workflow_service import create_automation_run, get_automation_run, update_run_status, add_log_to_run
from services.cve_scan import run_cve_scan, pull_from_velociraptor
from config import is_module_enabled


cve_bp = Blueprint('cve', __name__)

UPLOAD_ROOT = '/tmp/cve_uploads'

# Velociraptor hunt-download ZIPs contain one CSV per (client × artifact)
# at paths like `<HuntId>/clients/<client_id>/<artifact_name>.csv`. The
# CVE pipeline expects a single CSV per artifact with the canonical
# filenames below, so we merge all clients' rows per artifact.
_ARTIFACT_TO_CANONICAL = {
    'Windows.Sys.Programs':                              'system_programs.csv',
    'DetectRaptor.Windows.Detection.Applications':       'detectraptor_applications.csv',
    'DetectRaptor.Windows.Detection.LolRMM':             'detectraptor_lolrm.csv',
    'Generic.Client.Info':                               'windows versions.csv',
}


def _auto_run_name() -> str:
    """Default workflow row name. The operator can override later via
    the workflow's rename action; we no longer surface the name field
    in the UI because each run is unique by timestamp anyway."""
    return f"CVE Management — {datetime.now().strftime('%Y-%m-%d %H:%M')}"


def _extract_artifact_csvs_from_zip(zip_path: Path, dest_dir: Path) -> list[Path]:
    """Unpack a Velociraptor hunt ZIP and merge per-client CSVs into the
    four canonical artifact CSVs the CVE pipeline consumes. Returns the
    list of CSV paths written. Hosts get tagged with their `client_id`
    via a `_velo_client_id` column the underlying scan can read; the
    side-project scan is tolerant of extra columns."""
    merged_rows: dict[str, list[list[str]]] = {a: [] for a in _ARTIFACT_TO_CANONICAL}
    merged_headers: dict[str, list[str]] = {}

    with zipfile.ZipFile(str(zip_path)) as zf:
        for entry in zf.namelist():
            name_lower = entry.lower()
            if not name_lower.endswith('.csv'):
                continue
            # Match by basename — Velociraptor names CSVs after the
            # artifact regardless of path nesting.
            base = os.path.basename(entry)
            base_noext = base[:-4] if base_lower_ok(base) else base
            artifact = None
            for art in _ARTIFACT_TO_CANONICAL:
                # Accept exact match OR sub-source forms like
                # `<artifact>_<source>.csv` (Velociraptor uses both).
                if base_noext == art or base_noext.startswith(art + '_') or base_noext.startswith(art + '/'):
                    artifact = art
                    break
            if not artifact:
                continue
            # Client id is the segment immediately after "clients/" in
            # the ZIP entry path. Fall back to the parent dir name.
            client_id = ''
            parts = entry.split('/')
            if 'clients' in parts:
                try:
                    client_id = parts[parts.index('clients') + 1]
                except (ValueError, IndexError):
                    pass
            if not client_id and len(parts) >= 2:
                client_id = parts[-2]
            with zf.open(entry) as fh:
                text = io.TextIOWrapper(fh, encoding='utf-8', errors='replace', newline='')
                reader = csv.reader(text)
                rows = list(reader)
                if not rows:
                    continue
                header = rows[0]
                data = rows[1:]
                if artifact not in merged_headers:
                    merged_headers[artifact] = header + ['_velo_client_id']
                # Pad short rows / trim long rows to header width so the
                # merged CSV stays well-formed across heterogeneous hosts.
                width = len(header)
                for row in data:
                    if len(row) < width:
                        row = row + [''] * (width - len(row))
                    elif len(row) > width:
                        row = row[:width]
                    merged_rows[artifact].append(row + [client_id])

    written: list[Path] = []
    for artifact, rows in merged_rows.items():
        if not rows:
            continue
        out_path = dest_dir / _ARTIFACT_TO_CANONICAL[artifact]
        with open(out_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(merged_headers[artifact])
            writer.writerows(rows)
        written.append(out_path)
    return written


def base_lower_ok(name: str) -> bool:
    """csv-suffix check helper — keep the comparison case-insensitive
    without losing the original-case basename used for artifact match."""
    return name.lower().endswith('.csv')


def _module_check():
    """If the cve_scan module is disabled in config.yaml, the routes
    return a 400 rather than executing. Mirrors the existing
    `is_module_enabled('agentic')` / `is_module_enabled('aws')`
    gates."""
    if not is_module_enabled('cve_scan'):
        return jsonify({'error': 'CVE Scan module is not enabled in config.yaml.'}), 400
    return None


@cve_bp.route('/api/cve/scan/upload', methods=['POST'])
def upload_scan():
    """Operator uploads a Velociraptor hunt-download ZIP (the artifact
    bundle the Velociraptor UI hands back under
    `Full Download / Summary (CSV Only)`). We unpack it, merge the
    per-client CSVs into the four canonical artifacts the pipeline
    expects, and dispatch the scan in a background thread."""
    gate = _module_check()
    if gate:
        return gate
    try:
        zip_file = request.files.get('zip')
        if not zip_file or not zip_file.filename:
            return jsonify({'error': 'No ZIP file provided. Upload a Velociraptor hunt download ZIP.'}), 400
        if not zip_file.filename.lower().endswith('.zip'):
            return jsonify({'error': 'Expected a .zip file (Velociraptor hunt Full Download).'}), 400

        run_name = _auto_run_name()
        run_id = create_automation_run(
            automation_type='cve_scan',
            name=run_name,
            details={'phase': 'starting', 'mode': 'upload', 'source_filename': zip_file.filename},
        )
        run_dir = Path(UPLOAD_ROOT) / run_id
        run_dir.mkdir(parents=True, exist_ok=True)

        # Persist the raw upload first so we have something concrete to
        # unpack from disk (saves memory; the ZIPs can be hundreds of MB).
        zip_path = run_dir / secure_filename(zip_file.filename)
        zip_file.save(str(zip_path))
        add_log_to_run(run_id, f"[CVE] Received {zip_file.filename} ({zip_path.stat().st_size // 1024} KiB). Extracting…", "info")

        try:
            saved = _extract_artifact_csvs_from_zip(zip_path, run_dir)
        except zipfile.BadZipFile:
            update_run_status(run_id, 'failed', error="Uploaded file is not a valid ZIP")
            return jsonify({'error': 'Uploaded file is not a valid ZIP archive.', 'run_id': run_id}), 400

        if not saved:
            update_run_status(run_id, 'failed', error="ZIP contained no recognised artifact CSVs")
            return jsonify({
                'error': 'ZIP did not contain any recognised artifact CSVs '
                         '(Windows.Sys.Programs / DetectRaptor.* / Generic.Client.Info). '
                         'Make sure the hunt collected the cve_management artifacts.',
                'run_id': run_id,
            }), 400

        add_log_to_run(
            run_id,
            f"[CVE] Extracted {len(saved)} artifact CSV(s) from ZIP: " + ", ".join(p.name for p in saved),
            "info",
        )

        def _worker():
            try:
                run_cve_scan(run_id, saved, name=run_name)
            except Exception:
                pass
        threading.Thread(target=_worker, daemon=True).start()

        return jsonify({'run_id': run_id, 'status': 'started', 'extracted': len(saved)})

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@cve_bp.route('/api/cve/scan/from-flow', methods=['POST'])
def from_flow_scan():
    """Operator passes a Velociraptor flow_id or hunt_id. We pull
    the 4 required artifact result sets out of Velociraptor and run
    the scan against them. No file uploads needed."""
    gate = _module_check()
    if gate:
        return gate
    try:
        data = request.get_json() or {}
        flow_id = (data.get('flow_id') or '').strip() or None
        hunt_id = (data.get('hunt_id') or '').strip() or None
        if not flow_id and not hunt_id:
            return jsonify({'error': 'Provide flow_id or hunt_id.'}), 400

        name = (data.get('name') or '').strip() or _auto_run_name()
        run_id = create_automation_run(
            automation_type='cve_scan',
            name=name,
            details={
                'phase': 'starting',
                'mode': 'from-flow',
                'flow_id': flow_id,
                'hunt_id': hunt_id,
            },
        )
        run_dir = os.path.join(UPLOAD_ROOT, run_id)
        os.makedirs(run_dir, exist_ok=True)

        def _worker():
            try:
                update_run_status(run_id, 'running', progress=2)
                csvs = pull_from_velociraptor(run_id, flow_id, hunt_id, Path(run_dir))
                run_cve_scan(run_id, csvs, name=name)
            except Exception as e:
                add_log_to_run(run_id, f"[CVE] from-flow dispatch failed: {e}", "error")
                update_run_status(run_id, 'failed', error=str(e))
        threading.Thread(target=_worker, daemon=True).start()
        return jsonify({'run_id': run_id, 'status': 'started'})

    except Exception as e:
        return jsonify({'error': str(e)}), 500


# Artifact set the cve_management blueprint collects. Re-declared here so
# the route works even on installs where the operator has renamed or
# deleted the YAML blueprint — the four canonical artifact names are what
# the downstream NVD pipeline actually consumes.
_CVE_HUNT_ARTIFACTS = [
    'Windows.Sys.Programs',
    'DetectRaptor.Windows.Detection.Applications',
    'DetectRaptor.Windows.Detection.LolRMM',
    'Generic.Client.Info',
]


def _dispatch_cve_hunt(run_id: str, description: str) -> str | None:
    """Create a multi-artifact Velociraptor hunt with the cve_management
    artifact set. Returns the new hunt_id (H.xxx) or None on failure.
    Logs progress to the given workflow row.

    Mirrors the bulk-hunt VQL the bestpractice route uses
    (routes/velociraptor_routes.py:217), with the resource caps from
    the cve_management blueprint's settings."""
    import json as _json
    from services.velociraptor_service import setup_velociraptor_connection
    from pyvelociraptor import api_pb2, api_pb2_grpc

    channel = setup_velociraptor_connection()
    if not channel:
        add_log_to_run(run_id, "[CVE] Failed to connect to Velociraptor server", "error")
        return None
    try:
        stub = api_pb2_grpc.APIStub(channel)
        artifacts_list = _json.dumps(_CVE_HUNT_ARTIFACTS)
        spec_parts = ", ".join([f'`{a}`=dict()' for a in _CVE_HUNT_ARTIFACTS])
        # Mirrors the cve_management blueprint settings in
        # modules/backend/config/default_blueprints.yaml. Hunt expiry
        # is set equal to the per-client timeout so the hunt closes
        # itself instead of lingering open after clients have all
        # finished. The per-run "max wait" the operator sets in the UI
        # controls the *polling* timeout, not these hunt-side caps.
        timeout_seconds = 3600
        expire_seconds = timeout_seconds
        cpu_limit = 80
        flow_max_rows = 5_000_000
        flow_max_bytes = 10_240 * 1024 * 1024
        query = f"""
LET collection = hunt(
    description='{description}',
    artifacts={artifacts_list},
    spec=dict({spec_parts}),
    expires=now() + {expire_seconds},
    timeout={timeout_seconds},
    max_rows={flow_max_rows},
    max_bytes={flow_max_bytes},
    cpu_limit={cpu_limit}
)
SELECT HuntId FROM collection
"""
        request_obj = api_pb2.VQLCollectorArgs(
            max_wait=30,
            max_row=100,
            Query=[api_pb2.VQLRequest(VQL=query)],
        )
        hunt_id = None
        for response in stub.Query(request_obj, timeout=120):
            if response.Response:
                try:
                    resp_data = _json.loads(response.Response)
                    if resp_data and len(resp_data) > 0:
                        hunt_id = resp_data[0].get('HuntId')
                        if hunt_id:
                            break
                except Exception:
                    continue
        return hunt_id
    finally:
        try:
            channel.close()
        except Exception:
            pass


def _wait_for_hunt(run_id: str, hunt_id: str, timeout_seconds: int = 7200, poll_seconds: int = 30) -> bool:
    """Poll Velociraptor until the hunt is no longer RUNNING. Returns
    True on STOPPED/PAUSED, False on timeout. Best-effort; on connection
    failures the polls keep retrying until the timeout."""
    import json as _json
    import time as _time
    from services.velociraptor_service import setup_velociraptor_connection
    from pyvelociraptor import api_pb2, api_pb2_grpc

    start = _time.time()
    last_state = None
    while _time.time() - start < timeout_seconds:
        try:
            channel = setup_velociraptor_connection()
            if channel:
                try:
                    stub = api_pb2_grpc.APIStub(channel)
                    q = f"SELECT state FROM hunts() WHERE hunt_id='{hunt_id}'"
                    req = api_pb2.VQLCollectorArgs(
                        max_wait=10, max_row=10,
                        Query=[api_pb2.VQLRequest(VQL=q)],
                    )
                    for response in stub.Query(req, timeout=20):
                        if response.Response:
                            try:
                                rows = _json.loads(response.Response)
                                if rows and isinstance(rows, list):
                                    state = (rows[0].get('state') or '').upper()
                                    if state and state != last_state:
                                        add_log_to_run(run_id, f"[CVE] Hunt {hunt_id} state: {state}", "info")
                                        last_state = state
                                    # RUNNING keeps us polling; anything else means done.
                                    if state and state != 'RUNNING':
                                        return True
                            except Exception:
                                pass
                finally:
                    try:
                        channel.close()
                    except Exception:
                        pass
        except Exception as e:
            add_log_to_run(run_id, f"[CVE] Hunt poll error (will retry): {e}", "warning")
        _time.sleep(poll_seconds)
    add_log_to_run(run_id, f"[CVE] Hunt {hunt_id} did not finish within {timeout_seconds}s — leaving it running. "
                           f"Once it's done, use the 'Use existing hunt' tab to pull results.", "warning")
    return False


@cve_bp.route('/api/cve/scan/run-hunt', methods=['POST'])
def run_cve_hunt():
    """Dispatch a Velociraptor hunt using the cve_management artifact
    set. With chain_cve_scan=false, the hunt is the deliverable —
    operator returns later via the from-flow route. With
    chain_cve_scan=true, we additionally poll the hunt until finished,
    then pull CSVs + run the scan in the same workflow row."""
    gate = _module_check()
    if gate:
        return gate
    try:
        data = request.get_json() or {}
        chain = bool(data.get('chain_cve_scan'))
        run_name = (data.get('name') or '').strip() or _auto_run_name()
        # Operator-supplied poll cap in minutes (chain mode only). Clamp
        # to [1 min, 12 h] so a typo can't lock the worker thread for
        # days. Default 120 min matches the previous hardcoded ceiling.
        try:
            max_wait_minutes = int(data.get('max_wait_minutes') or 120)
        except (TypeError, ValueError):
            max_wait_minutes = 120
        max_wait_minutes = max(1, min(720, max_wait_minutes))
        max_wait_seconds = max_wait_minutes * 60

        # Workflow type splits on intent: cve_scan for chained runs (gets
        # the CVE CSV download button), velociraptor_hunt for hunt-only
        # so it sorts alongside other hunt rows.
        automation_type = 'cve_scan' if chain else 'velociraptor_hunt'
        details = {
            'phase': 'dispatching_hunt',
            'mode': 'run-hunt',
            'chain_cve_scan': chain,
            'artifacts': _CVE_HUNT_ARTIFACTS,
        }
        run_id = create_automation_run(
            automation_type=automation_type,
            name=run_name,
            details=details,
        )
        add_log_to_run(run_id, f"[CVE] Dispatching hunt with {len(_CVE_HUNT_ARTIFACTS)} artifacts "
                              f"({'will auto-scan when finished' if chain else 'hunt-only'})", "info")

        def _worker():
            try:
                update_run_status(run_id, 'running', progress=5)
                hunt_id = _dispatch_cve_hunt(run_id, description=f"Intact.AI CVE Scan: {run_name}")
                if not hunt_id:
                    add_log_to_run(run_id, "[CVE] Hunt creation failed — no HuntId returned", "error")
                    update_run_status(run_id, 'failed', error="Hunt creation failed")
                    return
                add_log_to_run(run_id, f"[CVE] Hunt created: {hunt_id}", "info")

                # Stash so the workflow page + the "From existing hunt"
                # tab can reference it directly.
                from services.file_storage_service import get_workflow, save_workflow
                wf = get_workflow(run_id) or {}
                wd = wf.get('details') or {}
                wd['hunt_id'] = hunt_id
                wf['details'] = wd
                save_workflow(wf)

                if not chain:
                    update_run_status(run_id, 'completed', progress=100)
                    add_log_to_run(run_id, f"[CVE] Hunt dispatched. To run the CVE scan later, paste "
                                          f"hunt id '{hunt_id}' into the 'Use existing hunt / flow' tab.", "info")
                    return

                # chain=true — wait then scan.
                update_run_status(run_id, 'running', progress=15)
                add_log_to_run(run_id, f"[CVE] Waiting for hunt to finish (polling every 30s, max {max_wait_minutes} min)…", "info")
                finished = _wait_for_hunt(run_id, hunt_id, timeout_seconds=max_wait_seconds)
                if not finished:
                    # The hunt is still running on Velociraptor — we just
                    # stopped polling. Surface the hunt_id in the error so
                    # the operator can paste it into 'Use existing hunt'
                    # once it completes, instead of having to dig through
                    # the logs to find it.
                    add_log_to_run(
                        run_id,
                        f"[CVE] Auto-scan skipped — hunt {hunt_id} still running. "
                        f"To finish: 'Use existing hunt / flow' → paste '{hunt_id}'.",
                        "warning",
                    )
                    update_run_status(
                        run_id,
                        'failed',
                        error=f"Auto-scan timed out after {max_wait_minutes} min — "
                              f"hunt {hunt_id} still running; paste it into 'Use existing hunt' to finish.",
                    )
                    return

                update_run_status(run_id, 'running', progress=40)
                run_dir = Path(os.path.join(UPLOAD_ROOT, run_id))
                csvs = pull_from_velociraptor(run_id, None, hunt_id, run_dir)
                if not csvs:
                    add_log_to_run(run_id, "[CVE] Hunt finished but no CSVs were produced (artifacts may have errored on every client).", "error")
                    update_run_status(run_id, 'failed', error="No CSVs pulled from hunt")
                    return
                run_cve_scan(run_id, csvs, name=run_name)
            except Exception as e:
                add_log_to_run(run_id, f"[CVE] run-hunt dispatch failed: {e}", "error")
                update_run_status(run_id, 'failed', error=str(e))

        threading.Thread(target=_worker, daemon=True).start()
        return jsonify({'run_id': run_id, 'status': 'started', 'chain_cve_scan': chain})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@cve_bp.route('/api/cve/run/<run_id>/download', methods=['GET'])
def download_combined(run_id):
    """Stream combined_cves.csv — the customer-facing deliverable."""
    try:
        run = get_automation_run(run_id)
        if not run:
            return jsonify({'error': 'Run not found'}), 404
        details = run.get('details') or {}
        path = details.get('combined_csv')
        if not path or not os.path.exists(path):
            # Fall back to deriving the canonical location from the run_id.
            path = f"/data/downloads/{run_id}/combined_cves.csv"
            if not os.path.exists(path):
                return jsonify({'error': 'combined_cves.csv not found for this run.'}), 404
        with open(path, 'rb') as f:
            content = f.read()
        return Response(
            content,
            mimetype='text/csv',
            headers={'Content-Disposition': f'attachment; filename="combined_cves_{run_id}.csv"'},
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@cve_bp.route('/api/cve/run/<run_id>/download/findings', methods=['GET'])
def download_findings(run_id):
    """Stream findings.json — machine-friendly form for the future
    Engagement Report integration (or for the operator's pipelines)."""
    try:
        path = f"/data/downloads/{run_id}/findings.json"
        if not os.path.exists(path):
            return jsonify({'error': 'findings.json not found for this run.'}), 404
        with open(path, 'rb') as f:
            content = f.read()
        return Response(
            content,
            mimetype='application/json',
            headers={'Content-Disposition': f'attachment; filename="findings_{run_id}.json"'},
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500
