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


def _coerce_scan_mode(value) -> str:
    """Normalize whatever the operator (or worker chaining a run-hunt
    call) sends. We accept 'full' or 'vulnerable_only'; anything else
    falls back to the safer vulnerable-only mode so the report stays
    legible if the field arrives empty / malformed."""
    if isinstance(value, str) and value.strip().lower() == "full":
        return "full"
    return "vulnerable_only"


def _extract_artifact_csvs_from_zip(zip_path: Path, dest_dir: Path) -> list[Path]:
    """Unpack a Velociraptor hunt ZIP and merge per-client CSVs into the
    four canonical artifact CSVs the CVE pipeline consumes. Returns the
    list of CSV paths written. Hosts get tagged with their `client_id`
    via a `_velo_client_id` column the underlying scan can read; the
    side-project scan is tolerant of extra columns."""
    merged_rows: dict[str, list[list[str]]] = {a: [] for a in _ARTIFACT_TO_CANONICAL}
    merged_headers: dict[str, list[str]] = {}
    # client_id → hostname map, built from Generic.Client.Info rows in
    # a pass-1 over the ZIP. Used to inject a `Hostname` column on
    # every artifact's merged CSV so the side-project's `_row_host()`
    # picks it up — otherwise `combined_cves.csv` shows "(unknown)"
    # for every finding pulled from a hunt-download ZIP.
    client_id_to_hostname: dict[str, str] = {}

    def _entry_client_id(entry_path: str) -> str:
        """Per-client folder name from a hunt-ZIP entry path. Velociraptor
        emits two structures depending on which Download button you use:

          1. "Full Download" of an offline-collector run:
             `clients/<client_id>/...`
          2. "Full Download" / "Summary" of a regular hunt:
             `<hostname>-<client_id>/results/<artifact>.csv`

        For (2), `parts[-2]` is always the literal string 'results' —
        which would (and did) collapse every host's rows under one
        bogus key. Walk for the segment that looks like a Velociraptor
        client folder (contains '-C.' or starts with 'C.'); fall back
        to the legacy 'clients/' lookup; finally the parent dir."""
        parts = entry_path.split('/')
        if 'clients' in parts:
            try:
                return parts[parts.index('clients') + 1]
            except (ValueError, IndexError):
                return ''
        for p in parts:
            if '-C.' in p or p.startswith('C.'):
                return p
        return parts[-2] if len(parts) >= 2 else ''


    def _hostname_from_folder(folder: str) -> str:
        """Velociraptor's per-client folder is `<Hostname>-C.<hash>` — so
        the hostname is everything before the last `-C.`. Useful as a
        fallback when the Generic.Client.Info CSV isn't present for that
        client (e.g. older hunt exports)."""
        if not folder or '-C.' not in folder:
            return ''
        return folder.rsplit('-C.', 1)[0]

    with zipfile.ZipFile(str(zip_path)) as zf:
        # Pass 1: harvest hostnames from Generic.Client.Info CSVs.
        # That artifact's rows carry `Hostname` (or `Fqdn`) directly.
        for entry in zf.namelist():
            if not entry.lower().endswith('.csv'):
                continue
            base = os.path.basename(entry)
            if not (base.startswith('Generic.Client.Info') or 'Client.Info' in base):
                continue
            cid = _entry_client_id(entry)
            if not cid:
                continue
            try:
                with zf.open(entry) as fh:
                    text = io.TextIOWrapper(fh, encoding='utf-8', errors='replace', newline='')
                    reader = csv.reader(text)
                    hdr = next(reader, None)
                    if not hdr:
                        continue
                    # Find Hostname/Fqdn column index — case-insensitive,
                    # accept either.
                    hcol = next((i for i, c in enumerate(hdr) if c.strip().lower() in ('hostname', 'fqdn')), -1)
                    if hcol < 0:
                        continue
                    for row in reader:
                        if hcol < len(row) and row[hcol].strip():
                            client_id_to_hostname[cid] = row[hcol].strip()
                            break  # one row is enough per file
            except Exception:
                continue

        # Pass 2: merge artifact CSVs into one file per artifact, with
        # the operator-facing `Hostname` column appended.
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
            client_id = _entry_client_id(entry)
            # Hostname resolution order:
            #   1. Generic.Client.Info CSV (pass 1) — most accurate
            #   2. Parse `<Hostname>-C.<hash>` from the folder name
            #   3. Fall back to the raw client_id
            hostname = (
                client_id_to_hostname.get(client_id)
                or _hostname_from_folder(client_id)
                or client_id
            )
            with zf.open(entry) as fh:
                text = io.TextIOWrapper(fh, encoding='utf-8', errors='replace', newline='')
                reader = csv.reader(text)
                rows = list(reader)
                if not rows:
                    continue
                header = rows[0]
                data = rows[1:]
                if artifact not in merged_headers:
                    # Append both _velo_client_id (for traceability) AND
                    # Hostname (which the side-project's _row_host()
                    # actually consumes). If hostname lookup failed we
                    # fall back to client_id so at least something
                    # human-meaningful appears in the report.
                    merged_headers[artifact] = header + ['_velo_client_id', 'Hostname']
                # Pad short rows / trim long rows to header width so the
                # merged CSV stays well-formed across heterogeneous hosts.
                width = len(header)
                for row in data:
                    if len(row) < width:
                        row = row + [''] * (width - len(row))
                    elif len(row) > width:
                        row = row[:width]
                    merged_rows[artifact].append(row + [client_id, hostname])

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
    """CVE Scan gates on ``config.yaml: modules.cve_scan.enabled``.

    Returns a Flask response tuple when disabled (so callers do
    ``gate = _module_check(); if gate: return gate``), or None when the
    module is enabled and the route should proceed.
    """
    if not is_module_enabled('cve_scan'):
        return jsonify({"error": "CVE Scan module is not enabled in config.yaml."}), 400
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
        scan_mode = _coerce_scan_mode(request.form.get('scan_mode'))
        run_id = create_automation_run(
            automation_type='cve_scan',
            name=run_name,
            details={'phase': 'starting', 'mode': 'upload', 'scan_mode': scan_mode, 'source_filename': zip_file.filename},
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

        from services.workflow_service import register_cancel_event, is_cancelled as _ic, get_automation_run as _gar
        register_cancel_event(run_id)

        def _worker():
            try:
                if _ic(run_id):
                    return
                run_cve_scan(run_id, saved, name=run_name, mode=scan_mode)
            except Exception:
                # Cancellation residue — request_stop already locked
                # state to 'cancelled'. Don't add an error.
                if _ic(run_id) or (_gar(run_id) or {}).get('status') == 'cancelled':
                    return
        threading.Thread(target=_worker, daemon=True).start()

        return jsonify({'run_id': run_id, 'status': 'started', 'extracted': len(saved), 'scan_mode': scan_mode})

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

    # Pre-flight: this route reads artifact CSVs from a Velociraptor flow
    # via gRPC. With the server down the pull would silently return zero
    # rows and the operator would see "no findings" without knowing why.
    from services.container_status import require_velociraptor
    err, status = require_velociraptor('cve_scan')
    if err:
        return jsonify(err), status

    try:
        data = request.get_json() or {}
        flow_id = (data.get('flow_id') or '').strip() or None
        hunt_id = (data.get('hunt_id') or '').strip() or None
        if not flow_id and not hunt_id:
            return jsonify({'error': 'Provide flow_id or hunt_id.'}), 400

        name = (data.get('name') or '').strip() or _auto_run_name()
        scan_mode = _coerce_scan_mode(data.get('scan_mode'))
        run_id = create_automation_run(
            automation_type='cve_scan',
            name=name,
            details={
                'phase': 'starting',
                'mode': 'from-flow',
                'scan_mode': scan_mode,
                'flow_id': flow_id,
                'hunt_id': hunt_id,
            },
        )
        run_dir = os.path.join(UPLOAD_ROOT, run_id)
        os.makedirs(run_dir, exist_ok=True)

        from services.workflow_service import register_cancel_event, is_cancelled as _ic2, get_automation_run as _gar2
        register_cancel_event(run_id)

        def _worker():
            try:
                update_run_status(run_id, 'running', progress=2)
                if _ic2(run_id):
                    return
                csvs = pull_from_velociraptor(run_id, flow_id, hunt_id, Path(run_dir))
                if _ic2(run_id):
                    return
                run_cve_scan(run_id, csvs, name=name, mode=scan_mode)
            except Exception as e:
                if _ic2(run_id) or (_gar2(run_id) or {}).get('status') == 'cancelled':
                    return
                add_log_to_run(run_id, f"[CVE] from-flow dispatch failed: {e}", "error")
                update_run_status(run_id, 'failed', error=str(e))
        threading.Thread(target=_worker, daemon=True).start()
        return jsonify({'run_id': run_id, 'status': 'started', 'scan_mode': scan_mode})

    except Exception as e:
        return jsonify({'error': str(e)}), 500


# CVE-hunt helpers moved to services/cve_scan/hunt.py so the scheduler can
# reuse the same env-wide hunt without importing this Flask routes module.
# Re-exported here so the route body (and its `_`-prefixed callers) are unchanged.
from services.cve_scan.hunt import (  # noqa: E402
    _CVE_HUNT_ARTIFACTS,
    _dispatch_cve_hunt,
    _stop_hunt,
    _wait_for_hunt,
)


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

    # Pre-flight: dispatching the cve_management hunt requires a reachable
    # Velociraptor server. Mirrors timesketch/memory routes — names the
    # primary artifact (Windows.Sys.Programs) in the error so the operator
    # knows which collection is blocked.
    from services.container_status import require_velociraptor
    err, vstatus = require_velociraptor('cve_scan')
    if err:
        return jsonify(err), vstatus

    try:
        data = request.get_json() or {}
        chain = bool(data.get('chain_cve_scan'))
        run_name = (data.get('name') or '').strip() or _auto_run_name()

        # SHAPE + LENGTH gate (Mythos finding #4). `run_name` flows
        # into `_dispatch_cve_hunt(description=f"Intact.AI CVE Scan:
        # {run_name}")` and ultimately into a VQL `hunt(description=
        # '{description}', ...)` string. The downstream f-string
        # assembly escapes the description via escape_vql_string
        # before concat (see _dispatch_cve_hunt); here we just cap
        # the length so an operator can't accidentally paste 100 KB
        # of text into the hunt name and clog the workflows table.
        # Free-form chars (apostrophe, dot, hyphen, parens) ARE
        # allowed — IR data contains them legitimately.
        if len(run_name) > 256:
            return jsonify({"error": "name must be 256 characters or fewer"}), 400
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
        scan_mode = _coerce_scan_mode(data.get('scan_mode'))
        details = {
            'phase': 'dispatching_hunt',
            'mode': 'run-hunt',
            'chain_cve_scan': chain,
            'scan_mode': scan_mode,
            'artifacts': _CVE_HUNT_ARTIFACTS,
        }
        run_id = create_automation_run(
            automation_type=automation_type,
            name=run_name,
            details=details,
        )
        add_log_to_run(run_id, f"[CVE] Dispatching hunt with {len(_CVE_HUNT_ARTIFACTS)} artifacts "
                              f"({'will auto-scan when finished' if chain else 'hunt-only'})", "info")

        # Register cancel event so the Stop button on the workflow row
        # actually interrupts this multi-phase pipeline (hunt dispatch
        # → poll → CSV pull → CVE scan).
        from services.workflow_service import register_cancel_event, is_cancelled, get_automation_run as _get_run
        register_cancel_event(run_id)

        def _worker():
            try:
                update_run_status(run_id, 'running', progress=5)
                if is_cancelled(run_id):
                    return
                # Pass the operator's max_wait through so the hunt's
                # `expires` matches the polling window — no orphan hunt
                # left running after we've already stopped watching.
                hunt_id = _dispatch_cve_hunt(
                    run_id,
                    description=f"Intact.AI CVE Scan: {run_name}",
                    max_wait_seconds=max_wait_seconds,
                )
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
                    # 'running', not 'completed' — the hunt was only just
                    # dispatched. dashboard_routes.get_automation_details()
                    # flips this to 'completed' once Velociraptor reports
                    # every scheduled client's flow actually finished (same
                    # reconciliation the velociraptor_hunt dispatch route uses;
                    # this run already carries automation_type='velociraptor_hunt'
                    # and details['hunt_id'], which is all that logic needs).
                    update_run_status(run_id, 'running', progress=90)
                    add_log_to_run(run_id, f"[CVE] Hunt dispatched. To run the CVE scan later, paste "
                                          f"hunt id '{hunt_id}' into the 'Use existing hunt / flow' tab.", "info")
                    return

                # chain=true — wait then scan.
                update_run_status(run_id, 'running', progress=15)
                add_log_to_run(run_id, f"[CVE] Waiting for hunt to finish (polling every 30s, max {max_wait_minutes} min)…", "info")
                finished = _wait_for_hunt(run_id, hunt_id, timeout_seconds=max_wait_seconds)
                partial = False
                if not finished:
                    # Timeout: stop the hunt on Velociraptor so it
                    # doesn't keep eating endpoint resources, then scan
                    # whatever results have already arrived. Partial
                    # data is more useful to the operator than a
                    # `failed` status with no output.
                    partial = True
                    add_log_to_run(
                        run_id,
                        f"[CVE] {max_wait_minutes} min timer expired — stopping hunt {hunt_id} "
                        f"and scanning whatever has been collected so far.",
                        "warning",
                    )
                    _stop_hunt(run_id, hunt_id)

                update_run_status(run_id, 'running', progress=40)
                run_dir = Path(os.path.join(UPLOAD_ROOT, run_id))
                csvs = pull_from_velociraptor(run_id, None, hunt_id, run_dir)
                if not csvs:
                    note = ("Hunt timer expired before any client checked in." if partial
                            else "Hunt finished but no CSVs were produced (artifacts may have errored on every client).")
                    add_log_to_run(run_id, f"[CVE] {note}", "error")
                    update_run_status(run_id, 'failed', error=note)
                    return
                if partial:
                    add_log_to_run(
                        run_id,
                        f"[CVE] Pulled partial results from {len(csvs)} CSV(s) — running NVD scan on partial data.",
                        "info",
                    )
                if is_cancelled(run_id):
                    return
                run_cve_scan(run_id, csvs, name=(f"{run_name} (partial)" if partial else run_name), mode=scan_mode)
            except Exception as e:
                # If the operator clicked Stop, the killed-subprocess
                # exception that bubbles up is not a real failure —
                # request_stop() already wrote the cancellation banner
                # and locked the status. Don't overwrite with an error.
                if is_cancelled(run_id) or (_get_run(run_id) or {}).get('status') == 'cancelled':
                    return
                add_log_to_run(run_id, f"[CVE] run-hunt dispatch failed: {e}", "error")
                update_run_status(run_id, 'failed', error=str(e))

        threading.Thread(target=_worker, daemon=True).start()
        return jsonify({'run_id': run_id, 'status': 'started', 'chain_cve_scan': chain, 'scan_mode': scan_mode})
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
