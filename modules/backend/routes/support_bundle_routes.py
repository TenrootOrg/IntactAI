#!/usr/bin/env python3
"""Support Bundle Routes — kick off a diagnostic-bundle workflow and
serve the resulting .zip for download.

Mirrors the prepare/download split used by the upgrade-prepare route
(routes/upgrade_routes.py:207-378) — POST creates a workflow run,
background thread builds the bundle, GET streams the file.
"""

import os
import threading
import traceback

from flask import Blueprint, jsonify, send_file

from services import (
    create_automation_run,
    add_log_to_run,
    update_run_status,
    get_automation_run,
)

support_bundle_bp = Blueprint('support_bundle', __name__)


@support_bundle_bp.route('/api/support-bundle/prepare', methods=['POST'])
def prepare_support_bundle_endpoint():
    """Kick off a support-bundle workflow. Returns the run_id immediately;
    progress is visible in the Workflows tab."""
    try:
        run_id = create_automation_run(
            automation_type='support_bundle',
            name='Generate Support Bundle',
            details={'trigger': 'manual'},
        )
        add_log_to_run(run_id, 'Starting support bundle generation', 'info')
        update_run_status(run_id, 'running', progress=1)

        from services.workflow_service import register_cancel_event, unregister_cancel
        register_cancel_event(run_id)

        def _worker():
            try:
                from services.support_bundle import prepare_support_bundle

                def logger(msg, level='info'):
                    add_log_to_run(run_id, msg, level)

                result = prepare_support_bundle(run_id, logger)

                # Persist the bundle metadata onto the run so the download
                # endpoint can find the file and the UI can render a
                # "Bundle (N MB)" button on the completed row.
                update_run_status(
                    run_id, 'completed', progress=100,
                    details={
                        'bundle_path': result['bundle_path'],
                        'bundle_name': result['bundle_name'],
                        'bundle_size_mb': result['bundle_size_mb'],
                        'container_count': result.get('container_count'),
                        'workflow_run_count': result.get('workflow_run_count'),
                        'service_log_file_count': result.get('service_log_file_count'),
                    },
                )

            except Exception as e:
                err = str(e)
                add_log_to_run(run_id, f'Support bundle generation failed: {err}', 'error')
                add_log_to_run(run_id, traceback.format_exc(), 'error')
                update_run_status(run_id, 'failed', progress=0, error=err)
            finally:
                unregister_cancel(run_id)

        threading.Thread(target=_worker, daemon=True).start()

        return jsonify({
            'success': True,
            'run_id': run_id,
            'message': 'Support bundle generation started — see Workflows tab',
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@support_bundle_bp.route('/api/support-bundle/<run_id>/download', methods=['GET'])
def download_support_bundle(run_id):
    """Stream the tar.gz built by the workflow `run_id`."""
    run = get_automation_run(run_id)
    if not run:
        return jsonify({'error': f'Workflow {run_id} not found'}), 404

    details = run.get('details') or {}
    bundle_path = details.get('bundle_path')
    bundle_name = details.get('bundle_name') or f'intact-support-{run_id}.zip'

    if not bundle_path:
        return jsonify({
            'error': 'No bundle is associated with this workflow yet — has it finished?'
        }), 404
    if not os.path.exists(bundle_path):
        # Likely the backend restarted since the bundle was built
        # (/data/support_bundles is on the container's ephemeral layer,
        # same as /data/upgrade_packages). Tell the operator to re-run.
        return jsonify({
            'error': 'Bundle file is no longer on disk (backend restart?). Run "Generate Support Bundle" again.'
        }), 410

    return send_file(
        bundle_path,
        as_attachment=True,
        download_name=bundle_name,
        mimetype='application/zip',
    )
