#!/usr/bin/env python3
"""
Agentic Routes - Velociraptor collection dispatch endpoint
"""

import threading
from flask import Blueprint, jsonify, request

from services.agentic import run_agentic_pipeline
from services.file_storage_service import get_agentic_blueprint, get_velociraptor_blueprint
from services.workflow_service import create_automation_run
from config import is_module_enabled

agentic_bp = Blueprint('agentic', __name__)


@agentic_bp.route('/api/agentic/run', methods=['POST'])
def start_agentic_run():
    """Start a Velociraptor collection (pure collect-only — analysis + reporting
    happen at Case Analysis / fusion)."""
    try:
        data = request.get_json()
        blueprint_id = data.get('blueprint_id')
        # Look up blueprint name from database if not provided (check both agentic and velociraptor tables)
        blueprint_name = data.get('blueprint')
        if not blueprint_name:
            bp = get_agentic_blueprint(blueprint_id) or get_velociraptor_blueprint(blueprint_id)
            blueprint_name = bp.get('name', 'Unknown') if bp else 'Unknown'
        # SHAPE VALIDATION (Mythos #2 extended): every `client_ids`
        # element flows into `services/agentic/collectors.py` VQL
        # strings via f-string concat (`get_flow(client_id='{cid}',
        # ...)`, `cancel_flow(client_id='{cid}', ...)`, etc. — 9+
        # sites). Reject anything that's not Velociraptor's strict
        # `C.<hex>` ID format. Legitimate clients always match.
        from services.vql_safety import validate_client_ids_list
        client_ids, _cid_err = validate_client_ids_list(data.get('client_ids'))
        if _cid_err:
            return jsonify({"error": _cid_err}), 400
        collection_minutes = data.get('collection_minutes', 30)

        # Validate
        if not blueprint_id:
            return jsonify({"error": "blueprint_id is required"}), 400
        if not client_ids or len(client_ids) == 0:
            return jsonify({"error": "At least one client must be selected"}), 400
        if collection_minutes < 1 or collection_minutes > 1440:
            return jsonify({"error": "collection_minutes must be between 1 and 1440"}), 400

        # Resolve hostnames upfront so the workflow name + run details
        # carry human-readable names from the moment the row appears in
        # the Workflows tab. Mirrors the Timesketch pattern (which uses
        # the client list it already has) — the agentic side only had
        # client_ids in hand at request time, so we add one VQL roundtrip
        # against the Velociraptor server here. Falls back to client_id
        # if the lookup fails (operator still sees something usable).
        from services.agentic.collectors import resolve_hostnames as _resolve
        hostnames = _resolve(client_ids)
        names = [hostnames.get(cid, cid) for cid in client_ids]

        # Workflow-name label uses the "show up to 3 names, then collapse"
        # rule. Past 3 the names string would overflow the table column
        # in the dashboard and stop being useful at a glance.
        if len(client_ids) <= 3:
            client_label = f"{len(client_ids)} clients ({', '.join(names)})"
        else:
            client_label = f"{len(client_ids)} clients"

        # Create workflow run
        run_id = create_automation_run(
            automation_type="velociraptor_collection",
            name=f"Velociraptor Collection - {client_label}, {collection_minutes}m",
            details={
                "blueprint_id": blueprint_id,
                "blueprint": blueprint_name,
                # Runs from the agentic pipeline are agentic by definition (the
                # run name doesn't carry the '[Agentic]' marker, so tag it
                # explicitly for the 'Velociraptor (Agentic)' fusion module).
                "is_agentic": True,
                "client_ids": client_ids,
                # Stashed so the report generator can read the same map
                # without re-querying. Keys are client_ids; values are
                # the human hostnames (or the client_id as fallback).
                "hostnames": hostnames,
                "collection_minutes": collection_minutes,
                "phase": "starting"
            }
        )

        print(f"[AGENTIC] Starting pipeline: run_id={run_id}, clients={len(client_ids)}, minutes={collection_minutes}", flush=True)

        # Register cancel event for stop support
        from services.workflow_service import register_cancel_event
        cancel_event = register_cancel_event(run_id)

        # Start pipeline in background thread
        thread = threading.Thread(
            target=run_agentic_pipeline,
            args=(run_id, blueprint_id, client_ids, collection_minutes, cancel_event),
            daemon=True
        )
        thread.start()

        return jsonify({
            "run_id": run_id,
            "status": "started"
        })

    except Exception as e:
        print(f"[AGENTIC] Error starting pipeline: {e}", flush=True)
        return jsonify({"error": str(e)}), 500
