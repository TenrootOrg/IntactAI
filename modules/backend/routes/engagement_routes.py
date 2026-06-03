"""Routes for the Engagement Report builder.

  POST   /api/engagement/generate          start a build (background thread)
  GET    /api/engagement/sources           list completed runs eligible as sources
  GET    /api/engagement/<run_id>/download download the assembled markdown
  GET    /api/engagement/run/<id>/chat     chat snapshot (delegates to shared chat module)
  POST   /api/engagement/run/<id>/chat     append a chat turn
  DELETE /api/engagement/run/<id>/chat     clear chat
  POST   /api/engagement/run/<id>/rerun    rebuild with chat-synthesised master prompt
"""
from __future__ import annotations

import threading
import json as _json
from flask import Blueprint, jsonify, request, Response

from services.workflow_service import (
    create_automation_run,
    get_automation_run,
    update_run_status,
    add_log_to_run,
)
from services.file_storage_service import load_frontend_config
from services.storage.report_store import get_report
from services.engagement.builder import run_engagement_build, run_engagement_reanalyze
from services.agentic import chat as interactive_chat

engagement_bp = Blueprint('engagement', __name__)


def _load_llm_config():
    return load_frontend_config() or {}


# ---------------------------------------------------------------------------
# Source discovery + build dispatch
# ---------------------------------------------------------------------------


_ELIGIBLE_TYPES = {'agentic', 'aws_scan', 'azure_scan', 'cve_scan'}


@engagement_bp.route('/api/engagement/sources', methods=['GET'])
def list_sources():
    """Return all completed runs the operator can pick as an
    Engagement Report source. The frontend already polls
    /api/dashboard/automations for the full workflows list — this
    endpoint just adds the filtering convenience + a stable shape
    so the engagement panel doesn't have to re-implement it."""
    try:
        from services.file_storage_service import load_workflows
        out = []
        for wf in load_workflows():
            if wf.get('status') != 'completed':
                continue
            atype = wf.get('automation_type')
            if atype not in _ELIGIBLE_TYPES:
                continue
            details = wf.get('details') or {}
            # Default-section heuristic. Agentic is Velociraptor
            # endpoint forensics, so it lands in the Endpoints section.
            default_section = {
                'agentic': 'Endpoints',
                'aws_scan': 'AWS',
                'azure_scan': 'Azure',
            }.get(atype, 'Other')
            out.append({
                'run_id': wf.get('run_id'),
                'name': wf.get('name'),
                'automation_type': atype,
                'updated_at': wf.get('updated_at'),
                'created_at': wf.get('created_at'),
                'blueprint': details.get('blueprint') or details.get('blueprint_id') or '',
                'client_count': details.get('client_count') or len(details.get('client_ids') or []) or None,
                'default_section': default_section,
            })
        out.sort(key=lambda r: r.get('updated_at') or '', reverse=True)
        return jsonify({'sources': out, 'total': len(out)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@engagement_bp.route('/api/engagement/generate', methods=['POST'])
def generate_engagement():
    """Start a new engagement report build. Returns immediately with
    the new workflow row's run_id; the actual build runs in a
    background thread (one LLM call for the synthesis layer)."""
    try:
        data = request.get_json() or {}
        name = (data.get('name') or '').strip() or 'Engagement Report'
        sources = data.get('sources') or []
        notes = data.get('notes') or ''

        # Operator-controlled engagement metadata. TLP defaults to AMBER
        # (sensitive but recipient may share within their org) — same
        # default the builder used to hardcode. Customer name + audience
        # + language tailor the LLM synthesis and PDF cover. Logo override
        # is stored as a base64 data URL so the PDF renderer can embed
        # it without needing host filesystem access.
        _ALLOWED_TLP = {'CLEAR', 'GREEN', 'AMBER', 'AMBER+STRICT', 'RED'}
        _ALLOWED_AUDIENCE = {'technical', 'executive', 'both'}
        _ALLOWED_LANGUAGE = {'en', 'he'}
        tlp = (data.get('tlp') or 'AMBER').upper().strip()
        if tlp not in _ALLOWED_TLP:
            return jsonify({'error': f"tlp must be one of {sorted(_ALLOWED_TLP)}"}), 400
        audience = (data.get('audience') or 'both').lower().strip()
        if audience not in _ALLOWED_AUDIENCE:
            return jsonify({'error': f"audience must be one of {sorted(_ALLOWED_AUDIENCE)}"}), 400
        language = (data.get('language') or 'en').lower().strip()
        if language not in _ALLOWED_LANGUAGE:
            return jsonify({'error': f"language must be one of {sorted(_ALLOWED_LANGUAGE)}"}), 400
        customer_name = (data.get('customer_name') or '').strip()[:120]
        customer_logo_b64 = data.get('customer_logo_b64') or ''
        # Defensive cap: 2 MiB of base64 → ~1.5 MiB raw image. Anything
        # larger is almost certainly a mistake.
        if customer_logo_b64 and len(customer_logo_b64) > 2_800_000:
            return jsonify({'error': 'customer_logo_b64 too large (>2 MiB)'}), 400

        if not isinstance(sources, list) or not sources:
            return jsonify({'error': 'sources must be a non-empty list'}), 400
        # Each source: {'run_id': str, 'section': str}
        cleaned = []
        for s in sources:
            if not isinstance(s, dict):
                continue
            rid = (s.get('run_id') or '').strip()
            if not rid:
                continue
            section = (s.get('section') or 'Other').strip() or 'Other'
            cleaned.append({'run_id': rid, 'section': section})
        if not cleaned:
            return jsonify({'error': 'no valid sources after parsing'}), 400

        # Create the workflow row up front so the operator sees it
        # immediately in the Workflows tab.
        run_id = create_automation_run(
            automation_type='engagement_report',
            name=name,
            details={
                'sources': cleaned,
                'notes': notes,
                'phase': 'starting',
                'tlp': tlp,
                'customer_name': customer_name,
                'audience': audience,
                'language': language,
                # Stash the logo override if provided. Stored as a data
                # URL (data:image/...;base64,...) so the PDF renderer
                # can drop it straight into an <img src>.
                'customer_logo_b64': customer_logo_b64,
            },
        )
        add_log_to_run(run_id, f"[Engagement] Build dispatched with {len(cleaned)} source(s)", "info")

        llm_config = _load_llm_config()

        def _worker():
            try:
                run_engagement_build(run_id, cleaned, notes, llm_config)
            except Exception as e:
                # run_engagement_build already handles its own errors;
                # this catches anything that crashed before it could.
                import traceback as _tb
                _tb.print_exc()
                add_log_to_run(run_id, f"[Engagement] Build worker crashed: {e}", "error")
                update_run_status(run_id, 'failed', error=str(e))

        threading.Thread(target=_worker, daemon=True).start()
        return jsonify({'run_id': run_id, 'status': 'started'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


def _load_engagement_markdown(run_id):
    """Shared loader used by both /download (markdown) and
    /download/pdf. Returns the engagement's markdown body, or None
    if no report has been generated yet."""
    raw = get_report(run_id)
    if not raw:
        return None
    try:
        parsed = _json.loads(raw)
        md = parsed.get('technical') if isinstance(parsed, dict) else None
        return md or raw
    except (ValueError, TypeError):
        return raw


@engagement_bp.route('/api/engagement/<run_id>/download', methods=['GET'])
def download_engagement(run_id):
    """Serve the assembled markdown — the internal-facing deliverable
    (raw, copy-pasteable into wikis, source-of-truth for the PDF)."""
    try:
        md = _load_engagement_markdown(run_id)
        if md is None:
            return jsonify({'error': 'Engagement report not found or not yet generated'}), 404
        return Response(
            md,
            mimetype='text/markdown',
            headers={'Content-Disposition': f'attachment; filename="engagement_{run_id}.md"'},
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@engagement_bp.route('/api/engagement/<run_id>/download/pdf', methods=['GET'])
def download_engagement_pdf(run_id):
    """Render and serve the customer-facing PDF.

    The markdown is the source of truth; this endpoint regenerates
    the PDF on every request rather than caching, so any chat-driven
    refinement of the underlying report flows straight through to
    the next download. Generation is sub-second for typical
    engagement sizes (~100-200 KB markdown → ~200-400 KB PDF)."""
    try:
        md = _load_engagement_markdown(run_id)
        if md is None:
            return jsonify({'error': 'Engagement report not found or not yet generated'}), 404
        # Pull the operator-supplied logo (data URL) if one was provided
        # at dispatch. Falls through to the embedded Tenroot brand when
        # absent.
        from services.file_storage_service import get_workflow as _get_wf
        _wf = _get_wf(run_id) or {}
        logo_b64 = (_wf.get('details') or {}).get('customer_logo_b64') or ''
        from services.engagement.pdf import render_engagement_pdf
        pdf_bytes = render_engagement_pdf(md, run_id, logo_b64=logo_b64)
        return Response(
            pdf_bytes,
            mimetype='application/pdf',
            headers={
                'Content-Disposition': f'attachment; filename="engagement_{run_id}.pdf"',
                'Content-Length': str(len(pdf_bytes)),
            },
        )
    except Exception as e:
        import traceback as _tb
        _tb.print_exc()
        return jsonify({'error': f'PDF generation failed: {e}'}), 500


# ---------------------------------------------------------------------------
# Interactive chat — same shape as /api/{agentic,aws,azure}/run/<id>/chat
# ---------------------------------------------------------------------------


@engagement_bp.route('/api/engagement/run/<run_id>/chat', methods=['GET'])
def get_engagement_chat(run_id):
    try:
        run = get_automation_run(run_id)
        if not run:
            return jsonify({'error': 'Run not found'}), 404
        return jsonify(interactive_chat.get_chat_state(run_id))
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@engagement_bp.route('/api/engagement/run/<run_id>/chat', methods=['POST'])
def post_engagement_chat(run_id):
    try:
        run = get_automation_run(run_id)
        if not run:
            return jsonify({'error': 'Run not found'}), 404
        data = request.get_json() or {}
        try:
            reply = interactive_chat.send_chat_message(run_id, data.get('message', ''), _load_llm_config())
        except ValueError as ve:
            return jsonify({'error': str(ve)}), 400
        except RuntimeError as re_:
            return jsonify({'error': str(re_)}), 502
        return jsonify({'assistant': reply})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@engagement_bp.route('/api/engagement/run/<run_id>/chat', methods=['DELETE'])
def clear_engagement_chat(run_id):
    try:
        run = get_automation_run(run_id)
        if not run:
            return jsonify({'error': 'Run not found'}), 404
        interactive_chat.clear_chat(run_id)
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@engagement_bp.route('/api/engagement/run/<run_id>/rerun', methods=['POST'])
def rerun_engagement(run_id):
    """Re-run the engagement build with the chat-synthesised master
    prompt threaded into the synthesis LLM. Both scope options
    collapse for engagement (only one LLM call), but the toggle is
    accepted for symmetry with AWS/Azure."""
    try:
        run = get_automation_run(run_id)
        if not run:
            return jsonify({'error': 'Run not found'}), 404
        if run.get('automation_type') != 'engagement_report':
            return jsonify({'error': 'Re-run only supported for engagement_report runs'}), 400
        if run.get('status') == 'running':
            return jsonify({'error': 'Run is already in progress'}), 409

        data = request.get_json() or {}
        scope = (data.get('scope') or 'reports_only').strip()
        if scope not in ('reports_only', 'full'):
            return jsonify({'error': "scope must be 'reports_only' or 'full'"}), 400

        details = run.get('details') or {}
        if not (details.get('chat_messages') or []):
            return jsonify({
                'error': 'No chat history — send at least one message '
                         'describing what to correct or investigate.'
            }), 400

        llm_config = _load_llm_config()
        add_log_to_run(run_id, f"[Pipeline] Interactive re-run (scope={scope}) starting", "info")
        update_run_status(run_id, 'running', progress=5)

        def _worker():
            try:
                add_log_to_run(run_id, "[Interactive] Synthesising master prompt from chat…", "info")
                mp = interactive_chat.synthesize_master_prompt(run_id, llm_config)
                mp = (mp or '').strip()
                if not mp:
                    raise RuntimeError("synthesised master prompt was empty — add more detail to the chat")
                run_engagement_reanalyze(run_id, mp, llm_config, scope=scope)
                update_run_status(run_id, 'completed', progress=100, force=True)
                add_log_to_run(run_id, f"[Pipeline] Engagement re-run ({scope}) complete", "success")
            except Exception as e:
                import traceback as _tb
                _tb.print_exc()
                add_log_to_run(run_id, f"[Pipeline] Engagement re-run failed: {e}", "error")
                update_run_status(run_id, 'failed', error=str(e))

        threading.Thread(target=_worker, daemon=True).start()
        return jsonify({'run_id': run_id, 'scope': scope, 'status': 'started'})

    except Exception as e:
        return jsonify({'error': str(e)}), 500
