// Interactive chat: operator validates the report findings with the
// customer's IT team, telling the assistant which findings are false
// positives, what to look at more closely, and the environment context.
// The chat itself IS the refinement loop — the LLM asks clarifying
// questions to sharpen the operator's input. On re-run, the backend
// silently compresses the conversation into a master prompt and folds
// it into every LLM call in the pipeline.
//
// Works for four workflow types:
//   - agentic           → /api/agentic/run/<run_id>/{chat,rerun}
//   - aws_scan          → /api/aws/run/<run_id>/{chat,rerun}
//   - azure_scan        → /api/azure/run/<run_id>/{chat,rerun}
//   - engagement_report → /api/engagement/run/<run_id>/{chat,rerun}
// The store keeps the same shape; only the URL prefix changes.

document.addEventListener('alpine:init', () => {
    Alpine.store('agenticChat', {
        isOpen: false,
        runId: null,
        // automation_type → URL prefix mapping. 'agentic' keeps the
        // existing /api/agentic/... endpoints; aws/azure use their
        // own routes. Set by open(runId, automationType).
        automationType: 'agentic',
        messages: [],
        draft: '',
        scope: 'reports_only',
        // Which client(s) the re-run should regenerate reports for.
        // 'all' = every client in the run. Otherwise a client_id string
        // (single-client target). For single-client runs the UI hides
        // the selector entirely — there's nothing to choose.
        target: 'all',
        // Pulled from /chat on open: [{client_id, hostname}, ...]
        clients: [],
        // False on runs that completed before the interactive-mode
        // caching landed (no artifact_summaries.json sidecar). The UI
        // disables the radio and force-selects 'full' so the operator
        // can't click into a guaranteed-to-fail scope.
        reportsOnlyAvailable: true,
        // False on runs whose original Velociraptor flow IDs weren't
        // stashed in details (e.g. anything that finished before that
        // persistence code landed). UI disables the radio.
        fullAnalysisAvailable: true,
        sending: false,
        rerunning: false,
        // `status` is {text, level} so we can colour the banner by
        // severity. level ∈ 'info' | 'success' | 'error'. Cleared by
        // dismissStatus() or overwritten by the next action.
        status: null,

        _setStatus(text, level = 'info') {
            this.status = text ? { text, level } : null;
        },
        dismissStatus() { this.status = null; },

        // Backend route prefix derived from automation_type. agentic →
        // /api/agentic/run/<id>, aws_scan → /api/aws/run/<id>,
        // azure_scan → /api/azure/run/<id>. Trailing path (chat / rerun)
        // is the same shape on all three.
        _urlBase() {
            switch (this.automationType) {
                case 'aws_scan':          return `/api/aws/run/${this.runId}`;
                case 'azure_scan':        return `/api/azure/run/${this.runId}`;
                case 'engagement_report': return `/api/engagement/run/${this.runId}`;
                case 'agentic':
                default:                  return `/api/agentic/run/${this.runId}`;
            }
        },

        async open(runId, automationType = 'agentic') {
            this.runId = runId;
            this.automationType = automationType || 'agentic';
            this.isOpen = true;
            this.messages = [];
            this.clients = [];
            this.target = 'all';
            this.draft = '';
            this.status = null;
            await this.loadState();
        },

        close() {
            this.isOpen = false;
            this.runId = null;
        },

        async loadState() {
            if (!this.runId) return;
            try {
                const r = await fetch(`${this._urlBase()}/chat`);
                if (!r.ok) throw new Error(`HTTP ${r.status}`);
                const data = await r.json();
                this.messages = data.messages || [];
                this.clients = data.clients || [];
                this.reportsOnlyAvailable = data.reports_only_available !== false;
                this.fullAnalysisAvailable = data.full_analysis_available !== false;
                // Force-select a viable scope when the current selection
                // can't run on this workflow, otherwise the operator
                // opens the modal with a disabled radio still "selected"
                // and clicking Re-run would fail immediately.
                if (!this.reportsOnlyAvailable && this.scope === 'reports_only' && this.fullAnalysisAvailable) {
                    this.scope = 'full';
                } else if (!this.fullAnalysisAvailable && this.scope === 'full' && this.reportsOnlyAvailable) {
                    this.scope = 'reports_only';
                }
                this._scrollToBottom();
            } catch (e) {
                console.error('[agentic-chat] loadState failed', e);
                this._setStatus(`Failed to load chat: ${e.message}`, 'error');
            }
        },

        get isMultiClient() { return (this.clients || []).length > 1; },

        // Strip the markdown formatting characters the LLM still likes to
        // emit (**bold**, ## headings, leading "- " bullets, code fences)
        // so each message reads as plain prose. We don't render markdown
        // to HTML — that would pull in a dependency + open an XSS hole —
        // we just drop the syntax.
        clean(text) {
            if (!text) return '';
            let s = String(text);
            s = s.replace(/```[\s\S]*?```/g, m => m.replace(/```/g, ''));
            s = s.replace(/`([^`]+)`/g, '$1');
            s = s.replace(/\*\*([^*]+)\*\*/g, '$1');
            s = s.replace(/(^|\s)\*([^*\n]+)\*/g, '$1$2');
            s = s.replace(/^#{1,6}\s+/gm, '');
            s = s.replace(/^\s*[-*]\s+/gm, '');
            s = s.replace(/^\s*\d+\.\s+/gm, '');
            s = s.replace(/\n{3,}/g, '\n\n');
            return s.trim();
        },

        async clear() {
            if (!this.runId) return;
            if (!confirm('Clear this chat? The conversation will be deleted.')) return;
            try {
                const r = await fetch(`${this._urlBase()}/chat`, { method: 'DELETE' });
                if (!r.ok) throw new Error(`HTTP ${r.status}`);
                this.messages = [];
                this._setStatus('Chat cleared.', 'info');
            } catch (e) {
                console.error('[agentic-chat] clear failed', e);
                this._setStatus(`Clear failed: ${e.message}`, 'error');
            }
        },

        async send() {
            const text = (this.draft || '').trim();
            if (!text || this.sending || !this.runId) return;
            this.sending = true;
            this.dismissStatus();
            // Optimistic append so the operator sees their own turn
            // immediately. Roll back on failure so they can edit + retry.
            this.messages.push({ role: 'user', content: text, ts: Math.floor(Date.now() / 1000) });
            this.draft = '';
            this._scrollToBottom();
            try {
                const r = await fetch(`${this._urlBase()}/chat`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ message: text }),
                });
                const data = await r.json();
                if (!r.ok) throw new Error(data.error || `HTTP ${r.status}`);
                this.messages.push({ role: 'assistant', content: data.assistant, ts: Math.floor(Date.now() / 1000) });
                this._scrollToBottom();
            } catch (e) {
                console.error('[agentic-chat] send failed', e);
                this._setStatus(`Send failed: ${e.message}`, 'error');
                this.messages.pop();
                this.draft = text;
            } finally {
                this.sending = false;
            }
        },

        async rerun() {
            if (!this.runId || this.rerunning) return;
            if (!this.messages.length) {
                this._setStatus('Send at least one chat message describing what to change.', 'error');
                return;
            }
            this.rerunning = true;
            this._setStatus(`Re-run starting…`, 'info');
            try {
                const body = { scope: this.scope };
                // Only send client_ids when the operator narrowed the
                // scope. 'all' means: regenerate every client report —
                // the backend defaults to that when client_ids is absent.
                if (this.isMultiClient && this.target && this.target !== 'all') {
                    body.client_ids = [this.target];
                }
                const r = await fetch(`${this._urlBase()}/rerun`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(body),
                });
                const data = await r.json();
                if (!r.ok) throw new Error(data.error || `HTTP ${r.status}`);
                // Re-run is now dispatched in a background thread on the
                // backend (for BOTH scopes). Close the modal so the
                // operator's eye goes back to the Workflows tab where
                // the row is already polling at 1 Hz and will paint a
                // progress arc like a normal pipeline run.
                if (Alpine.store('workflows')?.load) Alpine.store('workflows').load();
                this.close();
            } catch (e) {
                console.error('[agentic-chat] rerun failed', e);
                // On error, KEEP the modal open so the operator sees
                // the red banner with the reason (the most common case
                // is a 400 from the scope-validation pre-flight).
                this._setStatus(`Re-run failed: ${e.message}`, 'error');
            } finally {
                this.rerunning = false;
            }
        },

        _scrollToBottom() {
            setTimeout(() => {
                const el = document.getElementById('agentic-chat-scroll');
                if (el) el.scrollTop = el.scrollHeight;
            }, 50);
        },
    });
});
