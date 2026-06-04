/* Memory Forensics — Alpine store
 *
 * Wires the Memory tab to:
 *   POST /api/memory/run                — dispatch (acquire + extract + analyze)
 *   GET  /api/memory/run/<id>/status    — poll until terminal
 *   GET  /api/memory/run/<id>/download  — markdown report
 *   POST /api/memory/run/<id>/stop      — cancel
 *   GET  /api/memory/blueprints         — populate blueprint dropdown
 *   GET  /api/clients                   — populate client picker
 *
 * Reuses the existing $store.workflows.viewLogs() modal so we don't
 * duplicate the per-run log viewer + auto-scroll behaviour the
 * Workflows tab already gets right.
 *
 * Interactive validation: the "Validate (chat)" button reuses the
 * agentic chat modal — clicking it sets the chat modal's run_id
 * + module='memory' (so it POSTs /api/memory/run/<id>/chat instead
 * of /api/agentic/...). The chat modal itself is shared markup.
 */

document.addEventListener('alpine:init', () => {
    Alpine.store('memory', {
        // --------------------------------------------------------------
        // Inputs
        // --------------------------------------------------------------
        mode: 'layered',          // 'layered' | 'yara' | 'plugin' — layered is default
        useLlm: true,             // operator checkbox — uncheck to skip LLM synthesis
        // Default case name: "Memory YYYY-MM-DD" so operators get a
        // sensible group out of the box without having to type one.
        caseName: 'Memory ' + new Date().toISOString().split('T')[0],
        clientFilter: '',
        selectedClient: '',

        // --------------------------------------------------------------
        // Caches
        // --------------------------------------------------------------
        clients: [],
        clientsLoadedAt: 0,

        // --------------------------------------------------------------
        // In-flight run state
        // --------------------------------------------------------------
        currentRunId: '',
        currentStatus: '',
        currentProgress: 0,
        dispatching: false,
        lastStatus: '',
        _pollTimer: null,

        // --------------------------------------------------------------
        // Offline upload state
        // --------------------------------------------------------------
        uploadFile: null,            // File object selected via input
        uploading: false,
        uploadProgress: 0,           // 0-100, driven by XHR onprogress
        uploadStatus: '',            // operator-facing one-liner

        // --------------------------------------------------------------
        // Bootstrap
        // --------------------------------------------------------------
        async init() {
            await this.refreshClients();
        },

        async refreshClients() {
            try {
                const r = await fetch('/api/clients');
                const j = await r.json();
                this.clients = j.items || [];
                this.clientsLoadedAt = Date.now();
            } catch (_) { this.clients = []; }
        },

        // --------------------------------------------------------------
        // Client picker helpers
        // --------------------------------------------------------------
        filteredClients() {
            const q = (this.clientFilter || '').toLowerCase();
            const rows = !q
                ? this.clients
                : this.clients.filter(c =>
                    (c.hostname || '').toLowerCase().includes(q) ||
                    (c.client_id || '').toLowerCase().includes(q));
            // Surface freshest first — operators want the host they
            // just logged into at the top.
            return rows.slice().sort((a, b) => (b.last_seen_at || 0) - (a.last_seen_at || 0));
        },

        isFresh(c) {
            if (!c.last_seen_at) return false;
            // last_seen_at is microseconds-since-epoch (Velociraptor convention).
            const ageSec = (Date.now() - c.last_seen_at / 1000) / 1000;
            return ageSec < 300;
        },

        ageLabel(c) {
            if (!c.last_seen_at) return '—';
            const ageSec = Math.max(0, (Date.now() - c.last_seen_at / 1000) / 1000);
            if (ageSec < 60) return `${ageSec.toFixed(0)}s ago`;
            if (ageSec < 3600) return `${(ageSec / 60).toFixed(0)}m ago`;
            if (ageSec < 86400) return `${(ageSec / 3600).toFixed(0)}h ago`;
            return `${(ageSec / 86400).toFixed(0)}d ago`;
        },

        // --------------------------------------------------------------
        // Dispatch
        // --------------------------------------------------------------
        async startRun() {
            if (!this.selectedClient) { this.lastStatus = 'pick a client first'; return; }
            this.dispatching = true;
            this.lastStatus = '';
            try {
                const c = this.clients.find(x => x.client_id === this.selectedClient) || {};
                const body = {
                    client_id: this.selectedClient,
                    client_name: c.hostname || null,
                    mode: this.mode,
                    use_llm: !!this.useLlm,
                    case_name: this.caseName || ('Memory ' + new Date().toISOString().split('T')[0]),
                };

                const r = await fetch('/api/memory/run', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(body),
                });
                const j = await r.json();
                if (!r.ok || !j.run_id) {
                    this.lastStatus = j.error || `HTTP ${r.status}`;
                    return;
                }
                this.currentRunId = j.run_id;
                this.currentStatus = 'running';
                this.currentProgress = 1;
                this.lastStatus = `started: ${j.run_id}`;
                this._startPolling();
                // Refresh the workflows table so the new row appears there too.
                if (Alpine.store('workflows') && typeof Alpine.store('workflows').refresh === 'function') {
                    Alpine.store('workflows').refresh();
                }
            } catch (e) {
                this.lastStatus = String(e);
            } finally {
                this.dispatching = false;
            }
        },

        async stopRun() {
            if (!this.currentRunId) return;
            try {
                await fetch(`/api/memory/run/${this.currentRunId}/stop`, { method: 'POST' });
                this.lastStatus = 'stop requested';
            } catch (e) { this.lastStatus = String(e); }
        },

        // --------------------------------------------------------------
        // Offline upload — Velociraptor "Prepare Download" ZIP or raw image
        // --------------------------------------------------------------

        setUploadFile(f) {
            this.uploadFile = f || null;
            this.uploadStatus = '';
            this.uploadProgress = 0;
        },

        uploadSizeLabel() {
            if (!this.uploadFile) return '';
            const b = this.uploadFile.size || 0;
            if (b >= 1024**3) return (b / 1024**3).toFixed(1) + ' GB';
            if (b >= 1024**2) return (b / 1024**2).toFixed(0) + ' MB';
            if (b >= 1024)    return (b / 1024).toFixed(0) + ' KB';
            return b + ' B';
        },

        /** Multi-GB POST — use XHR (not fetch) so we get real progress
         *  events. fetch + ReadableStream upload progress isn't widely
         *  supported yet in Chromium's Alpine context. */
        startUpload() {
            if (!this.uploadFile) { this.uploadStatus = 'pick a file first'; return; }
            this.uploading = true;
            this.uploadStatus = '';
            this.uploadProgress = 0;

            const fd = new FormData();
            fd.append('file', this.uploadFile);
            fd.append('mode', this.mode);
            fd.append('use_llm', this.useLlm ? 'true' : 'false');
            fd.append('case_name', this.caseName || ('Memory ' + new Date().toISOString().split('T')[0]));
            // No client_name for now — the operator can rename the
            // workflow from the Workflows table if they care.

            const xhr = new XMLHttpRequest();
            xhr.open('POST', '/api/memory/upload', true);
            xhr.upload.addEventListener('progress', (e) => {
                if (e.lengthComputable) {
                    this.uploadProgress = Math.round((e.loaded / e.total) * 100);
                }
            });
            xhr.onreadystatechange = () => {
                if (xhr.readyState !== 4) return;
                this.uploading = false;
                try {
                    const j = JSON.parse(xhr.responseText || '{}');
                    if (xhr.status >= 200 && xhr.status < 300 && j.run_id) {
                        this.currentRunId = j.run_id;
                        this.currentStatus = 'running';
                        this.currentProgress = 1;
                        this.uploadStatus = `started: ${j.run_id}`;
                        // Reset file picker so a successful run is
                        // visually distinct from "still queued".
                        this.uploadFile = null;
                        this._startPolling();
                        if (Alpine.store('workflows') && typeof Alpine.store('workflows').refresh === 'function') {
                            Alpine.store('workflows').refresh();
                        }
                    } else {
                        this.uploadStatus = j.error || `HTTP ${xhr.status}`;
                    }
                } catch (e) {
                    this.uploadStatus = `parse error: ${e.message}`;
                }
            };
            xhr.onerror = () => {
                this.uploading = false;
                this.uploadStatus = 'network error';
            };
            xhr.send(fd);
        },

        // --------------------------------------------------------------
        // Polling
        // --------------------------------------------------------------
        _startPolling() {
            this._stopPolling();
            this._pollTimer = setInterval(() => this._poll(), 3000);
            this._poll();
        },

        _stopPolling() {
            if (this._pollTimer) { clearInterval(this._pollTimer); this._pollTimer = null; }
        },

        async _poll() {
            if (!this.currentRunId) return;
            try {
                const r = await fetch(`/api/memory/run/${this.currentRunId}/status`);
                const j = await r.json();
                this.currentStatus = j.status || '';
                this.currentProgress = j.progress || 0;
                if (['completed', 'failed', 'cancelled'].includes(this.currentStatus)) {
                    this._stopPolling();
                }
            } catch (_) { /* network blip — keep polling */ }
        },

        // --------------------------------------------------------------
        // Post-run actions
        // --------------------------------------------------------------
        downloadReport() {
            if (!this.currentRunId) return;
            window.location.href = `/api/memory/run/${this.currentRunId}/download`;
        },

        openChat() {
            if (!this.currentRunId) return;
            // Reuse the existing agentic chat modal — set its run_id +
            // module so it POSTs to the right endpoints. If the project
            // ever splits the chat modal per-module this is the seam.
            if (Alpine.store('agenticChat') && typeof Alpine.store('agenticChat').openForRun === 'function') {
                Alpine.store('agenticChat').openForRun(this.currentRunId, { module: 'memory' });
            } else {
                // Fallback: redirect to the workflows tab where chat
                // is accessible from the row's 3-dot menu.
                if (Alpine.store('app') && typeof Alpine.store('app').switchTab === 'function') {
                    Alpine.store('app').switchTab('workflows');
                }
            }
        },
    });
});
