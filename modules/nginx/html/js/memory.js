/* Memory Forensics — Alpine store
 *
 * Memory is a collector now: it acquires + extracts (Volatility 3 + YARA)
 * and persists findings for the case to analyze. No per-run LLM/report/chat.
 *
 * Wires the Memory tab to:
 *   POST /api/memory/run                — dispatch (acquire + extract; collect-only)
 *   GET  /api/memory/run/<id>/status    — poll until terminal
 *   POST /api/memory/run/<id>/stop      — cancel
 *   POST /api/memory/upload             — operator-supplied dump (ingest)
 *   GET  /api/memory/blueprints         — populate blueprint dropdown
 *   GET  /api/clients                   — populate client picker
 *
 * Reuses the existing $store.workflows.viewLogs() modal so we don't
 * duplicate the per-run log viewer + auto-scroll behaviour the
 * Workflows tab already gets right.
 */

// Shared faceted client picker (single-select). Kept OUTSIDE the Alpine store
// so its internal Set/state isn't wrapped in Alpine's reactive proxy. Its
// onChange mirrors the chosen client into $store.memory.selectedClient.
let memoryClientManager = null;

document.addEventListener('alpine:init', () => {
    Alpine.store('memory', {
        // --------------------------------------------------------------
        // Inputs
        // --------------------------------------------------------------
        // Blueprint picker — operator chooses which plugin set to run.
        // Mode (layered/yara/plugin) is derived from this + includeYara
        // at submit time, so the backend keeps its current 3-way schema.
        // Blank = pipeline uses CURATED_PLUGINS fallback.
        blueprintId: 'memory_layered_default',
        includeYara: true,        // independent of blueprint — adds yarascan layer
        // Default case name: "Memory YYYY-MM-DD" so operators get a
        // sensible group out of the box without having to type one.
        caseName: 'Volatile Memory ' + new Date().toISOString().split('T')[0],
        selectedClient: '',
        // Advanced-timeouts disclosure (closed by default). Operators
        // bump these for very large dumps or slow hardware. Blank or
        // zero → use server-side default.
        timeoutsOpen: false,
        acquireTimeoutS: null,
        pluginTimeoutS: null,
        yarascanTimeoutS: null,

        // --------------------------------------------------------------
        // Caches
        // --------------------------------------------------------------
        blueprints: [],
        blueprintsLoadedAt: 0,

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
            // Build the shared picker once; mirror its single selection into
            // this.selectedClient so the Acquire button's :disabled binding and
            // startRun() keep working unchanged.
            if (!memoryClientManager) {
                memoryClientManager = new ClientManager('memory-client-list', 'memory-client-radio', {
                    singleSelect: true,
                    onChange: (ids) => { Alpine.store('memory').selectedClient = ids[0] || ''; },
                });
                window.memoryClientManager = memoryClientManager;
            }
            await Promise.all([this.refreshClients(), this.refreshBlueprints()]);
        },

        async refreshClients() {
            if (memoryClientManager) await memoryClientManager.load();
        },

        async refreshBlueprints() {
            try {
                const r = await fetch('/api/memory/blueprints');
                const j = await r.json();
                this.blueprints = j.items || j.blueprints || [];
                this.blueprintsLoadedAt = Date.now();
            } catch (_) { this.blueprints = []; }
        },

        // Look up the currently-selected blueprint object (so the UI
        // can display its description + plugin count next to the
        // dropdown without re-fetching).
        selectedBlueprint() {
            return this.blueprints.find(b => b.id === this.blueprintId) || null;
        },

        // Derive the backend `mode` field from (blueprint, includeYara).
        // The backend schema still uses the 3-way mode; we just compute
        // it here so the UI surfaces the cleaner blueprint + checkbox
        // model the operator actually thinks in.
        //
        //   empty plugin_set            → "yara"      (YARA-only triage)
        //   plugin_set + includeYara=t  → "layered"   (plugins + yara)
        //   plugin_set + includeYara=f  → "plugin"    (plugins only)
        derivedMode() {
            const bp = this.selectedBlueprint();
            const pluginSet = (bp && bp.settings && bp.settings.plugin_set) || [];
            if (pluginSet.length === 0) return 'yara';
            return this.includeYara ? 'layered' : 'plugin';
        },

        // --------------------------------------------------------------
        // Dispatch
        // --------------------------------------------------------------
        async startRun() {
            if (!this.selectedClient) { this.lastStatus = 'pick a client first'; return; }
            this.dispatching = true;
            this.lastStatus = '';
            try {
                const c = (memoryClientManager && memoryClientManager.getClient(this.selectedClient)) || {};
                const body = {
                    client_id: this.selectedClient,
                    client_name: c.hostname || null,
                    blueprint_id: this.blueprintId || undefined,
                    mode: this.derivedMode(),
                    case_name: this.caseName || ('Volatile Memory ' + new Date().toISOString().split('T')[0]),
                };
                // Only send timeouts the operator actually overrode —
                // sending nulls / zeros would defeat the server-side
                // "fall back to default" path.
                if (this.acquireTimeoutS && this.acquireTimeoutS > 0)
                    body.acquire_flow_timeout_s = this.acquireTimeoutS;
                if (this.pluginTimeoutS && this.pluginTimeoutS > 0)
                    body.plugin_timeout_s = this.pluginTimeoutS;
                if (this.yarascanTimeoutS && this.yarascanTimeoutS > 0)
                    body.yarascan_timeout_s = this.yarascanTimeoutS;

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
                // Run status lives on the Workflows page like every other
                // module — refresh it and navigate there on dispatch.
                if (Alpine.store('workflows') && typeof Alpine.store('workflows').refresh === 'function') {
                    Alpine.store('workflows').refresh();
                }
                if (Alpine.store('app')?.switchTab) {
                    Alpine.store('app').switchTab('workflows');
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
            // This XHR bypasses the window.fetch System->Default auto-recover, so
            // redirect off the System workspace up front (mirrors the tus-upload
            // guard). blockIfSystem now switches to Default and resolves false;
            // re-enter once it's settled so the XHR tags the right workspace.
            if (window.ActiveCase && window.ActiveCase.blockIfSystem && !this._wsRedirected) {
                this._wsRedirected = true;
                window.ActiveCase.blockIfSystem().then(() => this.startUpload());
                return;
            }
            this._wsRedirected = false;
            this.uploading = true;
            this.uploadStatus = '';
            this.uploadProgress = 0;

            const fd = new FormData();
            fd.append('file', this.uploadFile);
            if (this.blueprintId) fd.append('blueprint_id', this.blueprintId);
            fd.append('mode', this.derivedMode());
            fd.append('case_name', this.caseName || ('Volatile Memory ' + new Date().toISOString().split('T')[0]));
            // No client_name for now — the operator can rename the
            // workflow from the Workflows table if they care.

            const xhr = new XMLHttpRequest();
            xhr.open('POST', '/api/memory/upload', true);
            // Raw XHR bypasses the window.fetch X-Case-Id hook, so set the active
            // workspace header explicitly — otherwise the run lands in Default.
            try {
                const _cid = window.ActiveCase && window.ActiveCase.get && window.ActiveCase.get();
                if (_cid) xhr.setRequestHeader('X-Case-Id', _cid);
            } catch (_) {}
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
                        // Run status lives on the Workflows page — refresh
                        // it and navigate there on dispatch.
                        if (Alpine.store('workflows') && typeof Alpine.store('workflows').refresh === 'function') {
                            Alpine.store('workflows').refresh();
                        }
                        if (Alpine.store('app')?.switchTab) {
                            Alpine.store('app').switchTab('workflows');
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

    });

    // Returning to the tab restores the defaults captured here. Exempt:
    // blueprints/blueprintsLoadedAt are an expensive cache, not operator
    // input; _pollTimer is a live handle that must not be orphaned (nulling
    // it leaks the interval); dispatching is the double-submit guard and
    // clearing it mid-dispatch would let a second run through.
    TabReset.arm(Alpine.store('memory'), 'modules-memory',
                 { keep: ['blueprints', 'blueprintsLoadedAt', '_pollTimer',
                          'dispatching'] });
});
