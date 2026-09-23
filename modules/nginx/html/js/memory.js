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
        // Keep the .raw after the run so a re-run costs nothing. Off by
        // default — on is a standing ~9 GB/host disk cost, and TabReset puts
        // it back to off on tab re-entry, which is the behaviour we want.
        keepDump: false,
        // Images already on the shared dumps volume — any case's, since the
        // volume is not per-case. Loaded on tab entry and on Refresh.
        dumps: [],
        dumpsLoading: false,
        selectedDump: '',
        reuseStatus: '',
        // Pull another case's memory findings in by workflow id.
        adoptId: '',
        adoptStatus: '',
        adoptFailed: false,
        adopting: false,
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
        uploading: false,            // double-submit guard only — there is no
                                     // upload UI on this page by design: the
                                     // run row owns progress, logs and the
                                     // outcome, and a second progress bar on a
                                     // tab nobody is watching only disagrees
                                     // with the first one.

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
            await Promise.all([this.refreshClients(), this.refreshBlueprints(), this.loadDumps()]);
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
        // Dumps already on the appliance
        // --------------------------------------------------------------
        async loadDumps() {
            this.dumpsLoading = true;
            try {
                const r = await fetch('/api/memory/dumps');
                const j = await r.json();
                this.dumps = (j && j.dumps) || [];
                // A dump can be purged between loads — don't leave a stale
                // selection pointing at a file that is gone.
                if (!this.dumps.some(d => d.path === this.selectedDump)) this.selectedDump = '';
            } catch (_) {
                this.dumps = [];
            } finally {
                this.dumpsLoading = false;
            }
        },

        dumpLabel(d) {
            const gb = (d.size_bytes / (1024 * 1024 * 1024));
            const size = gb >= 1 ? gb.toFixed(1) + ' GB'
                                 : Math.round(d.size_bytes / (1024 * 1024)) + ' MB';
            const when = d.mtime ? new Date(d.mtime * 1000).toLocaleString() : '';
            const o = d.origin;
            const from = o ? `from ${o.client_name || o.run_id}` : 'origin unknown';
            return [size, when, from].filter(Boolean).join(' · ');
        },

        async startReuse() {
            if (!this.selectedDump) { this.reuseStatus = 'pick an image first'; return; }
            this.dispatching = true;
            this.reuseStatus = '';
            try {
                const r = await fetch('/api/memory/run', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        dump_path: this.selectedDump,
                        blueprint_id: this.blueprintId || undefined,
                        mode: this.derivedMode(),
                        case_name: this.caseName || ('Volatile Memory ' + new Date().toISOString().split('T')[0]),
                    }),
                });
                const j = await r.json();
                if (!r.ok || !j.run_id) {
                    this.reuseStatus = j.error || `HTTP ${r.status}`;
                    return;
                }
                this.reuseStatus = `started: ${j.run_id}`;
                if (Alpine.store('workflows')?.refresh) Alpine.store('workflows').refresh();
                if (Alpine.store('app')?.switchTab) Alpine.store('app').switchTab('workflows');
            } catch (e) {
                this.reuseStatus = String(e);
            } finally {
                this.dispatching = false;
            }
        },

        // --------------------------------------------------------------
        // Pull another case's findings
        // --------------------------------------------------------------
        async adoptRun() {
            const ident = (this.adoptId || '').trim();
            if (!ident) { this.adoptFailed = true; this.adoptStatus = 'paste a workflow id first'; return; }
            this.adopting = true;
            this.adoptFailed = false;
            this.adoptStatus = '';
            try {
                const r = await fetch('/api/memory/adopt', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ run_id: ident }),
                });
                const j = await r.json();
                if (!r.ok || !j.run_id) {
                    this.adoptFailed = true;
                    this.adoptStatus = j.error || `HTTP ${r.status}`;
                    return;
                }
                this.adoptStatus = `pulled ${j.plugin_rows} plugin rows and ${j.yara_hits} YARA hits. Opening Workflows…`;
                this.adoptId = '';
                if (Alpine.store('workflows')?.refresh) Alpine.store('workflows').refresh();
                setTimeout(() => {
                    if (Alpine.store('app')?.switchTab) Alpine.store('app').switchTab('workflows');
                }, 1200);
            } catch (e) {
                this.adoptFailed = true;
                this.adoptStatus = String(e);
            } finally {
                this.adopting = false;
            }
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
                    keep_dump: !!this.keepDump,
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
        },

        uploadSizeLabel() {
            if (!this.uploadFile) return '';
            const b = this.uploadFile.size || 0;
            if (b >= 1024**3) return (b / 1024**3).toFixed(1) + ' GB';
            if (b >= 1024**2) return (b / 1024**2).toFixed(0) + ' MB';
            if (b >= 1024)    return (b / 1024).toFixed(0) + ' KB';
            return b + ' B';
        },

        /** Resumable upload, the same way Velociraptor imports a collector ZIP.
         *
         *  It used to be one giant XHR POST to /api/memory/upload, which nginx
         *  refuses above client_max_body_size (500M) with an HTML 413 page --
         *  so a 1.5 GB image died as "parse error: Unexpected token '<'", with
         *  no workflow row, no log line and nothing to retry, because the
         *  request never reached Flask at all.
         *
         *  tus chunks the file, survives a dropped connection or a page
         *  refresh, and the tusd hook opens the workflow row before the first
         *  byte lands -- so the upload itself is logged, has progress, and any
         *  failure is on the run where the operator is already looking. */
        startUpload() {
            if (!this.uploadFile) return;                 // the button is disabled anyway
            if (typeof tus === 'undefined' || typeof TusUploader === 'undefined') {
                alert('Upload component not loaded — reload the page.');
                return;
            }
            this.uploading = true;

            const uploader = new TusUploader({
                purpose: 'memory',
                // Everything the pipeline needs, decided HERE while the
                // operator's choices are on screen. The hook reads them back at
                // post-finish; nothing has to be remembered in the browser.
                metadata: {
                    mode: this.derivedMode(),
                    blueprint_id: this.blueprintId || '',
                    case_name: this.caseName || ('Volatile Memory ' + new Date().toISOString().split('T')[0]),
                    keep_dump: this.keepDump ? '1' : '0',
                },
                // No progress UI here on purpose: we hand off to Workflows
                // immediately (below), and the tusd post-receive hook writes
                // "Uploading: N%" onto the run itself. Two progress bars for
                // one upload, one of them on a tab nobody is looking at, is
                // how they end up disagreeing.
                onProgress: () => {},
                onSuccess: () => {
                    this.uploading = false;
                    if (Alpine.store('workflows')?.refresh) Alpine.store('workflows').refresh();
                },
                onError: (error) => {
                    // The operator is on the Workflows tab by now — an alert is
                    // the only thing that reaches them there. Same as the
                    // Velociraptor import.
                    this.uploading = false;
                    alert(`Memory upload failed: ${(error && error.message) || error}`);
                },
            });
            uploader.upload(this.uploadFile);

            // Follow the work, like the Velociraptor import does. The upload
            // keeps running after the tab switch — the run row is created by
            // the tusd hook before the first chunk lands, and carries the
            // progress, the log and the terminal state.
            this.uploadFile = null;
            if (Alpine.store('workflows')?.refresh) Alpine.store('workflows').refresh();
            if (Alpine.store('app')?.switchTab) Alpine.store('app').switchTab('workflows');
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
    // `dumps` is a cache like `blueprints` — wiping it would blank the picker
    // on every tab switch. `selectedDump`/`reuseStatus` ARE operator input and
    // reset as normal.
    TabReset.arm(Alpine.store('memory'), 'modules-memory',
                 { keep: ['blueprints', 'blueprintsLoadedAt', '_pollTimer',
                          'dispatching', 'dumps'] });

    // Re-scan on entry so an image a run has just kept is listed without the
    // operator having to press Refresh.
    window.addEventListener('automation-tab-entered', (ev) => {
        if (ev.detail === 'modules-memory') Alpine.store('memory').loadDumps();
    });
});
