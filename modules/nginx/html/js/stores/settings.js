// Settings store (config + maintenance + upgrade) — registered on Alpine init.
document.addEventListener('alpine:init', () => {
    // Settings store
    Alpine.store('settings', {
        config: {
            agentic: {
                // Must match DEFAULT_CONFIG in routes/config_routes.py. These
                // two disagreed on llm_mode and on the online provider/model,
                // so before a saved config existed the page showed Offline
                // while the backend would have run Online against OpenRouter —
                // the screen described a setup that was not the one in force.
                llm_mode: 'online',
                offline_llm: { provider: 'ollama', model: 'llama3.3:70b', url: 'http://localhost:11434' },
                online_llm: { provider: 'openrouter', api_key: '', model: '~anthropic/claude-haiku-latest' },
                ollama_context_size: 65536,
                ollama_timeout: 600
            },
            timesketch: {
                llm_mode: 'google',
                google_ai_key: '',
                google_ai_model: 'gemini-2.5-flash',
                ollama_url: 'http://localhost:11434',
                ollama_model: 'llama3.1:8b',
                // openrouter and litellm_proxy are contrib providers IntactAI
                // installs into the Timesketch container at start-up — see
                // modules/timesketch/llm_providers/README.md.
                openrouter_key: '',
                openrouter_model: 'anthropic/claude-3.5-sonnet',
                litellm_url: '',
                litellm_model: '',
                litellm_key: ''
            },
            cloud: {
                provider: 'aws',
                aws: {
                    access_key_id: '',
                    secret_access_key: '',
                    region: 'us-east-1',
                    session_token: ''
                },
                azure: {
                    tenant_id: '',
                    client_id: '',
                    client_secret: '',
                    subscription_id: ''
                }
            },
        },
        saving: false,
        // Offline model list, fetched live from whichever server the operator
        // points at. Not cached: a different URL is a different machine.
        offlineModels: [],
        offlineModelsLoading: false,
        offlineModelsError: '',
        llmTesting: false,
        llmTestResult: null,
        updatingCatalog: false,
        message: '',
        messageType: '',

        // Settings → Actions tab: system-operation run history (maintenance,
        // upgrades, package prepare/import, purge, support bundle, settings saves).
        // Served by GET /api/system/actions — System is no longer a workspace.
        actions: [],
        actionsLoading: false,

        async load() {
            try {
                // Load agentic config
                const agenticResponse = await fetch('/api/config');
                if (agenticResponse.ok) {
                    const data = await agenticResponse.json();
                    this.config.agentic = {
                        llm_mode: data.agentic?.llm_mode || 'online',
                        offline_llm: { ...this.config.agentic.offline_llm, ...data.agentic?.offline_llm },
                        online_llm: { ...this.config.agentic.online_llm, ...data.agentic?.online_llm },
                        ollama_context_size: data.agentic?.ollama_context_size || 65536,
                        ollama_timeout: data.agentic?.ollama_timeout || 600
                    };
                }

                // Load Timesketch LLM config from dedicated endpoint
                const tsResponse = await fetch('/api/timesketch/config/llm');
                if (tsResponse.ok) {
                    const tsData = await tsResponse.json();
                    this.config.timesketch = {
                        llm_mode: tsData.llm_mode || 'google',
                        google_ai_key: tsData.google_ai_key || '',
                        google_ai_model: tsData.google_ai_model || 'gemini-2.5-flash',
                        ollama_url: tsData.ollama_url || '',
                        ollama_model: tsData.ollama_model || '',
                        openrouter_key: tsData.openrouter_key || '',
                        openrouter_model: tsData.openrouter_model || 'anthropic/claude-3.5-sonnet',
                        litellm_url: tsData.litellm_url || '',
                        litellm_model: tsData.litellm_model || '',
                        litellm_key: tsData.litellm_key || ''
                    };
                }

                // Load Cloud config
                const cloudResponse = await fetch('/api/config/cloud');
                if (cloudResponse.ok) {
                    const cloudData = await cloudResponse.json();
                    this.config.cloud = {
                        provider: cloudData.provider || 'aws',
                        aws: { ...this.config.cloud.aws, ...cloudData.aws },
                        azure: { ...this.config.cloud.azure, ...cloudData.azure }
                    };
                }

                window.currentConfig = this.config;

                // If the saved provider is a subscription (CLI) one, begin the
                // detect poll straight away so the panel is accurate on first paint.
                if (this.isSubscription()) this.cliStartPolling();
            } catch (e) {
                console.error('Failed to load settings:', e);
            }
        },

        // Ask the configured self-hosted server which models it has.
        //
        // The list used to be four hardcoded names in the markup, so an
        // operator could pick a model their server had never pulled and only
        // find out mid-case, when the report failed with model-not-found.
        //
        // Errors are shown, not swallowed: "unreachable" and "server has no
        // models" need completely different fixes (check the URL vs pull a
        // model), so the reason from the backend is surfaced verbatim.
        async loadOfflineModels() {
            const off = this.config.agentic.offline_llm || {};
            const url = (off.url || '').trim();
            this.offlineModelsError = '';
            if (!url) { this.offlineModels = []; return; }
            this.offlineModelsLoading = true;
            try {
                const qs = new URLSearchParams({ url, kind: off.provider || 'ollama' });
                if (off.api_key) qs.set('api_key', off.api_key);
                const r = await fetch('/api/config/ollama/models?' + qs.toString());
                const d = await r.json();
                if (d && d.ok) {
                    this.offlineModels = d.models || [];
                    if (!this.offlineModels.length) {
                        this.offlineModelsError = 'That server has no models installed yet.';
                    }
                } else {
                    this.offlineModels = [];
                    this.offlineModelsError = (d && d.error) || 'Could not list models.';
                }
            } catch (e) {
                this.offlineModels = [];
                this.offlineModelsError = 'Could not reach the backend: ' + e.message;
            }
            this.offlineModelsLoading = false;
        },

        // Prove the LLM answers, before a report depends on it.
        //
        // Tests what is ON SCREEN rather than what is saved, so a key or URL
        // can be checked before committing it. A catalog refresh only ever
        // proved a key could LIST models — not that a completion works, that
        // the chosen model is one this key may use, or anything at all for a
        // self-hosted server.
        async testLlmConnection() {
            if (this.llmTesting) return;
            this.llmTesting = true;
            this.llmTestResult = null;
            try {
                const r = await fetch('/api/config/llm/test', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ agentic: this.config.agentic }),
                });
                this.llmTestResult = await r.json();
            } catch (e) {
                this.llmTestResult = { success: false, error: e.message };
            }
            this.llmTesting = false;
        },

        async saveAgentic() {
            this.saving = true;
            try {
                const response = await fetch('/api/config', {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ agentic: this.config.agentic })
                });
                if (response.ok) {
                    window.currentConfig = this.config;
                    this.showMessage('Agentic settings saved', 'success');
                    this._refreshCaseAnalysis();
                    // Fire-and-forget catalog refresh for the just-saved
                    // provider so the model dropdown picks up the full
                    // live list (Anthropic / OpenAI / Gemini /v1/models
                    // require an API key, which we just persisted). Then
                    // dispatch an event so the combobox re-queries.
                    const provider = this.config.agentic?.online_llm?.provider;
                    const providerToRoute = {
                        openrouter: 'refresh-openrouter-models',
                        claude:     'refresh-anthropic-models',
                        openai:     'refresh-openai-models',
                        gemini:     'refresh-gemini-models',
                        'codex-subscription': 'refresh-codex-models'
                    };
                    const route = providerToRoute[provider];
                    if (route) {
                        try {
                            await fetch('/api/maintenance/' + route, { method: 'POST' });
                        } catch (e) { /* best-effort */ }
                        window.dispatchEvent(new CustomEvent('llm-catalog-refreshed', { detail: { provider } }));
                    }
                } else {
                    this.showMessage('Failed to save Agentic config', 'error');
                }
            } catch (e) {
                this.showMessage('Error: ' + e.message, 'error');
            }
            this.saving = false;
        },

        // Refresh the selected provider's model catalog on demand.
        //
        // Same routes saveAgentic() fires, but reachable without re-saving —
        // catalogs otherwise only move when someone happens to save Agentic
        // settings, so a box configured once can serve months-old prices and
        // context windows. Nothing else in the UI updates them since System
        // Maintenance was removed.
        //
        // The backend never replaces a good catalog with an empty one (see
        // CatalogStore.write), so a failed update leaves the previous list in
        // place and says so, rather than emptying the model dropdown.
        // Refreshes EVERY provider's catalog, not only the selected one.
        //
        // Refreshing just the current provider looked reasonable and wasn't: the
        // reason to press this is usually that you are ABOUT to switch provider
        // and the new one's model list is stale or empty, which is exactly the
        // case where "refresh the current provider" does nothing useful. Each
        // provider is an independent catalog file, a failure on one must not stop
        // the others, and the ones with no credential simply return success=false
        // and are reported as skipped rather than as errors.
        async updateCatalog() {
            const providers = [
                ['OpenRouter', 'refresh-openrouter-models'],
                ['Anthropic',  'refresh-anthropic-models'],
                ['OpenAI',     'refresh-openai-models'],
                ['Gemini',     'refresh-gemini-models'],
                ['Codex',      'refresh-codex-models'],
            ];
            this.updatingCatalog = true;
            const ok = [], failed = [];
            // Sequential, not parallel: several of these hit the same upstream
            // account, and a burst is the fastest way to trip a rate limit on the
            // one action whose whole point is to succeed quietly.
            for (const [name, route] of providers) {
                try {
                    const r = await fetch('/api/maintenance/' + route, { method: 'POST' });
                    const d = await r.json().catch(() => ({}));
                    if (d && d.success) ok.push(name + ' ' + (d.model_count ?? '?'));
                    else failed.push(name);
                } catch (e) { failed.push(name); }
            }
            if (ok.length) {
                // The backend never replaces a good catalog with an empty one
                // (CatalogStore.write), so anything that failed still has whatever
                // it had before — say "skipped", not "lost".
                this.showMessage('Catalogs updated — ' + ok.join(', ')
                                 + (failed.length ? '  ·  skipped: ' + failed.join(', ')
                                                    + ' (no credential, or unreachable)' : ''),
                                 'success');
                window.dispatchEvent(new CustomEvent('llm-catalog-refreshed',
                    { detail: { provider: this.config.agentic?.online_llm?.provider } }));
                this._refreshCaseAnalysis();
            } else {
                this.showMessage('No catalog could be updated — previous lists kept. '
                                 + 'Check connectivity and provider credentials.', 'error');
            }
            this.updatingCatalog = false;
        },

        // Case Analysis runs in an IFRAME (cases.html?view=analysis), so it is a
        // separate document holding whatever it fetched when it loaded. Its cost
        // badge and "model max" default are priced from the CONFIGURED model, so
        // after the model changes here they describe the old one until something
        // reloads that frame — and nothing did. The operator saw Haiku pricing
        // while Sonnet was selected, with no indication it was stale.
        //
        // Reloaded only on an actual save, not on every tab switch: a reload
        // discards the frame's own state (open sub-tab, chat scroll position),
        // which is a poor trade for a value that only changes when settings do.
        // Same-origin, so this is a direct call rather than postMessage.
        _refreshCaseAnalysis() {
            try {
                const frame = document.getElementById('analysis-frame');
                if (frame && frame.contentWindow) frame.contentWindow.location.reload();
            } catch (e) { /* cross-origin or not loaded — nothing to refresh */ }
        },

        async saveTimesketch() {
            this.saving = true;
            try {
                const response = await fetch('/api/timesketch/config/llm', {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(this.config.timesketch)
                });
                if (response.ok) {
                    window.currentConfig = this.config;
                    this.showMessage('Timesketch settings saved - containers restarting...', 'success');
                    // Same fire-and-forget catalog refresh saveAgentic() does, so
                    // the model combobox on this tab works for an operator who has
                    // never opened Agentic. The OpenRouter catalog is shared and
                    // its /models endpoint needs no key, so this is safe to call
                    // whether or not one was just entered.
                    if (this.config.timesketch?.llm_mode === 'openrouter') {
                        try {
                            await fetch('/api/maintenance/refresh-openrouter-models', { method: 'POST' });
                        } catch (e) { /* best-effort */ }
                        window.dispatchEvent(new CustomEvent('llm-catalog-refreshed',
                            { detail: { provider: 'openrouter' } }));
                    }
                    setTimeout(() => {
                        window.ActiveCase.gotoSystemWorkflows();
                    }, 1000);
                } else {
                    this.showMessage('Failed to save Timesketch config', 'error');
                }
            } catch (e) {
                this.showMessage('Error: ' + e.message, 'error');
            }
            this.saving = false;
        },

        // Keep the cloud provider selector pointed at a module that exists.
        // A box with only Azure enabled still had 'aws' saved as the provider,
        // which rendered an AWS credential form for a module that isn't
        // installed — and saving it would persist credentials nothing reads.
        // Called from x-effect so it re-runs when service statuses land
        // (they arrive asynchronously, after this panel first renders).
        normalizeCloudProvider() {
            try {
                const svc = Alpine.store('services');
                const p = this.config.cloud.provider;
                if (p === 'aws' && !svc.has('aws_sigma') && svc.has('o365rc')) {
                    this.config.cloud.provider = 'azure';
                } else if (p === 'azure' && !svc.has('o365rc') && svc.has('aws_sigma')) {
                    this.config.cloud.provider = 'aws';
                }
            } catch (e) { /* services store not registered yet */ }
        },

        async saveCloud() {
            this.saving = true;
            try {
                const response = await fetch('/api/config/cloud', {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(this.config.cloud)
                });
                if (response.ok) {
                    window.currentConfig = this.config;
                    this.showMessage('Cloud settings saved', 'success');
                } else {
                    this.showMessage('Failed to save Cloud config', 'error');
                }
            } catch (e) {
                this.showMessage('Error: ' + e.message, 'error');
            }
            this.saving = false;
        },

        showMessage(msg, type) {
            this.message = msg;
            this.messageType = type;
            setTimeout(() => { this.message = ''; }, 3000);
        },

        // --- Settings → Actions (system-operation run history) ----------------
        actionsInitialLoad: true,
        async loadActions() {
            // Only show the loading spinner on the very first load — the 1s
            // auto-refresh poll otherwise flips actionsLoading true/false
            // every tick, which flashed the spinner and made the whole
            // panel look like it was "ticking"/jittering constantly.
            if (this.actionsInitialLoad) this.actionsLoading = true;
            try {
                const r = await fetch('/api/system/actions');
                const d = await r.json();
                const newActions = (d && d.actions) || [];
                // Same guard as $store.workflows.load(): only reassign (and
                // trigger a re-render) when the data actually changed, so a
                // no-op poll doesn't visibly redraw/jitter the whole table.
                if (this.actionsInitialLoad || JSON.stringify(this.actions) !== JSON.stringify(newActions)) {
                    this.actions = newActions;
                }
                this.actionsInitialLoad = false;
            } catch (e) {
                if (this.actionsInitialLoad) this.actions = [];
            } finally {
                this.actionsLoading = false;
            }
        },

        async generateSupportBundle() {
            this.saving = true;
            this.showMessage('Support bundle workflow starting...', 'info');
            try {
                const response = await fetch('/api/support-bundle/prepare', { method: 'POST' });
                const result = await response.json();
                if (response.ok && result.success) {
                    this.showMessage('Bundle generation started - redirecting to Workflows', 'success');
                    setTimeout(() => { window.ActiveCase.gotoSystemWorkflows(); }, 500);
                } else {
                    this.showMessage('Bundle start failed: ' + (result.error || 'Unknown error'), 'error');
                }
            } catch (e) {
                this.showMessage('Bundle start error: ' + e.message, 'error');
            } finally {
                this.saving = false;
            }
        },

        // ===== Section-aware purge =====
        // Two-step UX: (1) operator clicks "Purge…" → modal opens,
        // we GET /api/maintenance/purge/sections to populate per-section
        // sizes + counts. Operator ticks the sections they want gone.
        // (2) operator clicks "Purge selected" → POST with the chosen IDs.
        purgeModalOpen: false,
        purgeSections: [],
        purgeSelected: {},          // {section_id: bool}
        purgeScanning: false,
        purgeRunning: false,
        purgeError: '',

        /** Open the modal and scan sizes. */
        async openPurgeModal() {
            this.purgeModalOpen = true;
            this.purgeError = '';
            this.purgeSelected = {};
            await this.refreshPurgeSizes();
        },

        async refreshPurgeSizes() {
            this.purgeScanning = true;
            this.purgeError = '';
            try {
                const r = await fetch('/api/maintenance/purge/sections');
                const j = await r.json();
                if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`);
                this.purgeSections = j.sections || [];
                // Default-checked: nothing. Operator must pick explicitly.
                if (Object.keys(this.purgeSelected).length === 0) {
                    for (const s of this.purgeSections) this.purgeSelected[s.id] = false;
                }
            } catch (e) {
                this.purgeError = 'Scan failed: ' + e.message;
            } finally {
                this.purgeScanning = false;
            }
        },

        /** Sum of currently-checked sections — shown live in the footer. */
        purgeSelectedTotalBytes() {
            return (this.purgeSections || [])
                .filter(s => this.purgeSelected[s.id])
                .reduce((acc, s) => acc + (s.size_bytes || 0), 0);
        },

        _fmtBytes(b) {
            if (b >= 1024**3) return (b / 1024**3).toFixed(1) + ' GB';
            if (b >= 1024**2) return (b / 1024**2).toFixed(1) + ' MB';
            if (b >= 1024)    return (b / 1024).toFixed(1) + ' KB';
            return b + ' B';
        },

        purgeSelectedTotalLabel() {
            return this._fmtBytes(this.purgeSelectedTotalBytes());
        },

        /** Grand total of every section's size — shown in the modal
         *  header strip so the operator sees the "if I purge
         *  everything" number before they tick anything. */
        purgeGrandTotalLabel() {
            const total = (this.purgeSections || [])
                .reduce((acc, s) => acc + (s.size_bytes || 0), 0);
            return this._fmtBytes(total);
        },

        purgeSelectedCount() {
            return Object.values(this.purgeSelected).filter(Boolean).length;
        },

        purgeSelectAll(value) {
            // "Select all" never ticks sections the backend flags as
            // exclude_from_all (e.g. System Operation History — an audit trail
            // that must be removed deliberately, one tick at a time). "None"
            // (value=false) still clears everything.
            for (const s of this.purgeSections) {
                this.purgeSelected[s.id] = (value && s.exclude_from_all) ? false : !!value;
            }
        },

        async runPurgeSelected() {
            const ids = (this.purgeSections || [])
                .filter(s => this.purgeSelected[s.id])
                .map(s => s.id);
            if (!ids.length) {
                this.purgeError = 'Pick at least one section.';
                return;
            }
            const total = this.purgeSelectedTotalLabel();
            if (!confirm(`Purge ${ids.length} section(s) — frees ~${total}. This cannot be undone. Continue?`)) return;

            this.purgeRunning = true;
            this.purgeError = '';
            try {
                const r = await fetch('/api/maintenance/purge/sections', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ sections: ids }),
                });
                const j = await r.json();
                if (!r.ok || !j.run_id) throw new Error(j.error || `HTTP ${r.status}`);
                this.showMessage(`Purging ${ids.length} section(s) — redirecting to Workflows`, 'info');
                this.purgeModalOpen = false;
                setTimeout(() => { window.ActiveCase.gotoSystemWorkflows(); }, 500);
            } catch (e) {
                this.purgeError = 'Purge error: ' + e.message;
            } finally {
                this.purgeRunning = false;
            }
        },

        // Kept for backwards compat — old callsites (if any) still work.
        // The button itself now invokes `openPurgeModal`.
        async runPurge() { await this.openPurgeModal(); },

        // Fresh install flags (per module) - removes DB volumes for new schema
        dbOverwriteTimesketch: false,
        dbOverwriteIris: false,
        dbOverwriteElk: false,

        // Helper to get db_overwrite object
        getDbOverwrite() {
            return {
                timesketch: this.dbOverwriteTimesketch,
                iris: this.dbOverwriteIris,
                elk: this.dbOverwriteElk
            };
        },

        // ===== PREPARE UPGRADE PACKAGE =====
        showPreparePackageModal: false,
        prepareLoading: false,
        prepareRunId: null,
        preparePackageReady: false,
        preparePackageSize: '',
        // 'prepare' → POST /api/upgrade/prepare (offline flow, produces tar.gz)
        // 'online'  → POST /api/upgrade/online (combined prepare + apply)
        prepareModalMode: 'prepare',

        // ─── Apply Uploaded Package state ────────────────────────────
        // Lists pending tarballs from /api/upgrade/list-packages.
        // Clicking one opens a review modal that lets the operator
        // pick which modules from the manifest to actually apply.
        uploadedPackages: [],
        loadingPackages: false,
        showApplyPackageModal: false,
        applyPackage: null,         // {path, name, size_bytes, mtime, source}
        applyPackageFiles: [],      // all selected local assets (per-module import)
        applyManifest: null,        // result of /api/upgrade/package-info
        applySelectedModules: [],   // ticked module IDs (operator unchecks to skip)
        applyDbOverwrite: {},       // per-module fresh-install flags
        loadingApplyInfo: false,
        applying: false,
        // Map of module-name → current installed version, fetched in
        // parallel with the manifest when the apply modal opens. Drives
        // the "current → target [UPGRADE/NO CHANGE/INSTALL]" row
        // rendering and the same-version warning so the operator can
        // see at a glance whether the package would actually change
        // anything before clicking Apply (2026-06-15 incident: operator
        // re-applied an identical-versions package by mistake).
        applyCurrentVersions: {},

        async loadUploadedPackages() {
            this.loadingPackages = true;
            try {
                const r = await fetch('/api/upgrade/list-packages', {method: 'POST'});
                const d = await r.json();
                if (d && d.success) {
                    this.uploadedPackages = d.packages || [];
                } else {
                    this.showMessage('List packages failed: ' + (d.error || 'unknown'), 'error');
                }
            } catch (e) {
                this.showMessage('List packages request failed: ' + e.message, 'error');
            }
            this.loadingPackages = false;
        },

        async openApplyPackageModal(pkg) {
            this.applyPackage = pkg;
            this.applyManifest = null;
            this.applySelectedModules = [];
            this.applyDbOverwrite = {};
            this.applyCurrentVersions = {};
            this.showApplyPackageModal = true;
            this.loadingApplyInfo = true;
            try {
                // Fetch in parallel — manifest (what the package WILL
                // install) and current-versions (what's installed RIGHT
                // NOW). Both feed the side-by-side comparison rendered
                // in the modal. Current-versions is best-effort: on
                // failure we render rows with "?" as the current,
                // which is better than blocking the apply for a
                // cosmetic read.
                const [manifestRes, currentRes] = await Promise.all([
                    fetch('/api/upgrade/package-info', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({package_path: pkg.path}),
                    }),
                    fetch('/api/upgrade/current-versions', {method: 'GET'}),
                ]);
                const d = await manifestRes.json();
                if (d && (d.success || d.manifest)) {
                    this.applyManifest = d.manifest || d;
                } else {
                    this.showMessage('Manifest read failed: ' + (d.error || 'unknown'), 'error');
                }
                try {
                    const cur = await currentRes.json();
                    if (cur && cur.success) {
                        this.applyCurrentVersions = cur.versions || {};
                    }
                } catch (_) { /* current-versions is best-effort */ }
                // Now that BOTH the manifest and current-versions have
                // landed, seed the selection per the three rules:
                //   - upgrade / downgrade → forced (in selection, no opt-out)
                //   - install (module absent locally) → opt-in (NOT seeded)
                //   - no-change (already at target) → excluded (NOT seeded)
                // The HTML disables checkboxes for upgrade/no-change so
                // the operator can only toggle install rows.
                const versions = (this.applyManifest && this.applyManifest.versions) || {};
                this.applySelectedModules = [];
                for (const [name, target] of Object.entries(versions)) {
                    const action = this.applyModuleAction(name, target);
                    if (action === 'upgrade' || action === 'downgrade' || action === 'unknown') {
                        this.applySelectedModules.push(name);
                    }
                }
            } catch (e) {
                this.showMessage('Manifest request failed: ' + e.message, 'error');
            }
            this.loadingApplyInfo = false;
        },

        // Classify a packaged module against what's installed locally.
        // Returns one of: 'no-change' (same version), 'upgrade' (target
        // differs), 'install' (module not currently installed),
        // 'unknown' (current-versions probe failed). Drives both row
        // styling and the apply-button warning.
        applyModuleAction(module, target) {
            const cur = this.applyCurrentVersions[module];
            // A module the backend never reported at all is one it does not
            // know about — exactly what happens when a NEWER release's package
            // introduces a module this older backend has never heard of. That
            // is an INSTALL, not an unknown: it belongs in the opt-in section
            // (default unticked), not silently in the forced list showing "?".
            if (cur === undefined || cur === null) return 'install';
            if (!cur || cur === 'unknown') return 'unknown';
            if (cur === 'Not installed') return 'install';
            const curStr = String(cur).trim();
            const tgtStr = String(target).trim();
            if (curStr === tgtStr) return 'no-change';
            // Best-effort semver-ish ordering. Falls back to string
            // compare for non-numeric tags (timesketch's '20260326' vs
            // '20260611' compares correctly under both paths). Used
            // only for the UI chip label — backend doesn't gate.
            const tryNumeric = (s) => s.replace(/^v/, '').split(/[.\-]/).map(p => parseInt(p, 10));
            const a = tryNumeric(curStr), b = tryNumeric(tgtStr);
            if (a.every(n => !isNaN(n)) && b.every(n => !isNaN(n))) {
                for (let i = 0; i < Math.max(a.length, b.length); i++) {
                    const x = a[i] || 0, y = b[i] || 0;
                    if (x < y) return 'upgrade';
                    if (x > y) return 'downgrade';
                }
            }
            return curStr < tgtStr ? 'upgrade' : 'downgrade';
        },

        // Count of ticked modules that would actually do work. Used to
        // warn the operator when they're about to apply a package that
        // changes nothing (the 2026-06-15 same-version mishap).
        applyChangingCount() {
            const versions = (this.applyManifest?.versions) || {};
            let n = 0;
            for (const mod of this.applySelectedModules) {
                const action = this.applyModuleAction(mod, versions[mod]);
                if (action === 'upgrade' || action === 'install') n++;
            }
            return n;
        },

        closeApplyPackageModal() {
            this.showApplyPackageModal = false;
            this.applyPackage = null;
            this.applyPackageFiles = [];
            this.applyManifest = null;
        },

        toggleApplyModule(moduleId) {
            // Togglable: INSTALL (opt in to a module this host does not have)
            // and NO-CHANGE (opt in to a reinstall at the same version — the
            // row renders a checkbox titled "Reinstall this module..." and
            // relabels itself "reinstall" when ticked, so refusing the toggle
            // here made that control a decoration).
            //
            // NOT togglable: upgrade / downgrade / unknown. Those are forced,
            // matching the online-upgrade convention, and the markup gives
            // them a spacer instead of a checkbox — so this is belt-and-braces
            // for them, not the mechanism.
            //
            // Why the old `action !== 'install'` guard was worse than a dead
            // control: a click still flips the native checkbox in the DOM, but
            // returning early meant applySelectedModules never changed, so
            // Alpine had no reason to re-render and the tick STAYED on screen
            // while being absent from the selection. The next real mutation
            // (ticking an install row) re-evaluated every
            // :checked="...includes(name)" binding and those phantom ticks
            // vanished at once — which reads as "picking iris cleared my other
            // choices", when in truth they were never selected.
            const target = (this.applyManifest?.versions || {})[moduleId];
            const action = this.applyModuleAction(moduleId, target);
            if (action !== 'install' && action !== 'no-change') return;
            const idx = this.applySelectedModules.indexOf(moduleId);
            if (idx >= 0) {
                this.applySelectedModules.splice(idx, 1);
            } else {
                this.applySelectedModules.push(moduleId);
            }
        },

        async applyUploadedPackage() {
            if (!this.applyPackage) return;
            if (!this.applySelectedModules.length) {
                this.showMessage('Tick at least one module to apply', 'error');
                return;
            }
            this.applying = true;

            // Two code paths share this function:
            //  1. peek-flow — applyPackage.path is null because the
            //     local file hasn't been uploaded yet. Upload now via
            //     tus, then call /api/upgrade/offline with the
            //     resulting /data/uploads/<id> path.
            //  2. legacy-flow — applyPackage.path is already set
            //     (post-upload review). Skip straight to apply.
            let packagePath = this.applyPackage.path;
            if (!packagePath && this.applyPackage._localFile) {
                // Capture EVERYTHING from the Alpine state BEFORE
                // closing the modal — close() nulls applyPackage and
                // applyManifest, so any subsequent read on them throws
                // and the upload silently never starts. That's why the
                // operator saw "Apply" close the modal but no workflow
                // appeared.
                const file = this.applyPackage._localFile;
                const selected = this.applySelectedModules.slice();
                // Split the ticks the backend cannot re-derive: which of these
                // are already at the target version and are being re-applied
                // on purpose. Only this modal knows -- it is the same call
                // that renders the row as 'reinstall' rather than 'upgrade'.
                const reinstall = selected.filter(
                    (n) => this.applyModuleAction(n, (this.applyManifest?.versions || {})[n]) === 'no-change');
                const db_overwrite = Object.assign({}, this.applyDbOverwrite);
                console.log('[Import] Starting tus upload for', file.name,
                            '(', file.size, 'bytes), modules:', selected);
                // Create the workflow row NOW so it's visible the instant we
                // navigate to Workflows — instead of waiting for tusd's
                // post-create hook (which is why the operator "saw nothing" for
                // a while). The hook reuses this run_id (passed in metadata),
                // and as an upgrade_package_upload it lands in the SAME System
                // workspace as the apply — one row, one workspace.
                let uploadRunId = '';
                try {
                    const rr = await fetch('/api/upgrade/upload-run', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({filename: file.name, size_bytes: file.size}),
                    });
                    const rj = await rr.json();
                    if (rj && rj.success) uploadRunId = rj.run_id;
                } catch (_) { /* best-effort — hook still creates the run */ }
                this.showMessage('Uploading package… (progress shows in Workflows)', 'info');
                this.closeApplyPackageModal();
                window.ActiveCase.gotoSystemWorkflows();
                this.applying = false;
                // A release publishes one asset per module as well as a single
                // bundle, and an operator carrying assets into an air-gapped
                // site should be able to hand over the whole set rather than
                // reassembling it first. Upload each file under the SAME
                // upload_run_id so they land in one workflow, then apply them
                // together — the backend merges them into one package.
                const files = (this.applyPackageFiles && this.applyPackageFiles.length)
                    ? Array.from(this.applyPackageFiles) : [file];
                const uploadedPaths = [];
                let failed = false;

                const uploadOne = (f) => new Promise((resolve) => {
                    const up = new tus.Upload(f, {
                        endpoint: '/api/uploads/',
                        retryDelays: [0, 1000, 3000, 5000],
                        chunkSize: 32 * 1024 * 1024,  // see js/upload.js for why 32
                        // Clear the resume fingerprint once done so re-importing
                        // the same file later doesn't silently re-open /
                        // re-upload a stale entry (the "it uploaded again"
                        // artifact).
                        removeFingerprintOnSuccess: true,
                        metadata: {
                            filename: f.name,
                            filetype: f.type || 'application/gzip',
                            purpose: 'upgrade_package',
                            upload_run_id: uploadRunId,
                        },
                        onError: (error) => {
                            console.error('Upload error:', error);
                            this.showMessage('Upload failed (' + f.name + '): '
                                             + error.message, 'error');
                            failed = true;
                            resolve();
                        },
                        onSuccess: () => {
                            const parts = (up.url || '').split('/').filter(Boolean);
                            const id = parts.length ? parts[parts.length - 1] : null;
                            if (id) uploadedPaths.push('/data/uploads/' + id);
                            else failed = true;
                            resolve();
                        },
                    });
                    up.start();
                });

                (async () => {
                    // Sequential: N concurrent multi-GB uploads compete for the
                    // same uplink and make every one slower.
                    for (const f of files) {
                        await uploadOne(f);
                        if (failed) break;
                    }
                    if (failed || !uploadedPaths.length) {
                        if (!failed) this.showMessage('Upload succeeded but no ID returned', 'error');
                        return;
                    }
                    try {
                        const body = {
                            selected_modules: selected,
                            reinstall_modules: reinstall,
                            db_overwrite: db_overwrite,
                        };
                        // Tell the backend WHICH workflow row this apply
                        // belongs to. We created it ourselves above, so there
                        // is nothing to deduce — and deduction is what failed:
                        // the backend used to recover the row from a sidecar
                        // the upload hook writes, and this POST fires from the
                        // tus success path in the same second the hook runs, so
                        // it lost the race and opened a SECOND run while the
                        // upload row sat at 10% forever (2026-08-05). Sent only
                        // when we actually have one; the backend still falls
                        // back to its old inference for callers that don't.
                        if (uploadRunId) body.upload_run_id = uploadRunId;
                        // One file keeps the scalar shape every existing caller
                        // and every older backend understands.
                        if (uploadedPaths.length === 1) body.package_path = uploadedPaths[0];
                        else body.package_paths = uploadedPaths;
                        const r = await fetch('/api/upgrade/offline', {
                            method: 'POST',
                            headers: {'Content-Type': 'application/json'},
                            body: JSON.stringify(body),
                        });
                        const d = await r.json();
                        if (r.ok && d.success) {
                            this.showMessage('Apply started — see Workflows for progress', 'success');
                        } else {
                            this.showMessage('Apply failed: ' + (d.error || 'unknown'), 'error');
                        }
                    } catch (e) {
                        this.showMessage('Apply request failed: ' + e.message, 'error');
                    }
                })();
                return;
            }

            // Legacy-flow: tarball already on disk, just apply. No
            // upload_run_id goes with it — this path never uploaded anything,
            // so there is no upload row to continue. (A tarball uploaded in an
            // EARLIER session and picked from the list still has its .run
            // sidecar / details.upload_id, which the backend can find on its
            // own; sending a made-up id would be worse than sending none.)
            try {
                const r = await fetch('/api/upgrade/offline', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        package_path: packagePath,
                        selected_modules: this.applySelectedModules,
                        reinstall_modules: this.applySelectedModules.filter(
                            (n) => this.applyModuleAction(n, (this.applyManifest?.versions || {})[n]) === 'no-change'),
                        db_overwrite: this.applyDbOverwrite,
                    }),
                });
                const d = await r.json();
                if (r.ok && d.success) {
                    this.closeApplyPackageModal();
                    this.showMessage('Apply started — check Workflows for progress', 'success');
                    setTimeout(() => { window.ActiveCase.gotoSystemWorkflows(); }, 500);
                } else {
                    this.showMessage('Apply failed: ' + (d.error || 'unknown'), 'error');
                }
            } catch (e) {
                this.showMessage('Apply request failed: ' + e.message, 'error');
            }
            this.applying = false;
        },

        async openPreparePackageModal() {
            this.prepareModalMode = 'prepare';
            await this._openModuleModal();
        },

        async openOnlineUpgradeModal() {
            this.prepareModalMode = 'online';
            await this._openModuleModal();
        },

        // ─── Track-based upgrade flow state ──────────────────────────
        // The operator picks ONE Intact release, system derives the
        // per-module work list. See services/upgrade/resolver.py.
        upgradeRefs: [],            // populated by fetchUpgradeRefs()
        selectedRef: '',            // the ref the operator picked in the dropdown
        upgradePlan: null,          // ONLINE mode: forced/optional table from /api/upgrade/plan
        optedInOptional: [],        // ONLINE mode: module IDs the operator ticked in the optional table
        optedInReinstall: [],       // ONLINE mode: no-change module IDs ticked to FORCE a reinstall (bug recovery)
        fetchingRefs: false,
        computingPlan: false,
        showingPrepareModules: false,
        // Current installed Intact tag, fetched on modal open. Used
        // by the dropdown filter so older releases are NOT selectable
        // — prevents the operator from accidentally picking a
        // downgrade target. Unknown → no filter (permissive fallback).
        currentIntactVersion: '',
        // GitHub API rate-limit snapshot fetched on modal open. Drives
        // the in-modal banner — "X calls remaining, resets at HH:MM" —
        // and the warning when the quota is low enough that the next
        // workflow might 429.  Shape mirrors /api/upgrade/quota.
        githubQuota: null,
        // Persistent top-of-screen toast (separate from the bottom
        // ephemeral `message`). Used for errors that the operator MUST
        // see even when the upgrade modal is open and scrolled.
        topToast: { msg: '', type: 'info', show: false },
        _topToastTimer: null,

        // ─── Top-of-screen toast ─────────────────────────────────────
        // Fixed-position notification that floats over modals. Used
        // when the user MUST see an error even while the upgrade modal
        // is open and scrolled mid-list. Errors stay 8s; success 4s.
        showTopToast(msg, type = 'info') {
            if (this._topToastTimer) {
                clearTimeout(this._topToastTimer);
                this._topToastTimer = null;
            }
            this.topToast = { msg, type, show: true };
            const ms = type === 'error' ? 8000 : 4000;
            this._topToastTimer = setTimeout(() => {
                this.topToast = { ...this.topToast, show: false };
            }, ms);
        },

        // ─── Fetch with timeout ──────────────────────────────────────
        // Default 60 s — matches GitHub's worst-case response time on
        // a cold cache. The upgrade modal's three fetches (refs / plan
        // / prepare-list) all want this generous a budget; the
        // operator hit silent timeouts at the browser default
        // (~30 s) on slow upstream days.
        async _fetchWithTimeout(url, opts = {}, timeoutMs = 60000) {
            const controller = new AbortController();
            const timer = setTimeout(() => controller.abort(), timeoutMs);
            try {
                const r = await fetch(url, { ...opts, signal: controller.signal });
                // When the backend is down, nginx answers with an HTML error
                // page. Callers immediately do `await r.json()`, which throws
                // "Unexpected token '<', "<html>... is not valid JSON" — so a
                // backend outage is reported to the operator as malformed JSON.
                //
                // That is actively misleading. Observed 2026-08-03: every
                // /api/ call on the box was 502ing, and the Prepare Package
                // modal said "Fetch releases failed: Unexpected token '<'",
                // which reads like GitHub changed something and sent the
                // operator looking for a scraper that does not exist (we use
                // the REST API, not HTML).
                //
                // Label it here rather than at each call site: every caller
                // already funnels through this helper and surfaces e.message,
                // so one throw fixes the message everywhere at once.
                if (r.status === 502 || r.status === 503 || r.status === 504) {
                    throw new Error(
                        `the backend is not responding (HTTP ${r.status}). `
                        + 'This is a local problem, not a GitHub or network one — '
                        + 'check `docker ps` and `docker logs intact_backend`.');
                }
                return r;
            } finally {
                clearTimeout(timer);
            }
        },

        // ─── GitHub quota probe ──────────────────────────────────────
        // Hits the backend's cached rate_limit snapshot — no GitHub
        // round-trip. Stores the result on `githubQuota` so the modal
        // banner can render "X/Y remaining (resets HH:MM)" and the
        // auto-fetch chain can warn before spending the budget.
        // Fetch the running Intact version (VERSION file). Cheap
        // GET that doesn't touch GitHub. Drives the dropdown filter
        // so the operator can't pick an older release.
        async fetchCurrentIntactVersion() {
            try {
                const r = await this._fetchWithTimeout('/api/version', { method: 'GET' }, 5000);
                const d = await r.json();
                this.currentIntactVersion = (d && d.version) ? d.version : '';
            } catch (_) {
                this.currentIntactVersion = '';
            }
        },

        // Classify a ref relative to currentIntactVersion. Returns
        // 'newer' | 'same' | 'older' | 'rolling' | 'unknown'.
        //
        // Strategy: extract the YYYYMMDD date portion from
        // `intact-<date>[-suffix]` tag names and compare dates.
        // - same date + same name → 'same' (allow refresh)
        // - same date + different suffix (e.g. -old-modules) → 'older'
        //   (these are baseline / companion releases, not upgrade
        //   targets, so we hide them)
        // - different dates → numeric date compare
        // - `development` branch → always 'rolling' (allow)
        // - unparseable → 'unknown' (allow, permissive fallback)
        classifyUpgradeRef(ref) {
            if (!ref || !ref.name) return 'unknown';
            if (ref.kind === 'branch') return 'rolling';
            const cur = this.currentIntactVersion || '';
            const dateRx = /^intact-(\d{8})/;
            const curMatch = cur.match(dateRx);
            const refMatch = ref.name.match(dateRx);
            if (!curMatch || !refMatch) return 'unknown';
            const curDate = curMatch[1];
            const refDate = refMatch[1];
            if (refDate > curDate) return 'newer';
            if (refDate < curDate) return 'older';
            // Same date — only the EXACT same tag name counts as
            // "same release", not a companion variant.
            return ref.name === cur ? 'same' : 'older';
        },

        // Dropdown source: filter out 'older' refs so the operator
        // can't pick a downgrade target. Online mode applies the
        // filter; prepare mode keeps everything (the operator may
        // legitimately want to build a package for an older air-gap
        // host). `development` always survives the filter.
        // Is the installed version actually one of the published releases?
        //
        // Distinguishes the two reasons the online list can come back empty,
        // which the modal used to conflate into one (wrong) sentence:
        //   true  — level with the newest release, nothing published beyond it
        //   false — running something never published (a locally built tag, or
        //           a box ahead of GitHub), so there is nothing to move TO
        // Only the second case needs Import Package suggested instead.
        installedIsPublished() {
            const cur = this.currentIntactVersion || '';
            if (!cur) return true;   // unknown: keep the milder wording
            return this.upgradeRefs.some(r => r.name === cur);
        },

        // Newest published release by tag date, for context when the installed
        // version is not among them. Same date-from-the-tag rule the one-hop
        // filter uses, so the two can never disagree about ordering.
        newestPublishedRef() {
            const dateOf = (r) => {
                const m = (r.name || '').match(/(\d{8})/);
                return m ? m[1] : null;
            };
            const dated = this.upgradeRefs.filter(dateOf);
            if (!dated.length) return '';
            return dated.reduce((a, b) => (dateOf(a) >= dateOf(b) ? a : b)).name;
        },

        filteredUpgradeRefs() {
            if (this.prepareModalMode !== 'online') return this.upgradeRefs;
            // ONE HOP. An upgrade is only ever exercised a single release at a
            // time (N -> N+1), so offering N+3 invites a jump with no test
            // coverage behind it. "Next" is the NEAREST newer release, not the
            // newest -- ordered by the tag's own date (intact-YYYYMMDD sorts
            // correctly as a plain string), so it does not depend on GitHub's
            // ordering or on releases being published in date order.
            //
            // The CURRENT release stays on the list deliberately: re-applying
            // it is how an operator picks up a fix or adds a module they
            // skipped, which is not a downgrade.
            const dateOf = (r) => {
                const m = (r.name || '').match(/(\d{8})/);
                return m ? m[1] : null;
            };
            const same = this.upgradeRefs.filter(r => this.classifyUpgradeRef(r) === 'same');
            const newer = this.upgradeRefs
                .filter(r => this.classifyUpgradeRef(r) === 'newer' && dateOf(r))
                .sort((a, b) => dateOf(a).localeCompare(dateOf(b)));
            // Undated entries (e.g. the synthetic `development` ref) are not
            // part of the hop sequence; pass them through untouched.
            const undated = this.upgradeRefs.filter(
                r => !dateOf(r) && this.classifyUpgradeRef(r) !== 'older');
            return [...(newer.length ? [newer[0]] : []), ...same, ...undated];
        },

        async fetchGithubQuota() {
            try {
                const r = await this._fetchWithTimeout('/api/upgrade/quota', { method: 'GET' }, 10000);
                const d = await r.json();
                if (d && d.success) {
                    this.githubQuota = d;
                    return d;
                }
                this.githubQuota = null;
                return null;
            } catch (e) {
                this.githubQuota = null;
                return null;
            }
        },

        async fetchUpgradeRefs() {
            // Hits GitHub's releases endpoint (one anonymous call).
            // Backend caches for 30 min — auto-triggered on modal
            // open + reusable by the operator clicking the manual
            // refresh affordance. 60s timeout to ride out slow
            // GitHub days. selectedRef intentionally left empty —
            // the operator picks one, and the @change handler fires
            // the next step. No auto-pick + no auto-plan.
            this.fetchingRefs = true;
            this.upgradeRefs = [];
            this.selectedRef = '';
            this.upgradePlan = null;
            try {
                // force: always ask GitHub. Both callers are explicit operator
                // actions (opening the modal, pressing refresh), and the 30-min
                // cache made a release whose CI package had only just finished
                // invisible — with a refresh button that read the same cache and
                // so could not break out of it.
                const r = await this._fetchWithTimeout('/api/upgrade/refs', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ force: true }),
                });
                const d = await r.json();
                if (d && d.success) {
                    this.upgradeRefs = d.refs || [];
                    // The backend serves the last known list when a live fetch
                    // fails, rather than emptying the picker. Say so -- a list
                    // presented as current when it is an hour old is how an
                    // operator misses a release that exists.
                    if (d.stale) {
                        const mins = Math.round((d.stale_age_s || 0) / 60);
                        this.showTopToast(
                            'Showing the last known release list'
                            + (mins ? ` (${mins} min old)` : '')
                            + '. ' + (d.error || 'Could not refresh from GitHub.'),
                            'error');
                    }
                } else if (d && d.offline) {
                    this.showTopToast('No internet connection — cannot reach GitHub to list '
                                    + 'releases. Reconnect and press refresh.', 'error');
                } else {
                    this.showTopToast('Could not fetch releases: ' + (d.error || 'unknown'), 'error');
                }
            } catch (e) {
                const msg = e.name === 'AbortError'
                    ? 'Fetch releases timed out after 60s — GitHub may be slow; try again in a minute.'
                    : 'Fetch releases failed: ' + e.message;
                this.showTopToast(msg, 'error');
            }
            this.fetchingRefs = false;
        },

        async computeUpgradePlan() {
            if (!this.selectedRef) {
                this.showTopToast('Pick a release first', 'error');
                return;
            }
            this.computingPlan = true;
            this.upgradePlan = null;
            this.optedInOptional = [];
            this.optedInReinstall = [];
            try {
                const r = await this._fetchWithTimeout('/api/upgrade/plan', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({target: this.selectedRef}),
                });
                const d = await r.json();
                if (d && d.success) {
                    this.upgradePlan = d.plan;
                } else {
                    this.showTopToast('Plan failed: ' + (d.error || 'unknown'), 'error');
                }
            } catch (e) {
                const msg = e.name === 'AbortError'
                    ? 'Plan compute timed out after 60s — GitHub may be slow; try again.'
                    : 'Plan request failed: ' + e.message;
                this.showTopToast(msg, 'error');
            }
            this.computingPlan = false;
        },

        toggleOptionalModule(moduleId) {
            const idx = this.optedInOptional.indexOf(moduleId);
            if (idx >= 0) {
                this.optedInOptional.splice(idx, 1);
            } else {
                this.optedInOptional.push(moduleId);
            }
        },

        // Toggle a no-change (noop) module's forced-reinstall opt-in. Unchecked
        // by default (unchanged modules are skipped); ticking one re-applies it
        // even though it's already at the target version — the recovery path
        // for a module that broke at its current version.
        toggleReinstallModule(moduleId) {
            const idx = this.optedInReinstall.indexOf(moduleId);
            if (idx >= 0) {
                this.optedInReinstall.splice(idx, 1);
            } else {
                this.optedInReinstall.push(moduleId);
            }
        },

        // DOWNLOAD-ONLY: /api/upgrade/refs lists only releases that ship a
        // CI-built package and carries its size, so the modal can state exactly
        // what will be downloaded with no extra round-trip. There is no module
        // selection any more — the whole package comes down, and the operator
        // picks what to install when they import it.
        get selectedRefPackageMb() {
            const r = this.upgradeRefs.find(x => x.name === this.selectedRef);
            return r ? (r.package_mb || 0) : 0;
        },

        async startTrackUpgrade() {
            const isOnline = this.prepareModalMode === 'online';
            if (isOnline && !this.upgradePlan) {
                this.showMessage('Compute a plan first', 'error');
                return;
            }
            if (!isOnline && !this.selectedRef) {
                this.showMessage('Pick a release first', 'error');
                return;
            }
            // Zero ticks is intentionally allowed: the backend always
            // adds 'intact' to selected_set in upgrade_routes.py
            // (_modules_for_prepare), so a no-tick prepare ships an
            // intact-only package — useful for operators bundling a
            // platform-code-only refresh for an air-gap target.
            const endpoint = isOnline ? '/api/upgrade/online' : '/api/upgrade/prepare';
            const successMsg = isOnline
                ? 'Online upgrade started — check Workflows for progress'
                : 'Package preparation started — check Workflows for progress';
            const body = isOnline
                ? {target: this.selectedRef, opted_in_optional: this.optedInOptional,
                   opted_in_reinstall: this.optedInReinstall}
                : {target: this.selectedRef};
            this.prepareLoading = true;
            try {
                const r = await fetch(endpoint, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify(body),
                });
                const d = await r.json();
                if (r.ok && d.success) {
                    this.prepareRunId = d.run_id;
                    this.closePreparePackageModal();
                    this.showMessage(successMsg, 'success');
                    setTimeout(() => { window.ActiveCase.gotoSystemWorkflows(); }, 500);
                } else {
                    this.showMessage('Upgrade request failed: ' + (d.error || 'unknown'), 'error');
                }
            } catch (e) {
                this.showMessage('Upgrade request error: ' + e.message, 'error');
            }
            this.prepareLoading = false;
        },

        async _openModuleModal() {
            this.showPreparePackageModal = true;
            this.prepareLoading = false;
            this.prepareRunId = null;
            this.preparePackageReady = false;
            this.preparePackageSize = '';
            this.upgradeRefs = [];
            this.selectedRef = '';
            this.upgradePlan = null;
            this.optedInOptional = [];
            this.optedInReinstall = [];
            this.githubQuota = null;
            this.currentIntactVersion = '';
            // Fire-and-forget — independent of the refs fetch. Used by
            // the dropdown filter to hide older releases. Slow result
            // just means the filter falls back to permissive ("show
            // all") until it lands.
            this.fetchCurrentIntactVersion();

            // Minimal auto-chain on open: load the quota snapshot (for
            // the in-modal banner) and the release list (so the
            // dropdown is populated). The plan/module-list only fires
            // when the operator actually picks a release in the
            // dropdown — see onSelectedRefChange. Quota warning is the
            // only top-toast that fires on open, and only when the
            // quota is uncomfortably low.
            const quota = await this.fetchGithubQuota();
            if (quota && quota.success && quota.remaining <= 10) {
                this.showTopToast(
                    `GitHub quota low: ${quota.remaining}/${quota.limit} calls left ` +
                    `(resets ${quota.reset_hm}). The upgrade flow needs ~2 more.` +
                    (quota.authed ? '' : ' Set GITHUB_TOKEN in modules/backend/.env to raise the cap.'),
                    'error'
                );
            }
            await this.fetchUpgradeRefs();
        },

        // Operator picked a different release in the dropdown — re-run
        // the matching step automatically (plan for online, modules
        // for prepare). Saves a click; matches the "auto-show" UX.
        async onSelectedRefChange() {
            if (!this.selectedRef) return;
            if (this.prepareModalMode === 'online') {
                await this.computeUpgradePlan();
            } else {
            }
        },

        closePreparePackageModal() {
            this.showPreparePackageModal = false;
            this.preparePackageReady = false;
            this.prepareRunId = null;
        },

        async downloadPreparedPackage() {
            if (!this.prepareRunId) {
                this.showMessage('No package ready for download', 'error');
                return;
            }

            // Trigger download via new window/tab
            window.open(`/api/upgrade/prepare/${this.prepareRunId}/download`, '_blank');

            // Close modal after download initiated
            setTimeout(() => {
                this.closePreparePackageModal();
                this.showMessage('Package download started', 'success');
            }, 1000);
        },

        // ===== OFFLINE UPGRADE =====
        async importUpgradePackage(event) {
            const files = event.target.files;
            if (!files || files.length === 0) return;
            // A release ships one asset per module AND a single bundle. Both are
            // valid to import: the bundle because one file is easier to carry
            // into an air-gapped site, the module assets because they are what
            // the release is actually made of. Selecting several uploads them
            // into one workflow and the backend merges them.
            const selectedFiles = Array.from(files);
            const file = selectedFiles[0];
            event.target.value = '';

            // `.tar` BELONGS HERE. prepare_package.sh emits a plain
            // intact-upgrade-<tag>.tar -- the wrapper holds already-compressed
            // per-module assets, so the outer gzip bought 0.55% for a full
            // deflate pass over 5.4 GB and was dropped. Every reader downstream
            // was widened for it (upload_routes.py's pre-create hook,
            // peek-manifest's 'r|*' mode, wrapper_package_members, install.sh's
            // tar -xf), but this one client-side check was missed -- so the
            // browser refused the file before any of that could run and the
            // import path was dead for freshly prepared packages. Releases cut
            // before the change are still .tar.gz sitting on USB sticks, so all
            // three suffixes stay accepted forever.
            const bad = selectedFiles.filter(
                f => !f.name.endsWith('.tar.gz')
                  && !f.name.endsWith('.tgz')
                  && !f.name.endsWith('.tar'));
            if (bad.length) {
                this.showMessage(
                    'Not a .tar / .tar.gz / .tgz file: ' + bad[0].name, 'error');
                return;
            }

            // ─── DISK PREFLIGHT ─────────────────────────────────────────
            // Ask the appliance whether it can take this file BEFORE pushing
            // several GB at it. The apply refuses on low disk, and finding
            // that out afterwards means the operator spent the upload (and,
            // at an air-gapped site, a hand-carried copy) to be told no.
            // Also surfaces leftovers, so "free 4 GB" comes with "here is
            // where 6 GB of it already went".
            const totalBytes = selectedFiles.reduce((n, f) => n + f.size, 0);
            try {
                const pf = await (await fetch('/api/upgrade/upload-preflight', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({size_bytes: totalBytes}),
                })).json();
                const gb = (n) => (n / 1024 ** 3).toFixed(1) + ' GB';
                if (pf && pf.success) {
                    const stale = (pf.leftovers || []);
                    if (stale.length) {
                        console.info('[upgrade] package dirs already hold:',
                                     stale.map(l => `${l.dir}${l.name} (${gb(l.size_bytes)}, ${l.kind})`));
                    }
                    if (!pf.ok) {
                        // reclaimable_ok: clearing the leftovers alone would
                        // be enough, so name that rather than "free disk".
                        const advice = pf.reclaimable_ok && stale.length
                            ? `Removing what is already there would free ${gb(pf.leftover_bytes)} and be enough:\n  `
                              + stale.map(l => `${l.name} — ${gb(l.size_bytes)} (${l.kind})`).join('\n  ')
                            : 'Free disk space on the appliance and try again.';
                        this.showMessage(
                            `Not enough space: this ${gb(totalBytes)} package needs about `
                            + `${gb(pf.needed_bytes)} free (the upload plus unpacking it), `
                            + `but only ${gb(pf.free_bytes)} is available.`, 'error');
                        alert(
                            `Not enough disk space on the appliance\n\n`
                            + `Package        ${gb(totalBytes)}\n`
                            + `Needs about    ${gb(pf.needed_bytes)}  (upload + unpack)\n`
                            + `Free now       ${gb(pf.free_bytes)}\n\n`
                            + advice);
                        return;
                    }
                    if (stale.length) {
                        this.showMessage(
                            `Note: ${stale.length} leftover file(s) using ${gb(pf.leftover_bytes)} `
                            + `in the package folders. ${gb(pf.free_bytes)} free — enough to continue.`,
                            'info');
                    }
                }
            } catch (e) {
                // The check is an early warning, not a gate — a broken probe
                // must not stop an upload that would have worked.
                console.warn('upload preflight skipped:', e);
            }

            // ─── PEEK PHASE ─────────────────────────────────────────────
            // Read just the first 5 MB of the local file, POST it to
            // /api/upgrade/peek-manifest, get the manifest back, open
            // the review modal. The full 5 GB upload only happens after
            // the operator clicks Apply. If the operator cancels, no
            // upload bytes get sent at all.
            //
            // Why 5 MB: manifest.json lives in the first ~10 KB of any
            // tarball built by the new prepare flow (tar --files-from
            // ordering). 5 MB is a generous margin that covers
            // alignment, headers, and any pre-manifest entries. Costs
            // ~0.5 s on a typical link.
            this.showMessage('Reading manifest from local file…', 'info');
            const slice = file.slice(0, 5 * 1024 * 1024);
            let peek = null;
            try {
                const resp = await fetch('/api/upgrade/peek-manifest', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/octet-stream'},
                    body: slice,
                });
                peek = await resp.json();
            } catch (e) {
                console.error('peek-manifest request failed:', e);
                this.showMessage('Manifest peek failed: ' + e.message, 'error');
                return;
            }
            if (!peek || !peek.success) {
                // Older tarballs (manifest at end) land here. Operator
                // can still upload + review post-upload, but warn them
                // the upload will run with no preview.
                if (!confirm(
                    'Could not preview the manifest from the first 5 MB of this tarball ' +
                    '(likely a package built before the new ordering). Upload the FULL file ' +
                    'now and review afterwards?'
                )) return;
                return this._legacyUploadThenReview(file);
            }

            // Open the review modal with the peeked manifest. The
            // package_path stays NULL until the actual upload finishes
            // (Apply button is what triggers the upload).
            this.applyPackage = {
                _localFile: file,                          // kept for the upload step
                name: (selectedFiles.length > 1
                       ? `${selectedFiles.length} release assets`
                       : file.name),
                size_bytes: selectedFiles.reduce((n, f) => n + f.size, 0),
                source: 'local-pending',
                path: null,                                // filled in after upload
            };
            // The full set, so the apply step uploads every one of them. The
            // manifest above is peeked from the FIRST asset only -- enough to
            // show the operator what release this is, while the backend
            // assembles and re-validates the complete set before applying.
            this.applyPackageFiles = selectedFiles;
            this.applyManifest = peek.manifest || peek;
            this.applyDbOverwrite = {};
            this.applyCurrentVersions = {};
            this.showApplyPackageModal = true;
            // Fetch what's installed NOW so the modal shows current → target
            // and seeds the selection the SAME way the pending-package path
            // does: installed-module upgrades are forced, new modules are
            // opt-in, and no-change modules are skipped (grayed, tick to
            // reinstall). Without this the peek path showed "?" for every
            // module and pre-selected all of them.
            try {
                const cres = await fetch('/api/upgrade/current-versions', {method: 'GET'});
                const cur = await cres.json();
                if (cur && cur.success) this.applyCurrentVersions = cur.versions || {};
            } catch (_) { /* best-effort — modal still works, shows "?" */ }
            const versions = (this.applyManifest && this.applyManifest.versions) || {};
            this.applySelectedModules = [];
            for (const [name, target] of Object.entries(versions)) {
                const action = this.applyModuleAction(name, target);
                if (action === 'upgrade' || action === 'downgrade' || action === 'unknown') {
                    this.applySelectedModules.push(name);
                }
            }
            this.loadingApplyInfo = false;
        },

        // Legacy fallback for tarballs where the peek can't find
        // manifest.json in the first 5 MB. Uploads first, opens the
        // modal on tus success (matches the previous behavior).
        _legacyUploadThenReview(file) {
            this.showMessage(`Uploading ${file.name}...`, 'info');
            const upload = new tus.Upload(file, {
                endpoint: '/api/uploads/',
                retryDelays: [0, 1000, 3000, 5000],
                chunkSize: 32 * 1024 * 1024,  // see js/upload.js for why 32
                removeFingerprintOnSuccess: true,
                metadata: {
                    filename: file.name,
                    filetype: file.type || 'application/gzip',
                    purpose: 'upgrade_package',
                },
                onError: (error) => {
                    console.error('Upload error:', error);
                    this.showMessage('Upload failed: ' + error.message, 'error');
                },
                onSuccess: () => {
                    const parts = (upload.url || '').split('/').filter(Boolean);
                    const uploadId = parts.length ? parts[parts.length - 1] : null;
                    if (!uploadId) {
                        this.showMessage('Upload succeeded but no ID returned', 'error');
                        return;
                    }
                    this.openApplyPackageModal({
                        path: '/data/uploads/' + uploadId,
                        name: file.name,
                        size_bytes: file.size,
                        source: 'uploads',
                    });
                },
            });
            upload.start();
        },

        // ---- Subscription (CLI) providers -------------------------------
        // These spend an existing Codex/ChatGPT subscription through the vendor
        // CLI instead of a metered API key, so they have no key field.
        //
        // THE APPLIANCE NO LONGER INSTALLS OR SIGNS IN. It used to do both — an
        // Install CLI button that ran the vendor installer into a directory of
        // ours, and a device-code sign-in whose credential we stored. That is
        // gone. The operator installs codex on the host and runs `codex login`
        // the ordinary way; the backend finds it (mounted read-only into the
        // container) and uses their credential where it already is.
        //
        // Which leaves this panel with exactly one job: say whether the box can
        // see it, whether somebody is signed in, and whether it actually works.
        // Everything below is a read.
        SUBSCRIPTION_PROVIDERS: ['codex-subscription'],
        cli: { installed: false, authenticated: false, detail: '', label: '',
               version: null, path: null, source: null },
        cliBusy: false,
        cliTesting: false,
        _cliTimer: null,

        isSubscription() {
            return this.SUBSCRIPTION_PROVIDERS.includes(
                this.config?.agentic?.online_llm?.provider);
        },

        cliStatusText() {
            if (!this.cli.installed) return 'Not found on this system';
            if (this.cli.authenticated) return 'Ready' + (this.cli.version ? ' · ' + this.cli.version : '');
            return 'Found — not signed in';
        },

        // The one-liners an operator runs on the host. Kept here rather than in
        // the markup so the copy button has a single source for the text.
        // ONE command, the one the vendor's own page gives. The npm route was
        // offered alongside it and taken out again: two ways to install invites
        // an operator to pick the one we have exercised less, and detection is
        // strictly better on this one — the standalone installer publishes a
        // `current` marker naming the live release, so the appliance READS which
        // binary to run instead of inferring it from file timestamps.
        //
        // Detection still finds an npm install; it is just not what we tell
        // people to do.
        // Install AND sign in, in one block with one Copy. They are two steps of
        // one job — the appliance is no use after the first without the second —
        // and splitting them gave the operator two boxes and two buttons for
        // something they were always going to paste together.
        cliInstallCommands() {
            return 'curl -fsSL https://chatgpt.com/codex/install.sh | sh\n' +
                   'codex login';
        },
        cliLoginCommand() { return 'codex login'; },
        cliDocsUrl() { return 'https://developers.openai.com/codex/cli/'; },

        async cliRefresh() {
            if (!this.isSubscription()) return;
            const provider = this.config.agentic.online_llm.provider;
            try {
                const r = await fetch('/api/agentic/cli/status?provider=' + encodeURIComponent(provider));
                if (!r.ok) return;
                const d = await r.json();
                const wasAuthed = this.cli.authenticated;
                this.cli = {
                    installed: !!d.installed, authenticated: !!d.authenticated,
                    detail: d.detail || '', label: d.label || '',
                    version: d.version || null, path: d.path || null,
                    source: d.credential_source || null
                };
                // Signed in since the last poll → the catalog can finally be
                // listed (the CLI only knows the account's models once it is
                // authenticated). Fired on the TRANSITION, not on every poll.
                if (this.cli.authenticated && !wasAuthed) {
                    fetch('/api/maintenance/refresh-codex-models', { method: 'POST' })
                        .then(() => window.dispatchEvent(new CustomEvent('llm-catalog-refreshed',
                              { detail: { provider } })))
                        .catch(() => {});
                }
            } catch (e) { /* transient — the poll will retry */ }
        },

        // Called from the tab's x-init and whenever the provider changes.
        cliStartPolling() {
            this.cliStopPolling();
            if (!this.isSubscription()) return;
            this.cliRefresh();
            this._cliTimer = setInterval(() => this.cliRefresh(), 3000);
        },

        cliStopPolling() {
            if (this._cliTimer) { clearInterval(this._cliTimer); this._cliTimer = null; }
        },

        // Re-check is just cliRefresh with a message, so an operator who has
        // finished installing on the host gets an answer immediately instead of
        // waiting out the poll interval and wondering whether it is looking.
        async cliRecheck() {
            this.cliBusy = true;
            try {
                await this.cliRefresh();
                this.showMessage(this.cli.installed
                    ? (this.cli.authenticated ? 'codex is ready' : 'codex found — not signed in')
                    : 'codex still not visible to the appliance', 
                    this.cli.authenticated ? 'success' : 'info');
            } finally { this.cliBusy = false; }
        },

        cliCopy(text, what) {
            navigator.clipboard.writeText(text)
                .then(() => this.showMessage((what || 'Copied') + ' copied', 'success'))
                .catch(() => this.showMessage('Could not copy — select it manually', 'error'));
        },

        // Test runs as a `settings` workflow so its full log — the exact failure,
        // no internet, blocked proxy, expired login — is inspectable in
        // Settings → Actions like every other system operation.
        async _cliStartAction(path, label) {
            const provider = this.config.agentic.online_llm.provider;
            this.cliBusy = true;
            try {
                const r = await fetch(path, {
                    method: 'POST', headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ provider })
                });
                const d = await r.json();
                if (r.ok && d.success) {
                    this.showMessage(label + ' started — follow it in Actions', 'success');
                    window.ActiveCase.gotoSystemWorkflows();
                } else {
                    this.showMessage(label + ' could not start: ' + (d.error || 'unknown error'), 'error');
                }
                return d;
            } catch (e) {
                this.showMessage(label + ' could not start: ' + e.message, 'error');
                return null;
            } finally {
                this.cliBusy = false;
                this.cliRefresh();
            }
        },

        async cliTest() {
            this.cliTesting = true;
            try {
                await this._cliStartAction('/api/agentic/cli/test', 'Test Codex CLI');
            } finally {
                this.cliTesting = false;
            }
        },

        // Bash equivalent of Prepare Package, for an operator to run on a
        // machine that is not the appliance -- an air-gapped site's laptop,
        // or a box whose backend cannot reach GitHub.
        //
        // This emits a command that FETCHES AND RUNS scripts/prepare_package.sh
        // rather than embedding a copy of it. The appliance's own Prepare
        // Package runs that same script (routes/upgrade_routes.py shells out to
        // it), so there is exactly one implementation of "download the release
        // assets and wrap them into one file" -- no second copy here to drift
        // out of step with it.
        prepareManualScript() {
            // Always pulls prepare_package.sh from main (not the tag's own
            // copy) so every packaging run picks up the latest script fixes
            // (e.g. the download-resume/retry tuning) regardless of which
            // release is being packaged. tag falls back to the last known
            // release when selectedRef hasn't loaded (e.g. no connection).
            //
            // Deliberately a single plain-curl script, not a "simple vs
            // fast (aria2c)" choice -- that variant was tried and reverted.
            // GitHub's release assets redirect to a time-limited signed
            // URL; aria2c resolves it once and splits it into parallel
            // segments, so a long transfer or a stalled segment has no way
            // to get a fresh URL and everything hangs at once (reproduced
            // live against this release's own ELK asset). Plain curl's
            // --retry re-follows the redirect from the original URL on
            // every attempt, minting a fresh signed URL each time, which
            // is the actual correct fix -- see scripts/prepare_package.sh.
            const tag = this.selectedRef || 'intact-20260806';
            return [
                'curl -fsSL -o prepare_package.sh https://raw.githubusercontent.com/TenrootOrg/IntactAI/main/scripts/prepare_package.sh',
                'bash prepare_package.sh ' + tag + ' .',
            ].join('\n');
        },

        cliCopy(text, what) {
            if (!text) return;
            const done = () => this.showMessage((what || 'Value') + ' copied', 'success');
            if (navigator.clipboard?.writeText) {
                navigator.clipboard.writeText(text).then(done).catch(() => {});
                return;
            }
            // http:// origins have no clipboard API — fall back to a temp textarea
            try {
                const ta = document.createElement('textarea');
                ta.value = text; document.body.appendChild(ta); ta.select();
                document.execCommand('copy'); document.body.removeChild(ta); done();
            } catch (e) { /* operator can select the text shown below */ }
        },

        async onProviderChange() {
            // Pick a sensible default model when the operator switches
            // provider, plus auto-fill max_response_tokens from it.
            //
            // Per provider we prefer the higher-tier `*-latest` family
            // alias since those auto-update when the vendor ships a new
            // model and don't lock the operator to a specific version.
            // If the preferred id isn't in the catalog (older snapshot,
            // catalog filtered it out), fall back to results[0]
            // (newest entry by `created`).
            //
            // Route name mapping: the UI uses `claude` but the catalog
            // route is `/api/config/anthropic/models` — translate.
            const provider = this.config.agentic.online_llm.provider;

            // Subscription providers have no model catalog endpoint (there is no
            // key to enumerate models with), so skip the fetch entirely — it
            // would 404 and leave the field stale — and start the detect poll.
            if (this.isSubscription()) {
                // Blank = let the CLI choose a model the subscription is actually
                // entitled to. Pinning one here broke ChatGPT-account logins:
                // "The 'gpt-5-codex' model is not supported when using Codex
                // with a ChatGPT account." The catalog the combobox reads comes
                // from `codex debug models` (the CLI's own list, which the CLI
                // actually accepts), not from the vendor's web /models endpoint.
                this.config.agentic.online_llm.model = '';
                this._cliStopLogin();
                this.cliStartPolling();
                // populate the CLI-backed catalog (no-op until connected)
                try { await fetch('/api/maintenance/refresh-codex-models', { method: 'POST' }); } catch (e) {}
                window.dispatchEvent(new CustomEvent('llm-catalog-refreshed', { detail: { provider } }));
                return;
            }
            this.cliStopPolling();

            const route = provider === 'claude' ? 'anthropic' : provider;
            // No entry for `ollama-cloud` on purpose: its line-up is set by
            // Ollama and by the operator's plan, so any id hardcoded here
            // would be a guess that 404s at report time. Falling through to
            // list[0] picks something the account demonstrably has.
            const preferredId = {
                'claude':     'claude-sonnet-latest',
                'openai':     'gpt-latest',
                'gemini':     'gemini-pro-latest',
                'openrouter': '~anthropic/claude-sonnet-latest'
            }[provider];

            try {
                const resp = await fetch('/api/config/' + route + '/models?limit=30');
                const data = await resp.json();
                const list = data.models || [];
                let picked = preferredId ? list.find(m => m.id === preferredId) : null;
                if (!picked) picked = list[0];
                if (picked) {
                    this.config.agentic.online_llm.model = picked.id;
                    // (max_response_tokens removed — Case Analysis per-case Output token cap
                    //  defaults to the model's max output.)
                }
            } catch (e) {
                // Network/parse failure → fall back to a sensible
                // hardcoded default so the field isn't left stale from
                // the previous provider.
                const fallback = {
                    'openai':     'gpt-latest',
                    'claude':     'claude-sonnet-latest',
                    'gemini':     'gemini-pro-latest',
                    'openrouter': '~anthropic/claude-sonnet-latest'
                }[provider];
                // Clear rather than leave the previous provider's model in
                // place when there is no hardcoded fallback (ollama-cloud).
                // A stale id from another vendor looks like a valid choice and
                // fails later, at report time; an empty box asks to be filled.
                this.config.agentic.online_llm.model = fallback || '';
            }
        }
    });
});
