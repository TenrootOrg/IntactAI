// Settings store (config + maintenance + upgrade) — registered on Alpine init.
document.addEventListener('alpine:init', () => {
    // Settings store
    Alpine.store('settings', {
        // Read-only "what is running" panel. All that is left of the upgrade
        // UI: upgrading is `sudo bash scripts/upgrade.sh <tag>` on the appliance, so
        // the dashboard reports state and shows the command rather than
        // driving a workflow it can no longer see.
        installedVersions: {},
        async loadInstalledVersions() {
            try {
                const r = await fetch('/api/upgrade/current-versions');
                if (!r.ok) return;
                const d = await r.json();
                this.installedVersions = (d && d.versions) || {};
            } catch (e) {
                // Never let a version panel break the settings page.
            }
        },

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

        async runMaintenance() {
            this.showMessage('Maintenance workflow started...', 'info');
            try {
                const response = await fetch('/api/maintenance/run', { method: 'POST' });
                const result = await response.json();
                if (response.ok && result.success) {
                    this.showMessage('Maintenance started - redirecting to Workflows', 'success');
                    // Switch to workflows view after a short delay
                    setTimeout(() => {
                        window.ActiveCase.gotoSystemWorkflows();
                    }, 500);
                } else {
                    this.showMessage('Maintenance workflow failed: ' + (result.error || 'Unknown error'), 'error');
                }
            } catch (e) {
                this.showMessage('Maintenance workflow error: ' + e.message, 'error');
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



        applyPackage: null,         // {path, name, size_bytes, mtime, source}
        applyPackageFiles: [],      // all selected local assets (per-module import)
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



        // Classify a packaged module against what's installed locally.
        // Returns one of: 'no-change' (same version), 'upgrade' (target
        // differs), 'install' (module not currently installed),
        // 'unknown' (current-versions probe failed). Drives both row
        // styling and the apply-button warning.

        // Count of ticked modules that would actually do work. Used to
        // warn the operator when they're about to apply a package that
        // changes nothing (the 2026-06-15 same-version mishap).






        // ─── Track-based upgrade flow state ──────────────────────────
        // The operator picks ONE Intact release, system derives the
        // per-module work list. See services/upgrade/resolver.py.
        optedInReinstall: [],       // ONLINE mode: no-change module IDs ticked to FORCE a reinstall (bug recovery)
        fetchingRefs: false,
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


        // Dropdown source: filter out 'older' refs so the operator
        // can't pick a downgrade target. Online mode applies the
        // filter; prepare mode keeps everything (the operator may
        // legitimately want to build a package for an older air-gap
        // host). `development` always survives the filter.













        // Legacy fallback for tarballs where the peek can't find
        // manifest.json in the first 5 MB. Uploads first, opens the
        // modal on tus success (matches the previous behavior).

        // ---- Subscription (CLI) providers -------------------------------
        // These spend an existing Codex/ChatGPT subscription through the
        // vendor CLI instead of a metered API key, so they have no key field.
        // The panel polls /status every 3s while it is on screen: the CLI can
        // be installed, signed in, or expire outside this page's control.
        SUBSCRIPTION_PROVIDERS: ['codex-subscription'],
        cli: { installed: false, authenticated: false, detail: '', label: '', version: null },
        cliBusy: false,
        cliTesting: false,
        cliLogin: { url: '', code: '' },
        cliManualOpen: false,
        _cliTimer: null,

        isSubscription() {
            return this.SUBSCRIPTION_PROVIDERS.includes(
                this.config?.agentic?.online_llm?.provider);
        },

        cliStatusText() {
            if (!this.cli.installed) return 'CLI not installed';
            if (this.cli.authenticated) return 'Connected' + (this.cli.version ? ' · ' + this.cli.version : '');
            if (this.cliLogin.url) return 'Waiting for approval…';
            return 'Installed — not connected';
        },

        async cliRefresh() {
            if (!this.isSubscription()) return;
            const provider = this.config.agentic.online_llm.provider;
            try {
                const r = await fetch('/api/agentic/cli/status?provider=' + encodeURIComponent(provider));
                if (!r.ok) return;
                const d = await r.json();
                this.cli = {
                    installed: !!d.installed, authenticated: !!d.authenticated,
                    detail: d.detail || '', label: d.label || '', version: d.version || null
                };
                // a device login in flight → keep the URL/code buttons on screen
                if (d.login && d.login.url) {
                    this.cliLogin = { url: d.login.url, code: d.login.code || '' };
                } else if (!this.cli.authenticated) {
                    this.cliLogin = { url: '', code: '' };
                }
                // login finished out-of-band (or expired) → drop the code panel
                if (this.cli.authenticated && this.cliLogin.url) {
                    this._cliStopLogin();
                    // the CLI can only list models once it is signed in
                    fetch('/api/maintenance/refresh-codex-models', { method: 'POST' })
                        .then(() => window.dispatchEvent(new CustomEvent('llm-catalog-refreshed',
                              { detail: { provider: this.config.agentic.online_llm.provider } })))
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

        // Install / Connect / Test all run as `settings` workflows so their full
        // log (including the exact failure — no internet, blocked proxy, expired
        // code) is inspectable in Settings → Actions like every other system
        // operation. Starting one jumps straight to that tab.
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
                    // gotoSystemWorkflows() rather than a bare
                    // 'show-system-actions' dispatch: it also switches to the
                    // settings tab and re-fires after 400ms, so it still lands
                    // when the settings partial is mid-lazy-load. A single
                    // dispatch only worked because the operator happened to
                    // already be on this tab.
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

        async cliInstall() {
            await this._cliStartAction('/api/agentic/cli/install', 'Install Codex CLI');
        },

        // "Generate new code": discard the in-flight sign-in and issue a fresh
        // one. Needed when the ~15-minute code expires or the operator loses it —
        // otherwise a plain Connect would just hand back the same dead code.
        async cliNewCode() {
            this.cliLogin = { url: '', code: '' };
            const provider = this.config.agentic.online_llm.provider;
            this.cliBusy = true;
            try {
                const r = await fetch('/api/agentic/cli/login', {
                    method: 'POST', headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ provider, force: true })
                });
                const d = await r.json();
                if (r.ok && d.success) {
                    // Starts a `settings` workflow exactly like Connect does, so
                    // it jumps to Actions the same way. The device URL + new code
                    // are logged into that run, so the operator lands on the page
                    // that shows them rather than on a panel that has just been
                    // blanked by the cliLogin reset above.
                    this.showMessage('New code requested — follow it in Actions', 'success');
                    window.ActiveCase.gotoSystemWorkflows();
                } else {
                    this.showMessage('Could not get a new code: ' + (d.error || 'unknown error'), 'error');
                }
            } catch (e) {
                this.showMessage('Could not get a new code: ' + e.message, 'error');
            } finally {
                this.cliBusy = false;
                this.cliRefresh();
            }
        },

        async cliConnect() {
            // The device URL + one-time code are logged into the workflow AND
            // returned by /status, so the panel can show clickable/copyable
            // buttons while the operator watches the run in Actions.
            await this._cliStartAction('/api/agentic/cli/login', 'Configure Codex CLI');
        },

        _cliStopLogin() {
            this.cliLogin = { url: '', code: '' };
        },

        async cliCancelLogin() {
            const provider = this.config.agentic.online_llm.provider;
            this._cliStopLogin();
            try {
                await fetch('/api/agentic/cli/login/cancel', {
                    method: 'POST', headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ provider })
                });
            } catch (e) { /* nothing to do */ }
            this.cliRefresh();
        },

        async cliDisconnect() {
            const provider = this.config.agentic.online_llm.provider;
            try {
                await fetch('/api/agentic/cli/disconnect', {
                    method: 'POST', headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ provider })
                });
                this.showMessage('Subscription disconnected', 'success');
            } catch (e) {
                this.showMessage('Disconnect failed: ' + e.message, 'error');
            }
            this.cliRefresh();
        },

        async cliTest() {
            this.cliTesting = true;
            try {
                await this._cliStartAction('/api/agentic/cli/test', 'Test Codex CLI');
            } finally {
                this.cliTesting = false;
            }
        },

        // Escape hatch for sites whose egress rules block the in-app device flow:
        // the operator runs the login in a shell and we adopt the credential it
        // wrote, storing it in the DB and deleting the file.
        async cliImportManual() {
            const provider = this.config.agentic.online_llm.provider;
            try {
                const r = await fetch('/api/agentic/cli/import-credential', {
                    method: 'POST', headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ provider })
                });
                const d = await r.json();
                if (r.ok && d.success) {
                    this.showMessage('Login imported — subscription connected', 'success');
                    this.cliManualOpen = false;
                    this._cliStopLogin();
                } else {
                    this.showMessage('Import failed: ' + (d.error || 'unknown error'), 'error');
                }
            } catch (e) {
                this.showMessage('Import failed: ' + e.message, 'error');
            }
            this.cliRefresh();
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
