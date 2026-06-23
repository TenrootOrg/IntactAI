// Settings store (config + maintenance + upgrade) — registered on Alpine init.
document.addEventListener('alpine:init', () => {
    // Settings store
    Alpine.store('settings', {
        config: {
            agentic: {
                llm_mode: 'offline',
                offline_llm: { provider: 'ollama', model: 'llama3.3:70b', url: 'http://localhost:11434', batch_size: 100 },
                online_llm: { provider: 'claude', api_key: '', model: 'claude-sonnet-latest', batch_size: 100 },
                max_concurrent_requests: 5,
                max_response_tokens: 16384,
                ollama_context_size: 65536,
                ollama_timeout: 600
            },
            timesketch: {
                llm_mode: 'google',
                google_ai_key: '',
                google_ai_model: 'gemini-2.5-flash',
                ollama_url: 'http://localhost:11434',
                ollama_model: 'llama3.1:8b'
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
            cve_scan: {
                nvd_api_key: ''
            }
        },
        saving: false,
        message: '',
        messageType: '',

        async load() {
            try {
                // Load agentic config
                const agenticResponse = await fetch('/api/config');
                if (agenticResponse.ok) {
                    const data = await agenticResponse.json();
                    this.config.agentic = {
                        llm_mode: data.agentic?.llm_mode || 'offline',
                        offline_llm: { ...this.config.agentic.offline_llm, ...data.agentic?.offline_llm },
                        online_llm: { ...this.config.agentic.online_llm, ...data.agentic?.online_llm },
                        max_concurrent_requests: data.agentic?.max_concurrent_requests || 5,
                        max_response_tokens: data.agentic?.max_response_tokens || 16384,
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
                        ollama_model: tsData.ollama_model || ''
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

                // CVE Scan settings come back via the same /api/config
                // payload (frontend_config blob) — agenticResponse above
                // already has the full doc.
                try {
                    const r = await fetch('/api/config');
                    if (r.ok) {
                        const d = await r.json();
                        this.config.cve_scan = {
                            nvd_api_key: (d.cve_scan && d.cve_scan.nvd_api_key) || ''
                        };
                    }
                } catch (e) { /* best-effort */ }

                window.currentConfig = this.config;
            } catch (e) {
                console.error('Failed to load settings:', e);
            }
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
                        gemini:     'refresh-gemini-models'
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
                    setTimeout(() => {
                        Alpine.store('app').switchTab('workflows');
                    }, 1000);
                } else {
                    this.showMessage('Failed to save Timesketch config', 'error');
                }
            } catch (e) {
                this.showMessage('Error: ' + e.message, 'error');
            }
            this.saving = false;
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

        // CVE Scan settings — currently just the NVD API key. The
        // /api/config PUT endpoint replaces the whole frontend_config
        // doc, so we read-modify-write to preserve everything else
        // (agentic, timesketch refs etc.).
        async saveCveScan() {
            this.saving = true;
            try {
                const r = await fetch('/api/config');
                const cfg = r.ok ? (await r.json()) : {};
                cfg.cve_scan = Object.assign({}, cfg.cve_scan || {}, {
                    nvd_api_key: (this.config.cve_scan && this.config.cve_scan.nvd_api_key) || ''
                });
                const save = await fetch('/api/config', {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(cfg)
                });
                if (save.ok) {
                    window.currentConfig = this.config;
                    this.showMessage('CVE Scan settings saved', 'success');
                } else {
                    this.showMessage('Failed to save CVE Scan config', 'error');
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

        async runMaintenance() {
            this.showMessage('Maintenance workflow started...', 'info');
            try {
                const response = await fetch('/api/maintenance/run', { method: 'POST' });
                const result = await response.json();
                if (response.ok && result.success) {
                    this.showMessage('Maintenance started - redirecting to Workflows', 'success');
                    // Switch to workflows view after a short delay
                    setTimeout(() => {
                        Alpine.store('app').switchTab('workflows');
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
                    setTimeout(() => { Alpine.store('app').switchTab('workflows'); }, 500);
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
                setTimeout(() => { Alpine.store('app').switchTab('workflows'); }, 500);
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
            this.applyManifest = null;
        },

        toggleApplyModule(moduleId) {
            // Guard: only INSTALL rows are togglable. Upgrade /
            // downgrade are forced (matches the online-upgrade
            // convention — installed modules upgrade together with
            // the chosen package); no-change is excluded. The HTML
            // already disables those checkboxes; this is a
            // belt-and-braces check.
            const target = (this.applyManifest?.versions || {})[moduleId];
            const action = this.applyModuleAction(moduleId, target);
            if (action !== 'install') return;
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
                const db_overwrite = Object.assign({}, this.applyDbOverwrite);
                console.log('[Import] Starting tus upload for', file.name,
                            '(', file.size, 'bytes), modules:', selected);
                this.showMessage('Uploading package… (you can watch the upload run in Workflows)', 'info');
                this.closeApplyPackageModal();
                Alpine.store('app').switchTab('workflows');
                this.applying = false;
                const upload = new tus.Upload(file, {
                    endpoint: '/api/uploads/',
                    retryDelays: [0, 1000, 3000, 5000],
                    chunkSize: 5 * 1024 * 1024,
                    metadata: {
                        filename: file.name,
                        filetype: file.type || 'application/gzip',
                        purpose: 'upgrade_package',
                    },
                    onError: (error) => {
                        console.error('Upload error:', error);
                        this.showMessage('Upload failed: ' + error.message, 'error');
                    },
                    onSuccess: async () => {
                        const parts = (upload.url || '').split('/').filter(Boolean);
                        const uploadId = parts.length ? parts[parts.length - 1] : null;
                        if (!uploadId) {
                            this.showMessage('Upload succeeded but no ID returned', 'error');
                            return;
                        }
                        try {
                            const r = await fetch('/api/upgrade/offline', {
                                method: 'POST',
                                headers: {'Content-Type': 'application/json'},
                                body: JSON.stringify({
                                    package_path: '/data/uploads/' + uploadId,
                                    selected_modules: selected,
                                    db_overwrite: db_overwrite,
                                }),
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
                    },
                });
                upload.start();
                return;
            }

            // Legacy-flow: tarball already on disk, just apply.
            try {
                const r = await fetch('/api/upgrade/offline', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        package_path: packagePath,
                        selected_modules: this.applySelectedModules,
                        db_overwrite: this.applyDbOverwrite,
                    }),
                });
                const d = await r.json();
                if (r.ok && d.success) {
                    this.closeApplyPackageModal();
                    this.showMessage('Apply started — check Workflows for progress', 'success');
                    setTimeout(() => { Alpine.store('app').switchTab('workflows'); }, 500);
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
        prepareModules: null,       // PREPARE mode: flat list from /api/upgrade/prepare-list
        prepareSelected: [],        // PREPARE mode: ticked modules (operator unticks to exclude)
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
                return await fetch(url, { ...opts, signal: controller.signal });
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
        filteredUpgradeRefs() {
            if (this.prepareModalMode !== 'online') return this.upgradeRefs;
            return this.upgradeRefs.filter(r => this.classifyUpgradeRef(r) !== 'older');
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
                const r = await this._fetchWithTimeout('/api/upgrade/refs', { method: 'POST' });
                const d = await r.json();
                if (d && d.success) {
                    this.upgradeRefs = d.refs || [];
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

        // ─── PREPARE-mode helpers ────────────────────────────────────
        // Prepare semantics: bundle a subset of UPSTREAM modules at the
        // picked release's pinned versions. Build-server's installed
        // state is irrelevant (we're targeting an air-gap machine we
        // don't know yet).
        async showPrepareModules() {
            if (!this.selectedRef) {
                this.showTopToast('Pick a release first', 'error');
                return;
            }
            this.showingPrepareModules = true;
            this.prepareModules = null;
            this.prepareSelected = [];
            try {
                const r = await this._fetchWithTimeout('/api/upgrade/prepare-list', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({target: this.selectedRef}),
                });
                const d = await r.json();
                if (d && d.success) {
                    this.prepareModules = d.modules || [];
                    // Default: every module ticked. Operator unchecks to
                    // exclude from the tarball.
                    this.prepareSelected = this.prepareModules.map(r => r.module);
                } else {
                    this.showTopToast('Module list failed: ' + (d.error || 'unknown'), 'error');
                }
            } catch (e) {
                const msg = e.name === 'AbortError'
                    ? 'Module list timed out after 60s — GitHub may be slow; try again.'
                    : 'Module list request failed: ' + e.message;
                this.showTopToast(msg, 'error');
            }
            this.showingPrepareModules = false;
        },

        togglePrepareModule(moduleId) {
            // intact is the platform — a package without it has no
            // runtime to apply other modules. Guard against any code
            // path that tries to untick it.
            if (moduleId === 'intact') return;
            const idx = this.prepareSelected.indexOf(moduleId);
            if (idx >= 0) {
                this.prepareSelected.splice(idx, 1);
            } else {
                this.prepareSelected.push(moduleId);
            }
        },

        async startTrackUpgrade() {
            const isOnline = this.prepareModalMode === 'online';
            if (isOnline && !this.upgradePlan) {
                this.showMessage('Compute a plan first', 'error');
                return;
            }
            if (!isOnline && !this.prepareModules) {
                this.showMessage('Click "Show modules" first to load the list', 'error');
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
                ? {target: this.selectedRef, opted_in_optional: this.optedInOptional}
                : {target: this.selectedRef, selected_modules: this.prepareSelected};
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
                    setTimeout(() => { Alpine.store('app').switchTab('workflows'); }, 500);
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
            this.prepareModules = null;
            this.prepareSelected = [];
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
                await this.showPrepareModules();
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
            const file = files[0];
            event.target.value = '';

            if (!file.name.endsWith('.tar.gz') && !file.name.endsWith('.tgz')) {
                this.showMessage('Please select a .tar.gz or .tgz file', 'error');
                return;
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
                name: file.name,
                size_bytes: file.size,
                source: 'local-pending',
                path: null,                                // filled in after upload
            };
            this.applyManifest = peek.manifest || peek;
            this.applySelectedModules = Object.keys(
                (this.applyManifest && this.applyManifest.versions) || {}
            );
            this.applyDbOverwrite = {};
            this.showApplyPackageModal = true;
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
                chunkSize: 5 * 1024 * 1024,
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
            const route = provider === 'claude' ? 'anthropic' : provider;
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
                    if (picked.max_output_tokens) {
                        this.config.agentic.max_response_tokens = picked.max_output_tokens;
                    }
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
                if (fallback) this.config.agentic.online_llm.model = fallback;
            }
        }
    });
});
