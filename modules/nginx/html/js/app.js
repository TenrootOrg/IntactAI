/**
 * Intact.AI Platform - Alpine.js Application
 * Consolidates: main.js, services.js, settings.js, workflows.js
 */

// Global configuration
window.baseHost = window.location.hostname;
window.services = {
    velociraptor: { path: '/velociraptor/', protocol: 'https' },
    timesketch: { port: 5000, protocol: 'https' },
    kibana: { port: 5601, protocol: 'https' },
    iris: { port: 8443, protocol: 'https' },
    portainer: { port: 9443, protocol: 'https' },
    // VolWeb — main nginx terminates TLS on host port 8002 and
    // proxies to the internal intact_volweb_frontend:80. URL stays
    // clean (no sub-path) so Vue's hardcoded /assets/ paths work.
    volweb: { port: 8002, protocol: 'https' }
};

window.defaultConfig = {
    agentic: {
        llm_mode: "offline",
        offline_llm: { provider: "ollama", model: "llama3.3:70b", url: "http://localhost:11434", batch_size: 100 },
        online_llm: { provider: "claude", api_key: "", model: "claude-sonnet-latest", batch_size: 100 },
    }
};

// Utility functions
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function openService(serviceId) {
    const service = window.services[serviceId];
    const url = service.path
        ? `${service.protocol}://${window.baseHost}${service.path}`
        : `${service.protocol}://${window.baseHost}:${service.port}/`;
    window.open(url, '_blank');
}

// Alpine.js initialization
document.addEventListener('alpine:init', () => {
    // App store - tab switching and navigation
    Alpine.store('app', {
        currentTab: 'dashboard',
        modulesOpen: false,
        sidebarCollapsed: localStorage.getItem('sidebarCollapsed') === 'true',

        toggleSidebar() {
            this.sidebarCollapsed = !this.sidebarCollapsed;
            localStorage.setItem('sidebarCollapsed', this.sidebarCollapsed);
        },

        switchTab(tab) {
            this.currentTab = tab;
            window.location.hash = tab;
            if (tab.startsWith('modules-')) {
                this.modulesOpen = true;
            }
            // Module-specific initializations
            if (tab === 'modules-timesketch') { populateTimeSketchClients(); loadTimesketchBlueprintsDropdown(); }
            if (tab === 'modules-agentic') initAgentic();
            if (tab === 'blueprints') initBlueprints();
            if (tab === 'workflows') Alpine.store('workflows').load();
            if (tab === 'settings') Alpine.store('settings').load();
        },

        toggleModules() {
            this.modulesOpen = !this.modulesOpen;
        },

        isActive(tab) {
            return this.currentTab === tab;
        }
    });

    // Services status store
    Alpine.store('services', {
        statuses: {},
        clientCount: 0,
        onlineCount: 0,
        onlineClientCount: 0,

        async checkAll() {
            try {
                const response = await fetch('/api/system/containers');
                if (response.ok) {
                    const containerStatuses = await response.json();
                    
                    // Update statuses based on backend container info
                    for (const serviceId in containerStatuses) {
                        this.statuses[serviceId] = containerStatuses[serviceId];
                    }
                    
                    // Ensure any service not in container list (if it was added elsewhere) is handled
                    for (const serviceId in window.services) {
                        if (!(serviceId in containerStatuses)) {
                            // Fallback to offline if not managed by docker ps check
                            this.statuses[serviceId] = this.statuses[serviceId] || 'offline';
                        }
                    }
                } else {
                    console.error('Failed to fetch system container status');
                }
            } catch (e) {
                console.error('Error checking service status:', e);
                // Mark all as checking/offline if backend is unreachable
                for (const serviceId in window.services) {
                    this.statuses[serviceId] = 'offline';
                }
            }
            this.updateStats();
        },

        async checkService(serviceId) {
            // Service-specific checks now handled by checkAll bulk update
            await this.checkAll();
        },

        updateStats() {
            this.onlineCount = Object.values(this.statuses).filter(s => s === 'online').length;
        },

        getStatusClass(serviceId) {
            const status = this.statuses[serviceId] || 'checking';
            return `status-dot status-${status} w-3 h-3 rounded-full`;
        },

        async loadClients() {
            try {
                const response = await fetch('/api/clients');
                if (response.ok) {
                    const data = await response.json();
                    const clients = data.items || [];
                    this.clientCount = data.total || clients.length;

                    const now = Date.now() / 1000;
                    this.onlineClientCount = clients.filter(c => {
                        const lastSeen = c.last_seen_at ? c.last_seen_at / 1000000 : 0;
                        return (now - lastSeen) < 600;
                    }).length;
                }
            } catch (e) {
                console.error('Failed to load clients:', e);
            }
        },

        getHealthStatus() {
            return this.onlineCount >= 4 ? 'Good' : this.onlineCount >= 2 ? 'Fair' : 'Poor';
        }
    });

    // Workflows store
    Alpine.store('workflows', {
        runs: [],
        allRuns: [],
        typeFilter: '',
        loading: true,
        selectedRun: null,
        modalOpen: false,
        initialLoad: true,
        autoScroll: true,
        refreshInterval: null,
        currentRunId: null,

        async load() {
            // Only show loading spinner on initial load
            if (this.initialLoad) this.loading = true;

            try {
                const response = await fetch('/api/dashboard/automations');
                const data = await response.json();
                const newRuns = data.runs || [];

                // Smart merge - only update if data changed (prevents flickering)
                if (this.initialLoad || JSON.stringify(this.allRuns) !== JSON.stringify(newRuns)) {
                    this.allRuns = newRuns;
                    this.applyFilter();
                }
                this.initialLoad = false;
            } catch (e) {
                console.error('Failed to load workflows:', e);
                if (this.initialLoad) this.allRuns = [];
                this.runs = [];
            }
            this.loading = false;
        },

        applyFilter() {
            if (!this.typeFilter) {
                this.runs = this.allRuns;
            } else {
                this.runs = this.allRuns.filter(run => run.type === this.typeFilter);
            }
        },

        async viewLogs(runId) {
            try {
                const response = await fetch(`/api/dashboard/automation/${runId}`);
                this.selectedRun = await response.json();
                this.modalOpen = true;
                this.currentRunId = runId;
                this.startAutoRefresh(runId);
                this.scrollToBottom();
            } catch (e) {
                console.error('Failed to load logs:', e);
            }
        },

        startAutoRefresh(runId) {
            // Clear any existing interval
            this.stopAutoRefresh();

            // Refresh logs every 1 second
            this.refreshInterval = setInterval(async () => {
                if (!this.modalOpen) {
                    this.stopAutoRefresh();
                    return;
                }
                try {
                    const response = await fetch(`/api/dashboard/automation/${runId}`);
                    const newData = await response.json();

                    // Only update if logs changed
                    if (JSON.stringify(this.selectedRun?.logs) !== JSON.stringify(newData?.logs)) {
                        this.selectedRun = newData;
                        // Auto-scroll if enabled
                        if (this.autoScroll) {
                            this.scrollToBottom();
                        }
                    }
                } catch (e) {
                    console.error('Failed to refresh logs:', e);
                }
            }, 1000);
        },

        stopAutoRefresh() {
            if (this.refreshInterval) {
                clearInterval(this.refreshInterval);
                this.refreshInterval = null;
            }
        },

        scrollToBottom() {
            setTimeout(() => {
                const logsContainer = document.getElementById('workflow-logs-container');
                if (logsContainer) {
                    logsContainer.scrollTop = logsContainer.scrollHeight;
                }
            }, 50);
        },

        toggleAutoScroll() {
            this.autoScroll = !this.autoScroll;
            if (this.autoScroll) {
                this.scrollToBottom();
            }
        },

        downloadLogs() {
            const run = this.selectedRun;
            if (!run?.logs?.length) return;

            const content = run.logs.map(log =>
                `[${new Date(log.timestamp).toISOString()}] [${log.level.toUpperCase()}] ${log.message}`
            ).join('\n');

            const blob = new Blob([content], { type: 'text/plain' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `${run.name || run.id}-logs.txt`;
            a.click();
            URL.revokeObjectURL(url);
        },

        closeModal() {
            this.stopAutoRefresh();
            this.modalOpen = false;
            this.selectedRun = null;
            this.currentRunId = null;
        },

        async stopWorkflow(runId) {
            if (!confirm('Stop this workflow? Running operations will be cancelled.')) return;
            try {
                const response = await fetch(`/api/dashboard/automation/${runId}/stop`, { method: 'POST' });
                if (response.ok) {
                    this.load();
                    if (this.selectedRun && this.selectedRun.id === runId) {
                        this.selectedRun.status = 'cancelled';
                    }
                } else {
                    const data = await response.json();
                    alert('Failed to stop: ' + (data.error || 'Unknown error'));
                }
            } catch (e) {
                alert('Error stopping workflow: ' + e.message);
            }
        },

        getStatusColor(status) {
            const colors = { running: 'bg-blue-600', completed: 'bg-green-600', failed: 'bg-red-600', cancelled: 'bg-orange-600' };
            return colors[status] || 'bg-gray-600';
        },

        getTypeColor(type) {
            // Module-themed palette so each chip reflects which module produced
            // the run. Velociraptor family (incl. agentic + CVE) = green;
            // Timesketch = purple (avoids blue since Azure owns blue);
            // Settings / system actions = red; AWS = orange; Azure = blue;
            // Engagement Report = yellow (customer-facing deliverable).
            // Fallback is slate-700 — never gray-600, which reads black-on-dark.
            const colors = {
                // Velociraptor (incl. agentic + CVE-mgmt scans + offline collectors)
                agentic: 'bg-green-600',
                velociraptor_hunt: 'bg-green-700',
                velociraptor_upload: 'bg-green-700',
                velociraptor_offline_collector: 'bg-green-700',
                velociraptor_offline_import: 'bg-green-700',
                offline_collector: 'bg-green-700',
                offline_import: 'bg-green-700',
                hunt: 'bg-green-700',
                cve_scan: 'bg-green-700',
                artifact: 'bg-green-600',
                // Timesketch (and IRIS, when its runs get a workflow row)
                timesketch: 'bg-purple-600',
                timesketch_upload: 'bg-purple-700',
                iris: 'bg-purple-600',
                // AWS / Azure cloud scans
                aws_scan: 'bg-orange-600',
                azure_scan: 'bg-blue-600',
                // Settings + system-level actions (all red — destructive or
                // platform-affecting in nature)
                settings: 'bg-red-600',
                system_purge: 'bg-red-700',
                prepare_package: 'bg-red-700',
                upgrade: 'bg-red-700',
                support_bundle: 'bg-red-700',
                maintenance: 'bg-red-700',
                // Customer-facing reporting
                engagement_report: 'bg-yellow-600',
            };
            return colors[type] || 'bg-slate-700';
        },

        getLogColor(level) {
            const colors = { info: 'text-blue-400', success: 'text-green-400', error: 'text-red-400', warning: 'text-yellow-400' };
            return colors[level] || 'text-gray-400';
        },

        formatLogMessage(message) {
            // Make download URLs clickable
            if (message && message.includes('/api/velociraptor/offline/download/')) {
                const urlMatch = message.match(/(\/api\/velociraptor\/offline\/download\/[^\s]+)/);
                if (urlMatch) {
                    const url = urlMatch[1];
                    return message.replace(url, `<a href="${url}" class="text-purple-400 hover:text-purple-300 underline" download>Download Collector</a>`);
                }
            }
            // Escape HTML for safety
            const div = document.createElement('div');
            div.textContent = message;
            return div.innerHTML;
        },

        formatTime(timestamp) {
            return timestamp ? new Date(timestamp).toLocaleString() : 'Unknown';
        },

        downloadPackage(runId) {
            // Download immediately - package validity checked server-side
            window.location.href = `/api/upgrade/prepare/${runId}/download`;
        }
    });

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

        async runRefreshSkills() {
            this.showMessage('Refreshing DFIR skills from upstream...', 'info');
            try {
                const response = await fetch('/api/maintenance/refresh-skills', { method: 'POST' });
                const result = await response.json();
                if (response.ok && result.success) {
                    this.showMessage('Skills refresh started - redirecting to Workflows', 'success');
                    setTimeout(() => {
                        Alpine.store('app').switchTab('workflows');
                    }, 500);
                } else {
                    this.showMessage('Skills refresh failed: ' + (result.error || 'Unknown error'), 'error');
                }
            } catch (e) {
                this.showMessage('Skills refresh error: ' + e.message, 'error');
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
            for (const s of this.purgeSections) this.purgeSelected[s.id] = !!value;
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
        prepareModules: [
            { id: 'elk', name: 'ELK Stack', targetVersion: '', enabled: false, fallback: '8.17.0' },
            { id: 'timesketch', name: 'Timesketch', targetVersion: '', enabled: false, fallback: '20240919' },
            { id: 'plaso', name: 'Plaso (Timeline)', targetVersion: '', enabled: false, fallback: '20240308' },
            { id: 'iris', name: 'IRIS', targetVersion: '', enabled: false, fallback: 'v2.4.19' },
            { id: 'velociraptor', name: 'Velociraptor', targetVersion: '', enabled: false, fallback: '0.73.4' },
            { id: 'aws', name: 'AWS (Prowler)', targetVersion: '', enabled: false, fallback: '5.28.1' },
            { id: 'azure', name: 'Azure (DFIR-O365RC)', targetVersion: '', enabled: false, fallback: 'latest' },
            // VolWeb — apply orchestrator picks install_volweb_offline vs
            // upgrade_volweb_offline automatically based on whether
            // intact_volweb_backend exists on the host. Lets operators
            // package + deploy a module that wasn't selected at install
            // time without re-running install.sh.
            { id: 'volweb', name: 'VolWeb (Memory Forensics)', targetVersion: '', enabled: false, fallback: 'latest' },
            { id: 'intact', name: 'Intact.AI Source Code', targetVersion: 'intact-20260604', enabled: false, fallback: 'intact-20260604' },
        ],

        async openPreparePackageModal() {
            this.showPreparePackageModal = true;
            this.prepareLoading = true;
            this.prepareRunId = null;
            this.preparePackageReady = false;
            this.preparePackageSize = '';

            // Reset modules
            this.prepareModules.forEach(m => {
                m.enabled = false;
                m.targetVersion = '';
            });

            try {
                const response = await fetch('/api/upgrade/status');
                const data = await response.json();
                if (data.success && data.versions) {
                    this.prepareModules.forEach(m => {
                        // The `intact` module is a GitHub ref (release tag /
                        // branch / commit SHA), NOT a docker image tag — the
                        // /api/upgrade/status "latest" lookup queries Docker
                        // Hub for image tags and returns nonsense (e.g.
                        // "1.0.0") for intact. Use the configured fallback,
                        // which is a real GitHub release tag.
                        if (m.id === 'intact') {
                            m.targetVersion = m.fallback;
                            return;
                        }
                        const ver = data.versions[m.id];
                        if (ver) {
                            m.targetVersion = ver.latest || m.fallback;
                        }
                    });
                } else {
                    // Use fallback versions
                    this.prepareModules.forEach(m => {
                        m.targetVersion = m.fallback;
                    });
                }
            } catch (e) {
                console.error('Failed to fetch versions, using fallbacks:', e);
                this.prepareModules.forEach(m => {
                    m.targetVersion = m.fallback;
                });
            }
            this.prepareLoading = false;
        },

        closePreparePackageModal() {
            this.showPreparePackageModal = false;
            this.preparePackageReady = false;
            this.prepareRunId = null;
        },

        async startPackagePreparation() {
            const selected = this.prepareModules.filter(m => m.enabled);
            if (selected.length === 0) {
                this.showMessage('Select at least one module to include', 'error');
                return;
            }

            const modules = {};
            selected.forEach(m => {
                modules[m.id] = m.targetVersion || m.latest || '1.0.0';
            });

            this.prepareLoading = true;
            try {
                const response = await fetch('/api/upgrade/prepare', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ modules })
                });

                const result = await response.json();
                if (response.ok && result.success) {
                    this.prepareRunId = result.run_id;
                    this.closePreparePackageModal();
                    this.showMessage('Package preparation started - check Workflows for progress', 'success');
                    setTimeout(() => {
                        Alpine.store('app').switchTab('workflows');
                    }, 500);
                } else {
                    this.showMessage('Failed to start preparation: ' + (result.error || 'Unknown error'), 'error');
                }
            } catch (e) {
                this.showMessage('Preparation error: ' + e.message, 'error');
            }
            this.prepareLoading = false;
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
        importUpgradePackage(event) {
            const files = event.target.files;
            if (!files || files.length === 0) return;

            const file = files[0];

            // Validate file extension
            if (!file.name.endsWith('.tar.gz') && !file.name.endsWith('.tgz')) {
                this.showMessage('Please select a .tar.gz or .tgz file', 'error');
                event.target.value = ''; // Reset input
                return;
            }

            // Check if any fresh install is enabled
            const dbOverwrite = this.getDbOverwrite();
            const freshInstallModules = Object.entries(dbOverwrite).filter(([k, v]) => v).map(([k]) => k);
            if (freshInstallModules.length > 0) {
                if (!confirm(`Fresh install selected for: ${freshInstallModules.join(', ').toUpperCase()}\n\nThis will remove existing data to allow new database schema. Continue?`)) {
                    event.target.value = ''; // Reset input
                    return;
                }
            }

            // Show message and redirect to workflows immediately
            this.showMessage(`Uploading ${file.name}...`, 'info');
            Alpine.store('app').switchTab('workflows');

            // Start upload in background - backend will create workflow and auto-start upgrade
            const upload = new tus.Upload(file, {
                endpoint: '/api/uploads/',
                retryDelays: [0, 1000, 3000, 5000],
                chunkSize: 5 * 1024 * 1024,
                metadata: {
                    filename: file.name,
                    filetype: file.type || 'application/gzip',
                    purpose: 'upgrade_package',
                    db_overwrite: JSON.stringify(dbOverwrite)
                },
                onError: (error) => {
                    console.error('Upload error:', error);
                    this.showMessage('Upload failed: ' + error.message, 'error');
                },
                onSuccess: () => {
                    // Backend handles everything - just refresh workflows
                    Alpine.store('workflows').load();
                }
            });

            upload.start();
            event.target.value = ''; // Reset input for next upload
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

// Initialize on DOM ready
document.addEventListener('DOMContentLoaded', () => {
    // Wait for Alpine to be ready
    setTimeout(() => {
        // Initial load
        Alpine.store('services').checkAll();
        Alpine.store('services').loadClients();

        // Handle URL hash on initial load + on any subsequent change
        // (manual edit in URL bar, browser back/forward between hashes).
        // switchTab() writes the same hash value (line 54) so this never
        // loops.
        const applyHash = () => {
            const tab = window.location.hash.replace('#', '') || 'dashboard';
            Alpine.store('app').switchTab(tab);
        };
        if (window.location.hash) applyHash();
        window.addEventListener('hashchange', applyHash);

        // Load blueprints for all modules
        loadBlueprints('velociraptor').then(() => {
            populateBlueprintDropdown('bestpractice-blueprint-select', 'best_practice', 'velociraptor');
        });
        // Load timesketch blueprints
        loadBlueprints('timesketch').then(() => {
            loadTimesketchBlueprintsDropdown();
        });
        // Load unified forensics blueprints for offline collector
        loadBlueprints('forensics').then(() => {
            if (typeof loadOfflineBlueprints === 'function') {
                loadOfflineBlueprints().then(() => populateConfigDropdown());
            }
        });

        // Fast refresh for workflows (1 second)
        setInterval(() => {
            if (Alpine.store('app').currentTab === 'workflows') {
                Alpine.store('workflows').load();
            }
        }, 1000);

        // Slower refresh for services and clients (10 seconds)
        setInterval(() => {
            Alpine.store('services').checkAll();
            Alpine.store('services').loadClients();
            if (Alpine.store('app').currentTab === 'modules-timesketch') {
                populateTimeSketchClients();
            }
        }, 10000);
    }, 100);
});

// Global config for compatibility
window.currentConfig = null;
function getConfig() {
    return window.currentConfig || window.defaultConfig;
}

// Legacy function compatibility for onclick handlers in HTML
function switchTab(tabName) {
    Alpine.store('app').switchTab(tabName);
}

function toggleModulesDropdown() {
    Alpine.store('app').toggleModules();
}

function loadWorkflows() {
    Alpine.store('workflows').load();
}

function viewWorkflowLogs(runId) {
    Alpine.store('workflows').viewLogs(runId);
}

function closeLogModal() {
    Alpine.store('workflows').closeModal();
}

function loadSettings() {
    Alpine.store('settings').load();
}

function runSystemMaintenance() {
    Alpine.store('settings').runMaintenance();
}

function checkAllServices() {
    Alpine.store('services').checkAll();
}

function loadClientCount() {
    Alpine.store('services').loadClients();
}

function refreshAll() {
    Alpine.store('services').checkAll();
    Alpine.store('services').loadClients();
}

// Settings form init (legacy compatibility)
function initSettingsForm() {
    // Now handled by Alpine x-model bindings
}
