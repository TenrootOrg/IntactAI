/**
 * MSSP Platform - Alpine.js Application
 * Consolidates: main.js, services.js, settings.js, workflows.js
 */

// Global configuration
window.baseHost = window.location.hostname;
window.services = {
    velociraptor: { path: '/velociraptor/', protocol: 'https' },
    timesketch: { port: 5000, protocol: 'http' },
    kibana: { port: 5601, protocol: 'http' },
    iris: { port: 8443, protocol: 'https' },
    portainer: { port: 9443, protocol: 'https' }
};

window.defaultConfig = {
    agentic: {
        llm_mode: "offline",
        offline_llm: { provider: "ollama", model: "llama3.3:70b", url: "http://localhost:11434", batch_size: 100 },
        online_llm: { provider: "claude", api_key: "", model: "claude-sonnet-4-6", batch_size: 100 },
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
        clients: [],
        clientCount: 0,
        onlineCount: 0,
        onlineClients: [],

        async checkAll() {
            for (const serviceId in window.services) {
                await this.checkService(serviceId);
            }
            this.updateStats();
        },

        async checkService(serviceId) {
            const service = window.services[serviceId];
            this.statuses[serviceId] = 'checking';

            try {
                const controller = new AbortController();
                const timeoutId = setTimeout(() => controller.abort(), 3000);
                const url = service.path
                    ? `${service.protocol}://${window.baseHost}${service.path}`
                    : `${service.protocol}://${window.baseHost}:${service.port}/`;

                await fetch(url, { method: 'HEAD', signal: controller.signal, mode: 'no-cors', credentials: 'omit' });
                clearTimeout(timeoutId);
                this.statuses[serviceId] = 'online';
            } catch {
                this.statuses[serviceId] = 'offline';
            }
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
                    this.clients = data.items || [];
                    this.clientCount = this.clients.length;

                    const now = Date.now() / 1000;
                    this.onlineClients = this.clients.filter(c => {
                        const lastSeen = c.last_seen_at ? c.last_seen_at / 1000000 : 0;
                        return (now - lastSeen) < 600;
                    });

                    // Sort clients by online status
                    this.clients.sort((a, b) => {
                        const aOnline = (now - (a.last_seen_at ? a.last_seen_at / 1000000 : 0)) < 600;
                        const bOnline = (now - (b.last_seen_at ? b.last_seen_at / 1000000 : 0)) < 600;
                        if (aOnline && !bOnline) return -1;
                        if (!aOnline && bOnline) return 1;
                        return 0;
                    });
                }
            } catch (e) {
                console.error('Failed to load clients:', e);
            }
        },

        isClientOnline(client) {
            const now = Date.now() / 1000;
            const lastSeen = client.last_seen_at ? client.last_seen_at / 1000000 : 0;
            return (now - lastSeen) < 600;
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

                // Start auto-refresh every 2 seconds
                this.startAutoRefresh(runId);

                // Scroll to bottom if autoScroll enabled
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

        getStatusColor(status) {
            const colors = { running: 'bg-blue-600', completed: 'bg-green-600', failed: 'bg-red-600' };
            return colors[status] || 'bg-gray-600';
        },

        getTypeColor(type) {
            const colors = { timesketch: 'bg-purple-600', velociraptor_hunt: 'bg-green-600', hunt: 'bg-orange-600', artifact: 'bg-blue-600', agentic: 'bg-pink-600', maintenance: 'bg-yellow-600', velociraptor_offline_collector: 'bg-teal-600', velociraptor_offline_import: 'bg-teal-600', offline_collector: 'bg-teal-600', offline_import: 'bg-teal-600', settings: 'bg-red-600' };
            return colors[type] || 'bg-gray-600';
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

        async downloadPackage(runId) {
            try {
                // Check if package is available
                const response = await fetch(`/api/upgrade/prepare/${runId}/status`);
                const data = await response.json();

                if (data.ready) {
                    // Package available - trigger download
                    window.location.href = `/api/upgrade/prepare/${runId}/download`;
                } else {
                    // Package expired or not found
                    window.dispatchEvent(new CustomEvent('show-toast', {
                        detail: {
                            type: 'warning',
                            title: 'Package Expired',
                            message: 'Packages are deleted after 24 hours. Please prepare a new package.'
                        }
                    }));
                }
            } catch (e) {
                console.error('Failed to check package status:', e);
                window.dispatchEvent(new CustomEvent('show-toast', {
                    detail: {
                        type: 'error',
                        title: 'Error',
                        message: 'Failed to check package availability.'
                    }
                }));
            }
        }
    });

    // Settings store
    Alpine.store('settings', {
        config: {
            agentic: {
                llm_mode: 'offline',
                offline_llm: { provider: 'ollama', model: 'llama3.3:70b', url: 'http://localhost:11434', batch_size: 100 },
                online_llm: { provider: 'claude', api_key: '', model: 'claude-sonnet-4-6', batch_size: 100 },
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

        // Upgrade modal state
        showUpgradeModal: false,
        upgradeLoading: false,
        upgradeModules: [
            { id: 'elk', name: 'ELK Stack', current: '', targetVersion: '', enabled: false, note: 'Downgrades not supported' },
            { id: 'timesketch', name: 'Timesketch', current: '', targetVersion: '', enabled: false },
            { id: 'plaso', name: 'Plaso (Timeline)', current: '', targetVersion: '', enabled: false, note: 'Used by Timesketch' },
            { id: 'iris', name: 'IRIS', current: '', targetVersion: '', enabled: false },
            { id: 'velociraptor', name: 'Velociraptor', current: '', targetVersion: '', enabled: false },
            { id: 'risx', name: 'RISX Platform', current: '', targetVersion: '', enabled: false, note: 'Backend + Frontend' },
        ],

        async openUpgradeModal() {
            this.showUpgradeModal = true;
            this.upgradeLoading = true;

            // Reset modules
            this.upgradeModules.forEach(m => {
                m.enabled = false;
                m.current = '';
                m.targetVersion = '';
            });

            try {
                const response = await fetch('/api/upgrade/status');
                const data = await response.json();
                if (data.success && data.versions) {
                    this.upgradeModules.forEach(m => {
                        const ver = data.versions[m.id];
                        if (ver) {
                            m.current = ver.current || 'unknown';
                            m.targetVersion = ver.latest || ver.current || '';
                        }
                    });
                }
            } catch (e) {
                console.error('Failed to fetch versions:', e);
                this.showMessage('Failed to fetch module versions', 'error');
            }
            this.upgradeLoading = false;
        },

        closeUpgradeModal() {
            this.showUpgradeModal = false;
        },

        // Helper to compare version strings
        compareVersions(v1, v2) {
            const parse = (v) => (v || '0').replace(/^v/, '').split('.').map(n => parseInt(n) || 0);
            const p1 = parse(v1), p2 = parse(v2);
            const len = Math.max(p1.length, p2.length);
            for (let i = 0; i < len; i++) {
                const a = p1[i] || 0, b = p2[i] || 0;
                if (a < b) return -1;
                if (a > b) return 1;
            }
            return 0;
        },

        async startUpgrade() {
            const selected = this.upgradeModules.filter(m => m.enabled);
            if (selected.length === 0) {
                this.showMessage('Select at least one module to upgrade', 'error');
                return;
            }

            // Check for ELK downgrade attempt
            const elk = selected.find(m => m.id === 'elk');
            if (elk && this.compareVersions(elk.targetVersion, elk.current) < 0) {
                this.showMessage('ELK downgrade not supported. Elasticsearch only allows forward upgrades.', 'error');
                return;
            }

            const modules = {};
            selected.forEach(m => {
                modules[m.id] = m.targetVersion;
            });

            this.upgradeLoading = true;
            try {
                const response = await fetch('/api/upgrade/start', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ modules, mode: 'online' })
                });

                const result = await response.json();
                if (response.ok && result.success) {
                    this.closeUpgradeModal();
                    this.showMessage('Upgrade started - redirecting to Workflows', 'success');
                    setTimeout(() => {
                        Alpine.store('app').switchTab('workflows');
                    }, 500);
                } else {
                    this.showMessage('Failed to start upgrade: ' + (result.error || 'Unknown error'), 'error');
                }
            } catch (e) {
                this.showMessage('Upgrade error: ' + e.message, 'error');
            }
            this.upgradeLoading = false;
        },

        // ===== PREPARE UPGRADE PACKAGE =====
        showPreparePackageModal: false,
        prepareLoading: false,
        prepareRunId: null,
        preparePackageReady: false,
        preparePackageSize: '',
        prepareModules: [
            { id: 'elk', name: 'ELK Stack', latest: '', targetVersion: '', enabled: false },
            { id: 'timesketch', name: 'Timesketch', latest: '', targetVersion: '', enabled: false },
            { id: 'plaso', name: 'Plaso (Timeline)', latest: '', targetVersion: '', enabled: false },
            { id: 'iris', name: 'IRIS', latest: '', targetVersion: '', enabled: false },
            { id: 'velociraptor', name: 'Velociraptor', latest: '', targetVersion: '', enabled: false },
            { id: 'risx', name: 'RISX Source Code', latest: '1.0.0', targetVersion: '1.0.0', enabled: false },
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
                        const ver = data.versions[m.id];
                        if (ver) {
                            m.latest = ver.latest || 'unknown';
                            m.targetVersion = ver.latest || '';
                        }
                    });
                }
            } catch (e) {
                console.error('Failed to fetch versions:', e);
                this.showMessage('Failed to fetch module versions', 'error');
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
        showOfflineUpgradeModal: false,
        offlineUploadDragging: false,
        offlineUploadProgress: 0,
        offlinePackageInfo: null,
        offlinePackagePath: null,
        offlineUpgradeStarting: false,

        openOfflineUpgradeModal() {
            this.showOfflineUpgradeModal = true;
            this.offlineUploadProgress = 0;
            this.offlinePackageInfo = null;
            this.offlinePackagePath = null;
            this.offlineUpgradeStarting = false;
        },

        closeOfflineUpgradeModal() {
            this.showOfflineUpgradeModal = false;
            this.offlinePackageInfo = null;
            this.offlinePackagePath = null;
        },

        handleOfflineDrop(event) {
            this.offlineUploadDragging = false;
            const files = event.dataTransfer.files;
            if (files.length > 0) {
                this.uploadOfflinePackage(files[0]);
            }
        },

        selectOfflinePackage(event) {
            const files = event.target.files;
            if (files.length > 0) {
                this.uploadOfflinePackage(files[0]);
            }
        },

        async uploadOfflinePackage(file) {
            // Validate file extension
            if (!file.name.endsWith('.tar.gz') && !file.name.endsWith('.tgz')) {
                this.showMessage('Please select a .tar.gz or .tgz file', 'error');
                return;
            }

            this.offlineUploadProgress = 0;

            // Use tus upload
            const upload = new tus.Upload(file, {
                endpoint: '/api/uploads/',
                retryDelays: [0, 1000, 3000, 5000],
                chunkSize: 5 * 1024 * 1024, // 5MB chunks
                metadata: {
                    filename: file.name,
                    filetype: file.type || 'application/gzip',
                    purpose: 'upgrade_package'
                },
                onError: (error) => {
                    console.error('Upload error:', error);
                    this.showMessage('Upload failed: ' + error.message, 'error');
                    this.offlineUploadProgress = 0;
                },
                onProgress: (bytesUploaded, bytesTotal) => {
                    this.offlineUploadProgress = Math.round((bytesUploaded / bytesTotal) * 100);
                },
                onSuccess: async () => {
                    this.offlineUploadProgress = 100;

                    // Upload complete - backend auto-starts upgrade via tus hook
                    // Just close modal and switch to workflows to see progress
                    this.showMessage('Upload complete - upgrade starting automatically', 'success');
                    this.closeOfflineUpgradeModal();
                    setTimeout(() => {
                        Alpine.store('app').switchTab('workflows');
                    }, 500);
                }
            });

            upload.start();
        },

        async startOfflineUpgrade() {
            if (!this.offlinePackagePath) {
                this.showMessage('No package uploaded', 'error');
                return;
            }

            this.offlineUpgradeStarting = true;

            try {
                const response = await fetch('/api/upgrade/offline', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ package_path: this.offlinePackagePath })
                });

                const result = await response.json();
                if (response.ok && result.success) {
                    this.closeOfflineUpgradeModal();
                    this.showMessage('Offline upgrade started - redirecting to Workflows', 'success');
                    setTimeout(() => {
                        Alpine.store('app').switchTab('workflows');
                    }, 500);
                } else {
                    this.showMessage('Failed to start upgrade: ' + (result.error || 'Unknown error'), 'error');
                }
            } catch (e) {
                this.showMessage('Upgrade error: ' + e.message, 'error');
            }

            this.offlineUpgradeStarting = false;
        },

        onProviderChange() {
            const modelDefaults = {
                'openai': 'gpt-4o',
                'claude': 'claude-sonnet-4-6',
                'gemini': 'gemini-pro',
                'openrouter': 'anthropic/claude-opus-4-6'
            };
            const defaultModel = modelDefaults[this.config.agentic.online_llm.provider];
            if (defaultModel) {
                this.config.agentic.online_llm.model = defaultModel;
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

        // Handle URL hash
        const hash = window.location.hash.replace('#', '');
        if (hash) {
            Alpine.store('app').switchTab(hash);
        }

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
