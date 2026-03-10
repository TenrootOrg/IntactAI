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
        online_llm: { provider: "claude", api_key: "", model: "claude-sonnet-4-20250514", batch_size: 100 },
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
        }
    });

    // Settings store
    Alpine.store('settings', {
        config: {
            agentic: {
                llm_mode: 'offline',
                offline_llm: { provider: 'ollama', model: 'llama3.3:70b', url: 'http://localhost:11434', batch_size: 100 },
                online_llm: { provider: 'claude', api_key: '', model: 'claude-sonnet-4-20250514', batch_size: 100 },
                max_concurrent_requests: 5
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
                        max_concurrent_requests: data.agentic?.max_concurrent_requests || 5
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

        onProviderChange() {
            const modelDefaults = {
                'openai': 'gpt-4o',
                'claude': 'claude-sonnet-4-20250514',
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
