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
        offline_llm: { provider: "ollama", model: "llama3.3:70b", url: "http://localhost:11434" },
        online_llm: { provider: "claude", api_key: "", model: "claude-sonnet-latest" },
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
});

// Initialize after Alpine has started (partial-loader starts Alpine only once all
// partials are injected, so we hook 'alpine:initialized' rather than DOMContentLoaded).
document.addEventListener('alpine:initialized', () => {
    {
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
    }
});
