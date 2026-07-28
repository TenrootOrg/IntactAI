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

        // Wipe the "run started / redirecting…" banners an automation page
        // leaves behind. Starting a run shows one, then navigates to Workflows
        // 600ms later — but nothing ever cleared it, so coming back to
        // Velociraptor (or TimeSketch, or CVE) showed the PREVIOUS run's
        // message as if it had just happened. Worst case the operator reads a
        // stale run id and goes looking for the wrong workflow.
        //
        // Driven by the js-run-status class rather than a hardcoded id list,
        // so a new automation page gets this by adding the class — a list here
        // would silently rot the first time someone forgets to update it.
        // Store-backed banners have no element to find, so they are reset
        // explicitly; each guard is independent because these stores are
        // registered by separately-loaded partials and may not exist yet.
        _clearRunStatus() {
            // Banners are plain DOM (getElementById + innerHTML), so they are
            // invisible to the snapshot reset in TabReset. Driven by a class
            // rather than a hardcoded id list: a new automation page gets this
            // by adding js-run-status, whereas a list here rots silently the
            // first time someone forgets to update it.
            try {
                document.querySelectorAll('.js-run-status').forEach(el => {
                    el.innerHTML = '';
                    el.classList.add('hidden');
                });
            } catch (e) { /* pre-Alpine / headless */ }
        },

        // Restore plain form controls in the entered panel to their markup
        // defaults. Velociraptor and TimeSketch drive their forms with
        // getElementById rather than Alpine, so TabReset's snapshot cannot see
        // them — a client filter, a selection, a changed collection time all
        // survived a tab switch.
        //
        // x-model inputs are SKIPPED deliberately: Alpine owns those, and
        // writing .value behind its back desyncs the two (Alpine overwrites on
        // the next reactive tick, so the reset would appear to work and then
        // silently undo itself). Those panels are armed with TabReset instead.
        _resetPanelInputs(tab) {
            try {
                const panel = document.querySelector(`[data-automation-tab="${tab}"]`);
                if (!panel) return;
                panel.querySelectorAll('input, select, textarea').forEach(el => {
                    if (el.hasAttribute('x-model')) return;
                    if (el.type === 'checkbox' || el.type === 'radio') {
                        el.checked = el.defaultChecked;
                    } else if (el.tagName === 'SELECT') {
                        // defaultSelected is per-option; fall back to the first
                        // option when the markup marks none.
                        let restored = false;
                        Array.from(el.options).forEach(o => {
                            o.selected = o.defaultSelected;
                            restored = restored || o.defaultSelected;
                        });
                        if (!restored) el.selectedIndex = 0;
                    } else if (el.type !== 'file') {
                        el.value = el.defaultValue;
                    } else {
                        el.value = '';        // file inputs reject any other value
                    }
                });
            } catch (e) { /* headless */ }
        },

        switchTab(tab) {
            // Clear before the tab renders, so the incoming panel never paints
            // the previous run's banner, even for a frame.
            this._clearRunStatus();
            this._resetPanelInputs(tab);
            this.currentTab = tab;
            window.location.hash = tab;
            // Panels armed with TabReset.arm() restore their defaults here.
            // Fired AFTER currentTab so a panel's own x-init/$watch (which
            // repopulates dropdowns) runs against already-reset state rather
            // than being undone by it.
            try {
                window.dispatchEvent(new CustomEvent('automation-tab-entered',
                                                     { detail: tab }));
            } catch (e) { /* headless */ }
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
