/**
 * Client Manager - Shared client selection utilities
 *
 * Usage:
 *   const manager = new ClientManager('agentic-client-list', 'agentic-client-cb');
 *   await manager.load();
 *   manager.filter('hostname');
 *   manager.selectAll(true);
 *   const selected = manager.getSelected();
 */

class ClientManager {
    constructor(containerId, checkboxClass, options = {}) {
        this.containerId = containerId;
        this.checkboxClass = checkboxClass;
        this.cache = [];
        this.autoSelectOnline = options.autoSelectOnline !== false; // Default true
        this.onlineThreshold = options.onlineThreshold || 600; // 10 minutes
    }

    /**
     * Load clients from API and render
     */
    async load() {
        const container = document.getElementById(this.containerId);
        if (!container) return;

        try {
            const response = await fetch('/api/clients');
            if (!response.ok) {
                container.innerHTML = '<p class="text-sm text-red-400">Failed to load clients</p>';
                return;
            }

            const data = await response.json();
            const clients = data.items || [];

            if (clients.length === 0) {
                container.innerHTML = '<p class="text-sm text-gray-500">No clients found</p>';
                return;
            }

            // Sort: online first, then alphabetically
            const now = Date.now() / 1000;
            this.cache = clients.sort((a, b) => {
                const aOnline = this._isOnline(a, now);
                const bOnline = this._isOnline(b, now);
                if (aOnline && !bOnline) return -1;
                if (!aOnline && bOnline) return 1;
                return (a.hostname || '').localeCompare(b.hostname || '');
            });

            this.render(this.cache);
        } catch (error) {
            container.innerHTML = `<p class="text-sm text-red-400">Error: ${error.message}</p>`;
        }
    }

    /**
     * Render clients to container
     */
    render(clients, filter = '') {
        const container = document.getElementById(this.containerId);
        if (!container) return;

        const now = Date.now() / 1000;
        const selectedIds = this.getSelected();

        // Filter by hostname if provided
        const filtered = filter
            ? clients.filter(c => (c.hostname || '').toLowerCase().includes(filter.toLowerCase()))
            : clients;

        if (filtered.length === 0) {
            container.innerHTML = '<p class="text-sm text-gray-500">No clients match filter</p>';
            return;
        }

        container.innerHTML = filtered.map(client => {
            const isOnline = this._isOnline(client, now);
            const wasSelected = selectedIds.includes(client.client_id);
            const shouldCheck = wasSelected || (this.autoSelectOnline && isOnline && !filter);
            const dot = isOnline
                ? '<span class="inline-block w-2 h-2 bg-green-400 rounded-full"></span>'
                : '<span class="inline-block w-2 h-2 bg-gray-500 rounded-full"></span>';

            return `
                <label class="flex items-center gap-3 p-2 rounded hover:bg-gray-800 cursor-pointer">
                    <input type="checkbox" class="${this.checkboxClass}" value="${client.client_id}" ${shouldCheck ? 'checked' : ''}>
                    ${dot}
                    <div class="flex-1 min-w-0">
                        <span class="text-sm text-white">${client.hostname || 'Unknown'}</span>
                        <span class="text-xs text-gray-500 ml-2">${client.os || ''}</span>
                    </div>
                    <span class="text-xs text-gray-600 font-mono truncate">${client.client_id.substring(0, 12)}...</span>
                </label>
            `;
        }).join('');
    }

    /**
     * Filter clients by search term
     */
    filter(searchTerm) {
        this.render(this.cache, searchTerm);
    }

    /**
     * Select/deselect all visible clients
     */
    selectAll(checked) {
        document.querySelectorAll(`.${this.checkboxClass}`).forEach(cb => cb.checked = checked);
    }

    /**
     * Get selected client IDs
     */
    getSelected() {
        return Array.from(document.querySelectorAll(`.${this.checkboxClass}:checked`)).map(cb => cb.value);
    }

    /**
     * Get cached clients
     */
    getCache() {
        return this.cache;
    }

    /**
     * Check if client is online
     */
    _isOnline(client, now) {
        const lastSeen = client.last_seen_at ? client.last_seen_at / 1000000 : 0;
        return (now - lastSeen) < this.onlineThreshold;
    }
}

// Export for use in other modules
window.ClientManager = ClientManager;
