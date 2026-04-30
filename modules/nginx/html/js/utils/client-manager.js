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
        this.autoSelectOnline = options.autoSelectOnline !== false;
        this.onlineThreshold = options.onlineThreshold || 600;
        this.limit = options.limit || 20;
        this.totalClients = 0;
        this.filteredCount = 0;
        this._searchTimeout = null;
    }

    /**
     * Load clients from API with optional search and render
     */
    async load(search = '') {
        const container = document.getElementById(this.containerId);
        if (!container) return;

        try {
            let url = `/api/clients?limit=${this.limit}`;
            if (search) url += `&search=${encodeURIComponent(search)}`;

            const response = await fetch(url);
            if (!response.ok) {
                container.innerHTML = '<p class="text-sm text-red-400">Failed to load clients</p>';
                return;
            }

            const data = await response.json();
            const clients = data.items || [];
            this.totalClients = data.total || 0;
            this.filteredCount = data.filtered || clients.length;

            if (clients.length === 0) {
                container.innerHTML = search
                    ? '<p class="text-sm text-gray-500">No clients match your search</p>'
                    : '<p class="text-sm text-gray-500">No clients found</p>';
                return;
            }

            // Sort: online first, then alphabetically
            const now = Date.now() / 1000;
            clients.sort((a, b) => {
                const aOnline = this._isOnline(a, now);
                const bOnline = this._isOnline(b, now);
                if (aOnline && !bOnline) return -1;
                if (!aOnline && bOnline) return 1;
                return (a.hostname || '').localeCompare(b.hostname || '');
            });

            this.render(clients, search);
        } catch (error) {
            container.innerHTML = `<p class="text-sm text-red-400">Error: ${error.message}</p>`;
        }
    }

    /**
     * Render clients to container, grouped by OS. Only OSes that have at
     * least one client get a header; "Unknown" goes last when present.
     */
    render(clients, search = '') {
        const container = document.getElementById(this.containerId);
        if (!container) return;

        const now = Date.now() / 1000;
        const selectedIds = this.getSelected();

        // Group by normalized OS. Empty / missing values fall into a single
        // "Unknown" bucket so we render at most one fallback header.
        const groups = {};
        for (const c of clients) {
            const key = this._osKey(c.os);
            (groups[key] = groups[key] || []).push(c);
        }

        // Stable display order: Windows → Linux → macOS → others alphabetical
        // → Unknown last. Skip any group that's empty (cheap guard, shouldn't
        // happen since we only populated keys we saw, but defensive).
        const preferred = ['Windows', 'Linux', 'macOS'];
        const others = Object.keys(groups)
            .filter(k => !preferred.includes(k) && k !== 'Unknown')
            .sort();
        const orderedKeys = [
            ...preferred.filter(k => groups[k] && groups[k].length),
            ...others,
            ...(groups['Unknown'] && groups['Unknown'].length ? ['Unknown'] : []),
        ];

        const renderClient = (client) => {
            const isOnline = this._isOnline(client, now);
            const wasSelected = selectedIds.includes(client.client_id);
            const shouldCheck = wasSelected || (this.autoSelectOnline && isOnline && !search);
            const dot = isOnline
                ? '<span class="inline-block w-2 h-2 bg-green-400 rounded-full"></span>'
                : '<span class="inline-block w-2 h-2 bg-gray-500 rounded-full"></span>';
            return `
                <label class="flex items-center gap-3 p-2 rounded hover:bg-gray-800 cursor-pointer">
                    <input type="checkbox" class="${this.checkboxClass}" value="${client.client_id}" data-hostname="${client.hostname || 'Unknown'}" ${shouldCheck ? 'checked' : ''}>
                    ${dot}
                    <div class="flex-1 min-w-0">
                        <span class="text-sm text-white">${client.hostname || 'Unknown'}</span>
                        <span class="text-xs text-gray-500 ml-2">${client.os || ''}</span>
                    </div>
                    <span class="text-xs text-gray-600 font-mono truncate">${client.client_id.substring(0, 12)}...</span>
                </label>
            `;
        };

        let html = orderedKeys.map(key => {
            const groupClients = groups[key];
            const heading = `
                <div class="flex items-center gap-2 px-2 pt-2 pb-1 mt-1 border-t border-gray-800 first:border-t-0 first:mt-0 first:pt-0">
                    <span class="text-xs uppercase tracking-wide text-gray-400 font-semibold">${key}</span>
                    <span class="text-xs text-gray-600">(${groupClients.length})</span>
                </div>
            `;
            return heading + groupClients.map(renderClient).join('');
        }).join('');

        // Show "more results" hint if there are more than displayed
        if (this.filteredCount > clients.length) {
            const more = this.filteredCount - clients.length;
            html += `<p class="text-xs text-gray-500 text-center py-2">${more} more — refine your search</p>`;
        }

        container.innerHTML = html;
    }

    /**
     * Normalize a client's `os` field to a stable display key.
     * Returns 'Windows', 'Linux', 'macOS', 'Unknown', or a Title-Cased
     * version of the original value for anything we don't explicitly map.
     */
    _osKey(os) {
        if (!os) return 'Unknown';
        const s = String(os).trim().toLowerCase();
        if (!s) return 'Unknown';
        if (s === 'windows' || s.startsWith('win')) return 'Windows';
        if (s === 'linux') return 'Linux';
        if (s === 'darwin' || s === 'macos' || s === 'osx' || s === 'mac') return 'macOS';
        return s.charAt(0).toUpperCase() + s.slice(1);
    }

    /**
     * Filter clients by search term (debounced API call)
     */
    filter(searchTerm) {
        clearTimeout(this._searchTimeout);
        this._searchTimeout = setTimeout(() => this.load(searchTerm), 300);
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
     * Check if client is online
     */
    _isOnline(client, now) {
        const lastSeen = client.last_seen_at ? client.last_seen_at / 1000000 : 0;
        return (now - lastSeen) < this.onlineThreshold;
    }
}

window.ClientManager = ClientManager;
