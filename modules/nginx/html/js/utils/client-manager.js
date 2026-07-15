/**
 * Client Manager - Shared client selection component (used by EVERY module's
 * target-client picker: scheduler, timesketch, velociraptor-collection, memory).
 *
 * Faceted filter: narrow the fleet by OS + Velociraptor label + online state +
 * name, then include/exclude the *filtered* set ("Select shown" / "Deselect
 * shown"). Selection is a Set model (source of truth) so a client stays
 * selected even while a facet hides its row.
 *
 * Usage (multi-select):
 *   const m = new ClientManager('schedule-client-list', 'schedule-client-cb');
 *   await m.load();
 *   m.getSelected();                 // -> ['C.123', ...]
 *   m.setSelected(['C.123']);        // restore a saved selection
 *
 * Usage (single-select, e.g. Memory acquisition):
 *   const m = new ClientManager('memory-client-list', 'memory-client-radio',
 *       { singleSelect: true, onChange: ids => store.selectedClient = ids[0] || '' });
 */

class ClientManager {
    constructor(containerId, checkboxClass, options = {}) {
        this.containerId = containerId;
        this.checkboxClass = checkboxClass;
        this.singleSelect = options.singleSelect === true;
        // Auto-check online clients on first load — a sensible default for the
        // multi-select pickers. Never for single-select (don't pre-pick a host).
        this.autoSelectOnline = this.singleSelect ? false : (options.autoSelectOnline !== false);
        this.onlineThreshold = options.onlineThreshold || 600;
        // Load the WHOLE fleet (incl. offline) once and filter client-side, so
        // the OS/label facets + online toggle can operate over everything
        // without re-hitting the API on every keystroke. Fleets are tens–low
        // hundreds of hosts; 1000 is generous headroom (truncation is flagged).
        this.limit = options.limit || 1000;
        this.onChange = typeof options.onChange === 'function' ? options.onChange : null;

        // Selection is a Set of client_ids — the source of truth. Survives
        // facet filtering (a hidden row's id stays selected).
        this.selected = new Set();

        // Facet state.
        this.onlineOnly = options.onlineOnly !== undefined ? options.onlineOnly : true;
        this.activeOs = new Set();
        this.activeLabels = new Set();
        this.search = '';

        this._clients = [];        // full fleet from the last load()
        this._shownCount = 0;      // rows passing facets on the last render()
        this.totalClients = 0;
        // Once the user touches the picker we stop re-applying the "auto-check
        // online" default on refreshes (so Select None doesn't get undone).
        this._userHasInteracted = false;
        this._listenerAttached = false;
        this._facetBar = null;
        this._radioName = `${containerId}-radio`;
    }

    /**
     * Load the full fleet from the API and render.
     */
    async load(search = null) {
        if (search !== null) this.search = search;
        const container = document.getElementById(this.containerId);
        if (!container) return;

        // Delegated change listener (attached once — survives re-renders since
        // the container element persists) keeps the Set model in sync with the
        // checkbox/radio the user clicked, WITHOUT a full re-render (which would
        // jump the scroll position). We only refresh the counts in place.
        if (!this._listenerAttached) {
            container.addEventListener('change', (e) => {
                const t = e.target;
                if (t && t.classList && t.classList.contains(this.checkboxClass)) {
                    this._onCheckboxChange(t.value, t.checked);
                }
            });
            this._listenerAttached = true;
        }

        try {
            let url = `/api/clients?limit=${this.limit}&include_offline=true`;
            if (this.search) url += `&search=${encodeURIComponent(this.search)}`;

            const response = await fetch(url);
            if (!response.ok) {
                container.innerHTML = '<p class="text-sm text-red-400">Failed to load clients</p>';
                return;
            }

            const data = await response.json();
            this._clients = data.items || [];
            this.totalClients = data.total || this._clients.length;

            this._applyAutoSelect();
            this.render();
        } catch (error) {
            container.innerHTML = `<p class="text-sm text-red-400">Error: ${error.message}</p>`;
        }
    }

    /** First-load smart default: check online clients (multi-select only). */
    _applyAutoSelect() {
        if (this._userHasInteracted || !this.autoSelectOnline) return;
        const now = Date.now() / 1000;
        for (const c of this._clients) {
            if (this._isOnline(c, now)) this.selected.add(c.client_id);
        }
    }

    /**
     * Render the facet bar + the client list (grouped by OS), showing only the
     * clients that pass the active facets.
     */
    render() {
        const container = document.getElementById(this.containerId);
        if (!container) return;

        const now = Date.now() / 1000;

        // Rows passing the active facets, sorted online-first then by hostname.
        const shown = this._clients
            .filter(c => this._passesFacets(c, now))
            .sort((a, b) => {
                const ao = this._isOnline(a, now), bo = this._isOnline(b, now);
                if (ao !== bo) return ao ? -1 : 1;
                return (a.hostname || '').localeCompare(b.hostname || '');
            });
        this._shownCount = shown.length;

        this._renderFacetBar();

        if (this._clients.length === 0) {
            container.innerHTML = '<p class="text-sm text-gray-500">No clients found</p>';
            return;
        }
        if (shown.length === 0) {
            container.innerHTML = '<p class="text-sm text-gray-500">No clients match the current filter</p>';
            return;
        }

        // Group shown clients by normalized OS: Windows → Linux → macOS →
        // others (alpha) → Unknown last.
        const groups = {};
        for (const c of shown) {
            const key = this._osKey(c.os);
            (groups[key] = groups[key] || []).push(c);
        }
        const preferred = ['Windows', 'Linux', 'macOS'];
        const others = Object.keys(groups)
            .filter(k => !preferred.includes(k) && k !== 'Unknown')
            .sort();
        const orderedKeys = [
            ...preferred.filter(k => groups[k] && groups[k].length),
            ...others,
            ...(groups['Unknown'] && groups['Unknown'].length ? ['Unknown'] : []),
        ];

        const inputType = this.singleSelect ? 'radio' : 'checkbox';
        const nameAttr = this.singleSelect ? ` name="${this._radioName}"` : '';
        const inputShape = this.singleSelect ? '' : 'rounded';

        const renderClient = (client) => {
            const isOnline = this._isOnline(client, now);
            const checked = this.selected.has(client.client_id) ? 'checked' : '';
            const dot = isOnline
                ? '<span class="inline-block w-2 h-2 bg-green-400 rounded-full"></span>'
                : '<span class="inline-block w-2 h-2 bg-gray-500 rounded-full"></span>';
            const labels = Array.isArray(client.labels) ? client.labels : [];
            // hostname/os/labels are Velociraptor-reported endpoint metadata —
            // an attacker-renamed/compromised host round-trips this into the
            // UI, so it must be escaped before going into innerHTML (was
            // previously interpolated raw).
            const safeClientId = escapeHtml(client.client_id || '');
            const safeHostname = escapeHtml(client.hostname || 'Unknown');
            const safeOs = escapeHtml(client.os || '');
            const labelChips = labels.map(l =>
                `<span class="text-[10px] px-1.5 py-0.5 rounded bg-blue-900/50 text-blue-300 border border-blue-800/60">${escapeHtml(l)}</span>`
            ).join(' ');
            return `
                <label class="flex items-center gap-3 p-2 rounded hover:bg-gray-800 cursor-pointer">
                    <input type="${inputType}"${nameAttr} class="${this.checkboxClass} w-4 h-4 ${inputShape} border-gray-700 bg-gray-900 text-blue-600" value="${safeClientId}" data-hostname="${safeHostname}" ${checked}>
                    ${dot}
                    <div class="flex-1 min-w-0">
                        <div class="flex items-center gap-2 flex-wrap">
                            <span class="text-sm text-white">${safeHostname}</span>
                            <span class="text-xs text-gray-500">${safeOs}</span>
                            ${labelChips}
                        </div>
                    </div>
                    <span class="text-xs text-gray-600 font-mono truncate">${safeClientId.substring(0, 12)}...</span>
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

        if (this.totalClients > this._clients.length) {
            const more = this.totalClients - this._clients.length;
            html += `<p class="text-xs text-gray-500 text-center py-2">${more} more not shown — fleet exceeds display cap</p>`;
        }

        container.innerHTML = html;
    }

    // ------------------------------------------------------------------
    // Facet bar
    // ------------------------------------------------------------------

    /** Create the facet bar (once) as a sibling directly above the list. */
    _ensureFacetBar() {
        if (this._facetBar) return this._facetBar;
        const container = document.getElementById(this.containerId);
        if (!container || !container.parentNode) return null;

        const bar = document.createElement('div');
        bar.className = 'mb-2 space-y-2';
        container.parentNode.insertBefore(bar, container);
        this._facetBar = bar;

        // Delegated click: OS/label/online chips + Select/Deselect shown.
        bar.addEventListener('click', (e) => {
            const el = e.target.closest('[data-facet],[data-act]');
            if (!el) return;
            e.preventDefault();
            if (el.dataset.act === 'select-shown') return this.selectFiltered(true);
            if (el.dataset.act === 'deselect-shown') return this.selectFiltered(false);
            if (el.dataset.facet === 'online') return this.setOnlineOnly(!this.onlineOnly);
            if (el.dataset.facet === 'os') return this.setOsFacet(el.dataset.val);
            if (el.dataset.facet === 'label') return this.setLabelFacet(el.dataset.val);
        });
        return bar;
    }

    _renderFacetBar() {
        const bar = this._ensureFacetBar();
        if (!bar) return;

        // Available facet values derived from the full fleet.
        const osSet = new Set();
        const labelSet = new Set();
        for (const c of this._clients) {
            osSet.add(this._osKey(c.os));
            (Array.isArray(c.labels) ? c.labels : []).forEach(l => { if (l) labelSet.add(String(l)); });
        }
        const preferred = ['Windows', 'Linux', 'macOS'];
        const osOrder = [
            ...preferred.filter(k => osSet.has(k)),
            ...[...osSet].filter(k => !preferred.includes(k) && k !== 'Unknown').sort(),
            ...(osSet.has('Unknown') ? ['Unknown'] : []),
        ];
        const labelOrder = [...labelSet].sort();

        const chip = (facet, val, label, active) => {
            const cls = active
                ? 'bg-blue-600 text-white border-blue-500'
                : 'bg-gray-700 text-gray-300 border-gray-600 hover:bg-gray-600';
            return `<button type="button" data-facet="${facet}" data-val="${val}" class="text-[11px] px-2 py-0.5 rounded-full border ${cls} transition-colors">${label}</button>`;
        };

        const osChips = osOrder.map(o => chip('os', o, o, this.activeOs.has(o))).join(' ');
        const labelChips = labelOrder.map(l => chip('label', l, l, this.activeLabels.has(l))).join(' ');
        const onlineChip = chip('online', '', 'Online only', this.onlineOnly);

        // Row 1: facet chips.
        const groups = [];
        if (osOrder.length) groups.push(`<span class="text-[10px] uppercase tracking-wide text-gray-500 mr-0.5">OS</span>${osChips}`);
        if (labelOrder.length) groups.push(`<span class="text-[10px] uppercase tracking-wide text-gray-500 mr-0.5">Label</span>${labelChips}`);
        groups.push(onlineChip);
        const chipRow = `<div class="flex flex-wrap items-center gap-1.5">${groups.join('<span class="mx-1 text-gray-700">·</span>')}</div>`;

        // Row 2: include/exclude actions (multi-select only) + counts.
        const counts = this.singleSelect
            ? `${this._shownCount} shown`
            : `${this._shownCount} shown · ${this.selected.size} selected`;
        const actions = this.singleSelect ? '' : `
            <div class="flex gap-2">
                <button type="button" data-act="select-shown" class="text-[11px] bg-gray-700 hover:bg-gray-600 px-2 py-0.5 rounded">Select shown</button>
                <button type="button" data-act="deselect-shown" class="text-[11px] bg-gray-700 hover:bg-gray-600 px-2 py-0.5 rounded">Deselect shown</button>
            </div>`;
        const actionRow = `<div class="flex items-center justify-between">${actions || '<span></span>'}<span class="text-[11px] text-gray-500">${counts}</span></div>`;

        bar.innerHTML = chipRow + actionRow;
    }

    /** Update just the counts text (cheap, no list re-render / no scroll jump). */
    _updateCounts() {
        if (!this._facetBar) return;
        const span = this._facetBar.querySelector('.flex.items-center.justify-between > span:last-child');
        if (span) {
            span.textContent = this.singleSelect
                ? `${this._shownCount} shown`
                : `${this._shownCount} shown · ${this.selected.size} selected`;
        }
    }

    // ------------------------------------------------------------------
    // Facet toggles
    // ------------------------------------------------------------------

    setOsFacet(val) {
        if (this.activeOs.has(val)) this.activeOs.delete(val); else this.activeOs.add(val);
        this.render();
    }

    setLabelFacet(val) {
        if (this.activeLabels.has(val)) this.activeLabels.delete(val); else this.activeLabels.add(val);
        this.render();
    }

    setOnlineOnly(on) {
        this.onlineOnly = !!on;
        this.render();
    }

    /**
     * Does a client pass every active facet? Groups AND together; within the
     * label group, a client matches if it carries ANY selected label.
     */
    _passesFacets(client, now) {
        if (this.activeOs.size && !this.activeOs.has(this._osKey(client.os))) return false;
        if (this.activeLabels.size) {
            const labels = Array.isArray(client.labels) ? client.labels.map(String) : [];
            if (!labels.some(l => this.activeLabels.has(l))) return false;
        }
        if (this.onlineOnly && !this._isOnline(client, now)) return false;
        if (this.search) {
            const hay = [
                client.hostname || '', client.os || '', client.os_version || '',
                (Array.isArray(client.labels) ? client.labels.join(' ') : ''),
            ].join(' ').toLowerCase();
            if (!hay.includes(this.search.toLowerCase())) return false;
        }
        return true;
    }

    // ------------------------------------------------------------------
    // Selection
    // ------------------------------------------------------------------

    /** Individual checkbox/radio toggle — update the Set, refresh counts only. */
    _onCheckboxChange(clientId, checked) {
        this._userHasInteracted = true;
        if (this.singleSelect) {
            this.selected = new Set(checked ? [clientId] : []);
        } else if (checked) {
            this.selected.add(clientId);
        } else {
            this.selected.delete(clientId);
        }
        this._updateCounts();
        this._fireChange();
    }

    /**
     * Debounced-free client-side name filter (kept as `filter` for the existing
     * oninput handlers). Filtering is local, so it's instant.
     */
    filter(searchTerm) {
        this.search = searchTerm || '';
        this.render();
    }

    /** Select/deselect the ENTIRE fleet (ignores facets). */
    selectAll(checked) {
        this._userHasInteracted = true;
        if (checked) {
            this._clients.forEach(c => this.selected.add(c.client_id));
        } else {
            this.selected.clear();
        }
        this.render();
        this._fireChange();
    }

    /** Include/exclude the currently-FILTERED (shown) set. */
    selectFiltered(checked) {
        if (this.singleSelect) return;
        this._userHasInteracted = true;
        const now = Date.now() / 1000;
        for (const c of this._clients) {
            if (!this._passesFacets(c, now)) continue;
            if (checked) this.selected.add(c.client_id); else this.selected.delete(c.client_id);
        }
        this.render();
        this._fireChange();
    }

    /** Replace the selection (e.g. restoring a saved scheduled job). */
    setSelected(ids) {
        this._userHasInteracted = true;
        this.selected = new Set(ids || []);
        this.render();
        this._fireChange();
    }

    getSelected() {
        return Array.from(this.selected);
    }

    /** Look up a loaded client object by id (e.g. to read its hostname). */
    getClient(id) {
        return this._clients.find(c => c.client_id === id) || null;
    }

    _fireChange() {
        if (this.onChange) {
            try { this.onChange(this.getSelected()); } catch (_) {}
        }
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    _osKey(os) {
        if (!os) return 'Unknown';
        const s = String(os).trim().toLowerCase();
        if (!s) return 'Unknown';
        if (s === 'windows' || s.startsWith('win')) return 'Windows';
        if (s === 'linux') return 'Linux';
        if (s === 'darwin' || s === 'macos' || s === 'osx' || s === 'mac') return 'macOS';
        return s.charAt(0).toUpperCase() + s.slice(1);
    }

    _isOnline(client, now) {
        // last_seen_at is microseconds-since-epoch (Velociraptor convention).
        const lastSeen = client.last_seen_at ? client.last_seen_at / 1000000 : 0;
        return (now - lastSeen) < this.onlineThreshold;
    }
}

window.ClientManager = ClientManager;
