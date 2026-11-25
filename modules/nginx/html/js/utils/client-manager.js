/**
 * Client Manager - Shared client selection component (used by EVERY module's
 * target-client picker: scheduler, timesketch, velociraptor-collection, memory).
 *
 * Faceted filter: narrow the fleet by OS + Velociraptor label + online state +
 * name, then include/exclude the *filtered* set ("Select all matching (N)" /
 * "Deselect matching"). Selection is a Set model (source of truth) so a client
 * stays selected even while a facet hides its row or it was never loaded.
 *
 * Paged from the server, with no fleet cap (2026-11-25: a 1,000-row cap hid
 * every client past the thousandth). The browser holds one page of RENDER_PAGE
 * matches at a time ("Show more" fetches the next); /api/clients filters,
 * counts and sorts from its fleet cache, so a 20,000-client org never travels
 * whole. "Select all (matching)" asks the server for just the matching ids.
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
        // Nothing is pre-ticked. Pre-ticking every online client meant one click
        // on a 1,000-endpoint fleet started a collection on all of them.
        this.onlineThreshold = options.onlineThreshold || 600;
        this.onChange = typeof options.onChange === 'function' ? options.onChange : null;
        // () => case id: list the fleet of THAT case's Velociraptor org instead of
        // the active case's (the schedule form files its runs in a chosen case).
        this.caseId = typeof options.caseId === 'function' ? options.caseId : null;

        // Selection is a Set of client_ids — the source of truth. Survives
        // facet filtering and paging (a hidden or never-loaded id stays selected).
        this.selected = new Set();

        // Facet state.
        this.onlineOnly = options.onlineOnly !== undefined ? options.onlineOnly : true;
        // Shown in red on every offline row when set (the scheduler: a client can be
        // offline when the schedule is made and online when it runs, or not).
        this.offlineNote = options.offlineNote || '';
        // Shown in red instead of "No clients found" when the fleet is empty.
        this.emptyNote = options.emptyNote || '';
        this.activeOs = new Set();
        this.activeLabels = new Set();
        this.search = '';

        this._items = [];          // the loaded pages of matches, in server order
        this._known = new Map();   // client_id -> row (or {client_id, hostname}) ever seen
        this._filtered = 0;        // matches on the server, all pages
        this._groups = {};         // OS group -> matches
        this._facets = { os: {}, labels: {}, online: 0 };  // over the whole fleet
        this._hiddenSelected = 0;  // selected ids the current filter does not match
        this._seq = 0;             // newest list request; older answers are dropped
        this._loadingMore = false;
        this._filterTimer = null;  // pending debounced name filter
        this.totalClients = 0;
        this._listenerAttached = false;
        this._facetBar = null;
        this._radioName = `${containerId}-radio`;
        this._refreshing = false;  // a refresh is in flight (repeat clicks ignored)
        this._refreshError = '';   // shown in the bar; the list itself is kept
        this._loadedAt = null;     // when the fleet was last fetched

        // The active case's org changed: this list is another org's fleet now.
        // Drop the selection (those ids are not in the new org) and reload. Only a
        // list that was ever loaded -- a page not opened yet loads its own -- and
        // not one that follows its own case (caseId).
        if (typeof window !== 'undefined' && window.addEventListener) window.addEventListener('velo-org-changed', () => {
            if (!this._listenerAttached || this.caseId) return;
            this.selected.clear();
            this._fireChange();
            this.load();
        });
    }

    /** The first page of matches, from the server's fleet cache. */
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
            container.addEventListener('click', (e) => {
                if (!e.target.closest || !e.target.closest('[data-act="show-more"]')) return;
                e.preventDefault();
                this._showMore();
            });
            this._listenerAttached = true;
        }

        try {
            const data = await this._reload();
            if (data === null) {
                container.innerHTML = '<p class="text-sm text-red-400">Failed to load clients</p>';
            }
        } catch (error) {
            container.innerHTML = `<p class="text-sm text-red-400">Error: ${escapeHtml(error.message)}</p>`;
        }
    }

    // ------------------------------------------------------------------
    // Server
    // ------------------------------------------------------------------

    /** The current filters as /api/clients parameters. */
    _filterParams() {
        const p = {};
        if (this.search) p.search = this.search;
        if (this.activeOs.size) p.os = [...this.activeOs].join(',');
        if (this.activeLabels.size) p.label = [...this.activeLabels].join(',');
        if (this.onlineOnly) p.online = '1';
        return p;
    }

    /** GET /api/clients. Returns the JSON body, or null on a non-OK answer.
     *  Without `fresh` it is the server's fleet cache (at most 30 s old: one
     *  Velociraptor query for every picker and tab); the ↻ button asks live. */
    async _get(params) {
        const q = new URLSearchParams({ include_offline: 'true', ...params });
        const cid = this.caseId && this.caseId();
        // An explicit X-Case-Id wins over the active case (js/active-case.js).
        const response = await fetch(`/api/clients?${q}`, cid ? { headers: { 'X-Case-Id': cid } } : undefined);
        if (!response.ok) return null;
        return response.json();
    }

    /** [[client_id, hostname], ...] for every client matching `params`. */
    async _ids(params) {
        const data = await this._get({ ...params, ids: '1' });
        if (!data || !Array.isArray(data.ids)) throw new Error('the server did not return the client ids');
        for (const [id, hostname] of data.ids) {
            if (!this._known.has(id)) this._known.set(id, { client_id: id, hostname });
        }
        return data.ids.map(([id]) => id);
    }

    /** Start the list over at the first page of the current filter. Returns the
     *  page's data, null on a failed request, or undefined when a newer request
     *  overtook it (its answer is the one that renders). */
    async _reload(fresh = false) {
        const seq = ++this._seq;
        const params = { ...this._filterParams(), offset: '0', limit: String(ClientManager.RENDER_PAGE) };
        if (fresh) params.fresh = '1';
        const data = await this._get(params);
        if (seq !== this._seq) return undefined;
        if (!data) return null;
        this._items = [];
        this._applyPage(data);
        this.render();
        this._countHidden(seq);
        return data;
    }

    async _showMore() {
        if (this._loadingMore || this._items.length >= this._filtered) return;
        this._loadingMore = true;
        const seq = this._seq;
        try {
            const data = await this._get({ ...this._filterParams(), offset: String(this._items.length),
                                           limit: String(ClientManager.RENDER_PAGE) });
            if (data && seq === this._seq) {
                this._applyPage(data);
                this.render();
            }
        } finally {
            this._loadingMore = false;
        }
    }

    _applyPage(data) {
        const items = data.items || [];
        this._items = this._items.concat(items);
        for (const c of items) this._known.set(c.client_id, c);
        this.totalClients = data.total || 0;
        // An older backend answers without `filtered`: the whole list came back.
        this._filtered = typeof data.filtered === 'number' ? data.filtered : this._items.length;
        this._groups = data.groups || null;
        if (data.facets) this._facets = data.facets;
        this._loadedAt = new Date();
    }

    /** How many selected clients the current filter hides -- the header's
     *  Select All takes the whole fleet, offline ones included, while the list
     *  shows "Online only" by default; that used to be visible nowhere. */
    async _countHidden(seq) {
        const filtering = Object.keys(this._filterParams()).length > 0;
        if (!this.selected.size || !filtering) {
            this._hiddenSelected = 0;
            this._updateCounts();
            return;
        }
        try {
            const matching = new Set(await this._ids(this._filterParams()));
            if (seq !== this._seq) return;
            let hidden = 0;
            for (const id of this.selected) if (!matching.has(id)) hidden++;
            this._hiddenSelected = hidden;
            this._updateCounts();
        } catch (_) { /* the counts just leave the hidden part out */ }
    }

    /**
     * Re-fetch the fleet on demand (the ↻ Refresh button in every picker).
     *
     * Keeps everything the operator set: OS/label/online facets, the name
     * filter, and the selection -- except clients that no longer exist, which
     * are dropped so a job is never sent to one. A failed refresh KEEPS the list
     * on screen and says so; it never wipes a working picker. Clicks while a
     * refresh is in flight are ignored.
     */
    async refresh(button = null) {
        if (this._refreshing) return;
        const container = document.getElementById(this.containerId);
        if (!container) return;
        this._refreshing = true;
        this._refreshError = '';
        // The button lives in the module's header beside Select All / None, so it
        // is visible before the list has loaded. Show progress ON it.
        const label = button ? button.textContent : null;
        if (button) { button.disabled = true; button.textContent = 'Refreshing…'; }
        this._renderFacetBar();
        try {
            const data = await this._reload(true);
            if (data === null) throw new Error('the server did not return the client list');
            if (this.selected.size) {
                // The fleet the live query just cached: every id, not one page.
                const ids = new Set(await this._ids({}));
                const before = this.selected.size;
                this.selected = new Set([...this.selected].filter(id => ids.has(id)));
                if (this.selected.size !== before) { this.render(); this._fireChange(); }
            }
        } catch (error) {
            this._refreshError = 'Refresh failed — showing the previous list';
        } finally {
            this._refreshing = false;
            this._renderFacetBar();
            if (button) { button.disabled = false; button.textContent = label; }
        }
    }

    // ------------------------------------------------------------------
    // Render
    // ------------------------------------------------------------------

    /** The facet bar + the loaded pages of matches, grouped by OS. */
    render() {
        const container = document.getElementById(this.containerId);
        if (!container) return;

        const now = Date.now() / 1000;
        this._renderFacetBar();

        if (this.totalClients === 0) {
            container.innerHTML = this.emptyNote
                ? `<p class="text-sm" style="color:#f87171">${escapeHtml(this.emptyNote)}</p>`
                : '<p class="text-sm text-gray-500">No clients found</p>';
            return;
        }
        if (this._filtered === 0 || this._items.length === 0) {
            container.innerHTML = '<p class="text-sm text-gray-500">No clients match the current filter</p>';
            return;
        }

        // The server sends the matches already grouped (Windows → Linux → macOS →
        // others A-Z → Unknown), online first, then by hostname.
        const groups = {};
        const order = [];
        for (const c of this._items) {
            const key = this._osKey(c.os);
            if (!groups[key]) { groups[key] = []; order.push(key); }
            groups[key].push(c);
        }

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
                        ${!isOnline && this.offlineNote ? `<div class="text-xs" style="color:#f87171">${escapeHtml(this.offlineNote)}</div>` : ''}
                    </div>
                    <span class="text-xs text-gray-600 font-mono truncate">${safeClientId.substring(0, 12)}...</span>
                </label>
            `;
        };

        // Group headings count every match of the group on the server, loaded or not.
        let html = order.map(key => {
            const n = (this._groups && typeof this._groups[key] === 'number') ? this._groups[key] : groups[key].length;
            const heading = `
                <div class="flex items-center gap-2 px-2 pt-2 pb-1 mt-1 border-t border-gray-800 first:border-t-0 first:mt-0 first:pt-0">
                    <span class="text-xs uppercase tracking-wide text-gray-400 font-semibold">${escapeHtml(key)}</span>
                    <span class="text-xs text-gray-600">(${n})</span>
                </div>
            `;
            return heading + groups[key].map(renderClient).join('');
        }).join('');

        const notListed = this._filtered - this._items.length;
        if (notListed > 0) {
            const next = Math.min(notListed, ClientManager.RENDER_PAGE);
            html += `<button type="button" data-act="show-more" class="w-full text-xs text-blue-400 hover:text-blue-300 py-2">Show ${next} more (${notListed} not listed — narrow the filter, or use Select all matching)</button>`;
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

        // Facet values over the whole fleet, as the server counted them.
        const osSet = new Set(Object.keys(this._facets.os || {}));
        const preferred = ['Windows', 'Linux', 'macOS'];
        const osOrder = [
            ...preferred.filter(k => osSet.has(k)),
            ...[...osSet].filter(k => !preferred.includes(k) && k !== 'Unknown').sort(),
            ...(osSet.has('Unknown') ? ['Unknown'] : []),
        ];
        const labelOrder = Object.keys(this._facets.labels || {}).sort();

        const chip = (facet, val, label, active) => {
            const cls = active
                ? 'bg-blue-600 text-white border-blue-500'
                : 'bg-gray-700 text-gray-300 border-gray-600 hover:bg-gray-600';
            // OS and label values are endpoint-reported: escaped in the attribute and the text.
            return `<button type="button" data-facet="${facet}" data-val="${escapeHtml(val)}" class="text-[11px] px-2 py-0.5 rounded-full border ${cls} transition-colors">${escapeHtml(label)}</button>`;
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

        // Row 2: include/exclude (multi-select only) + counts. The ↻ Refresh button
        // is in each module's header, beside Select All / None.
        const counts = this._countsText();
        const selectBtns = this.singleSelect ? '' : `
                <button type="button" data-act="select-shown" class="text-[11px] bg-gray-700 hover:bg-gray-600 px-2 py-0.5 rounded">Select all matching (${this._filtered})</button>
                <button type="button" data-act="deselect-shown" class="text-[11px] bg-gray-700 hover:bg-gray-600 px-2 py-0.5 rounded">Deselect matching</button>`;
        const actions = `<div class="flex gap-2 items-center">${selectBtns}${this._refreshError ? `<span class="text-[11px] text-red-400">${escapeHtml(this._refreshError)}</span>` : ''}</div>`;
        const actionRow = `<div class="flex items-center justify-between">${actions}<span class="text-[11px] text-gray-500">${counts}</span></div>`;

        bar.innerHTML = chipRow + actionRow;
    }

    /** Update just the counts text (cheap, no list re-render / no scroll jump). */
    _updateCounts() {
        if (!this._facetBar) return;
        const span = this._facetBar.querySelector('.flex.items-center.justify-between > span:last-child');
        if (span) span.textContent = this._countsText();
    }

    _countsText() {
        const of = `${this._filtered} matching of ${this.totalClients}`;
        let base = of;
        if (!this.singleSelect) {
            base += ` · ${this.selected.size} selected`;
            if (this._hiddenSelected > 0) base += ` (${this._hiddenSelected} not in this view)`;
        }
        if (!this._loadedAt) return base;
        const p = n => String(n).padStart(2, '0');
        const t = this._loadedAt;
        return `${base} · updated ${p(t.getHours())}:${p(t.getMinutes())}:${p(t.getSeconds())}`;
    }

    // ------------------------------------------------------------------
    // Facet toggles
    // ------------------------------------------------------------------

    setOsFacet(val) {
        if (this.activeOs.has(val)) this.activeOs.delete(val); else this.activeOs.add(val);
        this._refilter();
    }

    setLabelFacet(val) {
        if (this.activeLabels.has(val)) this.activeLabels.delete(val); else this.activeLabels.add(val);
        this._refilter();
    }

    setOnlineOnly(on) {
        this.onlineOnly = !!on;
        this._refilter();
    }

    /** A new filter starts back at the first page of matches. */
    _refilter() {
        clearTimeout(this._filterTimer);
        return this._reload().catch(() => {});
    }

    // ------------------------------------------------------------------
    // Selection
    // ------------------------------------------------------------------

    /** Individual checkbox/radio toggle — update the Set, refresh counts only. */
    _onCheckboxChange(clientId, checked) {
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
     * Name filter (kept as `filter` for the existing oninput handlers). The
     * term is stored at once, so a submit or "Select all matching" acts on what
     * was typed; only the request is debounced, so typing a hostname is one
     * request, not one per keystroke.
     */
    filter(searchTerm) {
        this.search = searchTerm || '';
        clearTimeout(this._filterTimer);
        this._filterTimer = setTimeout(() => this._refilter(), ClientManager.FILTER_DEBOUNCE_MS);
    }

    /** Select the ENTIRE fleet (ignores the filters; the counts then say how
     *  many of them this view hides), or clear the selection. */
    async selectAll(checked) {
        if (checked) {
            if (this.singleSelect) return;
            const ids = await this._ids({});
            ids.forEach(id => this.selected.add(id));
        } else {
            this.selected.clear();
        }
        this.render();
        this._fireChange();
        this._countHidden(this._seq);
    }

    /** Include/exclude every client matching the current filters, loaded or not. */
    async selectFiltered(checked) {
        if (this.singleSelect) return;
        clearTimeout(this._filterTimer);   // a typed term counts even mid-debounce
        const ids = await this._ids(this._filterParams());
        for (const id of ids) {
            if (checked) this.selected.add(id); else this.selected.delete(id);
        }
        this.render();
        this._fireChange();
        this._countHidden(this._seq);
    }

    /** Replace the selection (e.g. restoring a saved scheduled job). */
    setSelected(ids) {
        this.selected = new Set(ids || []);
        this.render();
        this._fireChange();
        this._countHidden(this._seq);
    }

    getSelected() {
        return Array.from(this.selected);
    }

    /** Ask before acting on many clients: "Select all matching" puts the whole
     *  fleet one click away. */
    confirmMany(action) {
        if (this.selected.size <= ClientManager.CONFIRM_ABOVE) return true;
        return window.confirm(`${action} on ${this.describeSelected()}?\n\nCancel to change the selection.`);
    }

    /** "N clients (first 10: a, b, …)" -- a dialog that listed every hostname
     *  of a big selection (~15 KB) pushed its real content off-screen. */
    describeSelected(max = 10) {
        const ids = this.getSelected();
        const names = ids.slice(0, max).map(id => (this.getClient(id) || {}).hostname || id);
        const head = `${ids.length} client${ids.length === 1 ? '' : 's'}`;
        if (ids.length <= max) return `${head} (${names.join(', ')})`;
        return `${head} (first ${max}: ${names.join(', ')}, …)`;
    }

    /** A client seen on any page, or through a select-all (then only
     *  {client_id, hostname}) -- e.g. to read its hostname. */
    getClient(id) {
        return this._known.get(id) || null;
    }

    _fireChange() {
        if (this.onChange) {
            try { this.onChange(this.getSelected()); } catch (_) {}
        }
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    /** The OS group (routes/client_routes.py _os_key, same rule). */
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

ClientManager.CONFIRM_ABOVE = 10;   // more selected than this asks first
ClientManager.RENDER_PAGE = 200;    // matches fetched and drawn per page
ClientManager.FILTER_DEBOUNCE_MS = 200;

window.ClientManager = ClientManager;
