/**
 * Blueprints Module - Unified blueprint management for Velociraptor, Agentic, Timesketch, and Offline Collector
 */

// Unified cache for all blueprint types
window.blueprintsCache = {
    velociraptor: null,
    agentic: null,
    timesketch: null,
    forensics: null
};

// Legacy compatibility - keep old variables as getters
Object.defineProperty(window, 'velociraptorBlueprintsCache', {
    get: () => window.blueprintsCache.velociraptor,
    set: (v) => window.blueprintsCache.velociraptor = v
});
Object.defineProperty(window, 'agenticBlueprintsCache', {
    get: () => window.blueprintsCache.agentic,
    set: (v) => window.blueprintsCache.agentic = v
});
Object.defineProperty(window, 'timesketchBlueprintsCache', {
    get: () => window.blueprintsCache.timesketch,
    set: (v) => window.blueprintsCache.timesketch = v
});
Object.defineProperty(window, 'forensicsBlueprintsCache', {
    get: () => window.blueprintsCache.forensics,
    set: (v) => window.blueprintsCache.forensics = v
});

// Helper functions for cache access
function getBlueprintCache(type) {
    return window.blueprintsCache[type] || null;
}

function setBlueprintCache(type, data) {
    window.blueprintsCache[type] = data;
}

// Dynamic artifact list - fetched from Velociraptor
let ALL_AVAILABLE_ARTIFACTS = [];
let artifactsCacheTimestamp = 0;
const ARTIFACTS_CACHE_TTL = 300000; // 5 minutes in milliseconds

/**
 * Load available artifacts from Velociraptor server.
 * Results are cached for 5 minutes.
 */
async function loadAvailableArtifacts(forceRefresh = false) {
    const now = Date.now();

    // Return cached data if fresh
    if (!forceRefresh && ALL_AVAILABLE_ARTIFACTS.length > 0 && (now - artifactsCacheTimestamp) < ARTIFACTS_CACHE_TTL) {
        return ALL_AVAILABLE_ARTIFACTS;
    }

    try {
        const url = forceRefresh ? '/api/velociraptor/artifacts?refresh=true' : '/api/velociraptor/artifacts';
        const response = await fetch(url);
        const data = await response.json();

        if (response.ok && data.artifacts) {
            // Extract just artifact names for the list
            ALL_AVAILABLE_ARTIFACTS = data.artifacts.map(a => a.name);
            artifactsCacheTimestamp = now;
            console.log(`[Blueprints] Loaded ${ALL_AVAILABLE_ARTIFACTS.length} artifacts from Velociraptor`);
            return ALL_AVAILABLE_ARTIFACTS;
        }
    } catch (error) {
        console.error('[Blueprints] Error loading artifacts:', error);
    }

    // Return existing cache if fetch failed
    if (ALL_AVAILABLE_ARTIFACTS.length > 0) {
        console.warn('[Blueprints] Using stale artifact cache');
        return ALL_AVAILABLE_ARTIFACTS;
    }

    // Ultimate fallback - minimal set of common artifacts
    console.warn('[Blueprints] Using fallback artifact list');
    return [
        "Windows.System.Pslist",
        "Windows.Network.Netstat",
        "Windows.EventLogs.Evtx",
        "Generic.System.Pstree"
    ];
}

// Type labels and colors
// Note: Both velociraptor and agentic use the same badge (Velociraptor)
// The [Velociraptor] or [Agentic] prefix in the name is the only distinction
const TYPE_CONFIG = {
    velociraptor: { label: 'Velociraptor', badgeColor: 'bg-blue-900 text-blue-300', borderColor: 'border-blue-900' },
    timesketch: { label: 'Timesketch', badgeColor: 'bg-orange-900 text-orange-300', borderColor: 'border-orange-900' },
    memory: { label: 'Memory', badgeColor: 'bg-purple-900 text-purple-300', borderColor: 'border-purple-900' }
};

// ============================================================================
// Core API Functions
// ============================================================================

async function loadBlueprints(type) {
    try {
        const response = await fetch(`/api/blueprints/${type}`);
        const data = await response.json();
        if (response.ok && data.blueprints) {
            setBlueprintCache(type, data.blueprints);
            return data.blueprints;
        }
        return [];
    } catch (error) {
        console.error(`Error loading ${type} blueprints:`, error);
        return [];
    }
}

function clearAllBlueprintCaches() {
    Object.keys(window.blueprintsCache).forEach(type => {
        window.blueprintsCache[type] = null;
    });
}

async function populateBlueprintDropdown(selectId, defaultValue, type) {
    const select = document.getElementById(selectId);
    if (!select) return;

    const blueprints = getBlueprintCache(type) || await loadBlueprints(type);

    // For timesketch, show settings info instead of artifact count
    if (type === 'timesketch') {
        select.innerHTML = '<option value="">-- Select Blueprint --</option>' +
            blueprints.map(bp => {
                const badge = bp.is_default ? '' : ' (Custom)';
                const kape = escapeHtml(bp.settings?.kape_target || 'N/A');
                return `<option value="${escapeHtml(bp.id)}" ${defaultValue === bp.id ? 'selected' : ''}>${escapeHtml(bp.name)}${badge} [${kape}]</option>`;
            }).join('');
    } else {
        select.innerHTML = '<option value="">-- Select Blueprint --</option>' +
            blueprints.map(bp => {
                const badge = bp.is_default ? '' : ' (Custom)';
                const count = bp.artifacts ? bp.artifacts.length : 0;
                return `<option value="${escapeHtml(bp.id)}" ${defaultValue === bp.id ? 'selected' : ''}>${escapeHtml(bp.name)}${badge} (${count} artifacts)</option>`;
            }).join('');
    }
}

async function getBlueprintById(blueprintId, type) {
    if (!blueprintId) return null;

    const cache = getBlueprintCache(type);
    if (cache) {
        const found = cache.find(bp => bp.id === blueprintId);
        if (found) return found;
    }

    // For forensics type, fetch by blueprint_type stored in the blueprint
    if (type === 'forensics') {
        // Try from cache first
        const forensicsCache = window.forensicsBlueprintsCache || await loadBlueprints('forensics');
        const found = forensicsCache.find(bp => bp.id === blueprintId);
        if (found) return found;
    }

    try {
        const response = await fetch(`/api/blueprints/${type}/${blueprintId}`);
        if (response.ok) return await response.json();
    } catch (error) {
        console.error('Error fetching blueprint:', error);
    }
    return null;
}

// ============================================================================
// Blueprints Tab - Unified Management UI
// ============================================================================

// Cache for all blueprints
let allBlueprintsCache = [];

async function renderBlueprintsList() {
    const container = document.getElementById('blueprints-list');
    if (!container) return;

    // Load unified forensics blueprints (velociraptor + agentic combined) + timesketch + memory.
    // Memory blueprints expose a curated VolWeb plugin set per blueprint
    // (the operator picks one in the Memory page; YARA is a separate
    // checkbox there).
    const [forensicsBp, timesketchBp, memoryBp] = await Promise.all([
        loadBlueprints('forensics'),
        loadBlueprints('timesketch'),
        loadBlueprints('memory'),
    ]);

    // Combine all blueprints with type info and cache them
    // Forensics blueprints have blueprint_type set by API (velociraptor or agentic based on name)
    allBlueprintsCache = [
        ...forensicsBp.map(bp => ({
            ...bp,
            _type: 'velociraptor',
            _actualType: bp.blueprint_type || (bp.name?.includes('[Agentic]') ? 'agentic' : 'velociraptor')
        })),
        ...timesketchBp.map(bp => ({ ...bp, _type: 'timesketch', _actualType: 'timesketch' })),
        ...memoryBp.map(bp => ({ ...bp, _type: 'memory', _actualType: 'memory' })),
    ];

    // Apply current filter
    filterBlueprints();
}

function filterBlueprints() {
    const container = document.getElementById('blueprints-list');
    if (!container) return;

    const filterSelect = document.getElementById('blueprint-type-filter');
    const filterType = filterSelect ? filterSelect.value : 'all';

    // Filter blueprints based on selected type
    const filteredBlueprints = filterType === 'all'
        ? allBlueprintsCache
        : allBlueprintsCache.filter(bp => bp._type === filterType);

    if (filteredBlueprints.length === 0) {
        container.innerHTML = '<p class="text-gray-500">No blueprints found.</p>';
        return;
    }

    container.innerHTML = filteredBlueprints.map(bp => renderBlueprintCard(bp)).join('');
}

// Safely encode a value for interpolation into a single-quoted JS string
// literal that is itself embedded inside a double-quoted HTML attribute
// (e.g. onclick="fn('VALUE')"). bp.id is attacker-controlled (it can be set
// verbatim via POST /api/blueprints/<type>), so it must be neutralized
// against both the JS-string boundary (backslash/quote) and the outer HTML
// attribute boundary (", &, <, >) before being interpolated below.
function escapeJsAttr(value) {
    return String(value ?? '')
        .replace(/\\/g, '\\\\')
        .replace(/'/g, "\\'")
        .replace(/\n/g, '\\n')
        .replace(/\r/g, '\\r')
        .replace(/&/g, '&amp;')
        .replace(/"/g, '&quot;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');
}

function renderBlueprintCard(bp) {
    const artifactCount = bp.artifacts ? bp.artifacts.length : 0;
    const isDefault = bp.is_default;
    const actualType = bp._actualType || bp._type;  // Use actual type for API calls
    const displayType = bp._type;  // Use display type for filtering

    // Per-type badge/border styling. Velociraptor + Agentic share a
    // blue badge (the [Agentic] prefix in the name distinguishes them
    // visually); Timesketch is orange; Memory is purple.
    let badgeColor, badgeLabel, borderColor;
    if (displayType === 'timesketch') {
        badgeColor = 'bg-orange-900 text-orange-300';
        badgeLabel = 'Timesketch';
        borderColor = 'border-orange-900';
    } else if (displayType === 'memory') {
        badgeColor = 'bg-purple-900 text-purple-300';
        badgeLabel = 'Memory';
        borderColor = 'border-purple-900';
    } else {
        badgeColor = 'bg-blue-900 text-blue-300';
        badgeLabel = 'Velociraptor';
        borderColor = 'border-blue-900';
    }

    // Settings display varies by type
    let settingsHtml = '';
    if (displayType === 'timesketch') {
        const kape = bp.settings?.kape_target || '_KapeTriage';
        const plaso = bp.settings?.plaso_parser || 'win7';
        settingsHtml = `
            <span>Triage: ${kape}</span>
            <span>Plaso: ${plaso}</span>
        `;
    } else if (displayType === 'memory') {
        const ps = bp.settings?.plugin_set || [];
        let pluginLabel;
        if (ps.length === 1 && ps[0] === '*') {
            pluginLabel = 'all available';
        } else if (ps.length === 0) {
            pluginLabel = 'YARA-only';
        } else {
            pluginLabel = `${ps.length} plugin(s)`;
        }
        const cpu = bp.settings?.cpu_limit ?? 80;
        settingsHtml = `
            <span>${pluginLabel}</span>
            <span>CPU: ${cpu}%</span>
        `;
    } else {
        const expiry = bp.settings?.hunt_expiry || 120;
        const timeout = bp.settings?.timeout || 3600;
        const cpu = bp.settings?.cpu_limit || 90;
        settingsHtml = `
            <span>${artifactCount} artifacts</span>
            <span>Expiry: ${expiry}m</span>
            <span>Timeout: ${timeout}s</span>
            <span>CPU: ${cpu}%</span>
        `;
    }

    return `
    <div class="bg-gray-800 rounded-lg p-5 border ${borderColor} mb-3">
        <div class="flex items-start justify-between">
            <div class="flex-1">
                <div class="flex items-center gap-2 mb-1">
                    <h4 class="text-lg font-semibold text-white">${escapeHtml(bp.name)}</h4>
                    <span class="text-xs ${badgeColor} px-2 py-0.5 rounded">${badgeLabel}</span>
                    ${isDefault ? '<span class="text-xs bg-green-900 text-green-300 px-2 py-0.5 rounded">Default</span>' : ''}
                </div>
                <p class="text-sm text-gray-400 mb-3">${escapeHtml(bp.description || 'No description')}</p>
                <div class="flex gap-4 text-xs text-gray-500">
                    ${settingsHtml}
                </div>
            </div>
            <div class="flex gap-2 ml-4">
                <button onclick="editBlueprint('${escapeJsAttr(bp.id)}', '${actualType}')" class="text-xs bg-blue-700 hover:bg-blue-600 px-3 py-1.5 rounded">Edit</button>
                ${!isDefault ? `<button onclick="deleteBlueprintById('${escapeJsAttr(bp.id)}', '${actualType}')" class="text-xs bg-red-700 hover:bg-red-600 px-3 py-1.5 rounded">Delete</button>` : ''}
            </div>
        </div>
    </div>`;
}

// Track which type is being edited in the modal
window.currentBlueprintEditType = 'velociraptor';

function showNewBlueprintModal() {
    window.currentBlueprintEditType = 'velociraptor';
    document.getElementById('blueprint-modal').classList.remove('hidden');
    document.getElementById('blueprint-modal-title').textContent = 'New Blueprint';
    document.getElementById('blueprint-edit-id').value = '';
    document.getElementById('blueprint-name').value = '';
    document.getElementById('blueprint-description').value = '';

    // Clear search box
    const searchBox = document.getElementById('blueprint-artifact-search');
    if (searchBox) searchBox.value = '';

    // Show type selector for new blueprints
    const typeSelector = document.getElementById('blueprint-type-selector');
    if (typeSelector) {
        typeSelector.classList.remove('hidden');
        document.getElementById('blueprint-type').value = 'velociraptor';
    }

    // Show hunt settings, hide offline settings
    showSettingsForType('velociraptor');

    document.getElementById('blueprint-expiry').value = 120;
    document.getElementById('blueprint-timeout').value = 3600;
    document.getElementById('blueprint-cpu').value = 50;

    populateModalArtifacts([]);
}

function showSettingsForType(type) {
    const huntSettings = document.getElementById('blueprint-hunt-settings');
    const timesketchSettings = document.getElementById('blueprint-timesketch-settings');
    // Two new TS-only sections introduced for KAPE upload-cap fix.
    const tsFlowLimits = document.getElementById('blueprint-timesketch-flow-limits');
    const tsKapeEnv = document.getElementById('blueprint-timesketch-kape-env');
    const memorySettings = document.getElementById('blueprint-memory-settings');
    const artifactsSection = document.getElementById('blueprint-artifacts-section');

    // Hide all first
    if (huntSettings) huntSettings.classList.add('hidden');
    if (timesketchSettings) timesketchSettings.classList.add('hidden');
    if (tsFlowLimits) tsFlowLimits.classList.add('hidden');
    if (tsKapeEnv) tsKapeEnv.classList.add('hidden');
    if (memorySettings) memorySettings.classList.add('hidden');
    if (artifactsSection) artifactsSection.classList.remove('hidden');

    if (type === 'timesketch') {
        if (timesketchSettings) timesketchSettings.classList.remove('hidden');
        if (tsFlowLimits) tsFlowLimits.classList.remove('hidden');
        if (tsKapeEnv) tsKapeEnv.classList.remove('hidden');
        if (artifactsSection) artifactsSection.classList.add('hidden'); // No artifacts for timesketch
    } else if (type === 'memory') {
        if (memorySettings) memorySettings.classList.remove('hidden');
        if (artifactsSection) artifactsSection.classList.add('hidden'); // No Velociraptor artifacts for memory
    } else {
        if (huntSettings) huntSettings.classList.remove('hidden');
    }
}

function onBlueprintTypeChange() {
    const type = document.getElementById('blueprint-type').value;
    window.currentBlueprintEditType = type;
    showSettingsForType(type);

    // When switching INTO the memory type for a new blueprint, load the
    // plugin catalog into the checkbox grid with nothing pre-selected.
    // (editBlueprint() handles the pre-populated case.)
    const editId = document.getElementById('blueprint-edit-id').value;
    if (type === 'memory' && !editId) {
        document.getElementById('blueprint-memory-cpu').value = 80;
        document.getElementById('blueprint-memory-max-bytes').value = 68719476736;
        const allToggle = document.getElementById('blueprint-memory-all-plugins');
        if (allToggle) allToggle.checked = false;
        const search = document.getElementById('blueprint-memory-plugin-search');
        if (search) search.value = '';
        populateMemoryPluginCheckboxes([]);
    }
}

function closeBlueprintModal() {
    document.getElementById('blueprint-modal').classList.add('hidden');
}

async function editBlueprint(blueprintId, type) {
    window.currentBlueprintEditType = type || 'velociraptor';
    const bp = await getBlueprintById(blueprintId, type);
    if (!bp) return;

    document.getElementById('blueprint-modal').classList.remove('hidden');
    document.getElementById('blueprint-modal-title').textContent = 'Edit Blueprint: ' + bp.name;
    document.getElementById('blueprint-edit-id').value = bp.id;
    document.getElementById('blueprint-name').value = bp.name || '';
    document.getElementById('blueprint-description').value = bp.description || '';

    // Clear search box
    const searchBox = document.getElementById('blueprint-artifact-search');
    if (searchBox) searchBox.value = '';

    // Hide type selector when editing (can't change type)
    const typeSelector = document.getElementById('blueprint-type-selector');
    if (typeSelector) {
        typeSelector.classList.add('hidden');
    }

    // Show appropriate settings
    showSettingsForType(type);

    if (type === 'timesketch') {
        document.getElementById('blueprint-ts-kape').value = bp.settings?.kape_target || '_KapeTriage';
        document.getElementById('blueprint-ts-plaso').value = bp.settings?.plaso_parser || 'win7';
        document.getElementById('blueprint-ts-workers').value = bp.settings?.plaso_workers || 2;
        document.getElementById('blueprint-ts-timeout').value = bp.settings?.collection_timeout || 10000;
        document.getElementById('blueprint-ts-cpu').value = bp.settings?.cpu_limit || 80;
        document.getElementById('blueprint-ts-hasher').value = bp.settings?.plaso_hasher || 'none';
        document.getElementById('blueprint-ts-maxsize').value = bp.settings?.plaso_hasher_size || 100;
        // Flow resource limits (TS path uses collect_client). Defaults match the
        // backend's settings.get(...) fallbacks so the UI surfaces the real values.
        document.getElementById('blueprint-ts-flow-max-rows').value = bp.settings?.flow_max_rows ?? 10000000;
        document.getElementById('blueprint-ts-flow-max-logs').value = bp.settings?.flow_max_logs ?? 1000000;
        document.getElementById('blueprint-ts-flow-max-upload-mb').value = bp.settings?.flow_max_upload_mb ?? 51200;
        // KAPE artifact env params (env=dict() in the VQL).
        document.getElementById('blueprint-ts-kape-max-file-size').value = bp.settings?.kape_max_file_size ?? 10737418240;
        document.getElementById('blueprint-ts-kape-max-hash-size').value = bp.settings?.kape_max_hash_size ?? 0;
        document.getElementById('blueprint-ts-kape-collection-policy').value = bp.settings?.kape_collection_policy || 'ExcludeSigned';
        toggleHasherSize();
    } else if (type === 'memory') {
        const pluginSet = bp.settings?.plugin_set || [];
        document.getElementById('blueprint-memory-cpu').value = bp.settings?.cpu_limit ?? 80;
        document.getElementById('blueprint-memory-max-bytes').value = bp.settings?.max_bytes ?? 68719476736;
        await populateMemoryPluginCheckboxes(pluginSet);
    } else {
        document.getElementById('blueprint-expiry').value = bp.settings?.hunt_expiry || 120;
        document.getElementById('blueprint-timeout').value = bp.settings?.timeout || 3600;
        document.getElementById('blueprint-cpu').value = bp.settings?.cpu_limit || 90;
        // Flow resource limits (Velociraptor / Agentic — applied to hunt() VQL).
        document.getElementById('blueprint-flow-max-rows').value = bp.settings?.flow_max_rows ?? 10000000;
        document.getElementById('blueprint-flow-max-logs').value = bp.settings?.flow_max_logs ?? 1000000;
        document.getElementById('blueprint-flow-max-upload-mb').value = bp.settings?.flow_max_upload_mb ?? 51200;
    }

    populateModalArtifacts(bp.artifacts || []);
}

// ============================================================================
// Memory blueprint plugin catalog (used by the memory editor checkbox grid)
// ============================================================================

// Cached catalog (grouped by purpose). Loaded once per page session;
// the catalog ships with the backend so it doesn't change between
// blueprint edits.
let memoryPluginCatalogCache = null;

async function loadMemoryPluginCatalog() {
    if (memoryPluginCatalogCache) return memoryPluginCatalogCache;
    try {
        const r = await fetch('/api/memory/available_plugins');
        const j = await r.json();
        memoryPluginCatalogCache = j.groups || [];
    } catch (e) {
        console.error('Failed to load memory plugin catalog:', e);
        memoryPluginCatalogCache = [];
    }
    return memoryPluginCatalogCache;
}

async function populateMemoryPluginCheckboxes(selectedPlugins) {
    const container = document.getElementById('blueprint-memory-plugin-list');
    if (!container) return;

    const selected = new Set(selectedPlugins || []);
    const allToggle = document.getElementById('blueprint-memory-all-plugins');

    // The `['*']` marker means "every plugin VolWeb advertises" — flip
    // the dedicated toggle and clear the per-plugin checkboxes since
    // they'd be ignored at run time anyway.
    if (selected.size === 1 && selected.has('*')) {
        if (allToggle) allToggle.checked = true;
        selected.clear();
    } else if (allToggle) {
        allToggle.checked = false;
    }

    container.innerHTML = '<p class="text-gray-500 text-sm">Loading plugins…</p>';
    const groups = await loadMemoryPluginCatalog();

    if (!groups.length) {
        container.innerHTML = '<p class="text-red-400 text-sm">Failed to load plugin catalog.</p>';
        return;
    }

    container.innerHTML = groups.map(g => `
        <div class="memory-plugin-group">
            <div class="text-xs font-semibold text-purple-300 uppercase tracking-wide mt-2 mb-1">${escapeHtml(g.label)}</div>
            ${g.plugins.map(p => {
                const shortName = escapeHtml(p.split('.').slice(-1)[0]);  // last segment, e.g. "PsList"
                const safeP = escapeHtml(p);
                return `
                <label class="memory-plugin-row flex items-center gap-2 text-xs text-white hover:bg-gray-800 px-2 py-1 rounded cursor-pointer"
                       data-name="${escapeHtml(p.toLowerCase())}">
                    <input type="checkbox" class="blueprint-memory-plugin-cb" value="${safeP}"
                           ${selected.has(p) ? 'checked' : ''}
                           onchange="updateMemoryPluginCount()">
                    <span class="text-purple-200 font-mono">${shortName}</span>
                    <span class="text-gray-500 truncate">${safeP}</span>
                </label>
                `;
            }).join('')}
        </div>
    `).join('');

    onMemoryAllPluginsToggle();   // sets disabled state of per-row checkboxes
    updateMemoryPluginCount();
}

function updateMemoryPluginCount() {
    const checked = document.querySelectorAll('.blueprint-memory-plugin-cb:checked').length;
    const total = document.querySelectorAll('.blueprint-memory-plugin-cb').length;
    const checkedEl = document.getElementById('blueprint-memory-plugin-count');
    const totalEl = document.getElementById('blueprint-memory-plugin-total');
    if (checkedEl) checkedEl.textContent = checked;
    if (totalEl) totalEl.textContent = total;
}

function toggleAllMemoryPlugins(check) {
    // "All available" toggle wins — if it's on, individual checkboxes
    // are disabled and toggling them would be misleading.
    const allToggle = document.getElementById('blueprint-memory-all-plugins');
    if (allToggle && allToggle.checked) return;
    document.querySelectorAll('.blueprint-memory-plugin-cb').forEach(cb => {
        // Respect search-hidden rows — only toggle visible ones, so the
        // search box's filter doubles as a scope selector.
        const row = cb.closest('.memory-plugin-row');
        if (row && row.classList.contains('hidden')) return;
        cb.checked = check;
    });
    updateMemoryPluginCount();
}

function filterMemoryPluginList() {
    const q = (document.getElementById('blueprint-memory-plugin-search').value || '').toLowerCase().trim();
    document.querySelectorAll('.memory-plugin-row').forEach(row => {
        const name = row.dataset.name || '';
        row.classList.toggle('hidden', q !== '' && !name.includes(q));
    });
    // Hide group headers whose rows are all hidden so the list doesn't
    // show empty section labels.
    document.querySelectorAll('.memory-plugin-group').forEach(g => {
        const anyVisible = Array.from(g.querySelectorAll('.memory-plugin-row'))
            .some(row => !row.classList.contains('hidden'));
        g.classList.toggle('hidden', !anyVisible);
    });
}

function onMemoryAllPluginsToggle() {
    const allToggle = document.getElementById('blueprint-memory-all-plugins');
    const isAll = !!(allToggle && allToggle.checked);
    document.querySelectorAll('.blueprint-memory-plugin-cb').forEach(cb => {
        cb.disabled = isAll;
        // Visually grey out the row when the all-toggle is on.
        const row = cb.closest('.memory-plugin-row');
        if (row) row.classList.toggle('opacity-50', isAll);
    });
}


async function populateModalArtifacts(selectedArtifacts) {
    const container = document.getElementById('blueprint-artifacts-list');
    const selectedSet = new Set(selectedArtifacts);

    // Show loading state
    container.innerHTML = '<p class="text-gray-400 text-sm">Loading artifacts from Velociraptor...</p>';

    // Load artifacts dynamically from Velociraptor
    const artifacts = await loadAvailableArtifacts();

    container.innerHTML = artifacts.map(artifact =>
        `<label class="flex items-center gap-2 text-xs text-white hover:bg-gray-800 px-2 py-1 rounded cursor-pointer">
            <input type="checkbox" class="blueprint-artifact-cb" value="${escapeHtml(artifact)}" ${selectedSet.has(artifact) ? 'checked' : ''}
                onchange="updateBlueprintArtifactCount()">
            ${escapeHtml(artifact)}
        </label>`
    ).join('');

    // Update total count display
    const totalEl = document.getElementById('blueprint-artifact-total');
    if (totalEl) totalEl.textContent = artifacts.length;

    updateBlueprintArtifactCount();
}

function updateBlueprintArtifactCount() {
    const count = document.querySelectorAll('.blueprint-artifact-cb:checked').length;
    const el = document.getElementById('blueprint-artifact-count');
    if (el) el.textContent = count;
}

function toggleAllBlueprintArtifacts(checked) {
    // Only toggle visible (non-hidden) checkboxes
    document.querySelectorAll('.blueprint-artifact-cb').forEach(cb => {
        if (!cb.closest('label').classList.contains('hidden')) {
            cb.checked = checked;
        }
    });
    updateBlueprintArtifactCount();
}

function filterBlueprintArtifacts() {
    const searchInput = document.getElementById('blueprint-artifact-search');
    const searchTerm = searchInput ? searchInput.value.toLowerCase().trim() : '';
    const container = document.getElementById('blueprint-artifacts-list');
    const labels = container.querySelectorAll('label');

    let visibleCount = 0;
    labels.forEach(label => {
        const artifactName = label.textContent.toLowerCase();
        if (searchTerm === '' || artifactName.includes(searchTerm)) {
            label.classList.remove('hidden');
            visibleCount++;
        } else {
            label.classList.add('hidden');
        }
    });

    // Show message if no results
    let noResultsEl = container.querySelector('.no-results-msg');
    if (visibleCount === 0 && searchTerm !== '') {
        if (!noResultsEl) {
            noResultsEl = document.createElement('p');
            noResultsEl.className = 'no-results-msg text-gray-500 text-sm py-2';
            container.appendChild(noResultsEl);
        }
        noResultsEl.textContent = `No artifacts matching "${searchTerm}"`;
    } else if (noResultsEl) {
        noResultsEl.remove();
    }
}

function toggleHasherSize() {
    const hasher = document.getElementById('blueprint-ts-hasher')?.value;
    const container = document.getElementById('blueprint-ts-maxsize-container');
    if (container) {
        container.classList.toggle('hidden', hasher === 'none');
    }
}

async function saveBlueprintFromModal() {
    const editId = document.getElementById('blueprint-edit-id').value;
    const name = document.getElementById('blueprint-name').value.trim();
    const description = document.getElementById('blueprint-description').value.trim();
    const type = window.currentBlueprintEditType;

    if (!name) { alert('Please enter a blueprint name.'); return; }

    let settings;
    let data;

    if (type === 'timesketch') {
        const hasher = document.getElementById('blueprint-ts-hasher').value || 'none';
        settings = {
            kape_target: document.getElementById('blueprint-ts-kape').value || '_KapeTriage',
            plaso_parser: document.getElementById('blueprint-ts-plaso').value || 'win7',
            plaso_workers: parseInt(document.getElementById('blueprint-ts-workers').value) || 2,
            collection_timeout: parseInt(document.getElementById('blueprint-ts-timeout').value) || 10000,
            cpu_limit: parseInt(document.getElementById('blueprint-ts-cpu').value) || 80,
            plaso_hasher: hasher,
            plaso_hasher_size: hasher !== 'none' ? parseInt(document.getElementById('blueprint-ts-maxsize').value) || 100 : null,
            // Flow resource limits — backend reads these via settings.get(...) in
            // run_kape_collection_grpc / executor.run_timesketch_pipeline.
            flow_max_rows: parseInt(document.getElementById('blueprint-ts-flow-max-rows').value) || 10000000,
            flow_max_logs: parseInt(document.getElementById('blueprint-ts-flow-max-logs').value) || 1000000,
            flow_max_upload_mb: parseInt(document.getElementById('blueprint-ts-flow-max-upload-mb').value) || 51200,
            // KAPE artifact env params (env=dict()).
            kape_max_file_size: parseInt(document.getElementById('blueprint-ts-kape-max-file-size').value) || 10737418240,
            kape_max_hash_size: parseInt(document.getElementById('blueprint-ts-kape-max-hash-size').value) || 0,
            kape_collection_policy: document.getElementById('blueprint-ts-kape-collection-policy').value || 'ExcludeSigned'
        };
        data = { name, description, settings };  // No artifacts for timesketch
    } else if (type === 'memory') {
        // Collect plugin selection from the checkbox grid. The
        // "all-available" toggle stores the special ['*'] marker
        // which pipeline.py resolves at run time via
        // volweb.list_plugins(); otherwise we collect ticked
        // checkboxes (may be empty → YARA-only blueprint).
        const allToggle = document.getElementById('blueprint-memory-all-plugins');
        let pluginSet;
        if (allToggle && allToggle.checked) {
            pluginSet = ['*'];
        } else {
            pluginSet = Array.from(document.querySelectorAll('.blueprint-memory-plugin-cb:checked'))
                .map(cb => cb.value);
        }
        settings = {
            // `mode` is required by the backend schema today; we set it
            // to "plugin" here as a sane default. The Memory page
            // computes the effective mode at submit time from the
            // operator's blueprint choice + YARA checkbox, so this
            // baked-in value isn't actually consulted at run time.
            mode: 'plugin',
            plugin_set: pluginSet,
            yara_rulesets: [],
            compression: 'None',
            max_bytes: parseInt(document.getElementById('blueprint-memory-max-bytes').value) || 68719476736,
            cpu_limit: parseInt(document.getElementById('blueprint-memory-cpu').value) || 80,
        };
        data = { name, description, settings };
    } else {
        const artifacts = Array.from(document.querySelectorAll('.blueprint-artifact-cb:checked')).map(cb => cb.value);
        if (artifacts.length === 0) { alert('Please select at least one artifact.'); return; }
        settings = {
            hunt_expiry: parseInt(document.getElementById('blueprint-expiry').value) || 120,
            timeout: parseInt(document.getElementById('blueprint-timeout').value) || 3600,
            cpu_limit: parseInt(document.getElementById('blueprint-cpu').value) || 50,
            // Flow resource limits — backend reads these via settings.get(...) in
            // executor.run_velociraptor_hunt and routes/velociraptor_routes.run_bestpractice_hunts.
            flow_max_rows: parseInt(document.getElementById('blueprint-flow-max-rows').value) || 10000000,
            flow_max_logs: parseInt(document.getElementById('blueprint-flow-max-logs').value) || 1000000,
            flow_max_upload_mb: parseInt(document.getElementById('blueprint-flow-max-upload-mb').value) || 51200
        };
        data = { name, description, artifacts, settings };
    }

    try {
        const url = editId ? `/api/blueprints/${type}/${editId}` : `/api/blueprints/${type}`;
        const method = editId ? 'PUT' : 'POST';

        const response = await fetch(url, {
            method,
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
        });

        const result = await response.json();
        if (response.ok) {
            closeBlueprintModal();
            clearAllBlueprintCaches();
            await renderBlueprintsList();
            // Refresh dropdowns in other modules
            populateBlueprintDropdown('bestpractice-blueprint-select', null, 'velociraptor');
            populateBlueprintDropdown('agentic-blueprint-select', null, 'agentic');
            populateBlueprintDropdown('timesketch-blueprint-select', null, 'timesketch');
            // Refresh forensics tab blueprints
            initForensicsTab();
        } else {
            alert('Error: ' + (result.error || 'Failed to save'));
        }
    } catch (error) {
        alert('Error: ' + error.message);
    }
}

async function deleteBlueprintById(blueprintId, type) {
    if (!confirm('Are you sure you want to delete this blueprint?')) return;

    try {
        const response = await fetch(`/api/blueprints/${type}/${blueprintId}`, { method: 'DELETE' });
        const data = await response.json();
        if (response.ok && data.success) {
            clearAllBlueprintCaches();
            await renderBlueprintsList();
            populateBlueprintDropdown('timesketch-blueprint-select', null, 'timesketch');
            populateBlueprintDropdown('bestpractice-blueprint-select', null, 'velociraptor');
            populateBlueprintDropdown('agentic-blueprint-select', null, 'agentic');
            // Refresh forensics tab blueprints
            initForensicsTab();
        } else {
            alert('Error: ' + (data.error || 'Cannot delete blueprint'));
        }
    } catch (error) {
        alert('Error: ' + error.message);
    }
}

// ============================================================================
// Velociraptor Tab - Blueprint Info Display
// ============================================================================

async function onVelociraptorBlueprintChange(blueprintId) {
    const infoDiv = document.getElementById('bestpractice-blueprint-info');
    if (!blueprintId) {
        if (infoDiv) infoDiv.classList.add('hidden');
        return;
    }

    const bp = await getBlueprintById(blueprintId, 'velociraptor');
    if (!bp) return;

    document.getElementById('bestpractice-bp-name').textContent = bp.name;
    document.getElementById('bestpractice-bp-description').textContent = bp.description || '';
    document.getElementById('bestpractice-bp-artifact-count').textContent = (bp.artifacts?.length || 0) + ' artifacts';
    document.getElementById('bestpractice-bp-expiry').textContent = (bp.settings?.hunt_expiry || 120) + ' min';
    document.getElementById('bestpractice-bp-timeout').textContent = (bp.settings?.timeout || 3600) + 's';
    document.getElementById('bestpractice-bp-cpu').textContent = (bp.settings?.cpu_limit || 90) + '%';
    if (infoDiv) infoDiv.classList.remove('hidden');
}

// ============================================================================
// Offline Collectors Tab
// ============================================================================

async function loadOfflineCollectorBlueprints() {
    const select = document.getElementById('offline-gen-config');
    if (!select) return;

    // Parallel fetch of forensics (velociraptor + agentic) AND timesketch
    // blueprints. Timesketch blueprints are KAPE-style triage collections
    // (Windows.Triage.Targets with the kape_* env); the backend collector
    // generator now accepts them and emits a Velociraptor offline ZIP that
    // runs the same triage the live Timesketch hunt would.
    const [forensicsBp, timesketchBp] = await Promise.all([
        loadBlueprints('forensics'),
        loadBlueprints('timesketch'),
    ]);

    select.innerHTML = '<option value="">-- Select Blueprint --</option>';

    // Group A: forensics (velociraptor + agentic) — artifact-count badge
    const forensicsGroup = document.createElement('optgroup');
    forensicsGroup.label = 'Velociraptor / Agentic';
    let defaultBpId = null;
    let firstBpId = null;
    forensicsBp.forEach(bp => {
        const opt = document.createElement('option');
        opt.value = bp.id;
        opt.textContent = `${bp.name} (${bp.artifacts?.length || 0} artifacts)`;
        opt.dataset.type = bp.blueprint_type;
        forensicsGroup.appendChild(opt);
        if (!firstBpId) firstBpId = bp.id;
        if (bp.name && bp.name.includes('[Agentic] Full Triage')) defaultBpId = bp.id;
    });
    select.appendChild(forensicsGroup);

    // Group B: Timesketch — KAPE triage collections, badge by kape_target
    if (timesketchBp.length) {
        const tsGroup = document.createElement('optgroup');
        tsGroup.label = 'Timesketch (KAPE Triage)';
        timesketchBp.forEach(bp => {
            const target = bp.settings?.kape_target || '_KapeTriage';
            const opt = document.createElement('option');
            opt.value = bp.id;
            opt.textContent = `${bp.name} [KAPE: ${target}]`;
            opt.dataset.type = 'timesketch';
            tsGroup.appendChild(opt);
        });
        select.appendChild(tsGroup);
    }

    // Default selection: prefer Agentic Full Triage, fall back to first
    if (defaultBpId) select.value = defaultBpId;
    else if (firstBpId) select.value = firstBpId;
}

// ============================================================================
// Init - called when Blueprints tab is opened
// ============================================================================

function initBlueprints() {
    renderBlueprintsList();
}
