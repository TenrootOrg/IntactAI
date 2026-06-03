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
    timesketch: { label: 'Timesketch', badgeColor: 'bg-orange-900 text-orange-300', borderColor: 'border-orange-900' }
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
                const kape = bp.settings?.kape_target || 'N/A';
                return `<option value="${bp.id}" ${defaultValue === bp.id ? 'selected' : ''}>${bp.name}${badge} [${kape}]</option>`;
            }).join('');
    } else {
        select.innerHTML = '<option value="">-- Select Blueprint --</option>' +
            blueprints.map(bp => {
                const badge = bp.is_default ? '' : ' (Custom)';
                const count = bp.artifacts ? bp.artifacts.length : 0;
                return `<option value="${bp.id}" ${defaultValue === bp.id ? 'selected' : ''}>${bp.name}${badge} (${count} artifacts)</option>`;
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

    // Load unified forensics blueprints (velociraptor + agentic combined) and timesketch
    const forensicsBp = await loadBlueprints('forensics');
    const timesketchBp = await loadBlueprints('timesketch');

    // Combine all blueprints with type info and cache them
    // Forensics blueprints have blueprint_type set by API (velociraptor or agentic based on name)
    allBlueprintsCache = [
        ...forensicsBp.map(bp => ({
            ...bp,
            _type: 'velociraptor',
            _actualType: bp.blueprint_type || (bp.name?.includes('[Agentic]') ? 'agentic' : 'velociraptor')
        })),
        ...timesketchBp.map(bp => ({ ...bp, _type: 'timesketch', _actualType: 'timesketch' }))
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

function renderBlueprintCard(bp) {
    const artifactCount = bp.artifacts ? bp.artifacts.length : 0;
    const isDefault = bp.is_default;
    const actualType = bp._actualType || bp._type;  // Use actual type for API calls
    const displayType = bp._type;  // Use display type for filtering

    // All velociraptor/agentic blueprints show Velociraptor badge
    // The [Velociraptor] or [Agentic] prefix in the name is the only distinction
    const badgeColor = displayType === 'timesketch'
        ? 'bg-orange-900 text-orange-300'
        : 'bg-blue-900 text-blue-300';
    const badgeLabel = displayType === 'timesketch'
        ? 'Timesketch'
        : 'Velociraptor';
    const borderColor = displayType === 'timesketch'
        ? 'border-orange-900'
        : 'border-blue-900';

    // Settings display varies by type
    let settingsHtml = '';
    if (displayType === 'timesketch') {
        const kape = bp.settings?.kape_target || '_KapeTriage';
        const plaso = bp.settings?.plaso_parser || 'win7';
        settingsHtml = `
            <span>Triage: ${kape}</span>
            <span>Plaso: ${plaso}</span>
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
                    <h4 class="text-lg font-semibold text-white">${bp.name}</h4>
                    <span class="text-xs ${badgeColor} px-2 py-0.5 rounded">${badgeLabel}</span>
                    ${isDefault ? '<span class="text-xs bg-green-900 text-green-300 px-2 py-0.5 rounded">Default</span>' : ''}
                </div>
                <p class="text-sm text-gray-400 mb-3">${bp.description || 'No description'}</p>
                <div class="flex gap-4 text-xs text-gray-500">
                    ${settingsHtml}
                </div>
            </div>
            <div class="flex gap-2 ml-4">
                <button onclick="editBlueprint('${bp.id}', '${actualType}')" class="text-xs bg-blue-700 hover:bg-blue-600 px-3 py-1.5 rounded">Edit</button>
                ${!isDefault ? `<button onclick="deleteBlueprintById('${bp.id}', '${actualType}')" class="text-xs bg-red-700 hover:bg-red-600 px-3 py-1.5 rounded">Delete</button>` : ''}
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
    const artifactsSection = document.getElementById('blueprint-artifacts-section');

    // Hide all first
    if (huntSettings) huntSettings.classList.add('hidden');
    if (timesketchSettings) timesketchSettings.classList.add('hidden');
    if (tsFlowLimits) tsFlowLimits.classList.add('hidden');
    if (tsKapeEnv) tsKapeEnv.classList.add('hidden');
    if (artifactsSection) artifactsSection.classList.remove('hidden');

    if (type === 'timesketch') {
        if (timesketchSettings) timesketchSettings.classList.remove('hidden');
        if (tsFlowLimits) tsFlowLimits.classList.remove('hidden');
        if (tsKapeEnv) tsKapeEnv.classList.remove('hidden');
        if (artifactsSection) artifactsSection.classList.add('hidden'); // No artifacts for timesketch
    } else {
        if (huntSettings) huntSettings.classList.remove('hidden');
    }
}

function onBlueprintTypeChange() {
    const type = document.getElementById('blueprint-type').value;
    window.currentBlueprintEditType = type;
    showSettingsForType(type);
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

async function populateModalArtifacts(selectedArtifacts) {
    const container = document.getElementById('blueprint-artifacts-list');
    const selectedSet = new Set(selectedArtifacts);

    // Show loading state
    container.innerHTML = '<p class="text-gray-400 text-sm">Loading artifacts from Velociraptor...</p>';

    // Load artifacts dynamically from Velociraptor
    const artifacts = await loadAvailableArtifacts();

    container.innerHTML = artifacts.map(artifact =>
        `<label class="flex items-center gap-2 text-xs text-white hover:bg-gray-800 px-2 py-1 rounded cursor-pointer">
            <input type="checkbox" class="blueprint-artifact-cb" value="${artifact}" ${selectedSet.has(artifact) ? 'checked' : ''}
                onchange="updateBlueprintArtifactCount()">
            ${artifact}
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
// Agentic Tab - Blueprint Preview
// ============================================================================

async function onAgenticBlueprintChange(blueprintId) {
    const previewContainer = 'agentic-artifact-preview';
    const countEl = document.getElementById('agentic-artifact-count');

    if (!blueprintId) {
        renderAgenticArtifactPreview(previewContainer, []);
        if (countEl) countEl.textContent = '0';
        return;
    }

    const blueprint = await getBlueprintById(blueprintId, 'agentic');
    if (blueprint) {
        renderAgenticArtifactPreview(previewContainer, blueprint.artifacts);
        if (countEl) countEl.textContent = blueprint.artifacts.length;
    }
}

function renderAgenticArtifactPreview(containerId, artifacts) {
    const container = document.getElementById(containerId);
    if (!container) return;

    if (!artifacts || artifacts.length === 0) {
        container.innerHTML = '<p class="text-sm text-gray-500">No artifacts selected</p>';
        return;
    }

    container.innerHTML = artifacts.map(artifact =>
        `<div class="flex items-center gap-2 px-2 py-1 text-xs text-gray-300 bg-gray-900 rounded">
            <svg class="w-3 h-3 text-green-400 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20">
                <path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"></path>
            </svg>
            ${artifact}
        </div>`
    ).join('');
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
