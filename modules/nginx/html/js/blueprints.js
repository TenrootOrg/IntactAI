/**
 * Blueprints Module - Unified blueprint management for Velociraptor, Agentic, Timesketch, and Offline Collector
 */

window.velociraptorBlueprintsCache = null;
window.agenticBlueprintsCache = null;
window.timesketchBlueprintsCache = null;
window.forensicsBlueprintsCache = null;

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
            if (type === 'velociraptor') {
                window.velociraptorBlueprintsCache = data.blueprints;
            } else if (type === 'agentic') {
                window.agenticBlueprintsCache = data.blueprints;
            } else if (type === 'timesketch') {
                window.timesketchBlueprintsCache = data.blueprints;
            } else if (type === 'forensics') {
                window.forensicsBlueprintsCache = data.blueprints;
            }
            return data.blueprints;
        }
        return [];
    } catch (error) {
        console.error(`Error loading ${type} blueprints:`, error);
        return [];
    }
}

function clearAllBlueprintCaches() {
    window.velociraptorBlueprintsCache = null;
    window.agenticBlueprintsCache = null;
    window.timesketchBlueprintsCache = null;
    window.forensicsBlueprintsCache = null;
}

async function populateBlueprintDropdown(selectId, defaultValue, type) {
    const select = document.getElementById(selectId);
    if (!select) return;

    let cache;
    if (type === 'velociraptor') cache = window.velociraptorBlueprintsCache;
    else if (type === 'agentic') cache = window.agenticBlueprintsCache;
    else if (type === 'timesketch') cache = window.timesketchBlueprintsCache;
    else if (type === 'forensics') cache = window.forensicsBlueprintsCache;

    const blueprints = cache || await loadBlueprints(type);

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

    let cache;
    if (type === 'velociraptor') cache = window.velociraptorBlueprintsCache;
    else if (type === 'agentic') cache = window.agenticBlueprintsCache;
    else if (type === 'timesketch') cache = window.timesketchBlueprintsCache;
    else if (type === 'forensics') cache = window.forensicsBlueprintsCache;

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

    // Load all blueprint types (velociraptor, agentic, timesketch)
    const veloBp = await loadBlueprints('velociraptor');
    const agenticBp = await loadBlueprints('agentic');
    const timesketchBp = await loadBlueprints('timesketch');

    // Combine all blueprints with type info and cache them
    // Both velociraptor and agentic are under 'velociraptor' type for filtering
    // The [Velociraptor] or [Agentic] prefix in the name distinguishes them
    allBlueprintsCache = [
        ...veloBp.map(bp => ({ ...bp, _type: 'velociraptor', _actualType: 'velociraptor' })),
        ...agenticBp.map(bp => ({ ...bp, _type: 'velociraptor', _actualType: 'agentic' })),
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
            <span>KAPE: ${kape}</span>
            <span>Plaso: ${plaso}</span>
        `;
    } else {
        const expiry = bp.settings?.hunt_expiry || 120;
        const timeout = bp.settings?.timeout || 3600;
        const cpu = bp.settings?.cpu_limit || 50;
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
    const artifactsSection = document.getElementById('blueprint-artifacts-section');

    // Hide all first
    if (huntSettings) huntSettings.classList.add('hidden');
    if (timesketchSettings) timesketchSettings.classList.add('hidden');
    if (artifactsSection) artifactsSection.classList.remove('hidden');

    if (type === 'timesketch') {
        if (timesketchSettings) timesketchSettings.classList.remove('hidden');
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
        document.getElementById('blueprint-ts-hasher').value = bp.settings?.plaso_hasher || 'none';
        document.getElementById('blueprint-ts-maxsize').value = bp.settings?.plaso_hasher_size || 100;
        toggleHasherSize();
    } else {
        document.getElementById('blueprint-expiry').value = bp.settings?.hunt_expiry || 120;
        document.getElementById('blueprint-timeout').value = bp.settings?.timeout || 3600;
        document.getElementById('blueprint-cpu').value = bp.settings?.cpu_limit || 50;
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
            plaso_hasher: hasher,
            plaso_hasher_size: hasher !== 'none' ? parseInt(document.getElementById('blueprint-ts-maxsize').value) || 100 : null
        };
        data = { name, description, settings };  // No artifacts for timesketch
    } else {
        const artifacts = Array.from(document.querySelectorAll('.blueprint-artifact-cb:checked')).map(cb => cb.value);
        if (artifacts.length === 0) { alert('Please select at least one artifact.'); return; }
        settings = {
            hunt_expiry: parseInt(document.getElementById('blueprint-expiry').value) || 120,
            timeout: parseInt(document.getElementById('blueprint-timeout').value) || 3600,
            cpu_limit: parseInt(document.getElementById('blueprint-cpu').value) || 50
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
    document.getElementById('bestpractice-bp-cpu').textContent = (bp.settings?.cpu_limit || 50) + '%';
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
// Forensics Tab - Unified Velociraptor + Agentic
// ============================================================================

let forensicsSelectedClients = new Set();
let forensicsClientsCache = [];

async function initForensicsTab(mode = 'ai') {
    // Load unified blueprints (velociraptor + agentic combined)
    const blueprints = await loadBlueprints('forensics');

    // Populate blueprint dropdown
    const select = document.getElementById('forensics-blueprint-select');
    if (select) {
        select.innerHTML = '<option value="">-- Select Blueprint --</option>';

        // Add all blueprints (they have [Velociraptor] or [Agentic] prefix from backend)
        blueprints.forEach(bp => {
            const opt = document.createElement('option');
            opt.value = bp.id;
            opt.textContent = `${bp.name} (${bp.artifacts?.length || 0} artifacts)`;
            opt.dataset.type = bp.blueprint_type || (bp.name.startsWith('[Velociraptor]') ? 'velociraptor' : 'agentic');
            select.appendChild(opt);
        });

        // Set default based on mode
        setForensicsDefaultBlueprint(mode, blueprints);
    }

    // Load clients
    await loadForensicsClients();
}

// Set default blueprint based on mode
function setForensicsDefaultBlueprint(mode, blueprints = null) {
    const select = document.getElementById('forensics-blueprint-select');
    if (!select) return;

    // Use cached blueprints if not provided
    const bps = blueprints || window.forensicsBlueprintsCache || [];

    // Find the default blueprint based on mode
    let defaultBp = null;
    if (mode === 'ai') {
        // AI Analysis → [Agentic] Quick Wins
        defaultBp = bps.find(bp => bp.name && bp.name.includes('[Agentic] Quick Wins'));
    } else {
        // Raw Velociraptor → [Velociraptor] BestPractice
        defaultBp = bps.find(bp => bp.name && bp.name.includes('[Velociraptor] BestPractice'));
    }

    if (defaultBp) {
        select.value = defaultBp.id;
        onForensicsBlueprintChange(defaultBp.id);
    }
}

async function loadForensicsClients() {
    try {
        const response = await fetch('/api/clients');
        const data = await response.json();
        // API returns 'items' not 'clients'
        const clients = data.items || data.clients || [];
        if (clients.length > 0) {
            forensicsClientsCache = clients;
            renderForensicsClients(clients);
        } else {
            renderForensicsClients([]);
        }
    } catch (error) {
        console.error('[Forensics] Error loading clients:', error);
        renderForensicsClients([]);
    }
}

function renderForensicsClients(clients) {
    const container = document.getElementById('forensics-client-list');
    if (!container) return;

    if (!clients || clients.length === 0) {
        container.innerHTML = '<p class="text-sm text-gray-500">No clients available</p>';
        return;
    }

    container.innerHTML = clients.map(client => {
        // last_seen_at is in microseconds, convert to milliseconds
        const lastSeenMs = client.last_seen_at ? client.last_seen_at / 1000 : 0;
        const isOnline = lastSeenMs && (Date.now() - lastSeenMs) < 300000; // 5 minutes
        const checked = forensicsSelectedClients.has(client.client_id) ? 'checked' : '';
        return `
            <label class="flex items-center gap-2 cursor-pointer p-2 rounded hover:bg-gray-800">
                <input type="checkbox" ${checked}
                    onchange="toggleForensicsClient('${client.client_id}')"
                    class="w-4 h-4 rounded border-gray-700 bg-gray-900 text-blue-600">
                <span class="w-2 h-2 rounded-full ${isOnline ? 'bg-green-400' : 'bg-gray-500'}"></span>
                <span class="text-sm text-gray-300">${client.hostname || 'Unknown'}</span>
                <span class="text-xs text-gray-500">${client.os || ''}</span>
            </label>
        `;
    }).join('');
}

function toggleForensicsClient(clientId) {
    if (forensicsSelectedClients.has(clientId)) {
        forensicsSelectedClients.delete(clientId);
    } else {
        forensicsSelectedClients.add(clientId);
    }
}

function selectAllForensicsClients(select) {
    forensicsSelectedClients.clear();
    if (select) {
        forensicsClientsCache.forEach(c => forensicsSelectedClients.add(c.client_id));
    }
    renderForensicsClients(forensicsClientsCache);
}

function filterForensicsClients(query) {
    const filtered = forensicsClientsCache.filter(c =>
        (c.hostname || '').toLowerCase().includes(query.toLowerCase()) ||
        (c.os || '').toLowerCase().includes(query.toLowerCase())
    );
    renderForensicsClients(filtered);
}

async function onForensicsBlueprintChange(blueprintId) {
    const countEl = document.getElementById('forensics-artifact-count');
    const infoDiv = document.getElementById('forensics-blueprint-info');

    if (!blueprintId) {
        if (countEl) countEl.textContent = '0 artifacts';
        if (infoDiv) infoDiv.classList.add('hidden');
        return;
    }

    // Use forensics cache to find the blueprint
    const bp = await getBlueprintById(blueprintId, 'forensics');
    if (!bp) return;

    if (countEl) countEl.textContent = `${bp.artifacts?.length || 0} artifacts`;

    // Update info panel
    const descEl = document.getElementById('forensics-bp-description');
    if (descEl) descEl.textContent = bp.description || '';
    const expiryEl = document.getElementById('forensics-bp-expiry');
    if (expiryEl) expiryEl.textContent = (bp.settings?.hunt_expiry || 120) + ' min';
    const timeoutEl = document.getElementById('forensics-bp-timeout');
    if (timeoutEl) timeoutEl.textContent = (bp.settings?.timeout || 3600) + 's';
    const cpuEl = document.getElementById('forensics-bp-cpu');
    if (cpuEl) cpuEl.textContent = (bp.settings?.cpu_limit || 50) + '%';
    if (infoDiv) infoDiv.classList.remove('hidden');
}

function toggleForensicsAnonymization() {
    const toggle = document.getElementById('forensics-anonymize-toggle');
    const details = document.getElementById('forensics-anonymize-details');
    if (details) {
        details.classList.toggle('hidden', !toggle?.checked);
    }
}

function toggleForensicsIris() {
    const toggle = document.getElementById('forensics-iris-toggle');
    const details = document.getElementById('forensics-iris-details');
    if (details) {
        details.classList.toggle('hidden', !toggle?.checked);
    }
}

function toggleForensicsTimeFilter() {
    const toggle = document.getElementById('forensics-time-filter-toggle');
    const details = document.getElementById('forensics-time-filter-details');
    if (details) {
        details.classList.toggle('hidden', !toggle?.checked);
    }
}

function toggleTimeFilterMode() {
    const mode = document.querySelector('input[name="time-filter-mode"]:checked')?.value || 'relative';
    const relativeDiv = document.getElementById('time-filter-relative');
    const betweenDiv = document.getElementById('time-filter-between');

    if (mode === 'relative') {
        relativeDiv?.classList.remove('hidden');
        betweenDiv?.classList.add('hidden');
    } else {
        relativeDiv?.classList.add('hidden');
        betweenDiv?.classList.remove('hidden');
        // Initialize Flatpickr when switching to between mode
        initDatePickers();
    }
}

// Store Flatpickr instances
let fpStart = null;
let fpEnd = null;

function initDatePickers() {
    // Only initialize if Flatpickr is available
    if (typeof flatpickr === 'undefined') {
        console.warn('[DatePicker] Flatpickr not loaded');
        return;
    }

    const startEl = document.getElementById('forensics-time-start');
    const endEl = document.getElementById('forensics-time-end');

    if (!startEl || !endEl) {
        console.warn('[DatePicker] Elements not found');
        return;
    }

    // Destroy existing instances if they exist (needed for hidden element re-init)
    if (fpStart) {
        fpStart.destroy();
        fpStart = null;
    }
    if (fpEnd) {
        fpEnd.destroy();
        fpEnd = null;
    }

    const config = {
        enableTime: true,
        time_24hr: true,
        dateFormat: "Y-m-d H:i",
        minuteIncrement: 5,
        disableMobile: true,
        allowInput: false,
        clickOpens: true,
        animate: true,
        appendTo: document.body,
        defaultHour: 0,
        defaultMinute: 0
    };

    // Small delay to ensure element is visible
    setTimeout(() => {
        fpStart = flatpickr(startEl, {
            ...config,
            onChange: function(selectedDates, dateStr) {
                if (fpEnd && selectedDates[0]) {
                    fpEnd.set('minDate', selectedDates[0]);
                }
            }
        });

        fpEnd = flatpickr(endEl, {
            ...config,
            onChange: function(selectedDates, dateStr) {
                if (fpStart && selectedDates[0]) {
                    fpStart.set('maxDate', selectedDates[0]);
                }
            }
        });
        console.log('[DatePicker] Initialized successfully');
    }, 50);
}

function getForensicsTimeFilterSettings() {
    const enabled = document.getElementById('forensics-time-filter-toggle')?.checked || false;
    if (!enabled) return null;

    const modeRadio = document.querySelector('input[name="time-filter-mode"]:checked');
    const mode = modeRadio?.value || 'relative';

    if (mode === 'relative') {
        const relativeRange = document.getElementById('forensics-time-relative-range')?.value;
        if (!relativeRange) {
            console.warn('[TimeFilter] No relative range selected, defaulting to 7d');
        }
        return {
            enabled: true,
            mode: 'relative',
            relative_range: relativeRange || '7d'
        };
    } else {
        const startVal = document.getElementById('forensics-time-start')?.value;
        const endVal = document.getElementById('forensics-time-end')?.value;

        // Parse dates carefully
        let startDatetime = null;
        let endDatetime = null;

        if (startVal) {
            try {
                startDatetime = new Date(startVal).toISOString();
            } catch (e) {
                console.error('[TimeFilter] Invalid start date:', startVal);
            }
        }

        if (endVal) {
            try {
                endDatetime = new Date(endVal).toISOString();
            } catch (e) {
                console.error('[TimeFilter] Invalid end date:', endVal);
            }
        }

        return {
            enabled: true,
            mode: 'between',
            start_datetime: startDatetime,
            end_datetime: endDatetime
        };
    }
}

async function startForensicsCollection() {
    // Get mode by checking which mode button has the active class (border-purple/blue-500)
    const aiButton = document.getElementById('forensics-mode-ai');
    const rawButton = document.getElementById('forensics-mode-raw');
    const isAiMode = aiButton?.className.includes('border-purple-500') && !rawButton?.className.includes('border-blue-500');
    const collectionSource = document.querySelector('input[name="collection-source"]:checked')?.value || 'new';

    console.log('[Forensics] Mode detection:', { isAiMode, collectionSource, aiClass: aiButton?.className, rawClass: rawButton?.className });

    // If existing flow mode in AI mode, delegate to analyzeExistingCollection
    if (isAiMode && collectionSource === 'existing') {
        return analyzeExistingCollection();
    }

    const blueprintId = document.getElementById('forensics-blueprint-select')?.value;
    if (!blueprintId) {
        alert('Please select a blueprint');
        return;
    }

    // Only check for clients in AI mode with new collection
    if (isAiMode && collectionSource === 'new') {
        const selectedClients = Array.from(forensicsSelectedClients);
        if (selectedClients.length === 0) {
            alert('Please select at least one client');
            return;
        }
    }

    const statusEl = document.getElementById('forensics-status');
    statusEl?.classList.remove('hidden');
    statusEl.textContent = 'Starting collection...';

    // Get blueprint details
    const blueprint = await getBlueprintById(blueprintId, 'forensics');
    if (!blueprint) {
        statusEl.innerHTML = `<span class="text-red-400">Error: Blueprint not found</span>`;
        return;
    }

    try {
        if (isAiMode) {
            // AI Analysis mode - use agentic endpoint
            const selectedClients = Array.from(forensicsSelectedClients);
            const collectionTime = parseInt(document.getElementById('forensics-collection-time')?.value || '30');
            const reportTypes = ['technical'];
            const anonymizeData = document.getElementById('forensics-anonymize-toggle')?.checked || false;
            const customPatterns = document.getElementById('forensics-custom-patterns')?.value || '';
            const importToIris = document.getElementById('forensics-iris-toggle')?.checked || false;
            const irisCaseName = document.getElementById('forensics-iris-case-name')?.value || '';
            const timeFilter = getForensicsTimeFilterSettings();

            // Validate time filter settings
            if (timeFilter && timeFilter.enabled) {
                if (timeFilter.mode === 'between') {
                    if (!timeFilter.start_datetime) {
                        alert('Please select a start date for the time filter, or disable the time filter.');
                        statusEl?.classList.add('hidden');
                        return;
                    }
                    // end_datetime is optional - defaults to now on backend
                }
            }

            const response = await fetch('/api/agentic/run', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    blueprint_id: blueprintId,
                    client_ids: selectedClients,
                    collection_minutes: collectionTime,
                    report_types: reportTypes,
                    anonymize_data: anonymizeData,
                    custom_patterns: customPatterns,
                    import_to_iris: importToIris,
                    iris_case_name: irisCaseName,
                    time_filter: timeFilter
                })
            });

            const data = await response.json();
            if (response.ok) {
                statusEl.innerHTML = `<span class="text-green-400">AI Analysis started! Run ID: ${data.run_id}</span><br>Redirecting to Workflows...`;
                // Redirect to workflows tab after short delay
                setTimeout(() => {
                    if (window.Alpine && Alpine.store('app')) {
                        Alpine.store('app').switchTab('workflows');
                    }
                }, 1000);
            } else {
                statusEl.innerHTML = `<span class="text-red-400">Error: ${data.error}</span>`;
            }
        } else {
            // Raw Velociraptor mode - use bestpractice endpoint with artifacts from blueprint
            const response = await fetch('/api/velociraptor/bestpractice', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    artifacts: blueprint.artifacts || [],
                    blueprint_name: blueprint.name || 'Custom',
                    expire_minutes: blueprint.settings?.hunt_expiry || 120,
                    timeout_seconds: blueprint.settings?.timeout || 3600,
                    cpu_limit: blueprint.settings?.cpu_limit || 50
                })
            });

            const data = await response.json();
            if (response.ok) {
                statusEl.innerHTML = `<span class="text-green-400">Hunt started! Run ID: ${data.run_id}</span><br>Redirecting to Workflows...`;
                // Redirect to workflows tab after short delay
                setTimeout(() => {
                    if (window.Alpine && Alpine.store('app')) {
                        Alpine.store('app').switchTab('workflows');
                    }
                }, 1000);
            } else {
                statusEl.innerHTML = `<span class="text-red-400">Error: ${data.error}</span>`;
            }
        }
    } catch (error) {
        statusEl.innerHTML = `<span class="text-red-400">Error: ${error.message}</span>`;
    }
}

async function analyzeExistingCollection() {
    const existingId = document.getElementById('forensics-existing-id')?.value?.trim();
    if (!existingId) {
        alert('Please enter a Flow ID or Hunt ID');
        return;
    }

    // Determine if it's a flow or hunt
    const isFlow = existingId.startsWith('F.');
    const isHunt = existingId.startsWith('H.');

    if (!isFlow && !isHunt) {
        alert('Invalid ID format. Flow IDs start with "F." and Hunt IDs start with "H."');
        return;
    }

    // Use main status element (unified UI)
    const statusEl = document.getElementById('forensics-status') || document.getElementById('forensics-existing-status');
    statusEl?.classList.remove('hidden');
    statusEl.textContent = 'Starting AI analysis on existing collection...';

    try {
        const reportTypes = ['technical'];
        const anonymizeData = document.getElementById('forensics-anonymize-toggle')?.checked || false;
        const customPatterns = document.getElementById('forensics-custom-patterns')?.value || '';
        const importToIris = document.getElementById('forensics-iris-toggle')?.checked || false;
        const irisCaseName = document.getElementById('forensics-iris-case-name')?.value || '';
        const timeFilter = getForensicsTimeFilterSettings();

        // Validate time filter settings
        if (timeFilter && timeFilter.enabled) {
            if (timeFilter.mode === 'between') {
                if (!timeFilter.start_datetime) {
                    alert('Please select a start date for the time filter, or disable the time filter.');
                    statusEl?.classList.add('hidden');
                    return;
                }
            }
        }

        const response = await fetch('/api/agentic/analyze-existing', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                flow_id: isFlow ? existingId : null,
                hunt_id: isHunt ? existingId : null,
                report_types: reportTypes,
                anonymize_data: anonymizeData,
                custom_patterns: customPatterns,
                import_to_iris: importToIris,
                iris_case_name: irisCaseName,
                time_filter: timeFilter
            })
        });

        const data = await response.json();
        if (response.ok) {
            statusEl.innerHTML = `<span class="text-green-400">AI Analysis started! Run ID: ${data.run_id}</span><br>Redirecting to Workflows...`;
            // Redirect to workflows tab after short delay
            setTimeout(() => {
                if (window.Alpine && Alpine.store('app')) {
                    Alpine.store('app').switchTab('workflows');
                }
            }, 1000);
        } else {
            statusEl.innerHTML = `<span class="text-red-400">Error: ${data.error}</span>`;
        }
    } catch (error) {
        statusEl.innerHTML = `<span class="text-red-400">Error: ${error.message}</span>`;
    }
}

// ============================================================================
// Offline Collectors Tab
// ============================================================================

async function loadOfflineCollectorBlueprints() {
    // Use unified forensics blueprints for offline collector
    const blueprints = await loadBlueprints('forensics');
    const select = document.getElementById('offline-gen-config');
    if (select) {
        select.innerHTML = '<option value="">-- Select Blueprint --</option>';

        // Find default blueprint: [Agentic] Full Triage
        let defaultBpId = null;
        blueprints.forEach(bp => {
            const opt = document.createElement('option');
            opt.value = bp.id;
            opt.textContent = `${bp.name} (${bp.artifacts?.length || 0} artifacts)`;
            opt.dataset.type = bp.blueprint_type;
            select.appendChild(opt);

            // Check for default
            if (bp.name && bp.name.includes('[Agentic] Full Triage')) {
                defaultBpId = bp.id;
            }
        });

        // Set default selection
        if (defaultBpId) {
            select.value = defaultBpId;
        }
    }
}

// ============================================================================
// Init - called when Blueprints tab is opened
// ============================================================================

function initBlueprints() {
    renderBlueprintsList();
}
