/**
 * Timesketch Module - Timesketch workflow management
 */

// Store clients for filtering
let timesketchClientsCache = [];
// Store blueprints cache
let timesketchBlueprintsCache = [];

// Load timesketch blueprints into dropdown
async function loadTimesketchBlueprintsDropdown() {
    const select = document.getElementById('timesketch-blueprint-select');
    if (!select) return;

    try {
        const response = await fetch('/api/blueprints/timesketch');
        const data = await response.json();
        timesketchBlueprintsCache = data.blueprints || [];

        if (timesketchBlueprintsCache.length === 0) {
            select.innerHTML = '<option value="">No blueprints available</option>';
            return;
        }

        select.innerHTML = timesketchBlueprintsCache.map(bp =>
            `<option value="${bp.id}">${bp.name}</option>`
        ).join('');

        // Select first blueprint and show its info
        if (timesketchBlueprintsCache.length > 0) {
            onTimesketchBlueprintChange();
        }
    } catch (error) {
        console.error('Error loading timesketch blueprints:', error);
        select.innerHTML = '<option value="">Error loading blueprints</option>';
    }
}

// Handle blueprint selection change
function onTimesketchBlueprintChange() {
    const select = document.getElementById('timesketch-blueprint-select');
    const infoDiv = document.getElementById('timesketch-blueprint-info');
    const kapeSpan = document.getElementById('ts-blueprint-kape');
    const plasoSpan = document.getElementById('ts-blueprint-plaso');

    if (!select || !infoDiv) return;

    const blueprintId = select.value;
    const blueprint = timesketchBlueprintsCache.find(bp => bp.id === blueprintId);

    if (blueprint && blueprint.settings) {
        kapeSpan.textContent = `KAPE: ${blueprint.settings.kape_target || 'N/A'}`;
        plasoSpan.textContent = `Plaso: ${blueprint.settings.plaso_parser || 'N/A'}`;
        infoDiv.classList.remove('hidden');
    } else {
        infoDiv.classList.add('hidden');
    }
}

// Get current blueprint settings
function getTimesketchBlueprintSettings() {
    const select = document.getElementById('timesketch-blueprint-select');
    if (!select) return null;

    const blueprintId = select.value;
    const blueprint = timesketchBlueprintsCache.find(bp => bp.id === blueprintId);

    if (!blueprint) return null;

    return {
        kape_target: blueprint.settings?.kape_target || '_KapeTriage',
        plaso_parser: blueprint.settings?.plaso_parser || 'win7',
        plaso_workers: blueprint.settings?.plaso_workers || 2,
        plaso_hasher: blueprint.settings?.plaso_hasher || 'none',
        plaso_hasher_size: blueprint.settings?.plaso_hasher_size || 100,
        collection_timeout: blueprint.settings?.collection_timeout || 10000
    };
}

// Populate TimeSketch client list
async function populateTimeSketchClients() {
    const container = document.getElementById('timesketch-client-list');

    try {
        const response = await fetch('/api/clients');
        const data = await response.json();
        const clients = data.items || [];

        if (clients.length === 0) {
            container.innerHTML = '<p class="text-sm text-gray-500">No clients available</p>';
            return;
        }

        // Sort clients: online first, then by hostname
        const now = Date.now() / 1000;
        timesketchClientsCache = clients.sort((a, b) => {
            const aLastSeen = a.last_seen_at ? a.last_seen_at / 1000000 : 0;
            const bLastSeen = b.last_seen_at ? b.last_seen_at / 1000000 : 0;
            const aOnline = (now - aLastSeen) < 600;
            const bOnline = (now - bLastSeen) < 600;
            if (aOnline && !bOnline) return -1;
            if (!aOnline && bOnline) return 1;
            return (a.hostname || '').localeCompare(b.hostname || '');
        });

        renderTimesketchClients(timesketchClientsCache);
    } catch (error) {
        container.innerHTML = `<p class="text-sm text-red-400">Error: ${error.message}</p>`;
    }
}

// Render clients to container
function renderTimesketchClients(clients, filter = '') {
    const container = document.getElementById('timesketch-client-list');
    const now = Date.now() / 1000;
    const selectedIds = Array.from(document.querySelectorAll('.timesketch-client-checkbox:checked')).map(cb => cb.value);

    // Filter by hostname if filter provided
    const filtered = filter
        ? clients.filter(c => (c.hostname || '').toLowerCase().includes(filter.toLowerCase()))
        : clients;

    if (filtered.length === 0) {
        container.innerHTML = '<p class="text-sm text-gray-500">No clients match filter</p>';
        return;
    }

    container.innerHTML = filtered.map(client => {
        const lastSeen = client.last_seen_at ? client.last_seen_at / 1000000 : 0;
        const isOnline = (now - lastSeen) < 600;
        const wasSelected = selectedIds.includes(client.client_id);
        const dot = isOnline
            ? '<span class="inline-block w-2 h-2 bg-green-400 rounded-full"></span>'
            : '<span class="inline-block w-2 h-2 bg-gray-500 rounded-full"></span>';

        return `
            <label class="flex items-center gap-3 p-2 rounded hover:bg-gray-800 cursor-pointer">
                <input type="checkbox" class="timesketch-client-checkbox" value="${client.client_id}" data-hostname="${client.hostname || 'Unknown'}" ${wasSelected || (isOnline && !filter) ? 'checked' : ''}>
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

// Filter clients by search term
function filterTimesketchClients(searchTerm) {
    renderTimesketchClients(timesketchClientsCache, searchTerm);
}

// Select/deselect all visible clients
function selectAllTimeSketchClients() {
    document.querySelectorAll('.timesketch-client-checkbox').forEach(cb => cb.checked = true);
}

function deselectAllTimeSketchClients() {
    document.querySelectorAll('.timesketch-client-checkbox').forEach(cb => cb.checked = false);
}

// Sketch mode toggle
function toggleSketchMode() {
    const mode = document.querySelector('input[name="sketch-mode"]:checked').value;
    const newSketchDiv = document.getElementById('new-sketch-input');
    const existingSketchDiv = document.getElementById('existing-sketch-select');

    if (mode === 'new') {
        newSketchDiv.classList.remove('hidden');
        existingSketchDiv.classList.add('hidden');
    } else {
        newSketchDiv.classList.add('hidden');
        existingSketchDiv.classList.remove('hidden');
        loadExistingSketches();
    }
}

async function loadExistingSketches() {
    const select = document.getElementById('sketch-id');
    select.innerHTML = '<option value="">Loading sketches...</option>';

    try {
        const response = await fetch('/api/timesketch/sketches');
        const data = await response.json();

        if (data.sketches && data.sketches.length > 0) {
            select.innerHTML = '<option value="">-- Select a sketch --</option>' +
                data.sketches.map(s =>
                    `<option value="${s.id}">${s.name} (ID: ${s.id})</option>`
                ).join('');
        } else {
            select.innerHTML = '<option value="">No sketches found</option>';
        }
    } catch (error) {
        select.innerHTML = '<option value="">Error loading sketches</option>';
        console.error('Error loading sketches:', error);
    }
}

// Run TimeSketch workflow
async function runTimeSketchWorkflow() {
    const selectedClients = Array.from(document.querySelectorAll('.timesketch-client-checkbox:checked'));

    if (selectedClients.length === 0) {
        alert('Please select at least one client');
        return;
    }

    // Get blueprint settings
    const blueprintSettings = getTimesketchBlueprintSettings();
    if (!blueprintSettings) {
        alert('Please select a blueprint');
        return;
    }

    const sketchName = document.getElementById('sketch-name').value.trim() || `Investigation-${new Date().toISOString().split('T')[0]}`;
    const kapeTarget = blueprintSettings.kape_target;
    const timeoutSeconds = blueprintSettings.collection_timeout || 10000;
    const cpuLimit = 50; // Default CPU limit
    const monitorTimeout = blueprintSettings.collection_timeout || 10000;

    // Plaso settings from blueprint
    const plasoParser = blueprintSettings.plaso_parser;
    const plasoWorkers = blueprintSettings.plaso_workers;
    const plasoHasher = blueprintSettings.plaso_hasher === 'none' ? '' : blueprintSettings.plaso_hasher;
    const plasoHasherSizeMb = blueprintSettings.plaso_hasher_size;

    const clientIds = selectedClients.map(cb => cb.value);
    const hostnames = selectedClients.map(cb => cb.dataset.hostname).join(', ');

    const blueprintName = document.getElementById('timesketch-blueprint-select').selectedOptions[0]?.text || 'Unknown';

    if (!confirm(`Start KAPE collection and TimeSketch import for ${selectedClients.length} client(s)?\n\nBlueprint: ${blueprintName}\nClients: ${hostnames}\nKAPE Target: ${kapeTarget}\nPlaso Parser: ${plasoParser}\nCollection Timeout: ${timeoutSeconds}s\nSketch: ${sketchName}\n\nNote: If sketch already exists, timelines will be added to it.`)) {
        return;
    }

    try {
        let successCount = 0;
        for (let i = 0; i < selectedClients.length; i++) {
            const clientId = clientIds[i];
            const hostname = selectedClients[i].dataset.hostname;

            // Step 1: Start KAPE collection
            const blueprintId = document.getElementById('timesketch-blueprint-select').value;
            const kapeResponse = await fetch('/api/velociraptor/timesketch', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    client_id: clientId,
                    client_name: hostname,
                    kape_target: kapeTarget,
                    timeout_seconds: timeoutSeconds,
                    cpu_limit: cpuLimit,
                    blueprint_id: blueprintId,
                    blueprint: blueprintName
                })
            });

            const kapeData = await kapeResponse.json();
            if (!kapeResponse.ok) {
                console.error(`Failed to start KAPE for ${hostname}:`, kapeData.error);
                continue;
            }

            // Step 2: Start full import pipeline
            const importResponse = await fetch('/api/timesketch/import', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    flow_id: kapeData.flow_id,
                    client_id: clientId,
                    client_name: hostname,
                    sketch_name: sketchName,
                    timeline_name: hostname,
                    monitor_timeout: monitorTimeout,
                    // Plaso settings from blueprint
                    plaso_parser: plasoParser,
                    plaso_workers: plasoWorkers,
                    plaso_hasher: plasoHasher,
                    plaso_hasher_size_mb: plasoHasherSizeMb
                })
            });

            if (importResponse.ok) {
                successCount++;
            }
        }

        alert(`✓ Timesketch pipeline started for ${successCount} client(s)!\n\nSketch: ${sketchName}\nBlueprint: ${blueprintName}\nKAPE Target: ${kapeTarget}\n\nCheck the Workflows tab to monitor progress.`);

        switchTab('workflows');

    } catch (error) {
        alert(`Error starting workflow: ${error.message}`);
    }
}
