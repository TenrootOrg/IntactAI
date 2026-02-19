/**
 * Agentic Module - AI-powered forensics pipeline
 */

// Store clients for filtering
let agenticClientsCache = [];

// Initialize when tab opens
function initAgentic() {
    populateBlueprintDropdown('agentic-blueprint-select', 'quick_wins', 'agentic');
    loadAgenticClients();
}

// Load client list and render checkboxes
async function loadAgenticClients() {
    const container = document.getElementById('agentic-client-list');

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

        const now = Date.now() / 1000;
        agenticClientsCache = clients.sort((a, b) => {
            const aOnline = (now - (a.last_seen_at ? a.last_seen_at / 1000000 : 0)) < 600;
            const bOnline = (now - (b.last_seen_at ? b.last_seen_at / 1000000 : 0)) < 600;
            if (aOnline && !bOnline) return -1;
            if (!aOnline && bOnline) return 1;
            return (a.hostname || '').localeCompare(b.hostname || '');
        });

        renderAgenticClients(agenticClientsCache);

    } catch (error) {
        container.innerHTML = `<p class="text-sm text-red-400">Error: ${error.message}</p>`;
    }
}

// Render clients to container
function renderAgenticClients(clients, filter = '') {
    const container = document.getElementById('agentic-client-list');
    const now = Date.now() / 1000;
    const selectedIds = getSelectedAgenticClients();

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
                <input type="checkbox" class="agentic-client-cb" value="${client.client_id}" ${wasSelected || (isOnline && !filter) ? 'checked' : ''}>
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
function filterAgenticClients(searchTerm) {
    renderAgenticClients(agenticClientsCache, searchTerm);
}

// Select/deselect all visible clients
function selectAllAgenticClients(checked) {
    document.querySelectorAll('.agentic-client-cb').forEach(cb => cb.checked = checked);
}

// Get selected client IDs
function getSelectedAgenticClients() {
    return Array.from(document.querySelectorAll('.agentic-client-cb:checked')).map(cb => cb.value);
}

// Update artifact count when blueprint changes
async function onAgenticBlueprintChange(blueprintId) {
    const countEl = document.getElementById('agentic-artifact-count');
    if (!blueprintId) {
        countEl.textContent = '0 artifacts';
        return;
    }
    const bp = await getBlueprintById(blueprintId, 'agentic');
    if (bp) {
        countEl.textContent = `${bp.artifacts?.length || 0} artifacts`;
    }
}

// Get selected report types
function getSelectedReportTypes() {
    return ['technical'];
}

// Get anonymization settings
function getAnonymizationSettings() {
    const enabled = document.getElementById('agentic-anonymize-toggle')?.checked || false;
    const patternsText = document.getElementById('agentic-custom-patterns')?.value || '';
    const patterns = patternsText.split('\n').map(p => p.trim()).filter(p => p.length > 0);
    return { enabled, patterns };
}

// Toggle visibility of custom patterns textarea
function toggleAnonymizationDetails() {
    const toggle = document.getElementById('agentic-anonymize-toggle');
    const details = document.getElementById('agentic-anonymize-details');
    if (details) {
        details.classList.toggle('hidden', !toggle.checked);
    }
}

// Toggle visibility of IRIS options
function toggleIrisDetails() {
    const toggle = document.getElementById('agentic-iris-toggle');
    const details = document.getElementById('agentic-iris-details');
    if (details) {
        details.classList.toggle('hidden', !toggle.checked);
    }
}

// Get IRIS settings
function getIrisSettings() {
    return {
        enabled: document.getElementById('agentic-iris-toggle')?.checked || false,
        caseName: document.getElementById('agentic-iris-case-name')?.value?.trim() || ''
    };
}

// Get severity level filter
function getSeverityLevel() {
    return document.getElementById('agentic-severity-level')?.value || 'medium';
}

// Start the full pipeline
async function startAgenticPipeline() {
    const blueprintId = document.getElementById('agentic-blueprint-select').value;
    const clientIds = getSelectedAgenticClients();
    const collectionMinutes = parseInt(document.getElementById('agentic-collection-time').value) || 30;
    const reportTypes = getSelectedReportTypes();
    const anonymization = getAnonymizationSettings();
    const iris = getIrisSettings();
    const severityLevel = getSeverityLevel();

    if (!blueprintId) {
        alert('Please select a blueprint');
        return;
    }
    if (clientIds.length === 0) {
        alert('Please select at least one client');
        return;
    }

    // Get blueprint name for display
    const bp = await getBlueprintById(blueprintId, 'agentic');
    const blueprintName = bp ? bp.name : blueprintId;

    if (!confirm(`Start Agentic Analysis pipeline for ${clientIds.length} client(s)?\n\nBlueprint: ${blueprintName}\nArtifacts: ${bp?.artifacts?.length || 0}\nCollection Time: ${collectionMinutes} minutes\nSeverity Filter: ${severityLevel}\nReports: ${reportTypes.join(', ')}\n${anonymization.enabled ? '\nData Anonymization: Enabled' : ''}\n${iris.enabled ? '\nIRIS Import: Enabled' : ''}\n\nCheck the Workflows tab to monitor progress.`)) {
        return;
    }

    try {
        const response = await fetch('/api/agentic/run', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                blueprint_id: blueprintId,
                blueprint: blueprintName,
                client_ids: clientIds,
                collection_minutes: collectionMinutes,
                report_types: reportTypes,
                severity_level: severityLevel,
                anonymize_data: anonymization.enabled,
                custom_patterns: anonymization.patterns,
                import_to_iris: iris.enabled,
                iris_case_name: iris.caseName
            })
        });

        const data = await response.json();

        if (response.ok && data.run_id) {
            alert(`✓ Agentic pipeline started!\n\nBlueprint: ${blueprintName}\nCollection Time: ${collectionMinutes} minutes\n\nCheck the Workflows tab to monitor progress.`);
            switchTab('workflows');
        } else {
            alert(`Error: ${data.error || 'Failed to start pipeline'}`);
        }
    } catch (error) {
        alert(`Error: ${error.message}`);
    }
}

// No longer needed - pipeline runs in background and user monitors via Workflows tab
