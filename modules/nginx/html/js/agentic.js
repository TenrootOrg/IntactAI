/**
 * Agentic Module - AI-powered forensics pipeline
 */

// Client manager instance (uses shared utility)
const agenticClientManager = new ClientManager('agentic-client-list', 'agentic-client-cb');

// Initialize when tab opens
function initAgentic() {
    populateBlueprintDropdown('agentic-blueprint-select', 'quick_wins', 'agentic');
    agenticClientManager.load();
}

// Backwards-compatible wrapper functions
function loadAgenticClients() { agenticClientManager.load(); }
function filterAgenticClients(searchTerm) { agenticClientManager.filter(searchTerm); }
function selectAllAgenticClients(checked) { agenticClientManager.selectAll(checked); }
function getSelectedAgenticClients() { return agenticClientManager.getSelected(); }

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

// Start the full pipeline
async function startAgenticPipeline() {
    const blueprintId = document.getElementById('agentic-blueprint-select').value;
    const clientIds = getSelectedAgenticClients();
    const collectionMinutes = parseInt(document.getElementById('agentic-collection-time').value) || 30;
    const reportTypes = getSelectedReportTypes();
    const anonymization = getAnonymizationSettings();
    const iris = getIrisSettings();

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

    if (!confirm(`Start Agentic Analysis pipeline for ${clientIds.length} client(s)?\n\nBlueprint: ${blueprintName}\nArtifacts: ${bp?.artifacts?.length || 0}\nCollection Time: ${collectionMinutes} minutes\nReports: ${reportTypes.join(', ')}\n${anonymization.enabled ? '\nData Anonymization: Enabled' : ''}\n${iris.enabled ? '\nIRIS Import: Enabled' : ''}\n\nCheck the Workflows tab to monitor progress.`)) {
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
