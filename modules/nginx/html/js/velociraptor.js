/**
 * Velociraptor Module - Artifacts, hunts, offline collectors
 */

// Artifact mapping
const artifactNames = {
    'bestpractice': 'Custom.Intact.AI.BestPractice'
};

// Run artifact hunt
async function runArtifact(artifactId) {
    const artifactName = artifactNames[artifactId] || artifactId;

    const veloUrl = `https://${window.baseHost}/velociraptor/app/index.html#/hunts/new?artifact=${encodeURIComponent(artifactName)}`;

    if (confirm(`This will open Velociraptor to create a hunt for ${artifactName}.\n\nContinue?`)) {
        window.open(veloUrl, '_blank');

        const statusEl = document.getElementById(`${artifactId}-status`);
        statusEl.classList.remove('hidden');
        statusEl.innerHTML = '<span class="text-blue-400">→ Opening Velociraptor hunt creation...</span>';
    }
}

// Show artifact status
async function showArtifactStatus(artifactId) {
    const statusEl = document.getElementById(`${artifactId}-status`);
    statusEl.classList.remove('hidden');
    statusEl.innerHTML = '<span class="text-blue-400">Checking status...</span>';

    try {
        const response = await fetch('/api/velociraptor/status');
        const data = await response.json();

        const relevantJobs = data.active.filter(job => job.artifact_id === artifactId);

        if (relevantJobs.length === 0) {
            statusEl.innerHTML = '<span class="text-gray-400">No active jobs</span>';
        } else {
            const job = relevantJobs[0];
            statusEl.innerHTML = `<span class="text-blue-400">Hunt ${job.hunt_id}: ${job.status}</span><br><span class="text-gray-400">Started: ${new Date(job.started_at * 1000).toLocaleString()}</span>`;
        }
    } catch (error) {
        statusEl.innerHTML = `<span class="text-red-400">✗ Error: ${error.message}</span>`;
    }
}

// BestPractice Hunt Functions
function toggleAllBestPractice(checked) {
    document.querySelectorAll('.bestpractice-checkbox').forEach(cb => cb.checked = checked);
    updateBestPracticeCount();
}

function updateBestPracticeCount() {
    const count = document.querySelectorAll('.bestpractice-checkbox:checked').length;
    document.getElementById('bestpractice-count').textContent = count;
}

async function runBestPracticeHunts() {
    const blueprintId = document.getElementById('bestpractice-blueprint-select').value;
    if (!blueprintId) {
        alert('Please select a blueprint first');
        return;
    }

    const blueprint = await getBlueprintById(blueprintId, 'velociraptor');
    if (!blueprint || !blueprint.artifacts || blueprint.artifacts.length === 0) {
        alert('Selected blueprint has no artifacts');
        return;
    }

    const artifacts = blueprint.artifacts;
    const expireMinutes = blueprint.settings?.hunt_expiry || 120;
    const timeoutSeconds = blueprint.settings?.timeout || 3600;
    const cpuLimit = blueprint.settings?.cpu_limit || 90;

    if (!confirm(`Run "${blueprint.name}" (${artifacts.length} artifacts)?\n\nExpiry: ${expireMinutes} minutes\nTimeout: ${timeoutSeconds} seconds\nCPU Limit: ${cpuLimit}%`)) {
        return;
    }

    const statusDiv = document.getElementById('bestpractice-status');
    statusDiv.classList.remove('hidden');
    statusDiv.innerHTML = '<span class="text-yellow-400">Starting hunts...</span>';

    try {
        const response = await fetch('/api/velociraptor/bestpractice', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                artifacts: artifacts,
                blueprint_name: blueprint.name,
                expire_minutes: expireMinutes,
                timeout_seconds: timeoutSeconds,
                cpu_limit: cpuLimit
            })
        });

        const data = await response.json();
        if (response.ok) {
            const huntId = data.hunt_id || '';
            statusDiv.innerHTML = `<span class="text-green-400">Bulk hunt created${huntId ? ': ' + huntId : ''} (${artifacts.length} artifacts). Redirecting to workflows...</span>`;

            setTimeout(() => {
                switchTab('workflows');
                loadWorkflows();
                statusDiv.classList.add('hidden');
            }, 1500);
        } else {
            statusDiv.innerHTML = `<span class="text-red-400">Error: ${data.error}</span>`;
        }
    } catch (error) {
        statusDiv.innerHTML = `<span class="text-red-400">Error: ${error.message}</span>`;
    }
}

async function showBestPracticeStatus() {
    const statusDiv = document.getElementById('bestpractice-status');
    statusDiv.classList.remove('hidden');
    statusDiv.innerHTML = '<span class="text-gray-400">Loading status...</span>';

    try {
        const response = await fetch('/api/velociraptor/hunts/status');
        const data = await response.json();
        if (response.ok && data.hunts) {
            const huntList = data.hunts.slice(0, 5).map(h =>
                `${h.description || h.hunt_id}: ${h.state || 'unknown'}`
            ).join('<br>');
            statusDiv.innerHTML = huntList || '<span class="text-gray-400">No recent hunts</span>';
        } else {
            statusDiv.innerHTML = '<span class="text-gray-400">No hunt status available</span>';
        }
    } catch (error) {
        statusDiv.innerHTML = `<span class="text-red-400">Error: ${error.message}</span>`;
    }
}

// ============================================================================
// Offline Collector Functions
// ============================================================================

const OFFLINE_ARTIFACTS = [
    'Windows.NTFS.MFT', 'Windows.Sys.AllUsers', 'Generic.System.Pstree',
    'Windows.Forensics.Usn', 'Windows.Analysis.EvidenceOfExecution',
    'Windows.EventLogs.RDPAuth', 'Windows.Forensics.Timeline',
    'Windows.Registry.RecentDocs', 'Windows.Forensics.SRUM',
    'Windows.Forensics.Prefetch', 'Windows.System.Amcache',
    'Windows.Network.Netstat', 'Windows.Forensics.Lnk',
    'Windows.System.Pslist', 'Windows.Detection.BinaryRename',
    'Windows.Forensics.RecycleBin', 'Windows.EventLogs.Evtx',
    'Windows.Network.ArpCache', 'Windows.Sysinternals.Autoruns',
    'Generic.Collectors.File', 'Windows.Registry.Sysinternals.Eulacheck',
    'Windows.KapeFiles.Targets'
];

let offlineConfigs = [];
let selectedImportFile = null;

async function switchOfflineTab(tabName) {
    console.log('[Velociraptor] switchOfflineTab:', tabName);
    document.querySelectorAll('.offline-tab-content').forEach(tab => {
        tab.classList.add('hidden');
    });
    document.querySelectorAll('[id^="offline-tab-btn-"]').forEach(btn => {
        btn.classList.remove('text-purple-400', 'border-b-2', 'border-purple-400');
        btn.classList.add('text-gray-400');
    });
    document.getElementById(`offline-tab-${tabName}`).classList.remove('hidden');
    const activeBtn = document.getElementById(`offline-tab-btn-${tabName}`);
    activeBtn.classList.add('text-purple-400', 'border-b-2', 'border-purple-400');
    activeBtn.classList.remove('text-gray-400');

    if (tabName === 'generate') {
        // Load blueprints from unified API
        await loadOfflineBlueprints();
        console.log('[Velociraptor] offlineConfigs after load:', offlineConfigs.length);
        populateConfigDropdown();
    }
}

// Load offline collector blueprints from unified forensics API
async function loadOfflineBlueprints() {
    console.log('[Velociraptor] loadOfflineBlueprints starting...');
    try {
        const response = await fetch('/api/blueprints/forensics');
        console.log('[Velociraptor] Blueprint API response status:', response.status);
        const data = await response.json();
        console.log('[Velociraptor] Blueprint API data:', data);
        if (response.ok && data.blueprints) {
            // Transform to config format for compatibility with existing code
            offlineConfigs = data.blueprints.map(bp => ({
                config_id: bp.id,
                config_name: bp.name,
                description: bp.description,
                artifacts: bp.artifacts,
                parameters: bp.settings,
                is_template: bp.is_default,
                blueprint_type: bp.blueprint_type
            }));
            console.log('[Velociraptor] Loaded', offlineConfigs.length, 'forensics blueprints as configs');
        } else {
            console.warn('[Velociraptor] Blueprint API returned error or no blueprints:', data);
        }
    } catch (error) {
        console.error('[Velociraptor] Error loading forensics blueprints:', error);
    }
}

// Legacy function for compatibility (now uses blueprint API)
async function loadOfflineConfigs() {
    await loadOfflineBlueprints();
}

function populateConfigDropdown() {
    const select = document.getElementById('offline-gen-config');
    if (!select) return;

    if (offlineConfigs.length === 0) {
        select.innerHTML = '<option value="">No configurations - create one first</option>';
        return;
    }

    // Find BestPractice config to use as default
    const bestPractice = offlineConfigs.find(c =>
        (c.config_name || '').toLowerCase().includes('bestpractice') ||
        (c.config_name || '').toLowerCase().includes('best practice')
    );
    const defaultId = bestPractice ? bestPractice.config_id : '';

    select.innerHTML = '<option value="">Select a configuration...</option>' +
        offlineConfigs.map(c => {
            const selected = c.config_id === defaultId ? ' selected' : '';
            return `<option value="${c.config_id}"${selected}>${c.config_name || c.config_id}</option>`;
        }).join('');
}

function showNewConfigModal() {
    document.getElementById('new-config-modal').classList.remove('hidden');
    document.getElementById('config-modal-title').textContent = 'New Configuration';
    document.getElementById('config-id').value = '';
    document.getElementById('config-name').value = '';
    document.getElementById('config-description').value = '';
    populateOfflineArtifacts([]);
}

function closeConfigModal() {
    document.getElementById('new-config-modal').classList.add('hidden');
}

function populateOfflineArtifacts(selectedArtifacts = []) {
    const container = document.getElementById('offline-artifacts-list');
    container.innerHTML = OFFLINE_ARTIFACTS.map(artifact => `
        <label class="flex items-center gap-2 p-2 bg-gray-900 rounded hover:bg-gray-800 cursor-pointer">
            <input type="checkbox" class="offline-artifact-checkbox" value="${artifact}" ${selectedArtifacts.includes(artifact) ? 'checked' : ''}>
            <span class="text-sm">${artifact}</span>
        </label>
    `).join('');
}

function toggleAllOfflineArtifacts(checked) {
    document.querySelectorAll('.offline-artifact-checkbox').forEach(cb => cb.checked = checked);
}

function getSelectedOfflineArtifacts() {
    return Array.from(document.querySelectorAll('.offline-artifact-checkbox:checked')).map(cb => cb.value);
}

async function saveOfflineConfig() {
    const configId = document.getElementById('config-id').value;
    const configName = document.getElementById('config-name').value || 'Untitled';
    const description = document.getElementById('config-description').value || '';
    const artifacts = getSelectedOfflineArtifacts();

    if (artifacts.length === 0) {
        alert('Please select at least one artifact');
        return;
    }

    const configData = {
        config_name: configName,
        description: description,
        artifacts: artifacts,
        parameters: {
            CpuLimit: 50,
            MaxExecutionTimeInSeconds: 3600
        }
    };

    try {
        const url = configId ? `/api/velociraptor/offline/configs/${configId}` : '/api/velociraptor/offline/configs';
        const method = configId ? 'PUT' : 'POST';

        const response = await fetch(url, {
            method: method,
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(configData)
        });

        if (response.ok) {
            closeConfigModal();
            loadOfflineConfigs();
            alert('Configuration saved successfully');
        } else {
            const data = await response.json();
            alert('Error: ' + (data.error || 'Failed to save configuration'));
        }
    } catch (error) {
        alert('Error: ' + error.message);
    }
}

async function editOfflineConfig(configId) {
    const config = offlineConfigs.find(c => c.config_id === configId);
    if (!config) return;

    document.getElementById('new-config-modal').classList.remove('hidden');
    document.getElementById('config-modal-title').textContent = 'Edit Configuration';
    document.getElementById('config-id').value = configId;
    document.getElementById('config-name').value = config.config_name || '';
    document.getElementById('config-description').value = config.description || '';
    populateOfflineArtifacts(config.artifacts || []);
}

async function deleteOfflineConfig(configId) {
    if (!confirm('Are you sure you want to delete this configuration?')) return;

    try {
        const response = await fetch(`/api/velociraptor/offline/configs/${configId}`, { method: 'DELETE' });
        if (response.ok) {
            loadOfflineConfigs();
        } else {
            const data = await response.json();
            alert('Error: ' + (data.error || 'Failed to delete configuration'));
        }
    } catch (error) {
        alert('Error: ' + error.message);
    }
}

async function generateOfflineCollector() {
    const configId = document.getElementById('offline-gen-config').value;
    const os       = document.getElementById('offline-gen-os').value;
    // Three-way radio: 'standard' | 'musl' | 'legacy'. Default 'standard'.
    const variant  = document.querySelector('input[name="offline-gen-variant"]:checked')?.value || 'standard';

    if (!configId) {
        alert('Please select a configuration');
        return;
    }

    // Musl variant only makes sense on Linux. If picked for windows/darwin
    // we silently fall back to 'standard' for those platforms; the user
    // will see no warning, just the regular build.
    const variantEffective = (variant === 'musl' && os !== 'linux') ? 'standard' : variant;

    const statusEl = document.getElementById('offline-gen-status');
    statusEl.classList.remove('hidden');
    const variantTag = variantEffective === 'standard'
        ? ''
        : ` <span class="text-${variantEffective === 'legacy' ? 'purple' : 'orange'}-400">(${variantEffective})</span>`;
    statusEl.innerHTML = `<span class="text-yellow-400">Starting collector generation...</span>${variantTag}`;

    try {
        // Always use the install.sh-bundled binary (source=offline). The
        // backend still accepts an `online` mode for power-users hitting
        // the API directly, but the UI doesn't expose it — operators kept
        // hitting the GitHub button by accident.
        const body = { config_id: configId, os: os };
        if (variantEffective === 'legacy') {
            body.legacy = true;
            body.legacy_source = 'offline';
        } else if (variantEffective === 'musl') {
            body.musl = true;
        }
        const response = await fetch('/api/velociraptor/offline/generate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });

        const data = await response.json();
        if (response.ok && data.success) {
            statusEl.innerHTML = `<span class="text-green-400">✓ Generation started!</span><br><span class="text-gray-400">View Workflows tab for progress. Click the workflow to see the download link when ready.</span>`;
            // Switch to workflows view after a longer delay
            setTimeout(() => {
                Alpine.store('app').switchTab('workflows');
            }, 2500);
        } else {
            statusEl.innerHTML = `<span class="text-red-400">Error: ${data.error || 'Generation failed'}</span>`;
        }
    } catch (error) {
        statusEl.innerHTML = `<span class="text-red-400">Error: ${error.message}</span>`;
    }
}

// Handle file selection for offline import
function handleOfflineFileSelect(event) {
    const file = event.target.files[0];
    if (file) {
        if (!file.name.toLowerCase().endsWith('.zip')) {
            alert('Please select a ZIP file');
            return;
        }
        selectedImportFile = file;
        const dropzoneText = document.getElementById('offline-dropzone-text');
        const sizeStr = formatBytes(file.size);
        dropzoneText.innerHTML = `<span class="text-blue-400 font-medium">${file.name}</span><br><span class="text-xs">${sizeStr}</span>`;
        document.getElementById('offline-import-btn').disabled = false;
    }
}

// Legacy function for backward compatibility
function handleFileSelect(event) {
    handleOfflineFileSelect(event);
}

// Initialize offline import dropzone with drag & drop
function initOfflineImportDropzone() {
    const dropzone = document.getElementById('offline-dropzone');
    const fileInput = document.getElementById('offline-import-file');

    if (!dropzone || !fileInput) return;

    // Only initialize once
    if (dropzone.dataset.initialized) return;
    dropzone.dataset.initialized = 'true';

    // Click to browse
    dropzone.addEventListener('click', () => fileInput.click());

    // Drag events
    dropzone.addEventListener('dragover', (e) => {
        e.preventDefault();
        e.stopPropagation();
        dropzone.classList.add('border-blue-500', 'bg-blue-500/10');
    });

    dropzone.addEventListener('dragleave', (e) => {
        e.preventDefault();
        e.stopPropagation();
        dropzone.classList.remove('border-blue-500', 'bg-blue-500/10');
    });

    dropzone.addEventListener('drop', (e) => {
        e.preventDefault();
        e.stopPropagation();
        dropzone.classList.remove('border-blue-500', 'bg-blue-500/10');

        const files = e.dataTransfer.files;
        if (files.length > 0) {
            // Set file input and trigger handler
            const dataTransfer = new DataTransfer();
            dataTransfer.items.add(files[0]);
            fileInput.files = dataTransfer.files;
            handleOfflineFileSelect({ target: { files: [files[0]] } });
        }
    });
}

// Import offline collector results using tus protocol
function importOfflineResults() {
    if (!selectedImportFile) {
        alert('Please select a file to import');
        return;
    }

    // Show progress UI
    const progressDiv = document.getElementById('offline-upload-progress');
    const progressBar = document.getElementById('offline-upload-bar');
    const progressPercent = document.getElementById('offline-upload-percent');
    const progressSpeed = document.getElementById('offline-upload-speed');
    const filenameEl = document.getElementById('offline-upload-filename');
    const statusEl = document.getElementById('offline-import-status');
    const importBtn = document.getElementById('offline-import-btn');

    progressDiv.classList.remove('hidden');
    statusEl.classList.add('hidden');
    filenameEl.textContent = selectedImportFile.name;
    importBtn.disabled = true;

    // Create uploader - progress is tracked in Workflows tab via tus hooks
    const uploader = new TusUploader({
        purpose: 'velociraptor',
        metadata: {},
        onProgress: (info) => {
            // Progress is tracked in workflow logs, no need to update UI here
        },
        onSuccess: () => {
            // Upload complete - workflow will continue in background
            resetOfflineImport();
        },
        onError: (error) => {
            // Error will be logged in workflow, but show alert for immediate feedback
            alert(`Upload failed: ${error.message}`);
            resetOfflineImport();
        }
    });

    // Start upload
    uploader.upload(selectedImportFile);

    // Immediately switch to Workflows tab to watch progress there
    resetOfflineImport();
    Alpine.store('app').switchTab('workflows');
}

// Reset offline import UI
function resetOfflineImport() {
    selectedImportFile = null;
    const progressDiv = document.getElementById('offline-progress-container');
    const progressBar = document.getElementById('offline-progress-bar');
    const importBtn = document.getElementById('offline-import-btn');
    const dropzoneText = document.getElementById('offline-dropzone-text');
    const fileInput = document.getElementById('offline-import-file');

    if (progressDiv) progressDiv.classList.add('hidden');
    if (progressBar) progressBar.style.width = '0%';
    if (importBtn) importBtn.disabled = false;
    if (dropzoneText) dropzoneText.textContent = 'Click to select ZIP file or drag & drop';
    if (fileInput) fileInput.value = '';
}

// Initialize dropzone when the offline import tab is shown
document.addEventListener('DOMContentLoaded', () => {
    // Initialize after a short delay to ensure DOM is ready
    setTimeout(initOfflineImportDropzone, 500);
});
