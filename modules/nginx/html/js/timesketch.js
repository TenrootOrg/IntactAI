/**
 * Timesketch Module - Timesketch workflow management
 */

// Client manager instance (uses shared utility)
const timesketchClientManager = new ClientManager('timesketch-client-list', 'timesketch-client-checkbox');
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
        collection_timeout: blueprint.settings?.collection_timeout || 10000,
        cpu_limit: blueprint.settings?.cpu_limit || 80
    };
}

// Backwards-compatible wrapper functions for client management
function populateTimeSketchClients() { timesketchClientManager.load(); }
function filterTimesketchClients(searchTerm) { timesketchClientManager.filter(searchTerm); }
function selectAllTimeSketchClients() { timesketchClientManager.selectAll(true); }
function deselectAllTimeSketchClients() { timesketchClientManager.selectAll(false); }

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
    const cpuLimit = blueprintSettings.cpu_limit || 80;
    const monitorTimeout = blueprintSettings.collection_timeout || 10000;

    // Plaso settings from blueprint
    const plasoParser = blueprintSettings.plaso_parser;
    const plasoWorkers = blueprintSettings.plaso_workers;
    const plasoHasher = blueprintSettings.plaso_hasher === 'none' ? '' : blueprintSettings.plaso_hasher;
    const plasoHasherSizeMb = blueprintSettings.plaso_hasher_size;

    const clientIds = selectedClients.map(cb => cb.value);
    const hostnames = selectedClients.map(cb => cb.dataset.hostname).join(', ');

    const blueprintName = document.getElementById('timesketch-blueprint-select').selectedOptions[0]?.text || 'Unknown';

    if (!confirm(`Start KAPE collection and TimeSketch import for ${selectedClients.length} client(s)?\n\nBlueprint: ${blueprintName}\nClients: ${hostnames}\nKAPE Target: ${kapeTarget}\nPlaso Parser: ${plasoParser}\nCollection Timeout: ${timeoutSeconds}s\nCPU Limit: ${cpuLimit}%\nSketch: ${sketchName}\n\nNote: If sketch already exists, timelines will be added to it.`)) {
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
                    timeline_name: `${hostname}_${new Date().toISOString().slice(0,10).replace(/-/g, '')}_${new Date().toISOString().slice(11,19).replace(/:/g, '')}`,
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

// ============================================================================
// Upload Mode Functions
// ============================================================================

// Selected file for upload
let tsSelectedFile = null;

// Toggle between automation and upload modes
function toggleTimesketchMode() {
    const mode = document.querySelector('input[name="ts-mode"]:checked').value;
    const automationSection = document.getElementById('ts-automation-section');
    const uploadSection = document.getElementById('ts-upload-section');

    if (mode === 'automation') {
        automationSection.classList.remove('hidden');
        uploadSection.classList.add('hidden');
    } else {
        automationSection.classList.add('hidden');
        uploadSection.classList.remove('hidden');
        initTimesketchUploadDropzone();
    }
}

// Initialize upload dropzone
function initTimesketchUploadDropzone() {
    const dropzone = document.getElementById('ts-upload-dropzone');
    const fileInput = document.getElementById('ts-kape-file');
    const dropzoneText = document.getElementById('ts-dropzone-text');

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
        dropzone.classList.add('border-purple-500', 'bg-purple-500/10');
    });

    dropzone.addEventListener('dragleave', (e) => {
        e.preventDefault();
        e.stopPropagation();
        dropzone.classList.remove('border-purple-500', 'bg-purple-500/10');
    });

    dropzone.addEventListener('drop', (e) => {
        e.preventDefault();
        e.stopPropagation();
        dropzone.classList.remove('border-purple-500', 'bg-purple-500/10');

        const files = e.dataTransfer.files;
        if (files.length > 0) {
            handleTimesketchFileSelect(files[0]);
        }
    });

    // File input change
    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
            handleTimesketchFileSelect(e.target.files[0]);
        }
    });
}

// Handle file selection
function handleTimesketchFileSelect(file) {
    const dropzoneText = document.getElementById('ts-dropzone-text');

    if (!file.name.toLowerCase().endsWith('.zip')) {
        alert('Please select a ZIP file');
        return;
    }

    tsSelectedFile = file;

    // Update dropzone text
    const sizeStr = formatBytes(file.size);
    dropzoneText.innerHTML = `<span class="text-purple-400 font-medium">${file.name}</span><br><span class="text-xs">${sizeStr}</span>`;
}

// Upload KAPE file using tus protocol
function uploadKapeToTimesketch() {
    if (!tsSelectedFile) {
        alert('Please select a KAPE collection file');
        return;
    }

    // Get blueprint settings
    const blueprintSettings = getTimesketchBlueprintSettings();
    if (!blueprintSettings) {
        alert('Please select a blueprint');
        return;
    }

    const sketchName = document.getElementById('ts-upload-sketch').value.trim()
        || `Investigation-${new Date().toISOString().split('T')[0]}`;

    // Show progress UI
    const progressDiv = document.getElementById('ts-upload-progress');
    const progressBar = document.getElementById('ts-upload-bar');
    const progressPercent = document.getElementById('ts-upload-percent');
    const progressStatus = document.getElementById('ts-upload-status');
    const filenameEl = document.getElementById('ts-upload-filename');
    const uploadBtn = document.getElementById('ts-upload-btn');

    progressDiv.classList.remove('hidden');
    filenameEl.textContent = tsSelectedFile.name;
    uploadBtn.disabled = true;
    uploadBtn.classList.add('opacity-50', 'cursor-not-allowed');

    // Create uploader - progress is tracked in Workflows tab via tus hooks
    const uploader = new TusUploader({
        purpose: 'timesketch',
        metadata: {
            sketch_name: sketchName,
            plaso_parser: blueprintSettings.plaso_parser || 'win7',
            plaso_workers: String(blueprintSettings.plaso_workers || 2),
            plaso_hasher: blueprintSettings.plaso_hasher === 'none' ? '' : (blueprintSettings.plaso_hasher || ''),
            plaso_hasher_size: String(blueprintSettings.plaso_hasher_size || 100)
        },
        onProgress: (info) => {
            // Progress is tracked in workflow logs, no need to update UI here
        },
        onSuccess: () => {
            // Upload complete - workflow will continue in background
            resetTimesketchUpload();
        },
        onError: (error) => {
            // Error will be logged in workflow, but show alert for immediate feedback
            alert(`Upload failed: ${error.message}`);
            resetTimesketchUpload();
        }
    });

    // Start upload
    uploader.upload(tsSelectedFile);

    // Immediately switch to Workflows tab to watch progress there
    resetTimesketchUpload();
    switchTab('workflows');
}

// Reset upload UI
function resetTimesketchUpload() {
    const progressDiv = document.getElementById('ts-upload-progress');
    const progressBar = document.getElementById('ts-upload-bar');
    const dropzoneText = document.getElementById('ts-dropzone-text');
    const fileInput = document.getElementById('ts-kape-file');

    tsSelectedFile = null;
    progressDiv.classList.add('hidden');
    progressBar.style.width = '0%';
    dropzoneText.textContent = 'Drag & drop ZIP file or click to browse';
    if (fileInput) fileInput.value = '';
}
