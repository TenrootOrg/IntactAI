/**
 * Velociraptor Module - Artifacts, hunts, offline collectors
 */

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
            return `<option value="${escapeHtml(c.config_id)}"${selected}>${escapeHtml(c.config_name || c.config_id)}</option>`;
        }).join('');
}


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

function getSelectedOfflineArtifacts() {
    return Array.from(document.querySelectorAll('.offline-artifact-checkbox:checked')).map(cb => cb.value);
}

// Toggle the encryption inputs + explainer based on the selected scheme.
function onOfflineEncSchemeChange(scheme) {
    const pwWrap = document.getElementById('offline-enc-password-wrap');
    const expl = document.getElementById('offline-enc-explain');
    const explText = document.getElementById('offline-enc-explain-text');
    const explain = {
        password: "Symmetric: one secret encrypts and decrypts. Simplest and fully portable — import on any server by supplying the same password. The password is a shared secret, so protect it.",
        x509: "Asymmetric, integrated: uses THIS server's certificate (the CA managed in data/velociraptor). The server auto-decrypts on import — no password, nothing to manage. To import on a DIFFERENT server, copy data/velociraptor (the CA) to it, or use Password for full portability."
    };
    if (pwWrap) pwWrap.classList.toggle('hidden', scheme !== 'password');
    if (expl && explText) {
        if (explain[scheme]) { explText.textContent = explain[scheme]; expl.classList.remove('hidden'); }
        else expl.classList.add('hidden');
    }
}

async function generateOfflineCollector() {
    const configId = document.getElementById('offline-gen-config').value;
    // The radio group encodes both OS and variant in a single value
    // formatted "os:variant" (e.g. "linux:musl"). Six valid pairs
    // total — see the index.html "Target build" block. No JS filtering
    // is needed because the impossible combos simply aren't listed.
    const targetVal = document.querySelector('input[name="offline-gen-target"]:checked')?.value || 'windows:standard';
    const [os, variant] = targetVal.split(':');

    if (!configId) {
        alert('Please select a configuration');
        return;
    }

    const statusEl = document.getElementById('offline-gen-status');
    statusEl.classList.remove('hidden');
    const variantTag = variant === 'standard'
        ? ''
        : ` <span class="text-${variant === 'legacy' ? 'purple' : 'orange'}-400">(${variant})</span>`;
    statusEl.innerHTML = `<span class="text-yellow-400">Starting collector generation for ${os}...</span>${variantTag}`;

    try {
        // Always use the install.sh-bundled binary (source=offline). The
        // backend still accepts an `online` mode for power-users hitting
        // the API directly, but the UI doesn't expose it — operators kept
        // hitting the GitHub button by accident.
        const body = { config_id: configId, os: os };
        if (variant === 'legacy') {
            body.legacy = true;
            body.legacy_source = 'offline';
        } else if (variant === 'musl') {
            body.musl = true;
        }

        // Optional per-build no-progress watchdog (seconds)
        const ptRaw = (document.getElementById('offline-progress-timeout')?.value || '').trim();
        if (ptRaw) {
            const pt = parseInt(ptRaw, 10);
            if (isNaN(pt) || pt < 60 || pt > 86400) {
                alert('No-progress timeout must be between 60 and 86400 seconds (or blank for the default).');
                statusEl.classList.add('hidden'); return;
            }
            body.progress_timeout = pt;
        }

        // Optional container encryption
        const encScheme = document.getElementById('offline-enc-scheme')?.value || 'none';
        if (encScheme === 'password') {
            const pw = document.getElementById('offline-enc-password')?.value || '';
            if (!pw) { alert('Enter an encryption password (or set Encryption to None).'); statusEl.classList.add('hidden'); return; }
            body.encryption_scheme = 'password';
            body.encryption_password = pw;
        } else if (encScheme === 'x509') {
            // Always this server's certificate (the CA in data/velociraptor); the
            // server auto-decrypts on import. No key input.
            body.encryption_scheme = 'x509';
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
            statusEl.innerHTML = `<span class="text-red-400">Error: ${escapeHtml(data.error || 'Generation failed')}</span>`;
        }
    } catch (error) {
        statusEl.innerHTML = `<span class="text-red-400">Error: ${escapeHtml(error.message)}</span>`;
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
        dropzoneText.innerHTML = `<span class="text-blue-400 font-medium">${escapeHtml(file.name)}</span><br><span class="text-xs">${sizeStr}</span>`;
        document.getElementById('offline-import-btn').disabled = false;
    }
}


// Initialize offline import dropzone with drag & drop
function initOfflineImportDropzone() {
    // handleOfflineFileSelect is also wired as an inline onchange= in
    // partials/velociraptor.html, so it takes an event, not a File.
    initDropzone('offline-dropzone', 'offline-import-file',
                 (file) => handleOfflineFileSelect({ target: { files: [file] } }),
                 { highlight: ['border-blue-500', 'bg-blue-500/10'] });
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

    // Optional decryption password for an encrypted collection (sent via tus
    // metadata to the import hook). Empty for unencrypted collections.
    const importPw = document.getElementById('offline-import-password')?.value || '';
    const importMeta = importPw ? { password: importPw } : {};

    // Create uploader - progress is tracked in Workflows tab via tus hooks
    const uploader = new TusUploader({
        purpose: 'velociraptor',
        metadata: importMeta,
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

// Initialize dropzone once the Velociraptor partial (which holds the offline
// import UI) has been injected into the DOM.
document.addEventListener('partials:ready', () => {
    setTimeout(initOfflineImportDropzone, 100);
});


// =============================================================================
// Add by ID — adopt an existing Velociraptor flow/hunt into the active case
// =============================================================================
//
// Starts no collection. The backend reads results the Velociraptor server
// already holds for this id, keeps only the artifacts fusion has mappers for,
// and files it as a normal workflow run tagged to the active case — so progress,
// the full per-artifact log and Stop all live in the Workflows tab like every
// other module, rather than in a second progress UI here.
async function adoptVelociraptorId() {
    const idInput = document.getElementById('adopt-id');
    const statusDiv = document.getElementById('adopt-status');
    const btn = document.getElementById('adopt-btn');

    const ident = (idInput?.value || '').trim();

    statusDiv.classList.remove('hidden');

    if (!ident) {
        statusDiv.innerHTML = '<span class="text-red-400">Enter a flow id or hunt id.</span>';
        return;
    }

    btn.disabled = true;
    statusDiv.innerHTML = '<span class="text-yellow-400">Starting…</span>';

    try {
        const response = await fetch('/api/velociraptor/adopt', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ id: ident })
        });

        const data = await response.json();

        if (response.ok) {
            const kind = data.kind === 'hunt' ? 'Hunt' : 'Flow';
            statusDiv.innerHTML = `<span class="text-green-400">${kind} ${escapeHtml(data.id || ident)} `
                + `added to the case. Opening Workflows…</span>`;
            idInput.value = '';
            setTimeout(() => {
                switchTab('workflows');
                loadWorkflows();
                statusDiv.classList.add('hidden');
                btn.disabled = false;
            }, 1200);
            return;
        }

        // 409 = already in this case. Say which run holds it rather than a bare
        // error, so the operator can go straight to Fetch results on that row.
        statusDiv.innerHTML = `<span class="text-${response.status === 409 ? 'yellow' : 'red'}-400">`
            + `${escapeHtml(data.error || 'Request failed')}</span>`;
        btn.disabled = false;
    } catch (error) {
        statusDiv.innerHTML = `<span class="text-red-400">Error: ${escapeHtml(error.message)}</span>`;
        btn.disabled = false;
    }
}
