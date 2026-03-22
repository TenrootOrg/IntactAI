/**
 * Blueprints Forensics Module - Forensics tab functions for Velociraptor + Agentic
 * Split from blueprints.js for maintainability
 */

// ============================================================================
// Forensics Tab - Unified Velociraptor + Agentic
// ============================================================================

let forensicsSelectedClients = new Set();
let forensicsClientsCache = [];
let forensicsExternalFiles = [];  // [{upload_id, filename, status}, ...]

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
    if (cpuEl) cpuEl.textContent = (bp.settings?.cpu_limit || 90) + '%';
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

function toggleForensicsExternal() {
    const toggle = document.getElementById('forensics-external-toggle');
    const details = document.getElementById('forensics-external-details');
    if (details) {
        details.classList.toggle('hidden', !toggle?.checked);
    }
}

async function uploadExternalFiles(event) {
    const files = event.target.files;
    if (!files || files.length === 0) return;

    for (const file of files) {
        // Check file extension
        const ext = file.name.toLowerCase().split('.').pop();
        const allowedExts = ['csv', 'json', 'jsonl', 'log', 'txt', 'xml', 'tsv', 'syslog'];
        if (!allowedExts.includes(ext)) {
            alert(`Invalid file type: ${file.name}. Allowed: ${allowedExts.map(e => '.' + e).join(', ')}`);
            continue;
        }

        // Add to list with "uploading" status
        const fileEntry = {
            upload_id: null,
            filename: file.name,
            status: 'uploading'
        };
        forensicsExternalFiles.push(fileEntry);
        renderExternalFilesList();

        // Use TUS to upload
        try {
            const upload = new tus.Upload(file, {
                endpoint: '/files/',
                metadata: {
                    filename: file.name,
                    purpose: 'agentic_external'
                },
                onError: (error) => {
                    console.error('[External] Upload error:', error);
                    fileEntry.status = 'error';
                    renderExternalFilesList();
                },
                onProgress: (bytesUploaded, bytesTotal) => {
                    const pct = Math.round((bytesUploaded / bytesTotal) * 100);
                    fileEntry.status = `${pct}%`;
                    renderExternalFilesList();
                },
                onSuccess: () => {
                    // Extract upload_id from URL
                    const uploadId = upload.url.split('/').pop();
                    fileEntry.upload_id = uploadId;
                    fileEntry.status = 'ready';
                    console.log(`[External] Uploaded ${file.name} -> ${uploadId}`);
                    renderExternalFilesList();
                }
            });
            upload.start();
        } catch (err) {
            console.error('[External] Upload failed:', err);
            fileEntry.status = 'error';
            renderExternalFilesList();
        }
    }

    // Clear file input so same file can be selected again
    event.target.value = '';
}

function removeExternalFile(index) {
    forensicsExternalFiles.splice(index, 1);
    renderExternalFilesList();
}

function renderExternalFilesList() {
    const container = document.getElementById('forensics-external-files');
    if (!container) return;

    if (forensicsExternalFiles.length === 0) {
        container.innerHTML = '';
        return;
    }

    container.innerHTML = forensicsExternalFiles.map((file, idx) => {
        let statusClass = 'text-gray-400';
        let statusText = file.status;
        let statusIcon = '';

        if (file.status === 'ready') {
            statusClass = 'text-green-400';
            statusIcon = '<svg class="w-3 h-3" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"/></svg>';
        } else if (file.status === 'error') {
            statusClass = 'text-red-400';
            statusIcon = '<svg class="w-3 h-3" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd"/></svg>';
        } else if (file.status === 'uploading' || file.status.includes('%')) {
            statusClass = 'text-blue-400';
            statusIcon = '<svg class="w-3 h-3 animate-spin" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"/><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"/></svg>';
        }

        return '<div class="flex items-center gap-2 bg-gray-700/50 px-3 py-2 rounded-lg">' +
            '<svg class="w-4 h-4 text-gray-400 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">' +
            '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>' +
            '</svg>' +
            '<span class="flex-1 text-sm text-gray-300 truncate" title="' + file.filename + '">' + file.filename + '</span>' +
            '<span class="flex items-center gap-1 text-xs ' + statusClass + '">' +
            statusIcon +
            '<span>' + statusText + '</span>' +
            '</span>' +
            '<button onclick="removeExternalFile(' + idx + ')" class="text-gray-500 hover:text-red-400 transition-colors" title="Remove">' +
            '<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">' +
            '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>' +
            '</svg>' +
            '</button>' +
            '</div>';
    }).join('');
}

function getReadyExternalFiles() {
    // Return only files that are ready for submission
    return forensicsExternalFiles
        .filter(f => f.status === 'ready' && f.upload_id)
        .map(f => ({ upload_id: f.upload_id, filename: f.filename }));
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
let fpDateStart = null;
let fpDateEnd = null;

// Helper functions for time dropdowns - called from HTML onchange
function updateCombinedStartDateTime() {
    const dateEl = document.getElementById('forensics-date-start');
    const hourEl = document.getElementById('forensics-time-start-hour');
    const hiddenEl = document.getElementById('forensics-time-start');
    if (dateEl && hourEl && hiddenEl && dateEl.value) {
        hiddenEl.value = `${dateEl.value} ${hourEl.value}:00`;
    }
}

function updateCombinedEndDateTime() {
    const dateEl = document.getElementById('forensics-date-end');
    const hourEl = document.getElementById('forensics-time-end-hour');
    const hiddenEl = document.getElementById('forensics-time-end');
    if (dateEl && hourEl && hiddenEl && dateEl.value) {
        hiddenEl.value = `${dateEl.value} ${hourEl.value}:00`;
    }
}

function initDatePickers() {
    // Only initialize if Flatpickr is available
    if (typeof flatpickr === 'undefined') {
        console.warn('[DatePicker] Flatpickr not loaded');
        return;
    }

    const dateStartEl = document.getElementById('forensics-date-start');
    const dateEndEl = document.getElementById('forensics-date-end');

    if (!dateStartEl || !dateEndEl) {
        console.warn('[DatePicker] Date elements not found');
        return;
    }

    // Destroy existing instances
    if (fpDateStart) { fpDateStart.destroy(); fpDateStart = null; }
    if (fpDateEnd) { fpDateEnd.destroy(); fpDateEnd = null; }

    // Date picker config (date only, no time)
    const dateConfig = {
        dateFormat: "Y-m-d",
        disableMobile: true,
        allowInput: false,
        clickOpens: true,
        animate: true,
        appendTo: document.body
    };

    // Small delay to ensure element is visible
    setTimeout(() => {
        // Start date picker
        fpDateStart = flatpickr(dateStartEl, {
            ...dateConfig,
            onChange: function(selectedDates, dateStr) {
                updateCombinedStartDateTime();
                if (fpDateEnd && selectedDates[0]) {
                    fpDateEnd.set('minDate', selectedDates[0]);
                }
            }
        });

        // End date picker
        fpDateEnd = flatpickr(dateEndEl, {
            ...dateConfig,
            onChange: function(selectedDates, dateStr) {
                updateCombinedEndDateTime();
                if (fpDateStart && selectedDates[0]) {
                    fpDateStart.set('maxDate', selectedDates[0]);
                }
            }
        });

        console.log('[DatePicker] Initialized successfully with separate date/time pickers');
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

        // Parse dates - input is already in UTC, don't convert again
        let startDatetime = null;
        let endDatetime = null;

        if (startVal) {
            // Input format: "2026-03-10 06:00:00" -> "2026-03-10T06:00:00.000Z"
            startDatetime = startVal.replace(' ', 'T') + '.000Z';
        }

        if (endVal) {
            // Input format: "2026-03-10 10:00:00" -> "2026-03-10T10:00:00.000Z"
            endDatetime = endVal.replace(' ', 'T') + '.000Z';
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
            const minSeverity = document.getElementById('forensics-min-severity')?.value || 'informational';
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

            // Get external files if enabled
            const includeExternal = document.getElementById('forensics-external-toggle')?.checked || false;
            const externalFiles = includeExternal ? getReadyExternalFiles() : [];

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
                    time_filter: timeFilter,
                    min_severity: minSeverity,
                    external_files: externalFiles
                })
            });

            const data = await response.json();
            if (response.ok) {
                const extInfo = externalFiles.length > 0 ? ` (+${externalFiles.length} external files)` : '';
                statusEl.innerHTML = `<span class="text-green-400">AI Analysis started! Run ID: ${data.run_id}${extInfo}</span><br>Redirecting to Workflows...`;
                // Clear external files after successful start
                forensicsExternalFiles = [];
                renderExternalFilesList();
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
                    cpu_limit: blueprint.settings?.cpu_limit || 90
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
        const minSeverity = document.getElementById('forensics-min-severity')?.value || 'informational';
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

        // Get external files if enabled
        const includeExternal = document.getElementById('forensics-external-toggle')?.checked || false;
        const externalFiles = includeExternal ? getReadyExternalFiles() : [];

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
                time_filter: timeFilter,
                min_severity: minSeverity,
                external_files: externalFiles
            })
        });

        const data = await response.json();
        if (response.ok) {
            const extInfo = externalFiles.length > 0 ? ` (+${externalFiles.length} external files)` : '';
            statusEl.innerHTML = `<span class="text-green-400">AI Analysis started! Run ID: ${data.run_id}${extInfo}</span><br>Redirecting to Workflows...`;
            // Clear external files after successful start
            forensicsExternalFiles = [];
            renderExternalFilesList();
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
