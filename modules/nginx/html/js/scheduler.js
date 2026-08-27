/**
 * Scheduler Module - Manages recurring blueprint execution schedules
 */

// Initialize when tab opens
async function initScheduler() {
    await loadSchedulerJobs();
    await loadSchedulerClients();
    onScheduleBlueprintTypeChange(); // Load initial blueprints
}

// Load and render all scheduled jobs
async function loadSchedulerJobs() {
    const listContainer = document.getElementById('scheduler-jobs-list');
    const emptyState = document.getElementById('scheduler-empty-state');

    try {
        const response = await fetch('/api/scheduler/jobs');
        if (!response.ok) {
            listContainer.innerHTML = '<p class="text-red-400 text-sm">Failed to load scheduled jobs</p>';
            return;
        }

        const data = await response.json();
        const jobs = data.jobs || [];

        if (jobs.length === 0) {
            listContainer.innerHTML = '';
            emptyState.classList.remove('hidden');
            return;
        }

        emptyState.classList.add('hidden');
        listContainer.innerHTML = jobs.map(job => renderScheduleCard(job)).join('');

    } catch (error) {
        listContainer.innerHTML = `<p class="text-red-400 text-sm">Error: ${error.message}</p>`;
    }
}

// Render a single schedule card
function renderScheduleCard(job) {
    const isEnabled = job.enabled == 1;
    let typeLabel, typeBadgeColor;
    if (job.blueprint_type === 'agentic') {
        typeLabel = 'Velociraptor Collector';
        typeBadgeColor = 'bg-purple-900 text-purple-300';
    } else if (job.blueprint_type === 'timesketch') {
        typeLabel = 'Timesketch';
        typeBadgeColor = 'bg-cyan-900 text-cyan-300';
        typeBadgeColor = 'bg-amber-900 text-amber-300';
    } else if (job.blueprint_type === 'memory') {
        typeLabel = 'Volatile Memory';
        typeBadgeColor = 'bg-rose-900 text-rose-300';
    } else if (job.blueprint_type === 'aws') {
        typeLabel = 'AWS (CloudTrail)';
        typeBadgeColor = 'bg-orange-900 text-orange-300';
    } else {
        typeLabel = 'Velociraptor Hunt';
        typeBadgeColor = 'bg-blue-900 text-blue-300';
    }
    const statusDot = isEnabled ? 'bg-green-400' : 'bg-gray-500';
    const statusText = isEnabled ? 'Active' : 'Paused';

    // Format interval — every N days/weeks/months/years
    const unit = job.interval_unit || 'days';
    const n = parseInt(job.interval_value) || 1;
    const unitLabel = { days: 'day', weeks: 'week', months: 'month', years: 'year' }[unit] || 'day';
    const intervalText = n === 1 ? `Every ${unitLabel}` : `Every ${n} ${unitLabel}s`;

    // Format run time (already in UTC)
    let runTimeText = '';
    if (job.run_time) {
        runTimeText = ` at ${job.run_time} UTC`;
    }
    // Start-date anchor (first run / interval reference)
    if (job.start_at) {
        const d = String(job.start_at).slice(0, 10);
        runTimeText += ` · from ${d}`;
    }

    // Helper to format date in UTC
    function formatUtcDate(date) {
        const d = new Date(date);
        const year = d.getUTCFullYear();
        const month = String(d.getUTCMonth() + 1).padStart(2, '0');
        const day = String(d.getUTCDate()).padStart(2, '0');
        const hours = String(d.getUTCHours()).padStart(2, '0');
        const mins = String(d.getUTCMinutes()).padStart(2, '0');
        return `${year}-${month}-${day} ${hours}:${mins} UTC`;
    }

    // Format next run (display in UTC)
    let nextRunText = 'Not scheduled';
    if (job.next_run_at) {
        nextRunText = formatUtcDate(job.next_run_at);
    }

    // Format last run (display in UTC)
    let lastRunText = 'Never';
    if (job.last_run_at) {
        lastRunText = formatUtcDate(job.last_run_at);
    }

    // Parse client count
    let clientCount = 0;
    try {
        const clients = JSON.parse(job.client_ids || '[]');
        clientCount = clients.length;
    } catch (e) {}

    return `
    <div class="bg-gray-800 rounded-lg p-5 border border-gray-700">
        <div class="flex items-start justify-between">
            <div class="flex-1">
                <div class="flex items-center gap-2 mb-1">
                    <span class="inline-block w-2 h-2 ${statusDot} rounded-full"></span>
                    <h4 class="text-lg font-semibold text-white">${escapeHtml(job.name)}</h4>
                    <span class="text-xs ${typeBadgeColor} px-2 py-0.5 rounded">${typeLabel}</span>
                    <span class="text-xs bg-gray-700 text-gray-300 px-2 py-0.5 rounded">${statusText}</span>
                </div>
                ${job.description ? `<p class="text-sm text-gray-400 mb-2">${escapeHtml(job.description)}</p>` : ''}
                <div class="flex flex-wrap gap-4 text-xs text-gray-500">
                    <span title="Interval">${intervalText}${runTimeText}</span>
                    <span title="Next Run">Next: ${nextRunText}</span>
                    <span title="Last Run">Last: ${lastRunText}</span>
                    <span title="Run Count">Runs: ${job.run_count || 0}</span>
                    <span title="Clients">${clientCount} client(s)</span>
                </div>
            </div>
            <div class="flex gap-2 ml-4">
                <button onclick="runScheduleNow('${job.id}')" title="Run Now" class="text-xs bg-green-700 hover:bg-green-600 px-3 py-1.5 rounded flex items-center gap-1">
                    <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z"></path>
                    </svg>
                    Run
                </button>
                <button onclick="toggleSchedule('${job.id}', ${isEnabled ? 'false' : 'true'})" class="text-xs ${isEnabled ? 'bg-yellow-700 hover:bg-yellow-600' : 'bg-blue-700 hover:bg-blue-600'} px-3 py-1.5 rounded">
                    ${isEnabled ? 'Pause' : 'Resume'}
                </button>
                <button onclick="editSchedule('${job.id}')" class="text-xs bg-gray-700 hover:bg-gray-600 px-3 py-1.5 rounded">Edit</button>
                <button onclick="deleteSchedule('${job.id}')" class="text-xs bg-red-700 hover:bg-red-600 px-3 py-1.5 rounded">Delete</button>
            </div>
        </div>
    </div>`;
}

// Client manager instance (uses shared utility)
const schedulerClientManager = new ClientManager('schedule-client-list', 'schedule-client-cb');

// Backwards-compatible wrapper functions
function loadSchedulerClients() { schedulerClientManager.load(); }
function filterScheduleClients(searchTerm) { schedulerClientManager.filter(searchTerm); }
function selectAllScheduleClients(checked) { schedulerClientManager.selectAll(checked); }
function getSelectedScheduleClients() { return schedulerClientManager.getSelected(); }

// Handle blueprint type change
async function onScheduleBlueprintTypeChange() {
    const type = document.getElementById('schedule-blueprint-type').value;
    const select = document.getElementById('schedule-blueprint-select');
    const blueprintSelectContainer = select.parentElement;
    const clientSection = document.getElementById('schedule-client-section');

    // Hide every per-type options block; the active one is revealed below.
    ['timesketch', 'memory', 'collector', 'hunt', 'aws'].forEach(k => {
        const el = document.getElementById('schedule-' + k + '-options');
        if (el) el.classList.add('hidden');
    });

    // Client picker: shown for client-targeted types (Collector/Timesketch/Memory),
    // HIDDEN for env-wide types (Velociraptor Hunt, AWS).
    const envWide = (type === 'velociraptor' || type === 'aws');
    if (clientSection) clientSection.classList.toggle('hidden', envWide);

    // Reveal this type's options block.
    const optKey = { agentic: 'collector', velociraptor: 'hunt', timesketch: 'timesketch',
                     memory: 'memory', aws: 'aws' }[type];
    const optEl = optKey && document.getElementById('schedule-' + optKey + '-options');
    if (optEl) optEl.classList.remove('hidden');

    blueprintSelectContainer.classList.remove('hidden');

    // Blueprint list source: AWS has its own endpoint; everything else (agentic
    // collector / velociraptor hunt / timesketch / memory) is /api/blueprints/<type>.
    const url = (type === 'aws') ? '/api/aws/blueprints' : `/api/blueprints/${type}`;
    try {
        const response = await fetch(url);
        if (!response.ok) {
            select.innerHTML = '<option value="">Failed to load</option>';
            return;
        }
        const data = await response.json();
        const blueprints = data.blueprints || (Array.isArray(data) ? data : []);

        select.innerHTML = blueprints.map(bp => {
                const n = bp.artifacts ? bp.artifacts.length : 0;
                const name = escapeHtml(bp.name);
                const label = n ? `${name} (${n} artifacts)` : name;  // memory/aws bps have no artifacts
                return `<option value="${escapeHtml(bp.id)}">${label}</option>`;
            }).join('') || '<option value="">No blueprints available</option>';
        // Default to the first blueprint (no "-- Select --" placeholder).
        if (blueprints.length) select.value = blueprints[0].id;

    } catch (error) {
        select.innerHTML = '<option value="">Error loading blueprints</option>';
    }
}

// UTC clock interval reference
let utcClockInterval = null;

// Update the UTC clock display
function updateScheduleUtcClock() {
    const clockEl = document.getElementById('schedule-utc-clock');
    if (clockEl) {
        const now = new Date();
        const utcTime = now.toISOString().substring(11, 19); // HH:MM:SS
        const utcDate = now.toISOString().substring(0, 10);  // YYYY-MM-DD
        clockEl.textContent = `${utcDate} ${utcTime}`;
    }
}

// Start updating UTC clock
function startUtcClock() {
    updateScheduleUtcClock();
    if (utcClockInterval) clearInterval(utcClockInterval);
    utcClockInterval = setInterval(updateScheduleUtcClock, 1000);
}

// Stop UTC clock updates
function stopUtcClock() {
    if (utcClockInterval) {
        clearInterval(utcClockInterval);
        utcClockInterval = null;
    }
}

// Show modal for new schedule
function showNewScheduleModal() {
    document.getElementById('schedule-modal').classList.remove('hidden');
    document.getElementById('schedule-modal-title').textContent = 'New Scheduled Job';
    document.getElementById('schedule-edit-id').value = '';
    document.getElementById('schedule-name').value = '';
    document.getElementById('schedule-description').value = '';
    document.getElementById('schedule-interval-value').value = 1;
    document.getElementById('schedule-interval-unit').value = 'days';
    document.getElementById('schedule-blueprint-type').value = 'agentic';  // Velociraptor Collector (default)

    // Default start date = today (UTC); default run time 02:00
    document.getElementById('schedule-start-date').value = new Date().toISOString().slice(0, 10);
    document.getElementById('schedule-run-time').value = '02:00';

    // Start UTC clock
    startUtcClock();

    // Reset selection (new job starts with nothing selected)
    schedulerClientManager.setSelected([]);

    // Reset per-type option fields to their defaults
    document.getElementById('schedule-sketch-name').value = '';
    const setVal = (id, v) => { const el = document.getElementById(id); if (el) { if (el.type === 'checkbox') el.checked = v; else el.value = v; } };
    setVal('schedule-memory-yara', true); setVal('schedule-memory-case', '');
    setVal('schedule-memory-acq-timeout', ''); setVal('schedule-memory-plugin-timeout', ''); setVal('schedule-memory-yara-timeout', '');
    setVal('schedule-collector-minutes', '30');
    setVal('schedule-hunt-labels', '');
    setVal('schedule-aws-scope', 'account_wide'); setVal('schedule-aws-regions', ''); setVal('schedule-aws-max-events', '');

    onScheduleBlueprintTypeChange();
}

// Close modal
function closeScheduleModal() {
    document.getElementById('schedule-modal').classList.add('hidden');
    stopUtcClock();
}

// Edit existing schedule
async function editSchedule(jobId) {
    try {
        const response = await fetch(`/api/scheduler/jobs/${jobId}`);
        if (!response.ok) {
            alert('Failed to load job details');
            return;
        }

        const job = await response.json();

        document.getElementById('schedule-modal').classList.remove('hidden');
        document.getElementById('schedule-modal-title').textContent = 'Edit Scheduled Job';

        // Start UTC clock
        startUtcClock();
        document.getElementById('schedule-edit-id').value = job.id;
        document.getElementById('schedule-name').value = job.name || '';
        document.getElementById('schedule-description').value = job.description || '';
        document.getElementById('schedule-interval-value').value = job.interval_value || 1;
        document.getElementById('schedule-interval-unit').value = job.interval_unit || 'days';
        document.getElementById('schedule-blueprint-type').value = job.blueprint_type || 'velociraptor';

        // Start date anchor (from stored start_at datetime) + run time
        document.getElementById('schedule-start-date').value =
            (job.start_at ? String(job.start_at).slice(0, 10) : new Date().toISOString().slice(0, 10));
        document.getElementById('schedule-run-time').value = job.run_time || '02:00';

        // Load blueprints then set selected
        await onScheduleBlueprintTypeChange();
        document.getElementById('schedule-blueprint-select').value = job.blueprint_id || '';

        // Restore the saved client selection (Set model survives facet filtering)
        try {
            const clientIds = JSON.parse(job.client_ids || '[]');
            schedulerClientManager.setSelected(clientIds);
        } catch (e) {}

        // Sketch name for timesketch (the blueprint is set above via blueprint-select)
        if (job.blueprint_type === 'timesketch') {
            document.getElementById('schedule-sketch-name').value = job.description || '';
        }

        // Restore per-type run options
        let opts = {};
        try { opts = JSON.parse(job.options || '{}') || {}; } catch (e) {}
        const setV = (id, v) => { const el = document.getElementById(id); if (el && v !== undefined && v !== null) { if (el.type === 'checkbox') el.checked = !!v; else el.value = v; } };
        if ('include_yara' in opts) setV('schedule-memory-yara', opts.include_yara);
        setV('schedule-memory-case', opts.case_name);
        setV('schedule-memory-acq-timeout', opts.acquire_flow_timeout_s);
        setV('schedule-memory-plugin-timeout', opts.plugin_timeout_s);
        setV('schedule-memory-yara-timeout', opts.yarascan_timeout_s);
        setV('schedule-collector-minutes', opts.collection_minutes);
        setV('schedule-hunt-labels', (opts.include_labels || []).join(', '));
        setV('schedule-aws-scope', opts.scope_mode);
        setV('schedule-aws-max-events', opts.max_events_per_region);
        setV('schedule-aws-regions', (opts.regions || []).join(', '));

    } catch (error) {
        alert('Error loading job: ' + error.message);
    }
}

// Save schedule from modal
async function saveScheduleFromModal() {
    const editId = document.getElementById('schedule-edit-id').value;
    const name = document.getElementById('schedule-name').value.trim();
    let description = document.getElementById('schedule-description').value.trim();
    const blueprintType = document.getElementById('schedule-blueprint-type').value;
    const intervalValue = parseInt(document.getElementById('schedule-interval-value').value) || 1;
    const intervalUnit = document.getElementById('schedule-interval-unit').value || 'days';
    const startDate = document.getElementById('schedule-start-date').value || new Date().toISOString().slice(0, 10);
    const runTime = document.getElementById('schedule-run-time').value || '02:00';
    const clientIds = getSelectedScheduleClients();

    // Env-wide types run across every enrolled client / account (no picker):
    // Velociraptor Hunt, AWS.
    const envWide = (blueprintType === 'velociraptor' || blueprintType === 'aws');

    // Get blueprint ID based on type
    let blueprintId;
    blueprintId = document.getElementById('schedule-blueprint-select').value;
    if (blueprintType === 'timesketch') {
        // sketch name -> description (as before); the blueprint carries KAPE settings
        const sketchName = document.getElementById('schedule-sketch-name').value.trim();
        if (sketchName) description = sketchName;
    }

    // Per-type run options (stored as the job's `options` JSON blob).
    const num = (id) => { const v = parseInt((document.getElementById(id) || {}).value); return isNaN(v) ? null : v; };
    const csv = (id) => ((document.getElementById(id) || {}).value || '').split(',').map(s => s.trim()).filter(Boolean);
    let options = {};
    if (blueprintType === 'memory') {
        options = { include_yara: document.getElementById('schedule-memory-yara').checked,
                    case_name: (document.getElementById('schedule-memory-case').value || '').trim() || null,
                    acquire_flow_timeout_s: num('schedule-memory-acq-timeout'),
                    plugin_timeout_s: num('schedule-memory-plugin-timeout'),
                    yarascan_timeout_s: num('schedule-memory-yara-timeout') };
    } else if (blueprintType === 'agentic') {
        options = { collection_minutes: num('schedule-collector-minutes') || 30 };
    } else if (blueprintType === 'velociraptor') {
        options = { include_labels: csv('schedule-hunt-labels') };
    } else if (blueprintType === 'aws') {
        options = { scope_mode: document.getElementById('schedule-aws-scope').value,
                    regions: csv('schedule-aws-regions'),
                    max_events_per_region: num('schedule-aws-max-events') };
    }

    // Validation
    if (!name) {
        alert('Please enter a job name');
        return;
    }
    if (!blueprintId) {
        alert('Please select a blueprint');
        return;
    }
    // Client selection required only for client-targeted types.
    if (!envWide && clientIds.length === 0) {
        alert('Please select at least one client');
        return;
    }

    // Build payload
    const payload = {
        name,
        description,
        blueprint_id: blueprintId,
        blueprint_type: blueprintType,
        interval_value: intervalValue,
        interval_unit: intervalUnit,      // days | weeks | months | years
        start_date: startDate,            // anchor the interval to this date
        run_time: runTime,
        client_ids: clientIds,
        options: options                  // per-type run options
    };

    // Agentic runs are collection-only — no LLM report at the module level.
    if (blueprintType === 'agentic') {
        payload.report_types = [];
    }

    try {
        const url = editId ? `/api/scheduler/jobs/${editId}` : '/api/scheduler/jobs';
        const method = editId ? 'PUT' : 'POST';

        const response = await fetch(url, {
            method,
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        const result = await response.json();

        if (response.ok) {
            closeScheduleModal();
            await loadSchedulerJobs();
        } else {
            alert('Error: ' + (result.error || 'Failed to save'));
        }

    } catch (error) {
        alert('Error: ' + error.message);
    }
}

// Toggle schedule enabled/disabled
async function toggleSchedule(jobId, enabled) {
    try {
        const response = await fetch(`/api/scheduler/jobs/${jobId}/toggle`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enabled: enabled === 'true' || enabled === true })
        });

        if (response.ok) {
            await loadSchedulerJobs();
        } else {
            const data = await response.json();
            alert('Error: ' + (data.error || 'Failed to toggle'));
        }

    } catch (error) {
        alert('Error: ' + error.message);
    }
}

// Run schedule immediately
async function runScheduleNow(jobId) {
    if (!confirm('Run this scheduled job now?')) return;

    try {
        const response = await fetch(`/api/scheduler/jobs/${jobId}/run`, {
            method: 'POST'
        });

        const data = await response.json();

        if (response.ok) {
            alert('Job triggered successfully');
            await loadSchedulerJobs();
        } else {
            alert('Error: ' + (data.error || 'Failed to trigger'));
        }

    } catch (error) {
        alert('Error: ' + error.message);
    }
}

// Delete schedule
async function deleteSchedule(jobId) {
    if (!confirm('Are you sure you want to delete this scheduled job?')) return;

    try {
        const response = await fetch(`/api/scheduler/jobs/${jobId}`, {
            method: 'DELETE'
        });

        if (response.ok) {
            await loadSchedulerJobs();
        } else {
            const data = await response.json();
            alert('Error: ' + (data.error || 'Failed to delete'));
        }

    } catch (error) {
        alert('Error: ' + error.message);
    }
}
