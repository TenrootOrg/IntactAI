/**
 * Blueprints Forensics Module - Forensics tab functions for Velociraptor + Agentic
 * Split from blueprints.js for maintainability
 */

// ============================================================================
// Forensics Tab - Unified Velociraptor + Agentic
// ============================================================================

// Client picker for Collection mode — the shared faceted ClientManager (same
// component the scheduler/timesketch/memory pickers use). Selection lives in
// the manager's Set model; read it via getSelected() at submit time.
const forensicsClientManager = new ClientManager('forensics-client-list', 'forensics-client-cb');

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

    // Load clients (shared faceted picker)
    await forensicsClientManager.load();
    // Load the hunt label-target options (raw/hunt mode)
    await loadForensicsHuntLabels();
}

// Hunt label-target dropdown (raw/hunt mode). Single-line trigger shows a
// selection summary; clicking reveals a checkbox list of the available labels.
// No selection => all clients. When Velociraptor reports no labels, the dropdown
// is hidden and a "runs on all clients" note is shown.
const _forensicsSelectedLabels = new Set();

async function loadForensicsHuntLabels() {
    const dd = document.getElementById('forensics-hunt-labels-dd');
    const menu = document.getElementById('forensics-hunt-labels-menu');
    const empty = document.getElementById('forensics-hunt-labels-empty');
    if (!dd || !menu) return;

    _forensicsSelectedLabels.clear();
    let labels = [];
    try {
        const r = await fetch('/api/velociraptor/labels');
        const d = await r.json();
        labels = (d && d.labels) || [];
    } catch (e) {
        labels = [];
    }

    const none = labels.length === 0;
    dd.classList.toggle('hidden', none);
    if (empty) empty.classList.toggle('hidden', !none);

    // Render one checkbox row per (unique, backend-deduped) label.
    menu.innerHTML = '';
    labels.forEach(l => {
        const row = document.createElement('label');
        row.className = 'flex items-center gap-2 px-2 py-1.5 rounded hover:bg-gray-700 cursor-pointer text-sm text-gray-200';
        const cb = document.createElement('input');
        cb.type = 'checkbox';
        cb.value = l;
        cb.className = 'w-4 h-4 rounded border-gray-600 bg-gray-700 text-blue-600 focus:ring-blue-500';
        cb.addEventListener('change', () => onForensicsLabelToggle(l, cb.checked));
        const span = document.createElement('span');
        span.textContent = l;
        row.appendChild(cb);
        row.appendChild(span);
        menu.appendChild(row);
    });
    updateForensicsLabelsSummary();
}

function onForensicsLabelToggle(label, checked) {
    if (checked) _forensicsSelectedLabels.add(label);
    else _forensicsSelectedLabels.delete(label);
    updateForensicsLabelsSummary();
}

function updateForensicsLabelsSummary() {
    const el = document.getElementById('forensics-hunt-labels-summary');
    if (!el) return;
    const n = _forensicsSelectedLabels.size;
    el.textContent = n === 0 ? 'All clients'
        : n === 1 ? Array.from(_forensicsSelectedLabels)[0]
        : `${n} labels selected`;
}

function toggleForensicsLabelsDropdown(e) {
    if (e) e.stopPropagation();
    const menu = document.getElementById('forensics-hunt-labels-menu');
    if (menu) menu.classList.toggle('hidden');
}

// Close the dropdown on any outside click (bound once).
if (!window._forensicsLabelsOutsideBound) {
    window._forensicsLabelsOutsideBound = true;
    document.addEventListener('click', (e) => {
        const dd = document.getElementById('forensics-hunt-labels-dd');
        const menu = document.getElementById('forensics-hunt-labels-menu');
        if (dd && menu && !dd.contains(e.target)) menu.classList.add('hidden');
    });
}

// Currently-selected hunt labels; [] means "all clients".
function getSelectedForensicsLabels() {
    return Array.from(_forensicsSelectedLabels);
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
        // Collection → [Agentic] Quick Wins
        defaultBp = bps.find(bp => bp.name && bp.name.includes('[Agentic] Quick Wins'));
    } else {
        // Raw Velociraptor → [Velociraptor] BestPractice
        defaultBp = bps.find(bp => bp.name && bp.name.includes('[Velociraptor] BestPractice'));
    }

    // Fall back to the first blueprint so the dropdown never sits on the empty
    // placeholder (the preferred-name match above uses legacy [Agentic]/
    // [Velociraptor] markers that current blueprint names no longer carry).
    if (!defaultBp && bps.length) defaultBp = bps[0];
    if (defaultBp) {
        select.value = defaultBp.id;
        onForensicsBlueprintChange(defaultBp.id);
    }
}

// Backwards-compatible wrappers → shared faceted ClientManager.
function selectAllForensicsClients(select) { forensicsClientManager.selectAll(select); }
function filterForensicsClients(query) { forensicsClientManager.filter(query); }

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

async function startForensicsCollection() {
    // Get mode by checking which mode button has the active class (border-purple/blue-500)
    const aiButton = document.getElementById('forensics-mode-ai');
    const rawButton = document.getElementById('forensics-mode-raw');
    const isAiMode = aiButton?.className.includes('border-purple-500') && !rawButton?.className.includes('border-blue-500');

    const blueprintId = document.getElementById('forensics-blueprint-select')?.value;
    if (!blueprintId) {
        alert('Please select a blueprint');
        return;
    }

    // Collection mode requires at least one client.
    if (isAiMode) {
        const selectedClients = forensicsClientManager.getSelected();
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
            // Collection mode — agentic endpoint as a pure collector.
            // report_types=[] means the pipeline gathers + persists raw data
            // but skips all LLM/report work; analysis happens at the case level.
            const selectedClients = forensicsClientManager.getSelected();
            const collectionTime = parseInt(document.getElementById('forensics-collection-time')?.value || '30');

            const response = await fetch('/api/agentic/run', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    blueprint_id: blueprintId,
                    client_ids: selectedClients,
                    collection_minutes: collectionTime,
                    report_types: []
                })
            });

            const data = await response.json();
            if (response.ok) {
                statusEl.innerHTML = `<span class="text-green-400">Collection started! Run ID: ${data.run_id}</span><br>Redirecting to Workflows...`;
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
            const perArtifact = document.getElementById('forensics-per-artifact-toggle')?.checked || false;
            const response = await fetch('/api/velociraptor/bestpractice', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    artifacts: blueprint.artifacts || [],
                    blueprint_name: blueprint.name || 'Custom',
                    expire_minutes: blueprint.settings?.hunt_expiry || 120,
                    timeout_seconds: blueprint.settings?.timeout || 3600,
                    cpu_limit: blueprint.settings?.cpu_limit || 90,
                    per_artifact: perArtifact,
                    // Label targeting: [] => run on all clients.
                    include_labels: getSelectedForensicsLabels(),
                })
            });

            const data = await response.json();
            if (response.ok) {
                // Bulk path returns {run_id}; per-artifact path returns
                // {run_ids: [...]}. Render either flavour cleanly.
                const ids = data.run_ids || (data.run_id ? [data.run_id] : []);
                const idsDisplay = ids.length > 1 ? `${ids.length} separate hunts dispatched` : `Run ID: ${ids[0] || '?'}`;
                statusEl.innerHTML = `<span class="text-green-400">Hunt started! ${idsDisplay}</span><br>Redirecting to Workflows...`;
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
