/**
 * Blueprints Forensics Module - Forensics tab functions for Velociraptor + Agentic
 * Split from blueprints.js for maintainability
 */

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
        // Collection → [Agentic] Quick Wins
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

async function loadForensicsClients(search = '', includeOffline = false) {
    try {
        // Online-only by default (correct for new-collection mode where
        // offline endpoints can't receive a hunt). Existing-flow mode
        // bumps the limit + sends include_offline=true since the data
        // is already collected and offline endpoints are still valid
        // analysis targets.
        const limit = includeOffline ? 200 : 20;
        let url = `/api/clients?limit=${limit}`;
        if (search) url += `&search=${encodeURIComponent(search)}`;
        if (includeOffline) url += '&include_offline=true';
        const response = await fetch(url);
        const data = await response.json();
        const clients = data.items || [];
        forensicsClientsCache = clients;
        renderForensicsClients(clients);

        // Show "more results" hint
        const filtered = data.filtered || clients.length;
        if (filtered > clients.length) {
            const container = document.getElementById('forensics-client-list');
            if (container) {
                container.innerHTML += `<p class="text-xs text-gray-500 text-center py-2">${filtered - clients.length} more — refine your search</p>`;
            }
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

    // Same OS-grouping logic as ClientManager.render() — kept inline here
    // because this picker has its own rendering pipeline (selection model
    // is a Set, not derived from DOM checkbox state).
    const osKey = (os) => {
        if (!os) return 'Unknown';
        const s = String(os).trim().toLowerCase();
        if (!s) return 'Unknown';
        if (s === 'windows' || s.startsWith('win')) return 'Windows';
        if (s === 'linux') return 'Linux';
        if (s === 'darwin' || s === 'macos' || s === 'osx' || s === 'mac') return 'macOS';
        return s.charAt(0).toUpperCase() + s.slice(1);
    };

    const groups = {};
    for (const c of clients) {
        const k = osKey(c.os);
        (groups[k] = groups[k] || []).push(c);
    }
    const preferred = ['Windows', 'Linux', 'macOS'];
    const others = Object.keys(groups)
        .filter(k => !preferred.includes(k) && k !== 'Unknown')
        .sort();
    const orderedKeys = [
        ...preferred.filter(k => groups[k] && groups[k].length),
        ...others,
        ...(groups['Unknown'] && groups['Unknown'].length ? ['Unknown'] : []),
    ];

    const renderClient = (client) => {
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
    };

    container.innerHTML = orderedKeys.map(key => {
        const groupClients = groups[key];
        const heading = `
            <div class="flex items-center gap-2 px-2 pt-2 pb-1 mt-1 border-t border-gray-800 first:border-t-0 first:mt-0 first:pt-0">
                <span class="text-xs uppercase tracking-wide text-gray-400 font-semibold">${key}</span>
                <span class="text-xs text-gray-600">(${groupClients.length})</span>
            </div>
        `;
        return heading + groupClients.map(renderClient).join('');
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

let _forensicsSearchTimeout = null;
function filterForensicsClients(query) {
    clearTimeout(_forensicsSearchTimeout);
    _forensicsSearchTimeout = setTimeout(() => loadForensicsClients(query), 300);
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
            // Collection mode — agentic endpoint as a pure collector.
            // report_types=[] means the pipeline gathers + persists raw data
            // but skips all LLM/report work; analysis happens at the case level.
            const selectedClients = Array.from(forensicsSelectedClients);
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
