// Workflows store — registered on Alpine init.
document.addEventListener('alpine:init', () => {
    // Workflows store
    Alpine.store('workflows', {
        runs: [],
        allRuns: [],
        typeFilter: '',
        loading: true,
        selectedRun: null,
        modalOpen: false,
        initialLoad: true,
        autoScroll: true,
        refreshInterval: null,
        currentRunId: null,

        async load() {
            // Only show loading spinner on initial load
            if (this.initialLoad) this.loading = true;

            try {
                const response = await fetch('/api/dashboard/automations');
                if (!response.ok) throw new Error('HTTP ' + response.status);
                const data = await response.json();
                const newRuns = data.runs || [];

                // Only reassign allRuns when the data actually changed (avoids
                // flicker). But ALWAYS re-derive the visible `runs` from allRuns:
                // a prior transient error clears `runs` (below), and if we gated
                // applyFilter() on "data changed" the unchanged next poll would
                // skip it and leave the list permanently empty.
                if (this.initialLoad || JSON.stringify(this.allRuns) !== JSON.stringify(newRuns)) {
                    this.allRuns = newRuns;
                }
                this.applyFilter();
                this.initialLoad = false;
            } catch (e) {
                console.error('Failed to load workflows:', e);
                // Only blank the list on the very first load. On a transient poll
                // error keep the last-known-good list rather than flashing empty.
                if (this.initialLoad) { this.allRuns = []; this.runs = []; }
            }
            this.loading = false;
        },

        applyFilter() {
            if (!this.typeFilter) {
                this.runs = this.allRuns;
            } else {
                this.runs = this.allRuns.filter(run => run.type === this.typeFilter);
            }
        },

        async viewLogs(runId) {
            try {
                const response = await fetch(`/api/dashboard/automation/${runId}`);
                const data = await response.json();
                // A 404/error response is still valid JSON (e.g. {"error": "..."})
                // with none of a real run's fields — without this check it silently
                // became the modal's default "UNKNOWN | UNKNOWN | 0% Complete" /
                // "No logs available yet." with no indication anything went wrong.
                this.selectedRun = response.ok ? data : {
                    id: runId, name: 'Workflow Logs', logs: [],
                    fetchError: data?.error || `HTTP ${response.status}`,
                };
                this.modalOpen = true;
                this.currentRunId = runId;
                if (response.ok) this.startAutoRefresh(runId);
                this.scrollToBottom();
            } catch (e) {
                console.error('Failed to load logs:', e);
                this.selectedRun = { id: runId, name: 'Workflow Logs', logs: [], fetchError: e.message };
                this.modalOpen = true;
                this.currentRunId = runId;
            }
        },

        startAutoRefresh(runId) {
            // Clear any existing interval
            this.stopAutoRefresh();

            // Tolerate TRANSIENT failures. An offline upgrade RECREATES the
            // backend container mid-run, so these polls will briefly 502/timeout
            // for tens of seconds. The old code killed polling on the very first
            // failed fetch, freezing the log view on "Upload complete / Package
            // path" until the operator manually refreshed. Instead: keep polling,
            // show a reconnecting note, and only give up after a SUSTAINED outage
            // (well past a normal backend swap). Recovery clears the note.
            this._refreshFailures = 0;
            const MAX_CONSECUTIVE_FAILURES = 120;   // ~120s of continuous failure

            this.refreshInterval = setInterval(async () => {
                if (!this.modalOpen) {
                    this.stopAutoRefresh();
                    return;
                }
                try {
                    const response = await fetch(`/api/dashboard/automation/${runId}`);
                    if (!response.ok) {
                        this._refreshFailures++;
                        if (this._refreshFailures >= MAX_CONSECUTIVE_FAILURES) {
                            const data = await response.json().catch(() => null);
                            this.selectedRun = {
                                ...this.selectedRun,
                                reconnecting: false,
                                fetchError: data?.error || `HTTP ${response.status}`,
                            };
                            this.stopAutoRefresh();
                        } else {
                            // transient (backend mid-swap) — keep trying
                            this.selectedRun = { ...this.selectedRun, reconnecting: true };
                        }
                        return;
                    }
                    const newData = await response.json();
                    this._refreshFailures = 0;
                    newData.reconnecting = false;

                    // Update if we're recovering from a blip OR the logs changed.
                    const recovering = this.selectedRun?.reconnecting || this.selectedRun?.fetchError;
                    if (recovering ||
                        JSON.stringify(this.selectedRun?.logs) !== JSON.stringify(newData?.logs)) {
                        this.selectedRun = newData;
                        // Auto-scroll if enabled
                        if (this.autoScroll) {
                            this.scrollToBottom();
                        }
                    }
                } catch (e) {
                    this._refreshFailures++;
                    if (this._refreshFailures >= MAX_CONSECUTIVE_FAILURES) {
                        console.error('Failed to refresh logs:', e);
                        this.selectedRun = { ...this.selectedRun, reconnecting: false, fetchError: e.message };
                        this.stopAutoRefresh();
                    } else {
                        // transient network error while the backend restarts — keep trying
                        this.selectedRun = { ...this.selectedRun, reconnecting: true };
                    }
                }
            }, 1000);
        },

        stopAutoRefresh() {
            if (this.refreshInterval) {
                clearInterval(this.refreshInterval);
                this.refreshInterval = null;
            }
        },

        scrollToBottom() {
            setTimeout(() => {
                const logsContainer = document.getElementById('workflow-logs-container');
                if (logsContainer) {
                    logsContainer.scrollTop = logsContainer.scrollHeight;
                }
            }, 50);
        },

        toggleAutoScroll() {
            this.autoScroll = !this.autoScroll;
            if (this.autoScroll) {
                this.scrollToBottom();
            }
        },

        downloadLogs() {
            const run = this.selectedRun;
            if (!run?.logs?.length) return;

            const header = `# ${run.name || run.id} — workflow log\n# All times in UTC+00:00\n\n`;
            const content = header + run.logs.map(log =>
                `[${this.utcIso(log.timestamp)}] [${log.level.toUpperCase()}] ${log.message}`
            ).join('\n');

            const blob = new Blob([content], { type: 'text/plain' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `${run.name || run.id}-logs.txt`;
            a.click();
            URL.revokeObjectURL(url);
        },

        closeModal() {
            this.stopAutoRefresh();
            this.modalOpen = false;
            this.selectedRun = null;
            this.currentRunId = null;
        },

        async stopWorkflow(runId) {
            if (!confirm('Stop this workflow? Running operations will be cancelled.')) return;
            try {
                const response = await fetch(`/api/dashboard/automation/${runId}/stop`, { method: 'POST' });
                if (response.ok) {
                    this.load();
                    if (this.selectedRun && this.selectedRun.id === runId) {
                        this.selectedRun.status = 'cancelled';
                    }
                } else {
                    const data = await response.json();
                    alert('Failed to stop: ' + (data.error || 'Unknown error'));
                }
            } catch (e) {
                alert('Error stopping workflow: ' + e.message);
            }
        },

        getStatusColor(status) {
            const colors = { running: 'bg-blue-600', completed: 'bg-green-600', failed: 'bg-red-600', cancelled: 'bg-orange-600' };
            return colors[status] || 'bg-gray-600';
        },

        getTypeColor(type) {
            // Module-themed palette so each chip reflects which module produced
            // the run. Velociraptor family (incl. collection + CVE) = green;
            // Timesketch = purple (avoids blue since Azure owns blue);
            // Settings / system actions = red; AWS = orange; Azure = blue.
            // Fallback is slate-700 — never gray-600, which reads black-on-dark.
            const colors = {
                // Velociraptor (collection + CVE-mgmt scans + offline collectors)
                velociraptor_collection: 'bg-green-600',
                agentic: 'bg-green-600', // legacy alias for pre-migration rows
                velociraptor_hunt: 'bg-green-700',
                velociraptor_upload: 'bg-green-700',
                velociraptor_offline_collector: 'bg-green-700',
                velociraptor_offline_import: 'bg-green-700',
                offline_collector: 'bg-green-700',
                offline_import: 'bg-green-700',
                hunt: 'bg-green-700',
                cve_scan: 'bg-green-700',
                artifact: 'bg-green-600',
                // Timesketch (and IRIS, when its runs get a workflow row)
                timesketch: 'bg-purple-600',
                timesketch_upload: 'bg-purple-700',
                iris: 'bg-purple-600',
                // AWS / Azure cloud scans
                aws_scan: 'bg-orange-600',
                azure_scan: 'bg-blue-600',
                // Settings + system-level actions (all red — destructive or
                // platform-affecting in nature)
                settings: 'bg-red-600',
                system_purge: 'bg-red-700',
                prepare_package: 'bg-red-700',
                upgrade: 'bg-red-700',
                support_bundle: 'bg-red-700',
                maintenance: 'bg-red-700',
            };
            return colors[type] || 'bg-slate-700';
        },

        getLogColor(level) {
            const colors = { info: 'text-blue-400', success: 'text-green-400', error: 'text-red-400', warning: 'text-yellow-400' };
            return colors[level] || 'text-gray-400';
        },

        formatLogMessage(message) {
            // Escape FIRST, unconditionally — the URL branch below used to
            // return the raw message with only the URL substring replaced,
            // skipping escaping for the rest of the line whenever a download
            // URL was present (anything else HTML-significant in that same
            // log line rendered unescaped).
            const escapeHtml = (s) => {
                const div = document.createElement('div');
                div.textContent = s == null ? '' : String(s);
                return div.innerHTML;
            };
            const escaped = escapeHtml(message);

            // Make download URLs clickable — extract from the original
            // message (the regex needs the real characters), then escape
            // the extracted URL the same way so the substring lookup below
            // matches the already-escaped full message.
            const urlMatch = (message || '').match(/(\/api\/velociraptor\/offline\/download\/[^\s]+)/);
            if (urlMatch) {
                const escapedUrl = escapeHtml(urlMatch[1]);
                if (escaped.includes(escapedUrl)) {
                    return escaped.replace(escapedUrl, `<a href="${escapedUrl}" class="text-purple-400 hover:text-purple-300 underline" download>Download Collector</a>`);
                }
            }
            return escaped;
        },

        formatTime(timestamp) {
            return timestamp ? new Date(timestamp).toLocaleString() : 'Unknown';
        },

        // Workflow log timestamps are stored NAIVE but in UTC (the backend runs
        // in UTC). new Date() would treat a naive string as LOCAL and shift it,
        // so we declare it UTC by appending 'Z' when it carries no timezone.
        // Forces every log time to render in UTC+00:00.
        _asUtc(ts) {
            if (!ts) return new Date(NaN);
            return new Date(/[zZ]|[+-]\d{2}:?\d{2}$/.test(ts) ? ts : ts + 'Z');
        },
        utcTime(ts) {           // 'HH:MM:SSZ' for the UI log column
            const d = this._asUtc(ts);
            return isNaN(d) ? '' : d.toISOString().substr(11, 8) + 'Z';
        },
        utcIso(ts) {            // full ISO (…Z) for the downloaded log
            const d = this._asUtc(ts);
            return isNaN(d) ? String(ts || '') : d.toISOString();
        },

        downloadPackage(runId) {
            // Download immediately - package validity checked server-side
            window.location.href = `/api/upgrade/prepare/${runId}/download`;
        }
    });
});
