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
                const data = await response.json();
                const newRuns = data.runs || [];

                // Smart merge - only update if data changed (prevents flickering)
                if (this.initialLoad || JSON.stringify(this.allRuns) !== JSON.stringify(newRuns)) {
                    this.allRuns = newRuns;
                    this.applyFilter();
                }
                this.initialLoad = false;
            } catch (e) {
                console.error('Failed to load workflows:', e);
                if (this.initialLoad) this.allRuns = [];
                this.runs = [];
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
                this.selectedRun = await response.json();
                this.modalOpen = true;
                this.currentRunId = runId;
                this.startAutoRefresh(runId);
                this.scrollToBottom();
            } catch (e) {
                console.error('Failed to load logs:', e);
            }
        },

        startAutoRefresh(runId) {
            // Clear any existing interval
            this.stopAutoRefresh();

            // Refresh logs every 1 second
            this.refreshInterval = setInterval(async () => {
                if (!this.modalOpen) {
                    this.stopAutoRefresh();
                    return;
                }
                try {
                    const response = await fetch(`/api/dashboard/automation/${runId}`);
                    const newData = await response.json();

                    // Only update if logs changed
                    if (JSON.stringify(this.selectedRun?.logs) !== JSON.stringify(newData?.logs)) {
                        this.selectedRun = newData;
                        // Auto-scroll if enabled
                        if (this.autoScroll) {
                            this.scrollToBottom();
                        }
                    }
                } catch (e) {
                    console.error('Failed to refresh logs:', e);
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
            // Make download URLs clickable
            if (message && message.includes('/api/velociraptor/offline/download/')) {
                const urlMatch = message.match(/(\/api\/velociraptor\/offline\/download\/[^\s]+)/);
                if (urlMatch) {
                    const url = urlMatch[1];
                    return message.replace(url, `<a href="${url}" class="text-purple-400 hover:text-purple-300 underline" download>Download Collector</a>`);
                }
            }
            // Escape HTML for safety
            const div = document.createElement('div');
            div.textContent = message;
            return div.innerHTML;
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
