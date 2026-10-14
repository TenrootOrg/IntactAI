// Workflows store — registered on Alpine init.
document.addEventListener('alpine:init', () => {
    // Workflows store
    Alpine.store('workflows', {
        runs: [],
        typeFilter: '',
        loading: true,
        selectedRun: null,
        modalOpen: false,
        initialLoad: true,
        autoScroll: true,
        refreshInterval: null,
        currentRunId: null,
        rerunning: null,        // run_id currently being relaunched

        // An upgrade signs the operator out halfway through: the backend
        // restarts to load the new code, every session dies with it, and on a
        // pre-auth box the auth migration lands them on the SETUP page as well.
        // The run id lived only in this store, so the page that came back after
        // signing in had nothing to poll and just sat there. Operators read that
        // as "the upgrade is stuck at some point" -- on runs that were finishing
        // normally. Ask the SERVER what is in flight instead of trying to
        // remember across a page we know is about to be destroyed.
        async reattachToActiveRun() {
            if (this.modalOpen) return false;
            try {
                const r = await fetch('/api/upgrade/active');
                if (!r.ok) return false;
                const data = await r.json();
                const active = data && data.active;
                if (!active || !active.run_id) return false;
                await this.viewLogs(active.run_id);
                return true;
            } catch (e) {
                return false;   // never let this break the page it runs on
            }
        },

        // The list is one server-side page: summary rows only (no logs), filtered
        // by workspace and type in SQL. It used to be every run of every case
        // with every log line, once a second, JSON.stringify-compared here --
        // megabytes per poll at fleet scale, and the tab froze.
        PAGE_SIZE: 200,
        limit: 200,
        total: 0,
        _sig: '',

        async load() {
            // Only show loading spinner on initial load
            if (this.initialLoad) this.loading = true;

            const query = `limit=${this.limit}` +
                (this.typeFilter ? `&type=${encodeURIComponent(this.typeFilter)}` : '');
            try {
                const response = await fetch('/api/dashboard/automations?' + query);
                if (!response.ok) throw new Error('HTTP ' + response.status);
                const data = await response.json();
                // The filter or page size changed while this was in flight: a
                // newer load() owns the list.
                const now = `limit=${this.limit}` +
                    (this.typeFilter ? `&type=${encodeURIComponent(this.typeFilter)}` : '');
                if (now !== query) return;
                const newRuns = data.runs || [];
                this.total = data.total || newRuns.length;

                // Only reassign when something the table shows changed (avoids
                // flicker). A short per-row signature, not a stringify of it all.
                const sig = newRuns.map(r =>
                    `${r.id}|${r.status}|${r.progress}|${r.updated_at}|${r.error_count}`).join(',');
                if (this.initialLoad || sig !== this._sig || this.runs.length !== newRuns.length) {
                    this.runs = newRuns;
                    this._sig = sig;
                }
                const wasFirst = this.initialLoad;
                this.initialLoad = false;
                // First listing after a (re)load — including the one that
                // follows the mid-upgrade sign-out. If a run is still in
                // flight, reopen it instead of leaving a frozen page.
                if (wasFirst) this.reattachToActiveRun();
            } catch (e) {
                console.error('Failed to load workflows:', e);
                // Only blank the list on the very first load. On a transient poll
                // error keep the last-known-good list rather than flashing empty.
                if (this.initialLoad) { this.runs = []; this._sig = ''; }
            }
            this.loading = false;
        },

        // The type filter is applied server-side now; start again from page one.
        applyFilter() {
            this.limit = this.PAGE_SIZE;
            this.load();
        },

        showMore() {
            this.limit += this.PAGE_SIZE;
            this.load();
        },

        recollecting: null,

        // Relaunch a finished run with its ORIGINAL configuration.
        //
        // Two steps on purpose. The server returns a SPEC (endpoint + payload)
        // rebuilt from what the run persisted, and the browser POSTs it — so the
        // rerun goes through the exact same route the launch page uses, with the
        // same validation and the same active-workspace header. Re-dispatching
        // server-side would mean a second copy of the launch logic that drifts
        // the first time a route gains a parameter.
        //
        // A run that never recorded its configuration (died early, or was made
        // by an older release that stored less) reports supported:false with a
        // reason, rather than quietly relaunching with defaults — which would be
        // a different job wearing the same name.
        async rerun(runId) {
            if (this.rerunning) return;              // one at a time
            this.rerunning = runId;
            try {
                const specRes = await fetch(`/api/dashboard/automation/${runId}/rerun-spec`);
                const spec = await specRes.json();
                if (!spec || !spec.supported) {
                    alert(spec?.reason || spec?.error || 'This run cannot be relaunched.');
                    return;
                }
                const res = await fetch(spec.endpoint, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(spec.payload),
                });
                const d = await res.json();
                if (!res.ok || d.error) {
                    alert('Rerun failed: ' + (d.error || res.status));
                    return;
                }
                await this.load();
            } catch (e) {
                alert('Rerun failed: ' + e.message);
            } finally {
                this.rerunning = null;
            }
        },

        // Fetch results Velociraptor ALREADY HAS. Not a rerun.
        //
        // Deliberately a separate action with a separate word, because the two
        // differ enormously in cost and the difference is invisible from the
        // button: Rerun launches a fresh collection on the customer's endpoint;
        // this asks the Velociraptor server for rows it is already holding and
        // touches no endpoint at all.
        //
        // It exists because three ordinary things leave data behind: a
        // collection whose budget expired while the flow kept running
        // server-side, a hunt whose clients report over the following hours, and
        // runs collected before errored flows stopped being abandoned.
        async recollect(runId) {
            if (this.recollecting) return;
            this.recollecting = runId;
            try {
                const res = await fetch(`/api/dashboard/automation/${runId}/recollect`,
                                        { method: 'POST' });
                const d = await res.json();
                if (!res.ok || d.error) {
                    alert(d.error || `Re-collect failed (${res.status})`);
                    return;
                }
                // The fetch runs in the background and logs into this same run,
                // so send them where they can watch it rather than leaving a
                // button that looks like it did nothing.
                this.viewLogs(runId);
            } catch (e) {
                alert('Re-collect failed: ' + e.message);
            } finally {
                this.recollecting = null;
            }
        },

        // A run's log window. Same cursor pattern as viewSystemLog() below: the
        // first read is the last RUN_LOG_KEEP lines, every poll after asks only
        // for lines past the cursor and appends them, keeping the last
        // RUN_LOG_KEEP. It used to refetch the WHOLE run every second, compare
        // the arrays by JSON.stringify and re-render every line -- a fleet run's
        // 3k-10k lines froze the tab. "Download Log" still gets the whole log.
        RUN_LOG_KEEP: 5000,
        async viewLogs(runId) {
            this.stopAutoRefresh();
            const url = `/api/dashboard/automation/${encodeURIComponent(runId)}/logs`;
            this.selectedRun = { id: runId, name: 'Workflow Logs', logs: [] };
            this.modalOpen = true;
            this.currentRunId = runId;
            // Tolerate TRANSIENT failures. An offline upgrade RECREATES the
            // backend container mid-run, so these polls will briefly 502/timeout
            // for tens of seconds. Killing polling on the first failed fetch froze
            // the log view on "Upload complete / Package path" until the operator
            // refreshed. Instead: keep polling, show a reconnecting note, and only
            // give up after a SUSTAINED outage (well past a normal backend swap).
            const MAX_CONSECUTIVE_FAILURES = 120;   // ~120s of continuous failure
            let cursor = null, busy = false, failures = 0;
            const fail = (msg) => {
                // A failed FIRST read (404, bad id) is an answer, not a blip: say
                // so instead of the modal's default "UNKNOWN | 0% Complete" /
                // "No logs available yet.".
                if (cursor === null || ++failures >= MAX_CONSECUTIVE_FAILURES) {
                    this.selectedRun = { ...this.selectedRun, reconnecting: false, fetchError: msg };
                    this.stopAutoRefresh();
                } else this.selectedRun = { ...this.selectedRun, reconnecting: true };
            };
            const poll = async () => {
                if (busy || document.hidden || !this.modalOpen || this.currentRunId !== runId) return;
                busy = true;
                try {
                    const r = await fetch(url + (cursor === null ? `?limit=${this.RUN_LOG_KEEP}`
                                                                 : `?since=${cursor}&limit=${this.RUN_LOG_KEEP}`));
                    const d = await r.json().catch(() => ({}));
                    if (this.currentRunId !== runId) return;
                    if (!r.ok) return fail(d.error || `HTTP ${r.status}`);
                    failures = 0;
                    // No cursor = a backend from before log paging (the minute of an
                    // upgrade): it ignores `since` and sends the whole log every time,
                    // so replace, never append, or every line repeats each second.
                    const first = cursor === null || d.cursor === undefined,
                          fresh = d.logs || [], prev = this.selectedRun;
                    cursor = d.cursor ?? cursor ?? 0;
                    if (first || fresh.length || prev.reconnecting || prev.status !== d.status ||
                        prev.progress !== d.progress) {
                        const all = first ? fresh : prev.logs.concat(fresh);
                        this.selectedRun = {
                            ...prev, name: d.name || prev.name, type: d.type, status: d.status,
                            progress: d.progress, error: d.error, error_count: d.error_count,
                            reconnecting: false, fetchError: undefined,
                            truncated: (first ? d.truncated : prev.truncated) || all.length > this.RUN_LOG_KEEP,
                            logs: all.slice(-this.RUN_LOG_KEEP),
                        };
                        if (this.autoScroll) this.scrollToBottom();
                    }
                } catch (e) {
                    fail(e.message);
                } finally { busy = false; }
            };
            await poll();
            this.scrollToBottom();
            if (this.modalOpen && this.currentRunId === runId && !this.selectedRun.fetchError) {
                this.refreshInterval = setInterval(poll, 1000);
            }
        },

        // Settings → Logs: a container's log in this same viewer. The first read is
        // the last 1000 lines; every poll after asks only for lines past the cursor
        // and appends them. Polls only while the window is open and the browser tab
        // is visible -- closeModal() stops it like a run's.
        SYSTEM_LOG_KEEP: 5000,
        async viewSystemLog(name) {
            this.stopAutoRefresh();
            const url = `/api/system/logs/${encodeURIComponent(name)}`;
            this.selectedRun = { id: name, name, type: 'container log', is_system_log: true, logs: [] };
            this.modalOpen = true;
            this.currentRunId = name;
            let cursor = '', busy = false, failures = 0;
            const poll = async () => {
                if (busy || document.hidden || !this.modalOpen || this.currentRunId !== name) return;
                busy = true;
                try {
                    const r = await fetch(url + (cursor ? `?since=${encodeURIComponent(cursor)}` : ''));
                    const d = await r.json().catch(() => ({}));
                    if (this.currentRunId !== name) return;
                    if (!r.ok) {
                        if (++failures >= 120 || r.status === 404) {
                            this.selectedRun = { ...this.selectedRun, reconnecting: false, fetchError: d.error || `HTTP ${r.status}` };
                            this.stopAutoRefresh();
                        } else this.selectedRun = { ...this.selectedRun, reconnecting: true };
                        return;
                    }
                    failures = 0;
                    cursor = d.cursor || cursor;
                    const logs = (this.selectedRun.logs || []).concat(d.logs || []).slice(-this.SYSTEM_LOG_KEEP);
                    if ((d.logs || []).length || this.selectedRun.reconnecting || this.selectedRun.status !== d.status) {
                        this.selectedRun = { ...this.selectedRun, status: d.status, reconnecting: false, logs };
                        if (this.autoScroll) this.scrollToBottom();
                    }
                } catch (e) {
                    if (++failures >= 120) {
                        this.selectedRun = { ...this.selectedRun, reconnecting: false, fetchError: e.message };
                        this.stopAutoRefresh();
                    } else this.selectedRun = { ...this.selectedRun, reconnecting: true };
                } finally { busy = false; }
            };
            await poll();
            this.scrollToBottom();
            if (this.modalOpen && this.currentRunId === name) this.refreshInterval = setInterval(poll, 1000);
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

        async downloadLogs() {
            const run = this.selectedRun;
            // A container log: the server's longer tail (what a bundle holds), not
            // just the lines on screen.
            if (run?.is_system_log) {
                window.location.href = `/api/system/logs/${encodeURIComponent(run.id)}/download`;
                return;
            }
            if (!run?.logs?.length) return;
            // The window keeps only the last RUN_LOG_KEEP lines; the file gets
            // the whole log.
            let logs = run.logs;
            if (run.truncated) {
                try {
                    const r = await fetch(`/api/dashboard/automation/${encodeURIComponent(run.id)}/logs`);
                    if (r.ok) logs = (await r.json()).logs || logs;
                } catch (e) { /* the lines on screen beat no file at all */ }
            }

            const header = `# ${run.name || run.id} — workflow log\n# All times in UTC+00:00\n\n`;
            const content = header + logs.map(log =>
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
                // Stop the UPLOAD too, when this run still has one streaming.
                // Stopping only the row leaves the browser sending chunks: the
                // tus hook then fires minutes later for a run that is already
                // over, and the backend does the work anyway (a stopped memory
                // upload still staged 1.5 GB and registered VolWeb evidence).
                // Harmless for every other run type — nothing is registered.
                try {
                    const run = (this.runs || []).find(r => (r.id || r.run_id) === runId);
                    const uploadId = run && (run.details || {}).upload_id;
                    if (uploadId && window.TusUploader && TusUploader.abortUpload(uploadId)) {
                        console.log('[workflows] aborted the in-flight upload for', runId);
                    }
                } catch (e) { /* the server-side stop below is what matters */ }
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
            // the run. Velociraptor family (collection) = green;
            // Timesketch = purple (avoids blue since Azure owns blue);
            // Settings / system actions = red; AWS = orange; Azure = blue.
            // Fallback is slate-700 — never gray-600, which reads black-on-dark.
            const colors = {
                // Velociraptor (collection + offline collectors)
                velociraptor_collection: 'bg-green-600',
                agentic: 'bg-green-600', // legacy alias for pre-migration rows
                velociraptor_hunt: 'bg-green-700',
                velociraptor_upload: 'bg-green-700',
                velociraptor_offline_collector: 'bg-green-700',
                velociraptor_offline_import: 'bg-green-700',
                velociraptor_adopt: 'bg-green-700',
                offline_collector: 'bg-green-700',
                offline_import: 'bg-green-700',
                hunt: 'bg-green-700',
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
                // Decision-model relevance scoring (reads data, changes nothing) — not red.
                // jev_relevance: the same runs, stored before the 2026-10 rename.
                decision_relevance: 'bg-indigo-600',
                jev_relevance: 'bg-indigo-600',
                // a symbol table / pack added to the memory module's library
                memory_symbols_upload: 'bg-indigo-600',
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
