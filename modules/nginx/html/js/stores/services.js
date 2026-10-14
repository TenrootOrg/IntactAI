// Services status store — registered on Alpine init.
document.addEventListener('alpine:init', () => {
    // Services status store
    Alpine.store('services', {
        statuses: {},
        clientCount: 0,
        onlineCount: 0,
        // installedCount = modules whose container exists on the host
        // (running OR stopped). Drives the dashboard "Total Services"
        // card so it reflects what's actually deployed — including
        // modules added via online / offline upgrade apply, not just
        // the install.sh seed. 0 when nothing's installed yet → the
        // dashboard hides the Total card entirely (see x-show in
        // index.html).
        installedCount: 0,
        onlineClientCount: 0,

        async checkAll() {
            try {
                const response = await fetch('/api/system/containers');
                if (response.ok) {
                    const containerStatuses = await response.json();
                    
                    // Update statuses based on backend container info
                    for (const serviceId in containerStatuses) {
                        this.statuses[serviceId] = containerStatuses[serviceId];
                    }
                    
                    // Ensure any service not in container list (if it was added elsewhere) is handled
                    for (const serviceId in window.services) {
                        if (!(serviceId in containerStatuses)) {
                            // Fallback: assume not installed if backend
                            // doesn't know about it (was previously
                            // 'offline' but that conflated "stopped"
                            // with "never created" — now distinct).
                            this.statuses[serviceId] = this.statuses[serviceId] || 'not_installed';
                        }
                    }
                } else {
                    console.error('Failed to fetch system container status');
                }
            } catch (e) {
                console.error('Error checking service status:', e);
                // Mark all as not_installed if backend is unreachable —
                // we can't tell the difference between "stopped" and
                // "never created" without a docker ps reply, so we
                // conservatively assume nothing is installed (worst
                // case: the dashboard hides Total card briefly until
                // the next successful poll).
                for (const serviceId in window.services) {
                    this.statuses[serviceId] = 'not_installed';
                }
            }
            this.updateStats();
        },

        async checkService(serviceId) {
            // Service-specific checks now handled by checkAll bulk update
            await this.checkAll();
        },

        updateStats() {
            const vals = Object.values(this.statuses);
            this.onlineCount = vals.filter(s => s === 'online').length;
            // "installed" = container exists, regardless of running state.
            // This counts modules deployed via install.sh seed AND
            // modules added later via online/offline upgrade apply.
            this.installedCount = vals.filter(s => s !== 'not_installed').length;
        },

        // Is this module present on the host at all?
        //
        // 'not_installed' means the container was never created (or, for
        // on-demand modules like aws_sigma / o365rc, that config.yaml has
        // them disabled). Everything else — online, stopped, checking —
        // means it exists and its UI should be reachable.
        //
        // Exists so the sidebar and Settings gate on ONE expression. They
        // used to be written out separately, and Settings simply never got
        // the gate: a host with timesketch or the cloud modules disabled
        // still showed their Settings tabs, offering credentials for
        // something that isn't installed.
        has(serviceId) {
            return (this.statuses[serviceId] || 'checking') !== 'not_installed';
        },

        getStatusClass(serviceId) {
            const status = this.statuses[serviceId] || 'checking';
            // 'stopped' and 'not_installed' both render with the
            // existing 'offline' dot styling — the dashboard's count
            // cards already distinguish installed-vs-not via separate
            // numeric badges, so the per-service dot can stay simple.
            const dotStatus = (status === 'stopped' || status === 'not_installed') ? 'offline' : status;
            return `status-dot status-${dotStatus} w-3 h-3 rounded-full`;
        },

        async loadClients() {
            try {
                // Two numbers, not the fleet: every open tab polls this every 10 s,
                // and the full list is ~200 KB+ (a docker exec + VQL) at 1,000 hosts.
                const summary = await fetch('/api/clients/summary');
                if (summary.ok) {
                    const s = await summary.json();
                    this.clientCount = s.total || 0;
                    this.onlineClientCount = s.online || 0;
                    return;
                }
                // 404 = a backend older than the summary route (mid-upgrade): fall
                // back to counting the full list, as before.
                if (summary.status !== 404) return;
                // ALL enrolled clients: without include_offline the API returns only
                // the ones seen in the last 10 minutes, so "total" was the online count.
                const response = await fetch('/api/clients?include_offline=true');
                if (response.ok) {
                    const data = await response.json();
                    const clients = data.items || [];
                    this.clientCount = data.total || clients.length;

                    const now = Date.now() / 1000;
                    this.onlineClientCount = clients.filter(c => {
                        const lastSeen = c.last_seen_at ? c.last_seen_at / 1000000 : 0;
                        return (now - lastSeen) < 600;
                    }).length;
                }
            } catch (e) {
                console.error('Failed to load clients:', e);
            }
        },

        getHealthStatus() {
            return this.onlineCount >= 4 ? 'Good' : this.onlineCount >= 2 ? 'Fair' : 'Poor';
        }
    });
});
