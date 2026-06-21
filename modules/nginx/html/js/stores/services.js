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
                const response = await fetch('/api/clients');
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
