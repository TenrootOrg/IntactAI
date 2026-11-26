/**
 * Settings -> Security (partials/settings.html, x-data="securityPanel()") and
 * the Dashboard alert banner (partials/dashboard.html, x-data="securityBanner()").
 *
 * Audit forwarding sends every audit line to the customer's own syslog server
 * (services/audit_forward.py); the alerts come from services/security_alerts.py.
 * Admins and up only: the server enforces it (access_policy), and the banner
 * never polls for a lower role, because each refused call is itself audited
 * and enough of them raise a "refused" alert.
 */
(function () {
  function when(ts) { return ts ? new Date(ts).toLocaleString() : ''; }

  async function api(url, method, body) {
    const opts = { method: method || 'GET', credentials: 'same-origin' };
    if (body !== undefined) {
      opts.headers = { 'Content-Type': 'application/json' };
      opts.body = JSON.stringify(body);
    }
    const r = await fetch(url, opts);
    const d = await r.json().catch(() => ({}));
    return { ok: r.ok, status: r.status, d };
  }

  function isAdmin(s) { return !!(s && s.can && s.can.settings); }

  window.securityPanel = function () {
    return {
      cfg: { enabled: false, protocol: 'udp', host: '', port: 514 },
      st: null, alerts: [], unackedOnly: false,
      busy: false, err: '', msg: '', msgOk: true,

      init() {
        const acc = window.IntactAccess;
        if (!acc) return this.load();
        acc.ready.then(s => { if (isAdmin(s)) this.load(); });
      },

      async load() {
        this.err = '';
        try {
          const [f, a] = await Promise.all([
            api('/api/security/audit-forward'),
            api('/api/security/alerts' + (this.unackedOnly ? '?unacked=1' : '')),
          ]);
          if (f.ok) { this.cfg = Object.assign(this.cfg, f.d.config || {}); this.st = f.d.status || null; }
          if (a.ok) this.alerts = a.d.alerts || [];
          if (!f.ok || !a.ok) this.err = (f.d.message || a.d.message || 'Could not load the security settings.');
        } catch (e) {
          this.err = 'Could not reach the backend.';
        }
      },

      form() {
        return { enabled: !!this.cfg.enabled, protocol: this.cfg.protocol,
                 host: (this.cfg.host || '').trim(), port: Number(this.cfg.port) };
      },

      say(text, ok) { this.msg = text; this.msgOk = ok; },

      async save() {
        this.busy = true; this.say('', true);
        try {
          const r = await api('/api/security/audit-forward', 'PUT', this.form());
          if (r.ok) { this.cfg = Object.assign(this.cfg, r.d.config); this.st = r.d.status; this.say('Saved.', true); }
          else if (!(r.status === 403 && r.d.error === 'forbidden')) this.say(r.d.message || ('Error ' + r.status), false);
        } catch (e) { this.say('Could not reach the backend.', false); }
        this.busy = false;
      },

      async test() {
        this.busy = true; this.say('Sending a test message…', true);
        try {
          const r = await api('/api/security/audit-forward/test', 'POST', this.form());
          this.say(r.d.message || (r.ok ? 'Sent.' : 'Error ' + r.status), r.ok);
        } catch (e) { this.say('Could not reach the backend.', false); }
        this.busy = false;
      },

      statusLine() {
        const s = this.st;
        if (!this.cfg.enabled) return 'Forwarding is off. The audit log stays on this box only.';
        if (!s) return '';
        const tail = ' ' + s.queued + ' waiting, ' + s.dropped + ' dropped since the backend started.';
        // ISO times in UTC compare as strings.
        if (s.last_error && (!s.last_success || s.last_error_at > s.last_success))
          return 'Not reaching the server: ' + s.last_error + ' (' + when(s.last_error_at) + ').' + tail;
        if (s.last_success) return 'Working. Last sent ' + when(s.last_success) + '.' + tail;
        return 'Nothing sent yet.' + tail;
      },
      failing() {
        const s = this.st;
        return !!(this.cfg.enabled && s && s.last_error && (!s.last_success || s.last_error_at > s.last_success));
      },

      sevClass(a) { return a.severity === 'high' ? 'text-red-400' : a.severity === 'medium' ? 'text-yellow-300' : 'text-gray-400'; },
      when,

      async ack(a) {
        this.busy = true;
        try {
          const r = await api('/api/security/alerts/' + encodeURIComponent(a.id) + '/ack', 'POST', {});
          if (!r.ok && !(r.status === 403 && r.d.error === 'forbidden')) this.err = r.d.message || ('Error ' + r.status);
        } catch (e) { this.err = 'Could not reach the backend.'; }
        this.busy = false;
        window.dispatchEvent(new CustomEvent('security-alerts-changed'));
        this.load();
      },
    };
  };

  window.securityBanner = function () {
    return {
      count: 0, allowed: false,

      init() {
        const acc = window.IntactAccess;
        if (!acc) return;
        acc.ready.then(s => {
          this.allowed = isAdmin(s);
          if (!this.allowed) return;
          this.refresh();
          // Every 60 s, only while this browser tab is visible.
          setInterval(() => { if (!document.hidden) this.refresh(); }, 60000);
          document.addEventListener('visibilitychange', () => { if (!document.hidden) this.refresh(); });
          window.addEventListener('security-alerts-changed', () => this.refresh());
        });
      },

      async refresh() {
        try {
          const r = await api('/api/security/alerts/count');
          if (r.ok) this.count = r.d.unacknowledged || 0;
        } catch (e) { /* keep the last count */ }
      },

      text() { return this.count === 1 ? '1 security alert' : this.count + ' security alerts'; },

      open() {
        Alpine.store('app').switchTab('settings');
        // The Settings tab bar listens for this and opens its Security tab.
        setTimeout(() => window.dispatchEvent(new CustomEvent('show-security')), 0);
      },
    };
  };
})();
