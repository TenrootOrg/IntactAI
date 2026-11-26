/**
 * Settings -> Users (partials/settings.html, x-data="usersCard()").
 *
 * Mirrors the rank rule only to avoid dead buttons: a row gets actions when its
 * role is one the signed-in user may grant (strictly below their own), never
 * on their own row and never on the Super-admin's. routes/user_routes.py checks
 * every rule again. A change that needs the password re-typed (403
 * reauth_required) is prompted for and retried by the fetch hook
 * (js/active-case.js + js/access.js); a 403 forbidden toasts there too.
 */
window.usersCard = function () {
  return {
    users: [], roles: [], me: '', myRole: '',
    loading: false, busy: false, err: '',
    addName: '', addRole: '',
    otp: null, copied: false,
    transferTo: '', transferPw: '',

    init() {
      const acc = window.IntactAccess;
      if (!acc) return;
      acc.ready.then(s => {
        this.myRole = (s && s.role) || '';
        if (s && s.can && s.can.users) this.load();
      });
    },

    async load() {
      this.loading = true;
      try {
        const r = await fetch('/api/users', { credentials: 'same-origin' });
        const d = await r.json().catch(() => ({}));
        if (!r.ok) { this.err = d.message || 'Could not load the users.'; return; }
        this.users = d.users || [];
        this.roles = d.roles || [];
        this.me = d.me || '';
        if (!this.grantable().some(x => x.role === this.addRole)) {
          const g = this.grantable();
          this.addRole = g.length ? g[g.length - 1].role : '';   // the highest role you may give
        }
      } catch (e) {
        this.err = 'Could not reach the backend.';
      } finally {
        this.loading = false;
      }
    },

    grantable() { return this.roles.filter(r => r.grantable); },
    label(role) { return (this.roles.find(r => r.role === role) || {}).label || role; },
    canManage(u) {
      return u.username !== this.me && u.role !== 'superadmin' && this.grantable().some(r => r.role === u.role);
    },
    // Mirrors the backend's rule (admin and up must use two-step login) for the hint only.
    // The backend says (users.MFA_REQUIRED_ROLES); the role list is the fallback for an older one.
    mfaRequired(u) { return 'mfa_required' in u ? !!u.mfa_required : (u.role === 'admin' || u.role === 'superadmin'); },
    admins() { return this.users.filter(u => u.role === 'admin' && u.enabled && u.username !== this.me); },
    when(ts) { return ts ? new Date(ts * 1000).toLocaleString() : 'Never'; },

    // One request; the message to show on failure, or the JSON body.
    async send(url, method, body) {
      this.busy = true; this.err = '';
      try {
        const r = await fetch(url, {
          method, credentials: 'same-origin',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body || {}),
        });
        const d = await r.json().catch(() => ({}));
        if (r.ok) return d;
        // A 403 forbidden is already a toast; anything else is said here.
        if (!(r.status === 403 && d.error === 'forbidden')) this.err = d.message || ('Error ' + r.status);
        return null;
      } catch (e) {
        this.err = 'Could not reach the backend.';
        return null;
      } finally {
        this.busy = false;
      }
    },

    showOtp(d) {
      this.copied = false;
      this.otp = { name: d.username, password: d.temporary_password, hours: d.expires_hours || 24 };
    },

    async add() {
      const name = this.addName.trim().toLowerCase();
      if (!name || !this.addRole) return;
      const d = await this.send('/api/users', 'POST', { username: name, role: this.addRole });
      if (!d) return;
      this.addName = '';
      this.showOtp(d);
      this.load();
    },

    async setRole(u, role) {
      if (role === u.role) return;
      const d = await this.send('/api/users/' + encodeURIComponent(u.username), 'PATCH', { role });
      this.load();   // on refusal too: puts the select back
      return d;
    },

    async setEnabled(u, enabled) {
      if (!enabled && !confirm('Disable ' + u.username + '?\n\nThey are signed out at once and cannot sign in until an Admin enables them again.')) return;
      await this.send('/api/users/' + encodeURIComponent(u.username), 'PATCH', { enabled });
      this.load();
    },

    async reset(u) {
      if (!confirm('Reset the password of ' + u.username + '?\n\nTheir current password stops working. You get a one-time password to give them.')) return;
      const d = await this.send('/api/users/' + encodeURIComponent(u.username) + '/reset-password', 'POST', {});
      if (!d) return;
      this.showOtp(d);
      this.load();
    },

    async resetMfa(u) {
      if (!confirm('Reset two-step login for ' + u.username + '?\n\nTheir authenticator app and recovery codes stop working here. If their role requires two-step login, they must set it up again at their next sign-in.')) return;
      await this.send('/api/users/' + encodeURIComponent(u.username) + '/reset-mfa', 'POST', {});
      this.load();
    },

    async transfer() {
      const to = this.transferTo;
      if (!to || !this.transferPw) return;
      if (!confirm('Make ' + to + ' the Super-admin?\n\nYou become an Admin: no more upgrades, restores, data moves or Portainer for you. Only ' + to + ' can hand it back.')) return;
      const d = await this.send('/api/users/transfer-superadmin', 'POST', { to, current_password: this.transferPw });
      this.transferPw = '';
      if (d) location.reload();   // the role changed: every page must redraw for it
    },

    async copy() {
      const text = (this.otp && this.otp.password) || '';
      try {
        await navigator.clipboard.writeText(text);
      } catch (e) {
        // Plain http or an old browser: select it, so Ctrl+C works.
        const el = document.getElementById('otp-value');
        if (el && window.getSelection) {
          const range = document.createRange();
          range.selectNodeContents(el);
          window.getSelection().removeAllRanges();
          window.getSelection().addRange(range);
          try { document.execCommand('copy'); } catch (_) { /* nothing more to try */ }
        }
      }
      this.copied = true;
    },
  };
};
