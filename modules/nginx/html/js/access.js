/**
 * Roles in the UI: hide what the signed-in user's role cannot use.
 *
 * Hiding only. The server enforces every rule (services/access_policy.py) and
 * answers 403 regardless; this exists so a role is not shown dead buttons.
 *
 * Tag an element with data-needs="write" | "settings" | "users" | "host" |
 * "tool:<name>" (several, space-separated: each one must hold). The CSS below
 * keys off attributes set on <html> from GET /api/auth/status `can`. Until the
 * status arrives, or if it cannot be read, everything shows and the server's
 * 403 is the fallback. Without `write` the Automation tabs
 * ([data-automation-tab]) go too: they are launch consoles, nothing to read.
 *
 * Also the shared helpers the fetch hook in active-case.js calls: toast() for a
 * 403 forbidden, reauth() for a 403 reauth_required, and logout().
 * Load right after active-case.js, in <head>.
 */
(function () {
  var FLAGS = ['write', 'settings', 'users', 'host'];
  var TOOLS = ['velociraptor', 'timesketch', 'kibana', 'volweb', 'uploads', 'iris', 'portainer'];
  var root = document.documentElement;

  var rules = FLAGS.map(function (k) { return 'html[data-can-' + k + '="0"] [data-needs~="' + k + '"]'; })
    .concat(TOOLS.map(function (t) {
      return 'html[data-tools]:not([data-tools~="' + t + '"]) [data-needs~="tool:' + t + '"]';
    }))
    .concat(['html[data-can-write="0"] [data-automation-tab]']);
  var style = document.createElement('style');
  style.textContent = rules.join(',\n') + ' { display: none !important; }';
  (document.head || root).appendChild(style);

  function apply(s) {
    var c = s && s.can;
    if (!c) return;
    FLAGS.forEach(function (k) { root.setAttribute('data-can-' + k, c[k] ? '1' : '0'); });
    root.setAttribute('data-tools', (c.tools || []).join(' '));
  }

  var A = { status: null };
  A.ready = fetch('/api/auth/status', { credentials: 'same-origin' })
    .then(function (r) { return r.json(); })
    .then(function (s) { A.status = s || {}; apply(A.status); return A.status; })
    .catch(function () { return {}; });

  // From the Case Analysis iframe the toast stack lives in the dashboard.
  function topWindow() {
    try { if (window.top && window.top.document) return window.top; } catch (e) { /* cross-origin */ }
    return window;
  }

  var _toastAt = {};
  A.toast = function (message, type) {
    message = message || 'Your role does not allow this.';
    var now = Date.now();
    if (now - (_toastAt[message] || 0) < 2000) return;   // one click, one toast
    _toastAt[message] = now;
    var w = topWindow();
    try {
      var C = w.CustomEvent || CustomEvent;
      w.dispatchEvent(new C('show-toast', { detail: { type: type || 'error', title: 'Not allowed', message: message } }));
    } catch (e) { /* headless */ }
  };

  // One prompt for every request that needs it at the same moment.
  var _pending = null;
  A.reauth = function () {
    if (_pending) return _pending;
    _pending = new Promise(function (resolve) {
      var box = document.createElement('div');
      box.id = 'reauth-dialog';
      box.setAttribute('role', 'dialog');
      box.setAttribute('aria-modal', 'true');
      box.setAttribute('aria-labelledby', 'reauth-title');
      box.style.cssText = 'position:fixed;inset:0;z-index:10000;display:flex;align-items:center;' +
        'justify-content:center;background:rgba(0,0,0,.6);padding:16px';
      box.innerHTML =
        '<form style="width:100%;max-width:360px;background:#161b22;border:1px solid #374151;border-radius:10px;padding:20px;color:#fff;font-size:14px">' +
        '<div id="reauth-title" style="font-weight:600;margin-bottom:6px">Confirm your password</div>' +
        '<div style="color:#9ca3af;font-size:13px;margin-bottom:12px">Enter your password again to continue.</div>' +
        '<input type="password" autocomplete="current-password" aria-label="Password" ' +
        'style="width:100%;padding:9px 11px;border-radius:6px;background:#0d1117;border:1px solid #374151;color:#fff">' +
        '<div class="reauth-err" style="display:none;color:#f87171;font-size:13px;margin-top:8px"></div>' +
        '<div style="display:flex;justify-content:flex-end;gap:8px;margin-top:14px">' +
        '<button type="button" class="reauth-cancel" style="padding:7px 14px;border-radius:6px;background:#374151;color:#fff;border:none;cursor:pointer">Cancel</button>' +
        '<button type="submit" style="padding:7px 14px;border-radius:6px;background:#2563eb;color:#fff;border:none;cursor:pointer;font-weight:600">Continue</button>' +
        '</div></form>';
      var form = box.querySelector('form'), input = box.querySelector('input'), err = box.querySelector('.reauth-err');
      function done(ok) { box.remove(); resolve(ok); }
      box.querySelector('.reauth-cancel').addEventListener('click', function () { done(false); });
      box.addEventListener('keydown', function (e) { if (e.key === 'Escape') done(false); });
      form.addEventListener('submit', function (e) {
        e.preventDefault();
        err.style.display = 'none';
        fetch('/api/auth/reauth', {
          method: 'POST', credentials: 'same-origin',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ password: input.value })
        }).then(function (r) {
          return r.json().catch(function () { return {}; }).then(function (b) {
            if (r.ok && b.success) { done(true); return; }
            err.textContent = b.message || 'Password is incorrect.';
            err.style.display = 'block';
            input.value = '';
            input.focus();
          });
        }).catch(function () {
          err.textContent = 'Could not reach the backend. Try again in a moment.';
          err.style.display = 'block';
        });
      });
      document.body.appendChild(box);
      input.focus();
    }).then(function (ok) { _pending = null; return ok; });
    return _pending;
  };

  A.logout = function () {
    var go = function () { location.replace('/login.html?reason=logged_out'); };
    fetch('/api/auth/logout', { method: 'POST', credentials: 'same-origin' }).then(go, go);
  };

  window.IntactAccess = A;
})();
