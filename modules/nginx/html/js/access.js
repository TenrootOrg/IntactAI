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
 * 403 forbidden, reauth() for a 403 reauth_required, and logout(); mfaOff()
 * for the user menu. A role that requires two-step login and has not set it up
 * (status must_enroll) is sent to the setup screen from any page.
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
    .then(function (s) {
      A.status = s || {};
      // Appliance clock minus this browser's, in seconds, measured now: the
      // code prompts warn when an air-gapped box has drifted (codes then fail).
      // local-clock-ok: the skew between the two clocks IS what is measured.
      if (A.status.server_time) A.clockSkew = A.status.server_time - Date.now() / 1000;  // local-clock-ok
      apply(A.status);
      // The backend answers 403 mfa_enroll_required to everything else meanwhile.
      // top: from the Case Analysis iframe the whole dashboard must go.
      if (A.status.must_enroll) {
        var u = '/login.html?mfa=setup';
        try { window.top.location.replace(u); } catch (e) { location.replace(u); }
      }
      return A.status;
    })
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

  // A password (and, with two-step login on, a code) dialog that POSTs them to
  // o.url; resolves true on success, false on Cancel. A wrong entry keeps it open.
  function ask(o) {
    return new Promise(function (resolve) {
      var box = document.createElement('div');
      box.id = o.id;
      box.setAttribute('role', 'dialog');
      box.setAttribute('aria-modal', 'true');
      box.setAttribute('aria-labelledby', o.id + '-title');
      box.style.cssText = 'position:fixed;inset:0;z-index:10000;display:flex;align-items:center;' +
        'justify-content:center;background:rgba(0,0,0,.6);padding:16px';
      var field = 'width:100%;padding:9px 11px;border-radius:6px;background:#0d1117;border:1px solid #374151;color:#fff';
      box.innerHTML =
        '<form style="width:100%;max-width:360px;background:#161b22;border:1px solid #374151;border-radius:10px;padding:20px;color:#fff;font-size:14px">' +
        '<div id="' + o.id + '-title" style="font-weight:600;margin-bottom:6px"></div>' +
        '<div class="reauth-text" style="color:#9ca3af;font-size:13px;margin-bottom:12px"></div>' +
        '<input type="password" autocomplete="current-password" aria-label="Password" style="' + field + '">' +
        (o.code ? '<input type="text" class="reauth-code" autocomplete="one-time-code" ' +
                  'placeholder="6-digit code, or a recovery code" aria-label="6-digit code from your authenticator app, or a recovery code" style="' + field + ';margin-top:8px">' +
                  '<div class="reauth-clock" style="display:none;color:#fbbf24;font-size:12px;margin-top:8px"></div>' : '') +
        '<div class="reauth-err" style="display:none;color:#f87171;font-size:13px;margin-top:8px"></div>' +
        '<div style="display:flex;justify-content:flex-end;gap:8px;margin-top:14px">' +
        '<button type="button" class="reauth-cancel" style="padding:7px 14px;border-radius:6px;background:#374151;color:#fff;border:none;cursor:pointer">Cancel</button>' +
        '<button type="submit" style="padding:7px 14px;border-radius:6px;background:#2563eb;color:#fff;border:none;cursor:pointer;font-weight:600"></button>' +
        '</div></form>';
      box.querySelector('#' + o.id + '-title').textContent = o.title;
      box.querySelector('.reauth-text').textContent = o.text;
      box.querySelector('button[type=submit]').textContent = o.button || 'Continue';
      var clock = box.querySelector('.reauth-clock');
      if (clock && Math.abs(A.clockSkew || 0) > 60) {
        clock.textContent = "This computer's clock and the appliance's clock differ by " +
          Math.round(Math.abs(A.clockSkew) / 60) + " minute(s) - codes may be refused. " +
          "Ask an administrator to check the appliance's time.";
        clock.style.display = 'block';
      }
      var form = box.querySelector('form'), input = box.querySelector('input[type=password]'),
          code = box.querySelector('.reauth-code'), err = box.querySelector('.reauth-err');
      function done(ok) { box.remove(); resolve(ok); }
      box.querySelector('.reauth-cancel').addEventListener('click', function () { done(false); });
      box.addEventListener('keydown', function (e) { if (e.key === 'Escape') done(false); });
      form.addEventListener('submit', function (e) {
        e.preventDefault();
        err.style.display = 'none';
        var body = { password: input.value };
        if (code) {
          // Letters: a recovery code (xxxx-xxxx-xx); otherwise the app's 6 digits.
          var v = code.value.trim();
          if (/[a-z]/i.test(v)) body.recovery_code = v; else body.code = v.replace(/\s+/g, '');
        }
        fetch(o.url, {
          method: 'POST', credentials: 'same-origin',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body)
        }).then(function (r) {
          return r.json().catch(function () { return {}; }).then(function (b) {
            if (r.ok && b.success) { done(true); return; }
            var wrongCode = b.error === 'invalid_code' && code;
            err.textContent = b.message || (wrongCode ? 'The code is not right.' : 'Password is incorrect.');
            err.style.display = 'block';
            var again = wrongCode ? code : input;
            again.value = '';
            again.focus();
          });
        }).catch(function () {
          err.textContent = 'Could not reach the backend. Try again in a moment.';
          err.style.display = 'block';
        });
      });
      document.body.appendChild(box);
      input.focus();
    });
  }

  // One prompt for every request that needs it at the same moment.
  var _pending = null;
  A.reauth = function () {
    if (_pending) return _pending;
    var mfa = !!(A.status && A.status.mfa_enabled);
    _pending = ask({
      id: 'reauth-dialog', url: '/api/auth/reauth', code: mfa, title: 'Confirm your password',
      text: mfa ? 'Enter your password and a code from your authenticator app (or a recovery code) to continue.'
                : 'Enter your password again to continue.'
    }).then(function (ok) { _pending = null; return ok; });
    return _pending;
  };

  // User menu. The backend refuses (403 mfa_required_for_role) for a role that
  // requires it; the menu hides the action for those already.
  A.mfaOff = function () {
    return ask({
      id: 'mfa-off-dialog', url: '/api/auth/mfa/disable', code: true, button: 'Turn off',
      title: 'Turn off two-step login',
      text: 'Enter your password and a code from your authenticator app. After this, signing in needs only your password.'
    }).then(function (ok) { if (ok) location.reload(); return ok; });
  };

  A.logout = function () {
    var go = function () { location.replace('/login.html?reason=logged_out'); };
    fetch('/api/auth/logout', { method: 'POST', credentials: 'same-origin' }).then(go, go);
  };

  window.IntactAccess = A;
})();
