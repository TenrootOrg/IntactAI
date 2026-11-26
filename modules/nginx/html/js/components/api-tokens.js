/**
 * User menu -> API tokens: list, create and revoke your own tokens
 * (routes/api_token_routes.py). An Admin may also open another user's list.
 *
 * A new token is shown once, here; the backend keeps only its hash. Creating
 * one needs a recent password: the fetch hook (js/active-case.js) asks for it
 * on 403 reauth_required and retries. Plain CSS, like access.js's dialogs, so
 * no Tailwind class has to exist in the prebuilt css/tailwind.css.
 */
(function () {
  var BTN = 'padding:6px 12px;border-radius:6px;border:none;cursor:pointer;color:#fff;font-size:13px;';
  var FIELD = 'padding:7px 9px;border-radius:6px;background:#0d1117;border:1px solid #374151;color:#fff;font-size:13px';

  function el(tag, css, text) {
    var e = document.createElement(tag);
    if (css) e.style.cssText = css;
    if (text != null) e.textContent = text;
    return e;
  }
  function when(ts) { return ts ? new Date(ts * 1000).toLocaleString() : 'Never'; }

  async function call(url, method, body) {
    try {
      var r = await fetch(url, {
        method: method || 'GET', credentials: 'same-origin',
        headers: body ? { 'Content-Type': 'application/json' } : {},
        body: body ? JSON.stringify(body) : undefined
      });
      var d = await r.json().catch(function () { return {}; });
      return r.ok ? { ok: true, d: d } : { ok: false, msg: d.message || ('Error ' + r.status) };
    } catch (e) {
      return { ok: false, msg: 'Could not reach the backend.' };
    }
  }

  function open() {
    if (document.getElementById('api-tokens-dialog')) return;
    var s = (window.IntactAccess && window.IntactAccess.status) || {};
    var box = el('div', 'position:fixed;inset:0;z-index:10000;display:flex;align-items:center;' +
      'justify-content:center;background:rgba(0,0,0,.6);padding:16px');
    box.id = 'api-tokens-dialog';
    box.setAttribute('role', 'dialog');
    box.setAttribute('aria-modal', 'true');
    box.setAttribute('aria-labelledby', 'api-tokens-title');
    var card = el('div', 'width:100%;max-width:760px;max-height:90vh;overflow:auto;background:#161b22;' +
      'border:1px solid #374151;border-radius:10px;padding:20px;color:#fff;font-size:14px');
    box.appendChild(card);

    var title = el('div', 'font-weight:600;font-size:16px;margin-bottom:4px', 'API tokens');
    title.id = 'api-tokens-title';
    card.appendChild(title);
    card.appendChild(el('div', 'color:#9ca3af;font-size:13px;margin-bottom:12px',
      'A token lets a script use the dashboard API as you. Send it as "Authorization: Bearer <token>". ' +
      'Read tokens can only read. Write tokens can do what your role can, except manage users, ' +
      'passwords, two-step login and tokens. A token stops working when it expires, when you revoke it, ' +
      'or when your role or password changes.'));

    var err = el('div', 'display:none;color:#f87171;font-size:13px;margin-bottom:8px');
    var shown = el('div', 'display:none;border:1px solid #b45309;background:#2a1f0a;border-radius:8px;padding:10px;margin-bottom:12px');
    card.appendChild(err);
    card.appendChild(shown);

    // Whose tokens: yourself, or (Admin and up) a user below you.
    var who = s.user || '';
    var whoRow = el('div', 'display:none;gap:8px;align-items:center;margin-bottom:10px');
    var whoIn = el('input', FIELD + ';width:180px');
    whoIn.placeholder = 'User name';
    whoIn.setAttribute('aria-label', 'Show the tokens of this user');
    var whoBtn = el('button', BTN + 'background:#374151', 'Show');
    whoBtn.type = 'button';
    whoRow.appendChild(el('span', 'color:#9ca3af;font-size:13px', 'Tokens of'));
    whoRow.appendChild(whoIn);
    whoRow.appendChild(whoBtn);
    if (s.can && s.can.users) whoRow.style.display = 'flex';
    card.appendChild(whoRow);

    var list = el('div', 'margin-bottom:14px');
    card.appendChild(list);

    // Create (your own only).
    var form = el('form', 'display:flex;flex-wrap:wrap;gap:8px;align-items:center;border-top:1px solid #374151;padding-top:12px');
    var nameIn = el('input', FIELD + ';flex:1;min-width:160px');
    nameIn.placeholder = 'Name, e.g. nightly export';
    nameIn.maxLength = 64;
    nameIn.setAttribute('aria-label', 'Token name');
    var scopeIn = el('select', FIELD);
    scopeIn.setAttribute('aria-label', 'Scope');
    [['read', 'Read only'], ['write', 'Read and write']].forEach(function (o) {
      var op = el('option', null, o[1]); op.value = o[0]; scopeIn.appendChild(op);
    });
    var daysIn = el('input', FIELD + ';width:80px');
    daysIn.type = 'number'; daysIn.min = '1'; daysIn.max = '365'; daysIn.value = '30';
    daysIn.setAttribute('aria-label', 'Expires after this many days (1 to 365)');
    var createBtn = el('button', BTN + 'background:#2563eb;font-weight:600', 'Create token');
    createBtn.type = 'submit';
    form.appendChild(nameIn);
    form.appendChild(scopeIn);
    form.appendChild(daysIn);
    form.appendChild(el('span', 'color:#9ca3af;font-size:13px', 'days'));
    form.appendChild(createBtn);
    card.appendChild(form);

    var foot = el('div', 'display:flex;justify-content:flex-end;margin-top:14px');
    var closeBtn = el('button', BTN + 'background:#374151', 'Close');
    closeBtn.type = 'button';
    foot.appendChild(closeBtn);
    card.appendChild(foot);

    function fail(msg) { err.textContent = msg; err.style.display = msg ? 'block' : 'none'; }
    function close() { box.remove(); }
    closeBtn.addEventListener('click', close);
    box.addEventListener('keydown', function (e) { if (e.key === 'Escape') close(); });

    async function load() {
      fail('');
      var mine = !who || who === s.user;
      form.style.display = mine ? 'flex' : 'none';
      var res = await call('/api/tokens' + (mine ? '' : '?user=' + encodeURIComponent(who)));
      list.textContent = '';
      if (!res.ok) { fail(res.msg); return; }
      var toks = res.d.tokens || [];
      list.appendChild(el('div', 'color:#9ca3af;font-size:12px;margin-bottom:6px',
        mine ? 'Your tokens' : 'Tokens of ' + res.d.user));
      if (!toks.length) { list.appendChild(el('div', 'color:#9ca3af;font-size:13px', 'No tokens.')); return; }
      var t = el('table', 'width:100%;border-collapse:collapse;font-size:13px');
      var head = el('tr');
      ['Name', 'Starts with', 'Scope', 'Created', 'Expires', 'Last used', ''].forEach(function (h) {
        head.appendChild(el('th', 'text-align:left;color:#9ca3af;font-weight:500;padding:4px 6px;border-bottom:1px solid #374151', h));
      });
      t.appendChild(head);
      toks.forEach(function (k) {
        var tr = el('tr');
        var td = 'padding:5px 6px;border-bottom:1px solid #21262d;vertical-align:top';
        var nm = el('td', td, k.name);
        if (k.status !== 'active') {
          nm.appendChild(el('div', 'color:#fbbf24;font-size:12px',
            k.status === 'expired' ? 'Expired' : 'Stopped: role, password or account changed'));
        }
        tr.appendChild(nm);
        tr.appendChild(el('td', td + ';font-family:monospace', 'intact_' + k.prefix + '_...'));
        tr.appendChild(el('td', td, k.scope === 'write' ? 'Read and write' : 'Read only'));
        tr.appendChild(el('td', td, when(k.created_at)));
        tr.appendChild(el('td', td, when(k.expires_at)));
        tr.appendChild(el('td', td, when(k.last_used_at)));
        var act = el('td', td + ';text-align:right');
        var rv = el('button', BTN + 'background:#7f1d1d', 'Revoke');
        rv.type = 'button';
        rv.setAttribute('aria-label', 'Revoke token ' + k.name);
        rv.addEventListener('click', async function () {
          if (!confirm('Revoke "' + k.name + '"? Scripts using it stop working at once.')) return;
          var r = await call('/api/tokens/' + encodeURIComponent(k.id), 'DELETE');
          if (!r.ok) { fail(r.msg); return; }
          load();
        });
        act.appendChild(rv);
        tr.appendChild(act);
        t.appendChild(tr);
      });
      list.appendChild(t);
    }

    function showOnce(token) {
      shown.textContent = '';
      shown.appendChild(el('div', 'color:#fbbf24;font-weight:600;font-size:13px;margin-bottom:6px',
        'Copy this token now. It will not be shown again.'));
      var row = el('div', 'display:flex;gap:8px;align-items:center');
      var out = el('input', FIELD + ';flex:1;font-family:monospace');
      out.readOnly = true; out.value = token;
      out.setAttribute('aria-label', 'New token');
      var cp = el('button', BTN + 'background:#2563eb', 'Copy');
      cp.type = 'button';
      cp.addEventListener('click', function () {
        out.select();
        var ok = function () { cp.textContent = 'Copied'; };
        if (navigator.clipboard && window.isSecureContext) navigator.clipboard.writeText(token).then(ok, function () {});
        else { try { document.execCommand('copy'); ok(); } catch (e) { /* select() left it highlighted */ } }
      });
      row.appendChild(out);
      row.appendChild(cp);
      shown.appendChild(row);
      shown.style.display = 'block';
      out.select();
    }

    form.addEventListener('submit', async function (e) {
      e.preventDefault();
      fail('');
      createBtn.disabled = true;
      var res = await call('/api/tokens', 'POST', {
        name: nameIn.value.trim(), scope: scopeIn.value, days: parseInt(daysIn.value, 10)
      });
      createBtn.disabled = false;
      if (!res.ok) { fail(res.msg); return; }
      nameIn.value = '';
      showOnce(res.d.token);
      load();
    });
    whoBtn.addEventListener('click', function () { who = whoIn.value.trim().toLowerCase() || s.user; load(); });

    document.body.appendChild(box);
    nameIn.focus();
    load();
  }

  window.IntactApiTokens = { open: open };
})();
