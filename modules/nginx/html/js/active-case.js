/**
 * Active Case (workspace) — per-browser state + request tagging.
 *
 * MUST be loaded FIRST (before api-client.js / app.js / any inline fetch), because it
 * monkeypatches window.fetch to attach the `X-Case-Id` header to every same-origin /api
 * request. That single hook is how the browser's active case reaches the backend, which
 * tags new analysis runs to the workspace and filters run lists by it — with zero edits
 * to the ~38 module-launch call sites.
 */
(function () {
  const KEY = 'activeCaseId';
  const _fetch = window.fetch.bind(window);   // pristine fetch (no header) for bootstrap

  function get() { return localStorage.getItem(KEY) || ''; }
  // The active case for what fetch does not tag (download links, window.open): the
  // backend takes the Velociraptor org from it (app.py). A case id, never an org.
  function _caseCookie(id) {
    document.cookie = `intact_case=${encodeURIComponent(id || '')}; path=/; max-age=${id ? 31536000 : 0}; SameSite=Strict`;
  }
  try {
    _caseCookie(get());
    document.cookie = 'velo_org=; path=/; max-age=0; SameSite=Strict';   // the old per-page org pick
  } catch (e) { /* no document.cookie (headless) */ }
  function set(id) {
    localStorage.setItem(KEY, id || '');
    _caseCookie(id);
    window.dispatchEvent(new CustomEvent('active-case-changed', { detail: { id } }));
    // The case decides the Velociraptor org (VeloOrg below).
    if (window.VeloOrg && id) window.VeloOrg.syncFromCase(id);
  }

  // Surface "module run blocked in the System workspace" ONCE (debounced) — the
  // backend rejects module/feature runs in System with HTTP 409 +
  // code 'workspace_system_blocked'. Without this the run silently does nothing.
  let _wsBlockedAt = 0;
  function _showWorkspaceBlocked(msg) {
    const now = Date.now();
    if (now - _wsBlockedAt < 3000) return;   // collapse duplicate 409s from one action
    _wsBlockedAt = now;
    try { window.alert(msg); } catch (e) { /* headless / no window.alert */ }
  }

  // Redirect to the login page on the first 401 and swallow the rest.
  //
  // Debounced with a hard latch rather than the 3s window used above: the
  // dashboard runs 8 independent setInterval pollers, so a single expiry
  // produces a burst of simultaneous 401s and without the latch they would race
  // each other assigning location.href.
  let _redirecting = false;
  function _handleUnauthenticated(resp) {
    if (_redirecting) return;
    // Prefer the backend's reason ('expired' / 'credentials_changed' /
    // 'disabled'); fall back to a bare login page if the body isn't readable.
    const go = function (reason) {
      if (_redirecting) return;
      _redirecting = true;
      const q = reason ? ('?reason=' + encodeURIComponent(reason)) : '';
      try { location.replace('/login.html' + q); }
      catch (e) { location.href = '/login.html' + q; }
    };
    try {
      resp.clone().json()
        .then(function (d) {
          // A 401 naming another error is an answer, not a lost session: a
          // wrong password typed into the re-auth prompt or the Super-admin
          // transfer (invalid_credentials / forbidden). The caller shows it.
          if (d && d.error && d.error !== 'unauthenticated') return;
          go(d && d.reason);
        })
        .catch(function () { go(''); });
    } catch (e) { go(''); }
  }

  // --- GETs the role may not make ---------------------------------------------
  // /api/auth/status lists the GET routes closed to this role (routes/
  // auth_routes._get_rules). Pages and stores load a few of those in the
  // background; answering them here with the server's own 403 keeps them out
  // of the audit log as "denied". A path an open route also matches is sent:
  // the server decides, so this can only ever skip a request it would refuse.
  let _roleWaited = false;
  function _closedGet(input, init) {
    const st = window.IntactAccess && window.IntactAccess.status;
    const g = st && st.gets;
    if (!g) return false;
    const method = ((init && init.method) || (typeof input !== 'string' && input && input.method) || 'GET').toUpperCase();
    if (method !== 'GET') return false;
    let path;
    try { path = new URL((typeof input === 'string') ? input : input.url, location.href).pathname; }
    catch (e) { return false; }
    if (!g._re) g._re = { closed: g.closed.map(s => new RegExp(s)), open: g.open.map(s => new RegExp(s)) };
    return g._re.closed.some(r => r.test(path)) && !g._re.open.some(r => r.test(path));
  }
  function _forbidden() {
    return Promise.resolve(new Response(JSON.stringify({ error: 'forbidden', message: 'Your role does not allow this.' }),
      { status: 403, headers: { 'Content-Type': 'application/json' } }));
  }

  // --- the tagging hook -----------------------------------------------------
  window.fetch = function (input, init) {
    let isApi = false;
    try {
      const url = (typeof input === 'string') ? input : (input && input.url) || '';
      isApi = url.startsWith('/api') || url.indexOf(location.host + '/api') !== -1;
      const cid = get();
      if (isApi && cid) {
        init = init || {};
        const h = new Headers(init.headers || (typeof input !== 'string' && input.headers) || {});
        if (!h.has('X-Case-Id')) h.set('X-Case-Id', cid);
        init.headers = h;
      }
    } catch (e) { /* never let tagging break a request */ }

    if (isApi) {
      const acc = window.IntactAccess;
      const url = (typeof input === 'string') ? input : (input && input.url) || '';
      // Before the role is known, wait for it once (the status call itself
      // excepted; a failed status call must not hold requests back for ever).
      if (!_roleWaited && acc && !acc.status && acc.ready && url.indexOf('/api/auth/') === -1) {
        const again = () => { _roleWaited = true; return window.fetch(input, init); };
        return acc.ready.then(again, again);
      }
      if (_closedGet(input, init)) return _forbidden();
    }
    const p = _fetch(input, init);
    if (!isApi) return p;
    // Globally auto-recover from the System-workspace guard for EVERY module
    // launch — offline-collector import, hunts, timesketch, memory,
    // blueprints, cloud scans, … Modules must run in an investigation
    // workspace, so when a launch is rejected because System is active (409 +
    // workspace_system_blocked), silently switch to the Default workspace and
    // RETRY the request once — the run just works, mirroring how system
    // features switch TO System. Falls back to the old one-shot alert only if
    // the Default workspace can't be resolved. System features (upgrade /
    // maintenance / support bundle / purge / settings) run IN System so they
    // never hit this 409.
    return p.then(function (resp) {
      if (!resp) return resp;
      // Session gone (expired, or the password was changed) — bounce to the
      // login page, carrying the backend's reason so it can say WHICH of those
      // happened instead of showing a bare form.
      //
      // Hooked here rather than in api-client.js because this is the one place
      // every /api call passes through: there are ~116 raw fetch() call sites
      // across the frontend versus 3 that use api.get/api.post (api-client.js
      // says as much: "Existing code can gradually adopt these helpers"). Wiring
      // it there would cover 3 of them and leave every other panel silently
      // rendering empty on an expired session.
      if (resp.status === 401) { _handleUnauthenticated(resp); return resp; }
      if (resp.status === 403) {
        return resp.clone().json().then(function (d) {
          var err = d && d.error;
          // Signed in with a one-time or publicly known password, or a role
          // that requires two-step login without it set up: the backend
          // refuses everything but change-password / the setup until done.
          if (err === 'password_change_required' || err === 'mfa_enroll_required') {
            if (!_redirecting) {
              _redirecting = true;
              // top: from the Case Analysis iframe the whole dashboard must go.
              var u = err === 'mfa_enroll_required' ? '/login.html?mfa=setup'
                                                    : '/login.html?reason=password_change_required';
              try { window.top.location.replace(u); } catch (e) { location.replace(u); }
            }
            return resp;
          }
          var acc = window.IntactAccess;
          // User management wants the password typed in the last 15 minutes:
          // ask for it, then send the same request once more (not again after).
          if (err === 'reauth_required' && acc && !(init && init._intactReauth)) {
            return acc.reauth().then(function (ok) {
              return ok ? window.fetch(input, Object.assign({}, init, { _intactReauth: true })) : resp;
            });
          }
          // The role may not. Say so for what the user did; a background GET
          // (a poller on a page the role still sees) would toast every few
          // seconds, so those stay quiet and render their own empty state.
          var method = ((init && init.method) || (typeof input !== 'string' && input && input.method) || 'GET').toUpperCase();
          if (err === 'forbidden' && acc && method !== 'GET') acc.toast(d.message);
          return resp;
        }).catch(function () { return resp; });   // not JSON: an ordinary 403
      }
      // PRIMARY path: the backend redirects a module launched from the System
      // workspace to Default and echoes the effective workspace here. Follow it
      // so the UI + later requests use Default (the run already ran there). This
      // works for EVERY module uniformly — it doesn't depend on the launch route
      // surfacing the 409 (some wrap it into a plain 500), which is why the
      // header exists.
      try {
        var sw = resp.headers.get('X-Active-Case');
        if (sw && get() !== sw) set(sw);
      } catch (e) { /* header unreadable — ignore */ }

      if (resp.status !== 409) return resp;
      // FALLBACK: a route that still lets the WorkspaceError 409 through (e.g.
      // AWS) — switch to Default and retry once.
      return resp.clone().json().then(function (d) {
        // The active case is Closed: say so once, whatever module launched it.
        // No switch or retry -- which case to use instead is the analyst's call.
        if (d && d.code === 'case_closed') {
          _showWorkspaceBlocked(d.error || 'This case is closed. Reopen it in Case Management first.');
          return resp;
        }
        if (!d || d.code !== 'workspace_system_blocked') return resp;
        return _ensureDefaultCaseId().then(function (def) {
          if (def && get() !== def) {
            set(def);   // move active case -> Default
            // Retry once with X-Case-Id FORCED to Default. The first attempt
            // already stamped the stale System id onto init.headers, so we must
            // overwrite it (the hook only sets the header when absent). Use the
            // raw fetch so we don't re-enter this interceptor / re-retry.
            var rh = new Headers((init && init.headers) ||
              (typeof input !== 'string' && input && input.headers) || {});
            rh.set('X-Case-Id', def);
            var rinit = Object.assign({}, init, { headers: rh });
            return _fetch(input, rinit);
          }
          // Couldn't resolve Default (or already there) — surface the message.
          _showWorkspaceBlocked(d.error ||
            'This action runs against an investigation case, not System. ' +
            'Switch to or create an investigation case first.');
          return resp;
        });
      }).catch(function () { return resp; });   // non-JSON 409 — pass through
    });
  };

  // --- helpers --------------------------------------------------------------
  // These three use the PRISTINE `_fetch` deliberately (bootstrap runs before
  // an active case exists, and the 409 retry must not re-enter itself), which
  // also means they skip the 401 branch in the hook above. Check it explicitly
  // here — ensureActiveCase() runs on every page load, so without this an
  // expired session would sit on a blank dashboard instead of redirecting.
  async function _guard401(r) {
    if (r && r.status === 401) { _handleUnauthenticated(r); return true; }
    return false;
  }

  async function listCases() {
    try {
      const r = await _fetch('/api/cases');
      if (await _guard401(r)) return [];
      const d = await r.json();
      return d.cases || [];
    }
    catch (e) { return []; }
  }

  // Cache the System workspace id so the proactive guard below is cheap on repeat
  // calls. Resolved from /api/cases (the is_system flag) on first use.
  let _systemCaseId = null;
  async function _ensureSystemCaseId() {
    if (_systemCaseId) return _systemCaseId;
    const sys = (await listCases()).find(c => c.is_system);
    if (sys) _systemCaseId = sys.case_id;
    return _systemCaseId;
  }

  // Cache the built-in Default workspace id (is_default). This is where module
  // work auto-lands when the operator tries to run it from the System workspace.
  let _defaultCaseId = null;
  async function _ensureDefaultCaseId() {
    if (_defaultCaseId) return _defaultCaseId;
    const cases = await listCases();
    const def = cases.find(c => c.is_default) || cases.find(c => !c.is_system) || null;
    if (def) _defaultCaseId = def.case_id;
    return _defaultCaseId;
  }

  /**
   * PROACTIVE System-workspace redirect for module launches that DON'T go through
   * a fetch the UI can inspect — notably tus uploads (velociraptor offline
   * collector, timesketch import) + the memory-dump XHR upload, where the backend
   * creates the run server-side AFTER the upload finishes, so the window.fetch
   * 409 interceptor never sees it. Call this BEFORE starting such work: if the
   * active workspace is System it silently moves to the Default workspace (so the
   * upload rides in on an investigation workspace) and returns false (proceed).
   * It only returns true (caller should abort) if Default can't be resolved.
   * Kept the name/return-shape so existing callers work unchanged.
   */
  async function blockIfSystem(msg) {
    try {
      const sys = await _ensureSystemCaseId();
      if (sys && get() === sys) {
        const def = await _ensureDefaultCaseId();
        if (def) { set(def); return false; }   // redirect to Default, then proceed
        // No Default to fall back to — block with the alert rather than run it in System.
        _showWorkspaceBlocked(msg ||
          'This action runs against an investigation case, not System. ' +
          'Switch to or create an investigation case first.');
        return true;
      }
    } catch (e) { /* on any error, don't block — fall through to the backend 409 */ }
    return false;
  }

  async function createCase(name, extra) {
    const body = Object.assign({ name }, extra || {});
    const r = await _fetch('/api/cases', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body)
    });
    await _guard401(r);
    return r.json();
  }

  async function deleteCase(id) {
    const r = await _fetch('/api/cases/' + id, { method: 'DELETE' });
    await _guard401(r);
    return { status: r.status, body: await r.json().catch(() => ({})) };
  }

  // On load: make sure we have a valid active case. If unset/stale, pick the Default.
  async function ensureActiveCase() {
    let id = get();
    const cases = await listCases();
    const ids = cases.map(c => c.case_id);
    if (!id || ids.indexOf(id) === -1) {
      const def = cases.find(c => c.is_default) || cases[0];
      if (def) { set(def.case_id); id = def.case_id; }
    }
    const cur = cases.find(c => c.case_id === id);
    if (cur && window.VeloOrg) window.VeloOrg.apply(cur.velo_org);
    return { id, cases };
  }

  /**
   * Render a compact "Active case ▾" dropdown into `el`. Changing it persists the
   * selection and reloads so every case-scoped view refreshes. A "＋ New case" entry
   * quick-creates one; "Manage…" opens the management page.
   */
  async function renderCaseSelector(el, opts) {
    opts = opts || {};
    const { id, cases } = await ensureActiveCase();
    const options = cases.map(c =>
      `<option value="${c.case_id}" ${c.case_id === id ? 'selected' : ''}>` +
      `${c.is_default ? '★ ' : c.is_system ? '⚙ ' : ''}${c.restricted ? '🔒 ' : ''}${escapeHtml(c.name || c.case_id)}</option>`).join('');
    el.innerHTML =
      `<span style="font-size:12px;color:var(--muted,#8b949e)">Case</span>
       <select class="ac-select" style="width:auto;min-width:160px">${options}
         <option value="__new__" data-needs="write">＋ New case…</option></select>
       ${opts.manageLink === false ? '' :
        '<a href="/cases.html" title="Manage cases" style="font-size:12px">Manage</a>'}
       <span class="ac-org" style="font-size:12px;color:var(--muted,#8b949e)" title="The case's Velociraptor org: everything this case does in Velociraptor runs there. Change it by editing the case.">Org <b style="color:inherit;font-weight:600">${escapeHtml((cases.find(c => c.case_id === id) || {}).velo_org || 'root')}</b></span>`;
    if (window.VeloOrg) window.VeloOrg.nameOf((cases.find(c => c.case_id === id) || {}).velo_org)
      .then(n => { const b = el.querySelector('.ac-org b'); if (b) b.textContent = n; });
    const sel = el.querySelector('.ac-select');
    sel.addEventListener('change', async () => {
      if (sel.value === '__new__') {
        sel.value = id;
        // The New Case form in Case Management asks for the name AND status,
        // severity, owner and description. A name-only prompt() here created a
        // case that then had to be edited to fill in the rest.
        try { sessionStorage.setItem('intact:newCase', '1'); } catch (e) { /* private mode */ }
        if (opts.onNewCase) { opts.onNewCase(); return; }            // already on that page
        try {
          const app = window.parent !== window && window.parent.Alpine && window.parent.Alpine.store('app');
          if (app) { app.switchTab('cases'); return; }               // inside the dashboard
        } catch (e) { /* not embedded */ }
        location.href = '/cases.html?view=manage';
        return;
      }
      set(sel.value);
      if (opts.onChange) opts.onChange(sel.value); else location.reload();
    });
  }

  function escapeHtml(s) {
    return (s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  /**
   * Switch to the built-in System workspace, then land on the Workflows tab.
   *
   * System-operation runs (upgrade / online upgrade / prepare package / apply /
   * maintenance / support bundle / purge / settings) are ALWAYS tagged to the
   * System workspace by the backend (SYSTEM_TYPES in workflow_service.py), so the
   * workspace-scoped Workflows tab only shows them when System is active. Every
   * system feature must call this after kicking off its run — otherwise the run
   * is invisible until the operator manually switches workspaces. Changing the
   * active workspace requires a reload (like the workspace selector) so all
   * case-scoped views refresh; we restore the Workflows tab via the URL hash.
   * If System is already active, just switch the tab (no reload).
   */
  async function gotoSystemWorkflows() {
    // System is no longer a selectable workspace — system-operation run history now
    // lives in Settings → Actions. Navigate there and open the Actions tab. (Kept
    // the old name + shape so the ~7 settings.js callers work unchanged.) The
    // settings panel listens for the 'show-system-actions' window event; fire it
    // twice to cover the case where the settings partial is still lazy-loading.
    //
    // Callers can be INSIDE an iframe: the Cases tab embeds cases.html, and its
    // Export button ends here. Alpine and the settings panel live in the parent,
    // so switching this window's tab would do nothing visible — walk up to the
    // top window first. Same origin, so this is a plain property access; the
    // try/catch is for a headless/detached frame, not for a security boundary.
    let top = window;
    try {
      if (window.top && window.top !== window && window.top.document) top = window.top;
    } catch (e) { top = window; }
    try {
      if (top.Alpine && top.Alpine.store('app') && top.Alpine.store('app').switchTab) {
        top.Alpine.store('app').switchTab('settings');
      } else {
        top.location.hash = 'settings';
      }
    } catch (e) {
      try { top.location.hash = 'settings'; } catch (_) { /* headless */ }
    }
    // Build the event with the TARGET window's constructor. Dispatching an event
    // created in this frame's realm onto another realm's window is the kind of
    // thing that works until it doesn't; `top.CustomEvent` removes the question.
    const fire = () => {
      try {
        const C = (top && top.CustomEvent) || CustomEvent;
        top.dispatchEvent(new C('show-system-actions'));
      } catch (e) { /* headless / detached frame */ }
    };
    fire();
    setTimeout(fire, 400);
  }

  window.ActiveCase = { get, set, listCases, createCase, deleteCase, ensureActiveCase,
                        renderCaseSelector, gotoSystemWorkflows, blockIfSystem };
})();

/**
 * Velociraptor organization -- the ACTIVE CASE's org. A case is attached to one
 * org (chosen when it is created, editable in Case Management); nothing else
 * picks one. Pages that work with Velociraptor show it read-only in an empty
 * <div class="velo-org-slot"></div>, mounted here whenever one appears
 * (partials and modals render late).
 *
 * The backend takes the org from the case itself on every request (X-Case-Id,
 * or the `intact_case` cookie set above for download links and window.open), so
 * an org changed on the case applies at once. Here it is only known for display,
 * the Velociraptor GUI link and the tus metadata; each client list
 * (ClientManager) reloads on 'velo-org-changed'.
 */
(function () {
  const SYNC_KEY = 'veloOrgId';      // localStorage: the case's org, shared by frames / tabs
  const _fetch = window.fetch.bind(window);

  function get() {
    try { return localStorage.getItem(SYNC_KEY) || 'root'; } catch (e) { return 'root'; }
  }
  function _announce(id) {
    mountAll(true);
    window.dispatchEvent(new CustomEvent('velo-org-changed', { detail: { id } }));
  }
  /** Record the active case's org (only ActiveCase calls this). */
  function apply(id) {
    id = id || 'root';
    if (id === get()) return;
    try { localStorage.setItem(SYNC_KEY, id); } catch (e) {}
    _announce(id);
  }
  async function syncFromCase(caseId) {
    try {
      const r = await _fetch('/api/cases', { credentials: 'same-origin' });
      if (!r.ok) return;
      const c = ((await r.json()).cases || []).find(x => x.case_id === caseId);
      if (c) apply(c.velo_org);
    } catch (e) { /* the next page load syncs it */ }
  }
  // Another frame (Case Analysis is an iframe) or tab changed it.
  window.addEventListener('storage', e => { if (e.key === SYNC_KEY) _announce(get()); });

  // One request for every label on the page; a failed one is retried later.
  let _orgs = null;
  function list() {
    if (!_orgs) {
      _orgs = _fetch('/api/velociraptor/orgs', { credentials: 'same-origin' })
        .then(r => (r.ok ? r.json() : { orgs: [] }))
        .then(d => d.orgs || [])
        .catch(() => []);
      _orgs.then(o => { if (!o.length) _orgs = null; });
    }
    return _orgs;
  }
  /** An org's name, as the top bar shows it (the id only when Velociraptor cannot
   *  say: down, or the org is gone). The list is cached for the page, so an org
   *  made in Velociraptor after the page loaded is looked up once more first --
   *  the bar showed "OBH40" for a case's new org (2026-11-17). */
  async function nameOf(id) {
    id = id || 'root';
    let o = (await list()).find(x => x.id === id);
    if (!o && id !== 'root') { _orgs = null; o = (await list()).find(x => x.id === id); }
    return o ? o.name : id;
  }
  /** Velociraptor GUI url in the case's org (its GUI takes ?org_id=). */
  function guiUrl(hash) {
    const org = get();
    return `https://${location.hostname}/velociraptor/app/index.html` +
           (org !== 'root' ? `?org_id=${encodeURIComponent(org)}` : '') + (hash || '');
  }
  const esc = s => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/"/g, '&quot;');
  async function renderLabel(el) {
    if (!el) return;
    el.dataset.mounted = '1';
    const name = await nameOf(get());
    const hint = el.dataset.hint || 'Clients, hunts, collections and imports here use this org.';
    const text = `Velociraptor org: <b>${esc(name)}</b> &mdash; the active case's. ${esc(hint)} Change it by editing the case.`;
    el.innerHTML = el.dataset.style === 'case'            // Case Analysis (cases.html) styling
      ? `<div class="cfghint">${text}</div>`
      : `<p class="text-xs text-gray-400">${text}</p>`;
  }
  function mountAll(all) {
    document.querySelectorAll(all ? '.velo-org-slot' : '.velo-org-slot:not([data-mounted])').forEach(renderLabel);
  }
  let _t = null;
  new MutationObserver(() => { clearTimeout(_t); _t = setTimeout(() => mountAll(false), 50); })
    .observe(document.documentElement, { childList: true, subtree: true });
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', () => mountAll(false));
  else mountAll(false);

  window.VeloOrg = { get, apply, syncFromCase, list, nameOf, guiUrl };
})();
