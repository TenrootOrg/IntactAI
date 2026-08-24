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
  function set(id) {
    localStorage.setItem(KEY, id || '');
    window.dispatchEvent(new CustomEvent('active-case-changed', { detail: { id } }));
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
    _redirecting = true;
    // Prefer the backend's reason ('expired' / 'credentials_changed'); fall back
    // to a bare login page if the body isn't readable.
    const go = function (reason) {
      const q = reason ? ('?reason=' + encodeURIComponent(reason)) : '';
      try { location.replace('/login.html' + q); }
      catch (e) { location.href = '/login.html' + q; }
    };
    try {
      resp.clone().json()
        .then(function (d) { go(d && d.reason); })
        .catch(function () { go(''); });
    } catch (e) { go(''); }
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
      `${c.is_default ? '★ ' : c.is_system ? '⚙ ' : ''}${escapeHtml(c.name || c.case_id)}</option>`).join('');
    el.innerHTML =
      `<span style="font-size:12px;color:var(--muted,#8b949e)">Case</span>
       <select class="ac-select" style="width:auto;min-width:160px">${options}
         <option value="__new__">＋ New case…</option></select>
       ${opts.manageLink === false ? '' :
        '<a href="/cases.html" title="Manage cases" style="font-size:12px">Manage</a>'}`;
    const sel = el.querySelector('.ac-select');
    sel.addEventListener('change', async () => {
      if (sel.value === '__new__') {
        const name = (prompt('New case name (e.g. GOOGLE IR 05-03-2026):') || '').trim();
        if (!name) { sel.value = id; return; }
        const res = await createCase(name);
        if (res && res.case_id) { set(res.case_id); location.reload(); }
        else { sel.value = id; }
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
