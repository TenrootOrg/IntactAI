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

  // --- the tagging hook -----------------------------------------------------
  window.fetch = function (input, init) {
    try {
      const url = (typeof input === 'string') ? input : (input && input.url) || '';
      const isApi = url.startsWith('/api') || url.indexOf(location.host + '/api') !== -1;
      const cid = get();
      if (isApi && cid) {
        init = init || {};
        const h = new Headers(init.headers || (typeof input !== 'string' && input.headers) || {});
        if (!h.has('X-Case-Id')) h.set('X-Case-Id', cid);
        init.headers = h;
      }
    } catch (e) { /* never let tagging break a request */ }
    return _fetch(input, init);
  };

  // --- helpers --------------------------------------------------------------
  async function listCases() {
    try { const r = await _fetch('/api/cases'); const d = await r.json(); return d.cases || []; }
    catch (e) { return []; }
  }

  async function createCase(name, extra) {
    const body = Object.assign({ name }, extra || {});
    const r = await _fetch('/api/cases', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body)
    });
    return r.json();
  }

  async function deleteCase(id) {
    const r = await _fetch('/api/cases/' + id, { method: 'DELETE' });
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
      `<span style="font-size:12px;color:var(--muted,#8b949e)">Workspace</span>
       <select class="ac-select" style="width:auto;min-width:160px">${options}
         <option value="__new__">＋ New workspace…</option></select>
       ${opts.manageLink === false ? '' :
        '<a href="/cases.html" title="Manage workspaces" style="font-size:12px">Manage</a>'}`;
    const sel = el.querySelector('.ac-select');
    sel.addEventListener('change', async () => {
      if (sel.value === '__new__') {
        const name = (prompt('New workspace name (e.g. GOOGLE IR 05-03-2026):') || '').trim();
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

  window.ActiveCase = { get, set, listCases, createCase, deleteCase, ensureActiveCase,
                        renderCaseSelector };
})();
