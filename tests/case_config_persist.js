// The config rail's settings must still be on screen after a Refusion.
//
// Reported: change the Time window in Configuration, press Refusion, go to the
// Log (or come back to Configuration) and the old window is showing again. The
// backend DOES persist it — /config and /rescan both store what they are sent,
// checked live — so the values on screen came from a stale copy: doRefusion
// posted the config and never re-read the case, leaving `curInfo` (what every
// tab renders from) holding the pre-save settings.
//
// Drives the REAL doRefusion from cases.html with fakes for its collaborators.
//   node tests/case_config_persist.js <repo root>
const fs = require('fs'), path = require('path'), assert = require('assert');
const root = process.argv[2];
const html = fs.readFileSync(path.join(root, 'modules/nginx/html/cases.html'), 'utf8');

function slice(from, to) {
  const a = html.indexOf(from), b = html.indexOf(to);
  assert.ok(a !== -1 && b !== -1 && b > a, `could not find ${from} .. ${to}`);
  return html.slice(a, b);
}

// doRefusion + _railCfg, with every collaborator injected.
const code = slice('async function _railCfg(){', '// Rescan (LLM) = SAVE config');

function run({ railMounted = true, rescanReply = {} } = {}) {
  const calls = { api: [], tabs: [], toasts: [], openCase: [], logRefresh: 0 };
  const inputs = {
    'cf-sev': { value: 'medium' }, 'cf-start': { value: '2026-09-01T00:00:00' },
    'cf-end': { value: '2026-09-10T00:00:00' }, 'cf-alt': { value: 'auto' },
    'cf-cust': { value: '' }, 'cf-tlp': { value: 'AMBER' }, 'cf-mp': { value: '' },
    'cf-maxent': { value: '500000' }, 'cf-maxident': { value: '' },
    'cf-mask': { checked: false }, 'cf-maskpat': { value: '' },
    'cf-autoregen': { checked: true }, 'cf-logo': { files: [] },
  };
  const ctx = {
    $: (sel) => railMounted ? (inputs[sel.replace('#', '')] || null) : null,
    document: { querySelectorAll: () => [] },
    _fileToDataUrl: async () => null,
    api: async (url, opt) => { calls.api.push({ url, body: opt && JSON.parse(opt.body || '{}') }); return rescanReply; },
    setTab: (t) => calls.tabs.push(t),
    logRefresh: () => { calls.logRefresh++; },
    toast: (m) => calls.toasts.push(m),
    openCase: (id) => calls.openCase.push(id),
    _hostExc: new Set(),        // hosts unticked in the rail; empty for this test
    console,
  };
  const names = Object.keys(ctx);
  const api = new Function(...names, code + '; return {doRefusion, _railCfg};')(...names.map(n => ctx[n]));
  return { api, calls };
}

(async () => {
  const failures = [];
  const check = (ok, why) => { if (!ok) failures.push(why); };

  // 1. what it posts
  {
    const { api, calls } = run();
    await api.doRefusion('case_1');
    const rescan = calls.api.find(c => c.url.endsWith('/rescan'));
    check(!!rescan, 'Refusion must post /rescan');
    check(rescan && rescan.body.time_window.start === '2026-09-01T00:00:00',
      'the window the operator typed must be in the payload');
    check(rescan && rescan.body.trigger === 'refusion', 'the payload names the button');
  }

  // 2. THE BUG: after the rescan returns, the case must be re-read, or every tab
  //    keeps rendering the settings from before the save.
  {
    const { api, calls } = run();
    await api.doRefusion('case_1');
    check(calls.openCase.includes('case_1'),
      'after a Refusion the case must be re-read so the rail shows the saved settings '
      + `(openCase calls: ${JSON.stringify(calls.openCase)})`);
  }

  // 3. a busy backend (409-style reply) still persisted the config, so refresh too
  {
    const { api, calls } = run({ rescanReply: { busy: true } });
    await api.doRefusion('case_1');
    check(calls.openCase.includes('case_1'),
      'a busy reply still saved the config — the view must still be refreshed');
  }

  // 4. the rail is not mounted (Refusion pressed from another tab): post nothing,
  //    change nothing, but still refresh the view afterwards.
  {
    const { api, calls } = run({ railMounted: false });
    await api.doRefusion('case_1');
    const rescan = calls.api.find(c => c.url.endsWith('/rescan'));
    check(rescan && Object.keys(rescan.body).length === 1 && rescan.body.trigger === 'refusion',
      'an unmounted rail must post only the trigger, never guessed settings');
  }

  // 5. PREVENTION: any action that saves the rail must re-read the case, or the
  //    same "my settings reverted" report comes back through a different button.
  {
    const fnStart = /(?:async\s+)?function\s+(\w+)\s*\(/g;
    let m, bodies = [];
    while ((m = fnStart.exec(html))) {
      const from = m.index, next = html.indexOf('\nfunction ', from + 1), alt = html.indexOf('\nasync function ', from + 1);
      const ends = [next, alt].filter(i => i !== -1);
      bodies.push({ name: m[1], src: html.slice(from, ends.length ? Math.min(...ends) : from + 4000) });
    }
    const savers = bodies.filter(b => /\/rescan'|\/config'/.test(b.src) && /method:'POST'/.test(b.src));
    check(savers.length > 0, 'expected to find the config-saving actions in cases.html');
    for (const b of savers)
      check(/openCase\(/.test(b.src),
        `${b.name}() saves the config rail but never re-reads the case — its tabs will `
        + 'keep rendering the settings from before the save');
  }

  // 6. PREVENTION: every setting the rail RENDERS must be reachable from what the
  //    page holds — the case payload, or a field merged in from /report. A setting
  //    that is saved but not returned reads back as its default, which is the same
  //    "my configuration reverted" report wearing a different hat.
  {
    const routes = fs.readFileSync(path.join(root, 'modules/backend/routes/case_routes.py'), 'utf8');
    const rc = slice('function renderConfig(info){', 'function loadHosts(id){');
    const sc = slice('function showCase(id,info,rep){', 'function render(info,md,g){');
    const oc = slice('function openCase(id){', 'function showCase(id,info,rep){');
    const rendered = new Set([...rc.matchAll(/\binfo\.([a-z_]+)/g)].map(m => m[1]));
    // Supplied either by the backend (the key appears in a payload it builds) or
    // merged into `info` by the page itself (from /report, or a flag it sets).
    const merged = new Set([...(sc + oc).matchAll(/info\.([a-z_]+)\s*=/g)].map(m => m[1]));
    // Only the CASE-DETAIL endpoint counts. A key served by /report is not on
    // `info` unless showCase() merges it -- which is exactly how report_altitude
    // came to read back as "auto" however the operator set it.
    const detailStart = routes.indexOf('def get_case(case_id):');
    const detailEnd = routes.indexOf('@case_bp.route', detailStart);
    assert.ok(detailStart !== -1 && detailEnd > detailStart, 'could not find the case-detail route');
    const detail = routes.slice(detailStart, detailEnd);
    const served = new Set([...detail.matchAll(/"([a-z_]+)":/g)].map(m => m[1]));
    const skip = new Set(['case_id', 'counts', 'name', 'has_logo']);
    for (const k of rendered) {
      if (skip.has(k) || k.startsWith('_')) continue;   // internal view flags
      check(served.has(k) || merged.has(k),
        `the rail renders info.${k} but nothing supplies it — the backend does not return `
        + 'it on the case payload and showCase() does not merge it from /report, so it '
        + 'reads back as its default however it was saved');
    }
  }

  if (failures.length) {
    console.error('FAIL:\n  - ' + failures.join('\n  - '));
    process.exit(1);
  }
  console.log('case config persistence: all checks pass');
})();
