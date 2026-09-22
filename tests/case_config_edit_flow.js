// The operator's sequence, end to end, against the REAL functions in cases.html:
//
//   open the case -> the rail renders the STORED window
//   -> the operator types a new window
//   -> a background refresh lands (the 5s report poll calls openCase on
//      completion / phase change, which rebuilds the page)
//   -> the operator presses Refusion
//
// What must hold: the value the operator typed is what gets POSTed, and once it
// is saved the rail shows what the server stored. Three separate attempts on the
// appliance failed here, each time with the browser sending the PRE-EDIT values,
// so this runs the chain without a browser.
//
//   node tests/case_config_edit_flow.js <repo root>
const fs = require('fs'), path = require('path'), assert = require('assert');
const root = process.argv[2];
const html = fs.readFileSync(path.join(root, 'modules/nginx/html/cases.html'), 'utf8');
const slice = (a, b) => {
  const i = html.indexOf(a), j = html.indexOf(b);
  assert.ok(i !== -1 && j > i, `cannot slice ${a} .. ${b}`);
  return html.slice(i, j);
};

// A DOM just real enough: elements hold a value, innerHTML assignment REPLACES
// the children (which is what destroyed the operator's typing), and events
// bubble from an input to the container the page listens on.
function makeDom() {
  const listeners = {};
  const byId = new Map();
  const container = {
    _html: '',
    addEventListener(type, fn) { (listeners[type] = listeners[type] || []).push(fn); },
    set innerHTML(v) {
      this._html = v;
      // rebuild the fields from the markup, as a browser would: every id="cf-*"
      // becomes an element whose value is its value= attribute, its selected
      // <option>, or its <textarea> body.
      for (const k of [...byId.keys()]) if (k.startsWith('cf-')) byId.delete(k);
      for (const m of v.matchAll(/<(\w+)\s+([^>]*\bid="(cf-[a-z]+)"[^>]*)>/g)) {
        const [, tagRaw, attrs, id] = m, tag = tagRaw.toLowerCase();
        const val = /value="([^"]*)"/.exec(attrs);
        const el = mkInput(id, val ? val[1] : '');
        el.checked = /\bchecked\b/.test(attrs);
        if (tag === 'select') {
          const body = v.slice(m.index, v.indexOf('</select>', m.index));
          const sel = /<option[^>]*value="([^"]*)"[^>]*\bselected\b/.exec(body)
                   || /value="([^"]*)"\s+selected/.exec(body);
          el.value = sel ? sel[1] : '';
        } else if (tag === 'textarea') {
          const end = v.indexOf('</textarea>', m.index);
          el.value = end === -1 ? '' : v.slice(m.index + m[0].length, end);
        }
        byId.set(id, el);
      }
    },
    get innerHTML() { return this._html; },
  };
  function mkInput(id, value) {
    return {
      id, value, checked: false, files: [],
      dispatch(type) { (listeners[type] || []).forEach(fn => fn({ target: this })); },
    };
  }
  byId.set('tabc', container);
  byId.set('main', { set innerHTML(v) {}, get innerHTML() { return ''; }, addEventListener() {} });
  return {
    $: (sel) => byId.get(sel.replace('#', '')) || null,
    container, byId,
    type(id, v) { const el = byId.get(id); assert.ok(el, `${id} is not on screen`); el.value = v; el.dispatch('input'); },
  };
}

// Real globals the sliced code may legitimately reach for; everything else that
// is not in `ctx` (badge renderers, formatters) is auto-stubbed so the slice can
// run without dragging the whole 20k-line page in.
const REAL = new Set(['undefined', 'NaN', 'Infinity', 'Object', 'Array', 'JSON', 'Math',
  'Date', 'String', 'Number', 'Boolean', 'Promise', 'Set', 'Map', 'RegExp', 'Error',
  'parseInt', 'parseFloat', 'isNaN', 'console', 'Symbol']);

function load(dom, calls) {
  const ctx = {
    $: dom.$,
    document: { querySelectorAll: () => [] },
    esc: s => String(s == null ? '' : s),
    jsa: s => String(s == null ? '' : s),
    _fileToDataUrl: async () => null,
    loadHosts: () => {},
    flatpickr: undefined,
    api: async (url, opt) => { calls.push({ url, body: opt && opt.body ? JSON.parse(opt.body) : null }); return {}; },
    setTab: () => {}, logRefresh: () => {}, toast: () => {}, openCase: () => {},
    curInfo: null, tab: 'config',   // _hostExc/_hostList are declared by the sliced code itself
  };
  const scope = new Proxy(ctx, {
    has: (t, k) => typeof k === 'string' && !REAL.has(k),
    get: (t, k) => (k in t ? t[k] : () => ''),
  });
  const code = [
    // the page's own helper, not a copy of it: the proxy scope below turns any
    // name it does not know into () => '', which is how a missing helper reads
    // as "not a function" three frames deep instead of as a missing helper.
    slice('function asList(v){', '\n// safe value for a single-quoted'),
    slice('function renderConfig(info){', 'function loadHosts(id){'),
    slice('let _cfgDirty=false;', 'function drawTab(md){'),
    slice('async function _railCfg(){', '// Rescan (LLM) = SAVE config'),
  ].join('\n');
  return new Function('__scope', `with(__scope){ ${code}
    return {renderConfig, _railCfg, doRefusion, skipConfigRedraw,
            dirty: () => _cfgDirty, clear: () => { _cfgDirty = false; }}; }`)(scope);
}

(async () => {
  const failures = [];
  const check = (ok, why) => { if (!ok) failures.push(why); };
  const STORED = { start: '2016-09-15T09:07:04', end: '2026-09-15T09:07:04' };
  const TYPED = { start: '2026-09-01T00:00:00', end: '2026-09-10T12:00:00' };
  const info = () => ({
    case_id: 'case_1', time_window: { ...STORED }, min_severity: 'medium',
    masking: {}, report_altitude: 'auto', max_entities: 500000, fusion_modules: [],
  });

  // 1. the rail renders the stored window
  const dom = makeDom();
  const calls = [];
  const app = load(dom, calls);
  app.renderConfig(info());
  check(dom.$('#cf-start').value === STORED.start, `rail must show the stored start, got ${dom.$('#cf-start').value}`);

  // 2. the operator types a new window
  dom.type('cf-start', TYPED.start);
  dom.type('cf-end', TYPED.end);
  check(app.dirty() === true, 'typing must mark the rail as edited, or a refresh will discard it');

  // 3. a background refresh lands mid-edit. The page must NOT rebuild the rail.
  const wouldRebuild = !app.skipConfigRedraw('config', app.dirty(), !!dom.$('#cf-start'));
  check(wouldRebuild === false, 'a background refresh must not rebuild the rail while it is being edited');
  if (wouldRebuild) app.renderConfig(info());          // what the page would do
  check(dom.$('#cf-start').value === TYPED.start,
    `after a background refresh the typed start must still be there, got ${dom.$('#cf-start').value}`);

  // 4. Refusion posts what the operator typed
  await app.doRefusion('case_1');
  const rescan = calls.find(c => c.url.endsWith('/rescan'));
  check(!!rescan, 'Refusion must post /rescan');
  check(rescan && rescan.body.time_window.start === TYPED.start,
    `the POSTed start must be the operator's: sent ${rescan && rescan.body.time_window.start}`);
  check(rescan && rescan.body.time_window.end === TYPED.end,
    `the POSTed end must be the operator's: sent ${rescan && rescan.body.time_window.end}`);

  // 5. once saved, the rail redraws with what the server stored
  check(app.dirty() === false, 'saving must clear the edited flag so the rail can redraw');
  const saved = { ...info(), time_window: { ...TYPED } };
  const blocked = app.skipConfigRedraw('config', app.dirty(), !!dom.$('#cf-start'));
  check(blocked === false, 'after a save the rail must be free to redraw');
  app.renderConfig(saved);
  check(dom.$('#cf-start').value === TYPED.start, 'the saved window must be what the rail shows afterwards');

  if (failures.length) { console.error('FAIL:\n  - ' + failures.join('\n  - ')); process.exit(1); }
  console.log('config edit flow: typed values survive a background refresh, are POSTed, and are shown after saving');
})();
