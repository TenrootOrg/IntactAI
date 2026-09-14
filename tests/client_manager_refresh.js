// Runs the REAL ClientManager (modules/nginx/html/js/utils/client-manager.js)
// against a minimal fake DOM and a scripted /api/clients. `node <file> <root>`
const fs = require('fs'), path = require('path'), assert = require('assert');
const src = fs.readFileSync(path.join(process.argv[2], 'modules/nginx/html/js/utils/client-manager.js'), 'utf8');

function el() {
  const listeners = {};
  const node = {
    innerHTML: '', className: '', children: [],
    addEventListener: (t, f) => { listeners[t] = f; },
    _fire: (t, target) => listeners[t] && listeners[t]({ target, preventDefault() {} }),
    querySelector: () => null,
    parentNode: null,
  };
  return node;
}
function makePage() {
  const container = el();
  const parent = { insertBefore: (n) => { parent.bar = n; } };
  container.parentNode = parent;
  const doc = { getElementById: id => (id === 'list' ? container : null), createElement: () => el() };
  return { container, parent, doc };
}
const nowUs = () => Date.now() * 1000;
const client = (id, host, os = 'windows', online = true) =>
  ({ client_id: id, hostname: host, os, labels: [], last_seen_at: online ? nowUs() : 1 });

async function build(opts = {}) {
  const page = makePage();
  const responses = [];
  let calls = 0;
  const fetch = async () => {
    calls++;
    const r = responses.shift();
    if (r instanceof Error) throw r;
    if (r === 'bad') return { ok: false, json: async () => ({}) };
    if (r && r.delay) await new Promise(res => setTimeout(res, r.delay));
    return { ok: true, json: async () => r.body };
  };
  const escapeHtml = s => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  const window = {};
  new Function('document', 'fetch', 'escapeHtml', 'window', src)(page.doc, fetch, escapeHtml, window);
  const m = new window.ClientManager('list', 'cb', opts);
  return { m, page, responses, calls: () => calls };
}
const fleet = (...cs) => ({ body: { items: cs, total: cs.length } });

(async () => {
  // 1. every picker shows the button, single-select (Memory) too
  for (const single of [false, true]) {
    const t = await build({ singleSelect: single });
    t.responses.push(fleet(client('C.1', 'A')));
    await t.m.load();
    assert(t.page.parent.bar.innerHTML.includes('data-act="refresh"'), `refresh button missing (singleSelect=${single})`);
  }

  // 2. refresh keeps facets, search and selection; drops vanished clients; shows new ones
  {
    const t = await build();
    t.responses.push(fleet(client('C.1', 'A'), client('C.2', 'B'), client('C.3', 'LNX', 'linux')));
    await t.m.load();
    t.m.setOsFacet('Windows');
    t.m.filter('a');
    t.m.setSelected(['C.1', 'C.2']);
    let changed = null; t.m.onChange = ids => { changed = ids; };
    t.responses.push(fleet(client('C.1', 'A'), client('C.4', 'ALPHA-NEW')));      // C.2 removed, C.4 added
    await t.m.refresh();
    assert.deepStrictEqual(t.m.getSelected(), ['C.1'], 'a removed client must be dropped from the selection');
    assert.deepStrictEqual(changed, ['C.1'], 'the page is told the selection changed');
    assert(t.m.activeOs.has('Windows') && t.m.search === 'a', 'facets and search are kept');
    assert(t.page.container.innerHTML.includes('ALPHA-NEW'), 'a newly enrolled client appears');
    assert(!t.page.container.innerHTML.includes('>B<'), 'the removed client is gone from the list');
    assert(/updated \d\d:\d\d:\d\d/.test(t.page.parent.bar.innerHTML), 'the bar says when it was updated');
  }

  // 3. a failed refresh keeps the list and says so, and a later refresh recovers
  for (const failure of ['bad', new Error('network down')]) {
    const t = await build();
    t.responses.push(fleet(client('C.1', 'KEEPME')));
    await t.m.load();
    t.responses.push(failure);
    await t.m.refresh();
    assert(t.page.container.innerHTML.includes('KEEPME'), 'a failed refresh must not wipe the list');
    assert(t.page.parent.bar.innerHTML.includes('Refresh failed'), 'a failed refresh says so');
    assert(t.page.parent.bar.innerHTML.includes('↻ Refresh'), 'the button is usable again');
    t.responses.push(fleet(client('C.1', 'KEEPME')));
    await t.m.refresh();
    assert(!t.page.parent.bar.innerHTML.includes('Refresh failed'), 'a successful refresh clears the error');
  }

  // 4. clicking twice while a refresh is in flight fetches once
  {
    const t = await build();
    t.responses.push(fleet(client('C.1', 'A')));
    await t.m.load();
    t.responses.push({ delay: 30, body: { items: [client('C.1', 'A')], total: 1 } });
    const a = t.m.refresh(), b = t.m.refresh();
    assert(t.page.parent.bar.innerHTML.includes('Refreshing…'), 'the button shows it is working');
    await Promise.all([a, b]);
    assert.strictEqual(t.calls(), 2, 'one load + one refresh, not two refreshes');
  }

  // 5. the button in the bar actually calls refresh
  {
    const t = await build();
    t.responses.push(fleet(client('C.1', 'A')));
    await t.m.load();
    t.responses.push(fleet(client('C.1', 'A'), client('C.9', 'VIA-CLICK')));
    t.page.parent.bar._fire('click', { closest: () => ({ dataset: { act: 'refresh' } }) });
    await new Promise(r => setTimeout(r, 20));
    assert(t.page.container.innerHTML.includes('VIA-CLICK'), 'clicking ↻ Refresh reloads the list');
  }
  console.log('client manager refresh: all checks pass');
})().catch(e => { console.error('FAIL:', e.message); process.exit(1); });
