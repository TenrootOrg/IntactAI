// The REAL Forensics client picker at fleet scale, in jsdom: the real partial
// (partials/velociraptor.html, so the real oninput / button wiring), the real
// escapeHtml (js/stores/app.js), ClientManager and blueprints-forensics.js,
// against 1,000 fake clients.
// Nothing is pre-ticked, at most 200 rows are in the DOM, typing renders once
// (debounced), "Select all matching (N)" takes every match including rows never
// rendered, and the selection survives filtering.
// `node <file> <root>`; exit 77 = no jsdom.
const fs = require('fs'), path = require('path'), assert = require('assert');
let JSDOM;
try { ({ JSDOM } = require('jsdom')); } catch (e) { process.exit(77); }

const html = path.join(process.argv[2], 'modules/nginx/html');
const read = p => fs.readFileSync(path.join(html, p), 'utf8');
const appSrc = read('js/stores/app.js');
const at = appSrc.indexOf('function escapeHtml(');
const escSrc = appSrc.slice(at, appSrc.indexOf('\n}\n', at) + 3);

const { fakeClientsApi } = require('./fake_clients_api.js');

// 20,000 clients: every 5th online, Windows/Linux/macOS in turn, every 50th
// labelled dc. The picker never holds more than the pages it was shown.
const N = 20000;
const pad = i => String(i).padStart(5, '0');
const nowUs = Date.now() * 1000;
const fleet = Array.from({ length: N }, (_, i) => ({
  client_id: `C.${pad(i)}`, hostname: `HOST-${pad(i)}`, os: ['windows', 'linux', 'darwin'][i % 3],
  labels: i % 50 ? [] : ['dc'], last_ip: `10.0.${(i >> 8) & 255}.${i & 255}`,
  last_seen_at: i % 5 ? nowUs - 3600e6 : nowUs }));
const ONLINE = N / 5;

const sleep = ms => new Promise(r => setTimeout(r, ms));
const settle = () => sleep(20);

(async () => {
  const dom = new JSDOM(`<body>${read('partials/velociraptor.html')}</body>`, { runScripts: 'dangerously' });
  const w = dom.window, doc = w.document;
  const asked = [];
  w.confirm = msg => { asked.push(msg); return false; };
  const api = fakeClientsApi(fleet.slice());
  w.fetch = api.fetch;
  w.eval(escSrc + '\nwindow.escapeHtml = escapeHtml;');
  w.eval(read('js/utils/client-manager.js'));
  w.eval(read('js/blueprints-forensics.js') + '\nwindow.forensicsClientManager = forensicsClientManager;');
  const cm = w.forensicsClientManager;

  await cm.load();
  const list = doc.getElementById('forensics-client-list');
  const boxes = () => [...list.querySelectorAll('input.forensics-client-cb')];
  const bar = list.previousElementSibling;
  const click = async el => { el.click(); await settle(); };

  // 1. nothing pre-ticked; one page of 200 asked for and drawn, never the fleet
  assert.strictEqual(cm.getSelected().length, 0, 'clients were pre-selected');
  assert.strictEqual(boxes().filter(b => b.checked).length, 0, 'a box is ticked on load');
  assert.strictEqual(boxes().length, 200, `rendered ${boxes().length} rows, want 200`);
  assert.ok(api.calls.every(u => /limit=200/.test(u)), 'a request without a page size: ' + api.calls);
  assert.ok(new RegExp(`${ONLINE} matching of ${N}`).test(bar.textContent), 'counts: ' + bar.textContent);

  // 2. "Show more" fetches the next page only
  const more = list.querySelector('[data-act="show-more"]');
  assert.ok(more && new RegExp(`${ONLINE - 200} not listed`).test(more.textContent), 'Show more: ' + (more && more.textContent));
  await click(more);
  assert.strictEqual(boxes().length, 400, 'Show more did not add the next page');
  assert.ok(/offset=200/.test(api.calls[api.calls.length - 1]), 'the next page was not asked for');

  // 3. typing is debounced: three keystrokes, one request, through the real oninput
  const search = doc.getElementById('forensics-client-search');
  const type = async v => { search.value = v; search.dispatchEvent(new w.Event('input', { bubbles: true })); };
  const before = api.calls.length;
  type('h'); type('host-0'); type('host-000');
  assert.strictEqual(api.calls.length, before, 'asked the server on a keystroke before the debounce');
  await sleep(300);
  assert.strictEqual(api.calls.length - before, 1, `typing asked ${api.calls.length - before} times, want 1`);
  // HOST-00000..00099, online ones only: every 5th
  assert.strictEqual(boxes().length, 20, 'filter host-000 (online) should list 20');
  assert.ok(!list.querySelector('[data-act="show-more"]'), 'Show more with every match listed');

  // 4. search reaches clients never loaded, by client id and by IP
  type('c.19995'); await sleep(300);
  assert.deepStrictEqual(boxes().map(b => b.value), ['C.19995']);
  type('10.0.78.30'); await sleep(300);        // i = 78*256+30 = 19998: offline, hidden
  assert.strictEqual(boxes().length, 0, 'Online only must still apply to a search');

  // 5. "Select all matching (N)" selects every match, loaded or not
  type(''); await sleep(300);
  assert.strictEqual(boxes().length, 200, 'a new filter must start back at the first page');
  const selAll = () => bar.querySelector('[data-act="select-shown"]');
  assert.ok(new RegExp(`Select all matching \\(${ONLINE}\\)`).test(selAll().textContent), 'button: ' + selAll().textContent);
  await click(selAll());
  assert.strictEqual(cm.getSelected().length, ONLINE, 'select all matching missed clients never loaded');
  await click(bar.querySelector('[data-act="deselect-shown"]'));
  assert.strictEqual(cm.getSelected().length, 0, 'deselect matching left clients selected');

  // 6. a ticked row survives a filter that hides it; selecting matches adds to it
  boxes().find(b => b.value === 'C.00030').click();
  assert.deepStrictEqual([...cm.getSelected()], ['C.00030']);
  type('host-0090'); await sleep(300);
  assert.ok(!boxes().some(b => b.value === 'C.00030'), 'filter did not hide the row');
  await click(selAll());                           // HOST-00900..00909 online: 2
  type('host-001'); await sleep(300);
  assert.strictEqual(cm.getSelected().length, 3, 'selection lost while filtered: ' + cm.getSelected().length);
  assert.ok(cm.getSelected().includes('C.00030'), 'hidden ticked client dropped');
  assert.ok(/\(3 not in this view\)/.test(bar.textContent), 'hidden selection not said: ' + bar.textContent);

  // 7. the big-selection question is short: a count and the first 10 names --
  //    names known even for clients selected without ever being loaded
  type(''); await sleep(300);
  await click(doc.querySelector('[onclick*="selectAllForensicsClients(true)"]'));
  assert.strictEqual(cm.getSelected().length, N, 'the header Select All must take the whole fleet');
  assert.ok(new RegExp(`${N} selected \\(${N - ONLINE} not in this view\\)`).test(bar.textContent),
            'offline clients selected without a word: ' + bar.textContent);
  assert.strictEqual(cm.confirmMany('Start the collection'), false);
  assert.ok(new RegExp(`on ${N} clients \\(first 10: HOST-`).test(asked[0]) && !/C\.\d{5},/.test(asked[0]),
            'question: ' + asked[0]);
  assert.ok(asked[0].length < 300, `question is ${asked[0].length} chars`);
  await click(doc.querySelector('[onclick*="selectAllForensicsClients(false)"]'));
  assert.strictEqual(cm.getSelected().length, 0, 'None left clients selected');

  // 8. facet chips filter on the server and combine
  await click(bar.querySelector('[data-facet="os"][data-val="Linux"]'));
  await click(bar.querySelector('[data-facet="label"][data-val="dc"]'));
  assert.ok(boxes().length > 0 && boxes().every(b => cm.getClient(b.value).os === 'linux'
            && cm.getClient(b.value).labels.includes('dc')), 'OS + label chips did not combine');
  await click(bar.querySelector('[data-facet="online"]'));
  assert.ok(/133 matching of 20000/.test(bar.textContent), 'Linux + dc incl. offline: ' + bar.textContent);
  await click(bar.querySelector('[data-facet="os"][data-val="Linux"]'));
  await click(bar.querySelector('[data-facet="label"][data-val="dc"]'));
  await click(bar.querySelector('[data-facet="online"]'));

  // 9. Refresh is live, keeps the filters, and drops a selected client that is gone
  boxes()[0].click(); boxes()[1].click();
  const gone = cm.getSelected()[0];
  api.fleet = api.fleet.filter(c => c.client_id !== gone);
  await cm.refresh();
  assert.ok(/fresh=1/.test(api.calls.find(u => /fresh=1/.test(u)) || ''), 'refresh was not live');
  assert.strictEqual(cm.getSelected().length, 1, 'refresh kept a removed client');
  assert.ok(!cm.getSelected().includes(gone));
  console.log('ok');
})().catch(e => { console.error(e.stack || e.message); process.exit(1); });
