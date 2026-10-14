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

const N = 1000;
const pad = i => String(i).padStart(4, '0');
const nowUs = Date.now() * 1000;
const fleet = Array.from({ length: N }, (_, i) => ({
  client_id: `C.${pad(i)}`, hostname: `HOST-${pad(i)}`, os: i % 3 ? 'windows' : 'linux',
  labels: i % 10 ? [] : ['dc'], last_seen_at: nowUs }));

const sleep = ms => new Promise(r => setTimeout(r, ms));

(async () => {
  const dom = new JSDOM(`<body>${read('partials/velociraptor.html')}</body>`, { runScripts: 'dangerously' });
  const w = dom.window, doc = w.document;
  const asked = [];
  w.confirm = msg => { asked.push(msg); return false; };
  w.fetch = async () => ({ ok: true, json: async () => ({ total: N, items: fleet }) });
  w.eval(escSrc + '\nwindow.escapeHtml = escapeHtml;');
  w.eval(read('js/utils/client-manager.js'));
  w.eval(read('js/blueprints-forensics.js') + '\nwindow.forensicsClientManager = forensicsClientManager;');
  const cm = w.forensicsClientManager;
  let renders = 0;
  const realRender = cm.render.bind(cm);
  cm.render = () => { renders++; realRender(); };

  await cm.load();
  const list = doc.getElementById('forensics-client-list');
  const boxes = () => [...list.querySelectorAll('input.forensics-client-cb')];
  const bar = list.previousElementSibling;

  // 1. nothing pre-ticked
  assert.strictEqual(cm.getSelected().length, 0, 'clients were pre-selected');
  assert.strictEqual(boxes().filter(b => b.checked).length, 0, 'a box is ticked on load');

  // 2. at most 200 rows rendered, with a "Show more"
  assert.strictEqual(boxes().length, 200, `rendered ${boxes().length} rows, want 200`);
  const more = list.querySelector('[data-act="show-more"]');
  assert.ok(more && /800 not listed/.test(more.textContent), 'no Show more: ' + (more && more.textContent));
  assert.ok(/1000 matching/.test(bar.textContent), 'counts do not cover the whole fleet: ' + bar.textContent);
  more.click();
  assert.strictEqual(boxes().length, 400, 'Show more did not add the next page');

  // 3. typing is debounced: three keystrokes, one render, through the real oninput
  const search = doc.getElementById('forensics-client-search');
  const type = v => { search.value = v; search.dispatchEvent(new w.Event('input', { bubbles: true })); };
  const before = renders;
  type('h'); type('host-0'); type('host-00');
  assert.strictEqual(renders, before, 'rendered on a keystroke before the debounce');
  await sleep(300);
  assert.strictEqual(renders, before + 1, `typing rendered ${renders - before} times, want 1`);
  assert.strictEqual(boxes().length, 100, 'filter host-00 should list HOST-0000..0099');
  assert.ok(!list.querySelector('[data-act="show-more"]'), 'Show more with every match listed');

  // 4. "Select all matching (N)" selects every match, rendered or not
  type(''); await sleep(300);
  assert.strictEqual(boxes().length, 200, 'a new filter must start back at the first page');
  const selAll = bar.querySelector('[data-act="select-shown"]');
  assert.ok(/Select all matching \(1000\)/.test(selAll.textContent), 'button: ' + selAll.textContent);
  selAll.click();
  assert.strictEqual(cm.getSelected().length, N, 'select all matching missed unrendered clients');
  bar.querySelector('[data-act="deselect-shown"]').click();
  assert.strictEqual(cm.getSelected().length, 0, 'deselect matching left clients selected');

  // 5. a ticked row survives a filter that hides it; selection of matches adds to it
  const box = boxes().find(b => b.value === 'C.0007');
  box.click();                                   // a real click fires the change event
  assert.deepStrictEqual([...cm.getSelected()], ['C.0007']);
  type('host-09'); await sleep(300);
  assert.ok(!boxes().some(b => b.value === 'C.0007'), 'filter did not hide the row');
  bar.querySelector('[data-act="select-shown"]').click();
  type('host-01'); await sleep(300);
  assert.strictEqual(cm.getSelected().length, 101, 'selection lost while filtered: ' + cm.getSelected().length);
  assert.ok(cm.getSelected().includes('C.0007'), 'hidden ticked client dropped');

  // 6. the big-selection question is short: a count and the first 10 names
  assert.strictEqual(cm.confirmMany('Start the collection'), false);
  assert.ok(/on 101 clients \(first 10: HOST-0007, HOST-0900,/.test(asked[0]), 'question: ' + asked[0]);
  assert.ok(asked[0].length < 300, `question is ${asked[0].length} chars`);
  console.log('ok');
})().catch(e => { console.error(e.stack || e.message); process.exit(1); });
