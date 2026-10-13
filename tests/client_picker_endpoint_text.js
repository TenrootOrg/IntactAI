// Endpoint-reported text (hostname, OS, labels) must stay TEXT in the client picker.
// Runs the REAL escapeHtml (js/stores/app.js) and ClientManager in jsdom -- a real
// HTML parser, because a fake DOM cannot show an attribute being broken out of.
// `node <file> <root>`; exits 77 when jsdom is not installed (the wrapper skips).
const fs = require('fs'), path = require('path'), assert = require('assert');
let JSDOM;
try { ({ JSDOM } = require('jsdom')); } catch (e) { process.exit(77); }

const root = process.argv[2];
const html = path.join(root, 'modules/nginx/html/js');
const appSrc = fs.readFileSync(path.join(html, 'stores/app.js'), 'utf8');
const escSrc = appSrc.slice(appSrc.indexOf('function escapeHtml('), appSrc.indexOf('\n}\n', appSrc.indexOf('function escapeHtml(')) + 3);
const cmSrc = fs.readFileSync(path.join(html, 'utils/client-manager.js'), 'utf8');

const EVIL = '"><img src=x onerror=alert(1)>\' onmouseover=\'alert(2)';
const dom = new JSDOM('<div id="wrap"><div id="list"></div></div>', { runScripts: 'outside-only' });
const w = dom.window;
w.fetch = async () => ({ ok: true, json: async () => ({ total: 1, items: [{
  client_id: 'C.1' + EVIL, hostname: 'HOST' + EVIL, os: 'windows' + EVIL,
  labels: ['lab' + EVIL], last_seen_at: Date.now() * 1000 }] }) });
w.eval(escSrc + '\nwindow.escapeHtml = escapeHtml;');
w.eval(cmSrc);

(async () => {
  const cm = new w.ClientManager('list', 'cb');
  await cm.load();
  const doc = w.document;
  const injected = [...doc.querySelectorAll('img, script')].length;
  const handlers = [...doc.querySelectorAll('*')].filter(e => [...e.attributes].some(a => /^on/i.test(a.name)));
  assert.strictEqual(injected, 0, 'endpoint text created elements');
  assert.strictEqual(handlers.length, 0, 'endpoint text added event handlers: ' + handlers.map(e => e.outerHTML).join(' | '));
  const text = doc.getElementById('wrap').textContent;
  for (const v of ['HOST' + EVIL, 'lab' + EVIL]) assert.ok(text.includes(v), 'value not shown as text: ' + v);
  const box = doc.querySelector('input.cb');
  assert.strictEqual(box.getAttribute('data-hostname'), 'HOST' + EVIL, 'attribute value altered');
  const chip = doc.querySelector('[data-facet="label"]');
  assert.strictEqual(chip.dataset.val, 'lab' + EVIL, 'label chip value altered');
  console.log('ok');
})().catch(e => { console.error(e.message); process.exit(1); });
