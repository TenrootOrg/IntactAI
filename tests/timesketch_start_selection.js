// Timesketch "Start" sends every SELECTED client, not just the ticked boxes on
// screen (fleet-scale audit F30). Real partial (partials/timesketch.html, real
// button wiring), real escapeHtml, ClientManager and timesketch.js in jsdom,
// with 1,000 fake clients.
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
const fleet = Array.from({ length: N }, (_, i) => ({
  client_id: `C.${pad(i)}`, hostname: `HOST-${pad(i)}`, os: 'windows', labels: [],
  last_seen_at: Date.now() * 1000 }));
const sleep = ms => new Promise(r => setTimeout(r, ms));

(async () => {
  const dom = new JSDOM(`<body>${read('partials/timesketch.html')}</body>`, { runScripts: 'dangerously' });
  const w = dom.window, doc = w.document;
  const asked = [], posted = [];
  w.confirm = msg => { asked.push(msg); return true; };
  w.alert = () => {};
  w.switchTab = () => {};
  w.fetch = async (url, opts) => {
    if (String(url).startsWith('/api/timesketch/start-multi')) {
      posted.push(JSON.parse(opts.body));
      return { ok: true, json: async () => ({ run_id: 'r1' }) };
    }
    return { ok: true, json: async () => ({ total: N, items: fleet }) };
  };
  w.eval(escSrc + '\nwindow.escapeHtml = escapeHtml;');
  w.eval(read('js/utils/client-manager.js'));
  w.eval(read('js/timesketch.js') + '\nwindow.tcm = timesketchClientManager;');
  w.timesketchBlueprintsCache = [{ id: 'bp1', name: 'Triage', settings: { kape_target: '_KapeTriage', plaso_parser: 'win7' } }];
  doc.getElementById('timesketch-blueprint-select').innerHTML = '<option value="bp1">Triage</option>';

  const cm = w.tcm;
  await cm.load();
  const list = doc.getElementById('timesketch-client-list');
  const bar = list.previousElementSibling;
  const search = doc.getElementById('timesketch-client-search');
  const type = async v => { search.value = v; search.dispatchEvent(new w.Event('input', { bubbles: true })); await sleep(300); };

  // Select 100 hosts, then filter them all out of view.
  await type('host-00');
  bar.querySelector('[data-act="select-shown"]').click();
  await type('host-05');
  assert.strictEqual(list.querySelectorAll('input:checked').length, 0, 'a selected row is still on screen');

  [...doc.querySelectorAll('button')].find(b => /runTimeSketchWorkflow/.test(b.getAttribute('onclick') || '')).click();
  await sleep(50);

  assert.strictEqual(posted.length, 1, 'the pipeline was not started');
  const clients = posted[0].clients;
  assert.strictEqual(clients.length, 100, `sent ${clients.length} clients, want the 100 selected`);
  assert.deepStrictEqual(clients[0], { client_id: 'C.0000', client_name: 'HOST-0000' });
  assert.strictEqual(asked.length, 1, 'one question, not two');
  assert.ok(/for 100 client\(s\)/.test(asked[0]) && /100 clients \(first 10: HOST-0000, /.test(asked[0]), asked[0]);
  assert.ok(!asked[0].includes('HOST-0010'), 'the question lists more than 10 hosts');
  assert.ok(/Plaso Parser: win7/.test(asked[0]), 'the settings are still in the question');
  console.log('ok');
})().catch(e => { console.error(e.stack || e.message); process.exit(1); });
