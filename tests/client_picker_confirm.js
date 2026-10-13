// The real ClientManager in jsdom: a big selection asks first, a small one does not,
// and the count asked about includes clients hidden by a filter.
// `node <file> <root>`; exit 77 = no jsdom.
const fs = require('fs'), path = require('path'), assert = require('assert');
let JSDOM;
try { ({ JSDOM } = require('jsdom')); } catch (e) { process.exit(77); }

const src = fs.readFileSync(path.join(process.argv[2], 'modules/nginx/html/js/utils/client-manager.js'), 'utf8');

async function picker(n) {
  const dom = new JSDOM('<div><div id="list"></div></div>', { runScripts: 'outside-only' });
  const w = dom.window;
  const asked = [];
  w.confirm = (msg) => { asked.push(msg); return false; };
  w.escapeHtml = s => String(s);
  w.fetch = async () => ({ ok: true, json: async () => ({ total: n, items: Array.from({ length: n }, (_, i) => ({
    client_id: `C.${i}`, hostname: `HOST-${i}`, os: i % 2 ? 'linux' : 'windows', labels: [],
    last_seen_at: Date.now() * 1000 })) }) });
  w.eval(src);
  const cm = new w.ClientManager('list', 'cb');
  await cm.load();
  return { cm, asked };
}

(async () => {
  const big = await picker(12);
  assert.strictEqual(big.cm.getSelected().length, 12, 'online clients are pre-selected');
  big.cm.setOsFacet('Linux');                                  // hide the Windows half
  assert.strictEqual(big.cm.getSelected().length, 12, 'hidden selected clients dropped');
  assert.strictEqual(big.cm.confirmMany('Start the collection'), false, 'cancel must stop the run');
  assert.ok(/on 12 clients/.test(big.asked[0] || ''), 'the question names the count: ' + big.asked[0]);

  const small = await picker(3);
  assert.strictEqual(small.cm.confirmMany('Start the collection'), true);
  assert.strictEqual(small.asked.length, 0, 'a small selection is not asked about');
  console.log('ok');
})().catch(e => { console.error(e.message); process.exit(1); });
