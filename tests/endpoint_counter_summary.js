// The dashboard endpoint counter asks /api/clients/summary for two numbers
// instead of pulling the whole fleet every 10 s (fleet-scale audit F36), and
// falls back to the full list only when the route 404s (an older backend
// mid-upgrade). Real js/stores/services.js + real Alpine in jsdom.
// `node <file> <root>`; exit 77 = no jsdom.
const fs = require('fs'), path = require('path'), assert = require('assert');
let JSDOM;
try { ({ JSDOM } = require('jsdom')); } catch (e) { process.exit(77); }

const html = path.join(process.argv[2], 'modules/nginx/html');
const sleep = ms => new Promise(r => setTimeout(r, ms));
const nowUs = Date.now() * 1000;

async function page(summaryStatus) {
  const dom = new JSDOM('<body><span id="c" x-data x-text="`${$store.services.onlineClientCount}/${$store.services.clientCount}`"></span></body>',
                        { runScripts: 'outside-only', pretendToBeVisual: true });
  const w = dom.window, calls = [];
  w.fetch = async (url) => {
    calls.push(String(url));
    if (url === '/api/clients/summary') {
      return { ok: summaryStatus === 200, status: summaryStatus, json: async () => ({ online: 640, total: 1000 }) };
    }
    return { ok: true, status: 200, json: async () => ({ total: 3, items: [
      { client_id: 'C.1', last_seen_at: nowUs }, { client_id: 'C.2', last_seen_at: nowUs },
      { client_id: 'C.3', last_seen_at: 1 }] }) };
  };
  for (const f of ['js/stores/services.js', 'js/alpine.min.js'])
    w.eval(fs.readFileSync(path.join(html, f), 'utf8'));
  await sleep(100);
  await w.Alpine.store('services').loadClients();
  await sleep(50);
  return { calls, shown: w.document.getElementById('c').textContent };
}

(async () => {
  const fresh = await page(200);
  assert.deepStrictEqual(fresh.calls, ['/api/clients/summary'], 'the full fleet was fetched: ' + fresh.calls);
  assert.strictEqual(fresh.shown, '640/1000');

  const old = await page(404);
  assert.deepStrictEqual(old.calls, ['/api/clients/summary', '/api/clients?include_offline=true']);
  assert.strictEqual(old.shown, '2/3', 'fallback counts wrong: ' + old.shown);

  // Any other failure (a 500, a 502 during a restart) must not turn into a
  // full-fleet pull every 10 s.
  const broken = await page(502);
  assert.deepStrictEqual(broken.calls, ['/api/clients/summary']);
  console.log('ok');
})().catch(e => { console.error(e.stack || e.message); process.exit(1); });
