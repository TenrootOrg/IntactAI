// Settings → Velociraptor, driven for real: the tab's markup from partials/settings.html, the
// real settings/services stores and Alpine, against the live backend (reads relayed into
// intact_backend; every POST/PUT refused, so nothing changes on the box). Built when the tab
// was redesigned for fleets of 1,000+ (summary + one server-filtered page + pilot search).
//   NODE_PATH=<dir with jsdom@24>/node_modules node tests/velociraptor_tab_live_page.js modules/nginx/html
const fs = require('fs'), path = require('path');
const { execFileSync } = require('child_process');
const { JSDOM, VirtualConsole } = require('jsdom');
const HTML = process.argv[2];                       // modules/nginx/html
const relay = `import json, os, sys, urllib.request, urllib.error
req = urllib.request.Request("http://127.0.0.1:5001" + os.environ["P"])
try:
    r = urllib.request.urlopen(req, timeout=300); out, code = r.read(), r.status
except urllib.error.HTTPError as e:
    out, code = e.read(), e.code
sys.stdout.write(json.dumps({"status": code, "text": out.decode("utf-8", "replace")}))`;
fs.writeFileSync('/tmp/velo_relay.py', relay);
execFileSync('docker', ['cp', '/tmp/velo_relay.py', 'intact_backend:/tmp/velo_relay.py']);
const net = [];
function get(p) {
  const out = execFileSync('docker', ['exec', '-e', 'P=' + p, 'intact_backend', 'python3', '/tmp/velo_relay.py'],
                           { encoding: 'utf8', maxBuffer: 64 << 20 });
  return JSON.parse(out.slice(out.indexOf('{')));
}
const part = fs.readFileSync(path.join(HTML, 'partials/settings.html'), 'utf8');
const tab = part.slice(part.indexOf('<!-- Velociraptor Tab'), part.indexOf('<!-- Cloud Tab -->'));
const errors = [];
const vc = new VirtualConsole();
vc.on('error', e => errors.push(String(e && e.message || e)));
vc.on('warn', e => errors.push('warn: ' + String(e && e.message || e)));
vc.on('jsdomError', e => errors.push('jsdom: ' + e.message));
const dom = new JSDOM(`<!doctype html><body><div x-data="{ settingsTab: 'velociraptor' }">${tab}</div></body>`,
                      { runScripts: 'outside-only', pretendToBeVisual: true, virtualConsole: vc, url: 'https://intact.local/' });
const w = dom.window;
w.fetch = async (p, opt) => {
  const method = (opt && opt.method) || 'GET';
  net.push(method + ' ' + p);
  if (method !== 'GET') return { ok: false, status: 599, json: async () => ({ error: 'write blocked by the test' }) };
  const r = get(p);
  return { ok: r.status < 400, status: r.status, json: async () => JSON.parse(r.text), text: async () => r.text };
};
w.ActiveCase = { gotoSystemWorkflows() {} };
w.confirm = () => false;
for (const f of ['js/stores/services.js', 'js/stores/settings.js', 'js/alpine.min.js'])
  w.eval(fs.readFileSync(path.join(HTML, f), 'utf8'));
const sleep = ms => new Promise(r => setTimeout(r, ms));
// the relay blocks the event loop (sync docker exec): wait for a state, never a fixed time
const waitFor = async (fn, ms = 8000) => { const end = Date.now() + ms; while (Date.now() < end) { if (fn()) return true; await sleep(100); } return fn(); };
const $ = sel => w.document.querySelector(sel), $$ = sel => [...w.document.querySelectorAll(sel)];
const text = () => w.document.body.textContent.replace(/\s+/g, ' ');
let fail = 0;
const check = (name, ok, got) => { console.log((ok ? 'ok   ' : 'FAIL ') + name + (ok ? '' : '  -> ' + got)); if (!ok) fail++; };
(async () => {
  await sleep(300);
  const A = w.Alpine, st = A.store('settings');
  A.store('services').statuses = { velociraptor: 'online' };
  await st.loadVelociraptor(); await sleep(300);
  const rows = () => $$('tbody tr').length;
  const sm = st.velo.summary;
  check('summary loaded', !!sm && sm.total >= 1, JSON.stringify(st.velo).slice(0, 200));
  check('progress line', text().includes(`${sm.counts.current} of ${sm.total} clients on the server's version ${sm.server_version}`), text().slice(0, 300));
  check('table shows one page (<= 50) of rows', rows() === Math.min(50, sm.total), rows());
  check('by-version panel lists versions', $$('button').some(b => /0\.77\.2/.test(b.textContent)), '');
  check('not-upgradable grouped with a count', text().includes('Version unknown — Refresh client info'), text().slice(0, 600));
  // click the "version unknown" count -> filtered on the server
  const unk = $$('button').find(b => /version unknown$/.test(b.textContent.trim()));
  check('state chip present', !!unk, '');
  if (unk) { unk.click(); await waitFor(() => rows() === sm.counts.unknown);
    check('chip filters on the server (state=unknown)', net.some(n => n.includes('state=unknown')), net.slice(-3).join(' | '));
    check('only unknown rows shown', rows() === sm.counts.unknown && $$('tbody tr').every(r => r.textContent.includes('unknown')), rows()); }
  st.clearVeloFilter(); await sleep(400);
  // search
  const box = $('input[placeholder="Search host or client ID"]');
  box.value = 'DESKTOP'; box.dispatchEvent(new w.Event('input'));
  await waitFor(() => rows() === 1);
  await waitFor(() => $$('button').some(b => b.textContent.trim() === 'clear filters' && b.style.display !== 'none'));
  check('search filters on the server (q=DESKTOP)', net.some(n => n.includes('q=DESKTOP')), net.slice(-3).join(' | '));
  check('search shows the matching host', rows() === 1 && $('tbody tr').textContent.includes('DESKTOP-2175T02'), rows());
  check('"clear filters" offered', $$('button').some(b => b.textContent.trim() === 'clear filters' && b.style.display !== 'none'), '');
  st.clearVeloFilter();
  await waitFor(() => $$('button').filter(b => b.textContent.trim() === 'clear filters').every(b => b.style.display === 'none'));
  check('"clear filters" gone after clearing', $$('button').filter(b => b.textContent.trim() === 'clear filters').every(b => b.style.display === 'none'), '');
  st.clearVeloFilter(); await sleep(400);
  // pilot search
  st.veloPilotQ = ''; await st.searchVeloPilot(); await sleep(200);
  check('pilot search calls the server', net.some(n => n.includes('/pilot-candidates?q=')), '');
  check('pilot candidates are online + eligible only', st.veloPilotHits.length === (st.veloUpgrade.eligible_online || 0) || st.veloPilotHits.length === 20, st.veloPilotHits.length);
  check('wave text', st.veloWaveText().length > 10, st.veloWaveText());
  check('upgrade wave disabled without a passed pilot or eligible clients',
        $$('button').find(b => b.textContent.trim() === 'Upgrade wave').disabled === !(st.veloUpgrade.pilot_passed && st.veloUpgrade.eligible), '');
  check('pager hidden for one page', st.velo.pages > 1 || $$('button').filter(b => /Prev/.test(b.textContent)).every(b => b.parentElement.style.display === 'none'), '');
  check('no Alpine / script errors', errors.length === 0, errors.slice(0, 3).join(' || '));
  console.log(fail ? `\n${fail} FAILED` : '\nall ok', '| requests:', net.length);
  process.exit(fail ? 1 : 0);
})();
