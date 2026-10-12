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
  const sm = st.velo.summary;
  const rows = () => $$('tbody tr').length;
  const visible = el => el && el.style.display !== 'none' && (!el.parentElement || visible(el.parentElement) || el.parentElement === w.document.body);
  const btn = t => $$('button').find(b => b.textContent.trim().startsWith(t));
  check('summary loaded', !!sm && sm.agents >= 1, JSON.stringify(st.velo).slice(0, 200));
  check('one status line', text().includes(`Server ${sm.server_version} · ${sm.agents} agent`), text().slice(0, 300));
  check('offline-collection imports counted apart', !sm.imported || text().includes(`${sm.imported} offline-collection import(s) (no agent) not counted`), text().slice(0, 400));
  check('upgrade steps only when something is behind',
        sm.counts.behind ? text().includes('Pilot one client') : text().includes('Nothing to upgrade'), text().slice(0, 600));
  check('auto-rebuild switch present', text().includes('Rebuild packages automatically after a server upgrade'), '');
  const tbl = $('table');
  check('client list hidden until asked', tbl && tbl.closest('div[x-show]').style.display === 'none', tbl && tbl.closest('div[x-show]').style.display);
  btn('Show clients').click();
  await waitFor(() => tbl.closest('div[x-show]').style.display !== 'none');
  check('Show clients opens the list', tbl.closest('div[x-show]').style.display !== 'none', '');
  check('imports are not listed by default', rows() === Math.min(50, sm.agents) && $$('tbody tr').every(r => !r.textContent.includes('import (no agent)')), rows());
  const sel = $$('select').find(x => [...x.options].some(o => o.value === 'imported'));
  sel.value = 'imported'; sel.dispatchEvent(new w.Event('change'));
  await waitFor(() => net.some(n => n.includes('state=imported')) && rows() === Math.min(50, sm.imported));
  check('"offline-collection imports" lists them (server-side)', net.some(n => n.includes('state=imported')) && (sm.imported === 0 || $$('tbody tr').every(r => r.textContent.includes('import (no agent)'))), rows());
  sel.value = ''; sel.dispatchEvent(new w.Event('change'));
  await waitFor(() => rows() === Math.min(50, sm.agents));
  const box = $('input[placeholder="Search host"]');
  box.value = 'DESKTOP'; box.dispatchEvent(new w.Event('input'));
  await waitFor(() => net.some(n => n.includes('q=DESKTOP')) && rows() === 1);
  check('search filters on the server', net.some(n => n.includes('q=DESKTOP')) && rows() === 1 && $('tbody tr').textContent.includes('DESKTOP-2175T02'), rows());
  // the box may have nothing behind: show the three steps from the page's own state (nothing is sent)
  st.velo = { ...st.velo, summary: { ...st.velo.summary, counts: { ...st.velo.summary.counts, behind: 3 } } };
  st.veloUpgrade = { ...st.veloUpgrade, eligible: 3, pilot_passed: false };
  await waitFor(() => text().includes('Pilot one client'));
  check('with clients behind: the three steps show', ['Pilot one client', 'Everyone else', 'Upgrade 3 client(s)', '· 3 behind'].every(t => text().includes(t)), text().slice(0, 500));
  check('"Upgrade 3 client(s)" waits for the pilot', btn('Upgrade 3').disabled === true, '');
  check('no Alpine / script errors', errors.length === 0, errors.slice(0, 3).join(' || '));
  console.log(fail ? `\n${fail} FAILED` : '\nall ok', '| requests:', net.length);
  process.exit(fail ? 1 : 0);
})();
