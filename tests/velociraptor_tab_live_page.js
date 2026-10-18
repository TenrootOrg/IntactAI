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
  // the summary: one card, three columns (Updated / Upgradeable / Version unknown), each number once
  const cols = $$('div.grid.grid-cols-3.rounded-lg > div').map(d => d.textContent.replace(/\s+/g, ' ').trim());
  const reported = sm.total - sm.counts.unknown;
  check('summary: three columns', cols.length === 3 && /^Updated/.test(cols[0]) && /^Upgradeable/.test(cols[1]) && /^Version unknown/.test(cols[2]), JSON.stringify(cols));
  check('updated = current / clients that reported a version', cols[0].startsWith(`Updated ${sm.counts.current} / ${reported} on ${sm.server_version}`), cols[0]);
  check('the bar shows updated of reported', $('div.grid.grid-cols-3.rounded-lg div.h-2 > div').style.width === Math.round(100 * sm.counts.current / Math.max(1, reported)) + '%', '');
  check('upgradeable count', cols[1].startsWith(`Upgradeable ${sm.eligible}`), cols[1]);
  // Offline-collection imports are counted apart from agents that did not report.
  check('version unknown counts agents only; imports apart', cols[2].startsWith(`Version unknown ${sm.counts.unknown} ` +
        (sm.counts.imported ? `+ ${sm.counts.imported} offline collections (no agent)` : 'agents that have not reported yet')), cols[2]);
  check('table shows one page, unknown versions collapsed', rows() === Math.min(50, sm.total - sm.counts.unknown)
        && $$('tbody tr').every(r => !/unknown/.test(r.textContent)), rows());
  if (sm.counts.unknown) {
    const tog = () => $$('button').find(b => /with unknown version/.test(b.textContent));
    check('"Show N with unknown version" offered', !!tog() && tog().textContent.includes(`Show ${sm.counts.unknown} with unknown version`), tog() && tog().textContent);
    tog().click();
    await waitFor(() => rows() === Math.min(50, sm.total));
    check('... shows them', rows() === Math.min(50, sm.total) && /^Hide the/.test(tog().textContent.trim()), rows());
    tog().click();
    await waitFor(() => rows() === Math.min(50, sm.total - sm.counts.unknown));
    check('... and hides them again', rows() === Math.min(50, sm.total - sm.counts.unknown), rows());
  }
  check('meta line under the title', text().includes(`Server ${sm.server_version} · ${sm.counts.online} of ${sm.total} online`), '');
  check('nothing in the summary is clickable but "ask clients to report again"', [...$('div.grid.grid-cols-3.rounded-lg').querySelectorAll('button')].every(b => /report again|asking/.test(b.textContent)), '');
  const box0 = $('input[placeholder="Search host or client ID"]'), row = box0.parentElement;
  check('filter row = search box only', !row.querySelector('select') && !$$('button').some(b => /upgradable from here|clear filters/.test(b.textContent)), row.innerHTML.slice(0, 200));
  // search
  const box = $('input[placeholder="Search host or client ID"]');
  box.value = 'DESKTOP'; box.dispatchEvent(new w.Event('input'));
  // wait for the search request itself: with unknown versions collapsed the table may already be 1 row
  await waitFor(() => net.some(n => n.includes('q=DESKTOP')));
  await waitFor(() => rows() === 1);
  check('search filters on the server (q=DESKTOP)', net.some(n => n.includes('q=DESKTOP')), net.slice(-3).join(' | '));
  check('search shows the matching host', rows() === 1 && $('tbody tr').textContent.includes('DESKTOP-2175T02'), rows());
  st.setVeloFilter({ q: '' }); await waitFor(() => rows() === Math.min(50, sm.total));
  // pilot box: autocompletes from every client as you type; only those that may pilot can be picked
  const pq = $('input[placeholder="Search an online client to pilot"]');
  pq.value = 'DESK'; pq.dispatchEvent(new w.Event('input'));
  await waitFor(() => net.some(n => n.includes('/pilot-candidates?q=DESK')) && st.veloPilotHits.length > 0);
  const hit = st.veloPilotHits.find(c => c.hostname === 'DESKTOP-2175T02');
  check('pilot box autocompletes from all clients', !!hit, JSON.stringify(st.veloPilotHits).slice(0, 200));
  await waitFor(() => $$('div[title]').some(d => d.textContent.includes('DESKTOP-2175T02')));
  const opt = $$('div.px-2.py-1').find(d => d.textContent.includes('DESKTOP-2175T02'));
  check('a client that cannot pilot is shown greyed with why', hit && (hit.ok || (opt && /cursor-not-allowed/.test(opt.className) && /server's version/.test(opt.textContent))), opt && opt.outerHTML.slice(0, 200));
  if (opt && hit && !hit.ok) { opt.dispatchEvent(new w.MouseEvent('mousedown', { bubbles: true })); await sleep(100);
    check('... and cannot be picked', st.veloPilot === null, JSON.stringify(st.veloPilot)); }
  check('wave text', st.veloWaveText().length > 10, st.veloWaveText());
  const all = $$('button').find(b => b.textContent.trim().startsWith('Upgrade all ('));
  check('one "Upgrade all (N)" button, no label/size fields', !!all && !$('input[placeholder="Label (optional)"]') && !$('input[placeholder="Max clients"]'), '');
  check('Upgrade all clickable whenever a client is behind (the pilot is optional)', all.disabled === !st.veloUpgrade.eligible, '');
  // sortable headers (server-side) + the Upgrade column
  const th = t => $$('th').find(h => h.textContent.trim().startsWith(t));
  check('Upgrade column', !!th('Upgrade') && !th('State'), $$('th').map(h => h.textContent.trim()).join(','));
  th('Version').click();
  await waitFor(() => net.some(n => n.includes('sort=version')));
  check('click a header: sorted on the server', net.some(n => n.includes('sort=version')) && th('Version').textContent.includes('▲'), th('Version').textContent);
  th('Version').click();
  await waitFor(() => net.some(n => n.includes('sort=version') && n.includes('dir=desc')));
  check('click again: reversed', th('Version').textContent.includes('▼'), th('Version').textContent);
  const vm = $$('tbody tr').find(r => r.textContent.includes('DESKTOP-2175T02'));
  check('the VM row says its upgrade status', vm && /up to date|will upgrade/.test(vm.textContent), vm && vm.textContent);
  // a refused action says why NEXT TO the buttons (the top banner is off-screen there): the page's
  // own POST is refused by this driver (599), which must show up inline
  st.veloPilot = { client_id: 'C.x', hostname: 'X' }; w.confirm = () => true;
  await st.startVeloUpgrade('pilot'); await sleep(100);
  const msg = $$('p').find(p => /^Pilot not started:/.test(p.textContent.trim()));
  check('a refused pilot says why next to the buttons', !!msg && msg.style.display !== 'none' && /text-red-400/.test(msg.className), msg && msg.outerHTML.slice(0, 160));
  w.confirm = () => false; st.veloPilot = null; st.veloAction = null;
  // no Reload / Refresh buttons in the header; "ask clients to report again" sits in the unknown column
  check('no Reload / Refresh client info buttons', !$$('button').some(b => /^(Reload|Loading…|Refresh client info)$/.test(b.textContent.trim())), '');
  const ask = $$('button').find(b => b.textContent.trim() === 'ask clients to report again');
  check('"ask clients to report again" in the Version unknown column', !!ask && !!ask.closest('div[title]') && /Version unknown/.test(ask.closest('div[title]').textContent), '');
  await st.refreshVeloClientInfo(); await sleep(100);          // the driver refuses the POST: the reason shows inline
  const res = ask.parentElement.querySelector('div[x-show*="veloRefreshMsg"]');
  check('... its result shows right under it', !!res && res.style.display !== 'none' && /^Could not ask/.test(res.textContent.trim()), res && res.outerHTML.slice(0, 160));
  st.veloRefreshMsg = null;
  // the page refreshes itself every 30 s while the tab is open
  const before = net.filter(n => n.includes('/clients/versions')).length;
  await waitFor(() => net.filter(n => n.includes('/clients/versions')).length > before, 40000);
  check('refreshes itself within 30 s', net.filter(n => n.includes('/clients/versions')).length > before, before);
  // while an upgrade is followed: a notice at the top, and Pilot / Upgrade all greyed (from the page's own state)
  const realRunning = st.veloUpgrade.running;
  st.veloUpgrade = { ...st.veloUpgrade, running: { stage: 'rest', started: '2026-10-12T10:00:00', watch_until: 1791900000, total: 4, upgraded: 3, failed: 0 } };
  await waitFor(() => text().includes('Client upgrade in progress'));
  check('in-progress notice: "3 of 4 upgraded so far", "no need to start it again"', text().includes('Client upgrade in progress — all clients: 3 of 4 upgraded so far') && text().includes('No need to start it again'), '');
  const bAll = $$('button').find(b => b.textContent.trim().startsWith('Upgrade all ('));
  check('Upgrade all / pilot greyed while it runs', bAll.disabled && $$('button').find(b => b.textContent.trim() === 'Upgrade pilot').disabled && /in progress/.test(bAll.title), bAll.title);
  st.veloUpgrade = { ...st.veloUpgrade, running: { ...st.veloUpgrade.running, upgraded: 4 } };
  await waitFor(() => text().includes('Client upgrade: all 4 upgraded'));
  check('all done: "all 4 upgraded — the run closes at its next hourly check"', text().includes('Client upgrade: all 4 upgraded — the run closes at its next hourly check'), '');
  st.veloUpgrade = { ...st.veloUpgrade, running: realRunning };
  check('no "Prepare packages" button or rebuild switch (the run builds them)', !$$('button').some(b => /Prepare packages/.test(b.textContent)) && !/Rebuild automatically/.test(text()), '');
  check('pager hidden for one page', st.velo.pages > 1 || $$('button').filter(b => /Prev/.test(b.textContent)).every(b => b.parentElement.style.display === 'none'), '');
  check('no Alpine / script errors', errors.length === 0, errors.slice(0, 3).join(' || '));
  console.log(fail ? `\n${fail} FAILED` : '\nall ok', '| requests:', net.length);
  process.exit(fail ? 1 : 0);
})();
