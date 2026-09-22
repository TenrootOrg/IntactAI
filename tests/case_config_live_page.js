// The operator's own sequence, in a REAL DOM, against a LIVE appliance.
//
// Three fixes for "the time window I set doesn't stick" passed their unit
// harness and still failed on the box, because the unit harness fakes the DOM:
// it cannot run flatpickr, innerHTML re-parsing, the 5s report poll, the
// sessionStorage view memo or the active-case re-open. This one runs the real
// page (jsdom) against the real backend and does what the operator does:
// open the case, pick a date in the calendar, let background refreshes land,
// press Refusion, follow the page to the Log and back, then reload.
//
// It needs a running appliance, so it is NOT part of the offline suite -- the
// python wrapper skips unless docker, the backend container and jsdom are all
// present. API calls are relayed through `docker exec` so they originate on the
// container's own loopback, inside the auth gate's exemption; the case it works
// on is created and deleted by the test, so nothing of the operator's is touched.
//
//   node tests/case_config_live_page.js <path to cases.html>
const fs = require('fs'), path = require('path');
const { execFileSync } = require('child_process');
const { JSDOM, VirtualConsole } = require('jsdom');

const PAGE = process.argv[2];
const DIR = path.dirname(PAGE);
const CONTAINER = process.env.INTACT_BACKEND || 'intact_backend';

// The relay: runs INSIDE the backend container, so its requests come from the
// container's own loopback and the auth gate lets them through without a session.
const RELAY = `import json, os, sys, urllib.request, urllib.error
m, p = os.environ["M"], os.environ["P"]
body = (os.environ.get("BODY") or "").encode() or None
req = urllib.request.Request("http://127.0.0.1:5001" + p, data=body, method=m)
if body: req.add_header("Content-Type", "application/json")
try:
    r = urllib.request.urlopen(req, timeout=900); out, code = r.read(), r.status
except urllib.error.HTTPError as e:
    out, code = e.read(), e.code
sys.stdout.write(json.dumps({"status": code, "text": out.decode("utf-8", "replace")}))
`;
{
  const tmp = path.join(require('os').tmpdir(), 'intact_api_relay.py');
  fs.writeFileSync(tmp, RELAY);
  execFileSync('docker', ['cp', tmp, CONTAINER + ':/tmp/api_call.py']);
}

function call(method, p, body) {
  const env = { ...process.env, M: method, P: p, BODY: body ? JSON.stringify(body) : '' };
  const out = execFileSync('docker', ['exec', '-i',
    '-e', 'M', '-e', 'P', '-e', 'BODY', CONTAINER, 'python3', '/tmp/api_call.py'],
    { env, encoding: 'utf8', maxBuffer: 256 * 1024 * 1024 });
  return JSON.parse(out.slice(out.indexOf('{')));
}

const netlog = [];
function makeFetch(win) {
  return (p, opt) => {
    const method = (opt && opt.method) || 'GET';
    const body = opt && opt.body ? JSON.parse(opt.body) : null;
    netlog.push({ method, p, body });
    if (process.env.TRACE) console.log('   net', method, p);
    const r = call(method, p, body);
    return Promise.resolve({
      ok: r.status < 400, status: r.status,
      json: () => Promise.resolve(JSON.parse(r.text)),
      text: () => Promise.resolve(r.text),
    });
  };
}

function boot(sessionSeed, activeCase) {
  let html = fs.readFileSync(PAGE, 'utf8');
  // inline the vendor scripts (no network in this harness), drop stylesheets
  html = html.replace(/<script src="([^"]+)"><\/script>/g, (m, src) => {
    src = src.split('?')[0];
    const f = path.join(DIR, src);
    return fs.existsSync(f) ? `<script>${fs.readFileSync(f, 'utf8')}</script>` : '';
  }).replace(/<link[^>]+stylesheet[^>]*>/g, '');
  const vc = new VirtualConsole();
  vc.on('jsdomError', e => console.error('PAGE ERROR:', e.message));
  const dom = new JSDOM(html, {
    url: 'http://localhost/cases.html?embed=1&view=analysis',
    runScripts: 'dangerously', pretendToBeVisual: true, virtualConsole: vc,
    beforeParse(win) {
      win.fetch = makeFetch(win);
      win.scrollTo = () => {};
      if (sessionSeed) for (const [k, v] of Object.entries(sessionSeed)) win.sessionStorage.setItem(k, v);
      if (activeCase) win.localStorage.setItem('activeCaseId', activeCase);
    },
  });
  return dom;
}

const sleep = ms => new Promise(r => setTimeout(r, ms));
const dumpSession = win => Object.fromEntries(
  Object.keys(win.sessionStorage).map(k => [k, win.sessionStorage.getItem(k)]));

(async () => {
  const failures = [];
  const check = (ok, why) => { if (!ok) failures.push(why); console.log((ok ? '  ok   ' : '  FAIL ') + why); };

  // a throwaway case, so nothing of the operator's is touched
  const name = 'tw-probe-' + Date.now();
  const cid = JSON.parse(call('POST', '/api/cases', { name }).text).case_id;
  console.log('probe case:', cid, name);
  const stored = () => JSON.parse(call('GET', '/api/cases/' + cid).text).time_window;
  console.log('window as created:', JSON.stringify(stored()));

  try {
    let dom = boot(null, cid);
    let win = dom.window;
    await new Promise(r => win.addEventListener('load', r));
    if (process.env.TRACE) {
      const sc = win.showCase;
      win.showCase = (id, info, rep) => { console.log('   showCase', id, JSON.stringify(info && info.time_window)); return sc(id, info, rep); };
      const st = win.setTab;
      win.setTab = (t) => { console.log('   setTab', t); return st(t); };
    }
    await sleep(2000);
    win.setTab('config');
    await sleep(800);

    const $ = s => win.document.querySelector(s);
    check(!!$('#cf-start'), 'the Configuration rail is on screen');
    console.log('rail shows:', $('#cf-start') && $('#cf-start').value, '->', $('#cf-end') && $('#cf-end').value);
    check($('#cf-start').value === stored().start,
      `rail start matches the stored one (rail=${$('#cf-start') && $('#cf-start').value} stored=${stored().start})`);

    // the operator picks a new start IN THE CALENDAR — flatpickr's own path
    const TYPED = '2021-03-04T05:00:00';
    const el = $('#cf-start');
    check(!!el._flatpickr, 'the date picker is attached to the start box');
    el._flatpickr.setDate(TYPED, true);          // true = fire onChange, as a click does
    await sleep(200);
    check($('#cf-start').value === TYPED, `the picker put the date in the box (${$('#cf-start').value})`);

    // the 5s report poll lands twice while the edit is unsaved
    win.openCase(cid); await sleep(1200);
    win.openCase(cid); await sleep(1200);
    check($('#cf-start') && $('#cf-start').value === TYPED,
      `the edit survives two background refreshes (${$('#cf-start') && $('#cf-start').value})`);
    check($('#cf-start').value === TYPED, `the typed value stays in the box (${$('#cf-start').value})`);

    // press Refusion
    netlog.length = 0;
    win.doRefusion(cid);
    await sleep(4000);
    const posted = netlog.find(c => c.p.endsWith('/rescan'));
    console.log('POSTed:', posted && JSON.stringify(posted.body && posted.body.time_window));
    check(posted && posted.body.time_window.start === TYPED,
      `Refusion posts the operator's start (sent ${posted && posted.body.time_window.start})`);
    check(stored().start === TYPED, `the backend stored it (${stored().start})`);
    // the scope line under the case name must name the new start too — it is
    // drawn by render(), which does not run again until the whole fuse ends
    const since = win.document.querySelector('#case-since');
    console.log('scope line:', since && since.textContent);
    check(since && since.textContent === 'since ' + TYPED,
      `the scope line follows the save (${since && since.textContent})`);

    // a Refusion switches to the Log to show progress; back to Configuration
    win.setTab('config'); await sleep(1000);
    console.log('rail after Refusion -> Log -> Configuration:', $('#cf-start') && $('#cf-start').value);
    check($('#cf-start') && $('#cf-start').value === TYPED,
      `the window survives Refusion + the Log round-trip (${$('#cf-start') && $('#cf-start').value})`);

    // reload the page, carrying sessionStorage over, as a browser refresh does
    const seed = dumpSession(win);
    dom.window.close();
    dom = boot(seed, cid); win = dom.window;
    await new Promise(r => win.addEventListener('load', r));
    await sleep(2500);
    win.setTab('config');
    await sleep(800);
    const after = win.document.querySelector('#cf-start');
    console.log('rail after reload:', after && after.value);
    check(after && after.value === TYPED,
      `the window survives a page refresh (${after && after.value})`);

    // ...and the same for EVERY other setting in the rail, because they all
    // round-trip through the same three places (POST -> case payload -> render)
    // and the window is only the one that got reported.
    const EDITS = {
      'cf-start': '2019-07-08T09:10:00', 'cf-end': '2024-11-12T13:14:00',
      'cf-sev': 'high', 'cf-maxent': '250000', 'cf-maxident': '1200',
      'cf-alt': 'macro', 'cf-tlp': 'RED', 'cf-cust': 'Acme Corp',
      'cf-maskpat': 'secretproject', 'cf-mp': 'focus on lateral movement',
    };
    const q = s => win.document.querySelector(s);
    for (const [id, v] of Object.entries(EDITS)) {
      const e = q('#' + id);
      if (!e) { check(false, `${id} is on the rail`); continue; }
      if (e._flatpickr) e._flatpickr.setDate(v, true);
      else { e.value = v; e.dispatchEvent(new win.Event('change', { bubbles: true })); }
    }
    for (const [id, v] of Object.entries(TOGGLES)) {
      const e = q('#' + id);
      if (!e) { check(false, `${id} is on the rail`); continue; }
      e.checked = v; e.dispatchEvent(new win.Event('change', { bubbles: true }));
    }
    win.doRefusion(cid);
    await sleep(5000);

    const seed2 = dumpSession(win);
    dom.window.close();
    dom = boot(seed2, cid); win = dom.window;
    await new Promise(r => win.addEventListener('load', r));
    await sleep(2500);
    win.setTab('config');
    await sleep(1200);
    const q2 = s => win.document.querySelector(s);
    for (const [id, v] of Object.entries(EDITS)) {
      const e = q2('#' + id);
      check(e && e.value === v, `${id} reads back as set after a refresh (want ${v}, got ${e ? e.value : '(absent)'})`);
    }
    for (const [id, v] of Object.entries(TOGGLES)) {
      const e = q2('#' + id);
      check(e && e.checked === v, `${id} reads back as set after a refresh (want ${v}, got ${e ? e.checked : '(absent)'})`);
    }
    dom.window.close();
  } finally {
    call('DELETE', '/api/cases/' + cid);
    console.log('probe case deleted');
  }

  if (failures.length) { console.error('\nFAIL (' + failures.length + ')'); process.exit(1); }
  console.log('\nall good');
})();
