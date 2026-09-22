// The Scope row, in a REAL DOM, against a LIVE appliance.
//
// QA TASK-12679: "Analyze this scope" was a one-way door — it overwrote the
// macro report and left nothing to click. The way back is a row of chips above
// the report, so what has to hold is the chips being DRAWN from the case payload
// and a click actually switching the case. A fake-DOM harness cannot see either:
// the chips are built inside renderReport's innerHTML, and the click goes through
// the page's own fetch + openCase redraw.
//
// Works on a throwaway case it creates and deletes, so nothing of the operator's
// is touched. The case has no evidence, so its scopes are seeded through the same
// docker relay the other live harness uses — the page, the routes and the store
// are all real.
//
//   node tests/scope_chips_live_page.js <path to cases.html>
const fs = require('fs'), path = require('path');
const { execFileSync } = require('child_process');
const { JSDOM, VirtualConsole } = require('jsdom');

const PAGE = process.argv[2];
const DIR = path.dirname(PAGE);
const CONTAINER = process.env.INTACT_BACKEND || 'intact_backend';

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
  const out = execFileSync('docker', ['exec', '-i', '-e', 'M', '-e', 'P', '-e', 'BODY',
    CONTAINER, 'python3', '/tmp/api_call.py'], { env, encoding: 'utf8', maxBuffer: 1 << 28 });
  return JSON.parse(out.slice(out.indexOf('{')));
}

// Two saved scopes on a case with no evidence: what a zoomed case looks like,
// written through the store's own merge so the payload is built the real way.
function seedScopes(cid) {
  const py = `
import sys; sys.path.insert(0, '/app')
from services.fusion import store
store._merge_case_details(${JSON.stringify(cid)}, {
  "active_scope": "tf_1",
  "report_md": "PHASE REPORT BODY",
  "report_scopes": [
    {"id": "full", "label": "Full case", "window": {"start": "2016-01-01T00:00:00", "end": None},
     "excluded_hosts": [], "report_md": "MACRO REPORT BODY", "cached": False},
    {"id": "tf_1", "label": "Phase 1 \\u2014 Initial access",
     "window": {"start": "2026-06-16T00:00:00", "end": "2026-06-23T00:00:00"},
     "excluded_hosts": [], "report_md": "PHASE REPORT BODY", "cached": False}]})
print("seeded")
`;
  const out = execFileSync('docker', ['exec', '-i', CONTAINER, 'python3', '-c', py],
    { encoding: 'utf8' });
  if (!out.includes('seeded')) throw new Error('seed failed: ' + out);
}

function boot(activeCase) {
  let html = fs.readFileSync(PAGE, 'utf8');
  html = html.replace(/<script src="([^"]+)"><\/script>/g, (m, src) => {
    const f = path.join(DIR, src.split('?')[0]);
    return fs.existsSync(f) ? `<script>${fs.readFileSync(f, 'utf8')}</script>` : '';
  }).replace(/<link[^>]+stylesheet[^>]*>/g, '');
  const vc = new VirtualConsole();
  vc.on('jsdomError', e => console.error('PAGE ERROR:', e.message));
  return new JSDOM(html, {
    url: 'http://localhost/cases.html?embed=1&view=analysis',
    runScripts: 'dangerously', pretendToBeVisual: true, virtualConsole: vc,
    beforeParse(win) {
      win.fetch = (p, opt) => {
        const r = call((opt && opt.method) || 'GET', p, opt && opt.body ? JSON.parse(opt.body) : null);
        return Promise.resolve({ ok: r.status < 400, status: r.status,
          json: () => Promise.resolve(JSON.parse(r.text)), text: () => Promise.resolve(r.text) });
      };
      win.scrollTo = () => {};
      win.localStorage.setItem('activeCaseId', activeCase);
    },
  });
}

const sleep = ms => new Promise(r => setTimeout(r, ms));

(async () => {
  const failures = [];
  const check = (ok, why) => { if (!ok) failures.push(why); console.log((ok ? '  ok   ' : '  FAIL ') + why); };

  const cid = JSON.parse(call('POST', '/api/cases', { name: 'scope-probe-' + Date.now() }).text).case_id;
  console.log('probe case:', cid);
  try {
    seedScopes(cid);
    const dom = boot(cid), win = dom.window;
    await new Promise(r => win.addEventListener('load', r));
    await sleep(2500);
    win.setTab('report');
    await sleep(1200);

    const chips = () => [...win.document.querySelectorAll('.scopechip')];
    console.log('chips:', chips().map(c => c.textContent + (c.classList.contains('on') ? '*' : '')).join(' | '));
    check(chips().length === 2, `both saved scopes are on screen (${chips().length})`);
    check(chips().some(c => c.textContent.includes('Full case')),
      'the way back to the full case is one of them');
    const active = chips().filter(c => c.classList.contains('on'));
    check(active.length === 1 && active[0].textContent.includes('Phase 1'),
      `the scope on screen is marked active (${active.map(c => c.textContent)})`);
    check(win.document.querySelector('.md').textContent.includes('PHASE REPORT BODY'),
      'the active scope\'s report is what the tab shows');

    // the operator clicks "Full case"
    const back = chips().find(c => c.textContent.includes('Full case'));
    check(back.tagName === 'BUTTON', 'the inactive scope is clickable');
    back.click();
    await sleep(6000);
    const stored = JSON.parse(call('GET', '/api/cases/' + cid).text);
    check(stored.active_scope === 'full', `the click switched the case (${stored.active_scope})`);
    win.setTab('report'); await sleep(1500);
    console.log('chips after:', chips().map(c => c.textContent + (c.classList.contains('on') ? '*' : '')).join(' | '));
    check(win.document.querySelector('.md').textContent.includes('MACRO REPORT BODY'),
      'the full case report is back on screen');
    const nowOn = chips().filter(c => c.classList.contains('on'));
    check(nowOn.length === 1 && nowOn[0].textContent.includes('Full case'),
      `the active chip moved (${nowOn.map(c => c.textContent)})`);
    dom.window.close();
  } finally {
    call('DELETE', '/api/cases/' + cid);
    console.log('probe case deleted');
  }
  if (failures.length) { console.error('\nFAILED:\n - ' + failures.join('\n - ')); process.exit(1); }
  console.log('\nall checks passed');
})().catch(e => { console.error(e); process.exit(1); });
