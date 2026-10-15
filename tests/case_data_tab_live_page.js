// The Data tab on the REAL page against a LIVE appliance: data (log imports,
// incident notes) apart from evidence, and a notes file's facts on demand.
// Read-only: it switches tabs and loads facts, nothing on the case changes.
//   node tests/case_data_tab_live_page.js <path to cases.html> <case id>
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
const CASE = process.argv[3];

(async () => {
  const failures = [];
  const check = (ok, why) => { if (!ok) failures.push(why); console.log((ok ? '  ok   ' : '  FAIL ') + why); };
  const dom = boot(null, CASE), win = dom.window;
  await new Promise(r => win.addEventListener('load', r));
  await sleep(2500);
  const tabc = () => win.document.querySelector('#tabc').innerHTML;
  const files = JSON.parse(call('GET', '/api/cases/' + CASE).text).case_files || [];
  const data = files.filter(x => x.data_type), ev = files.filter(x => !x.data_type);
  const notes = data.find(x => x.data_type === 'notes');
  check(!!win.document.querySelector('[data-tab="data"]'), 'the Data tab is on the page');

  win.setTab('data'); await sleep(1500);
  let page = tabc();
  check(data.every(x => page.includes(x.name)), `the Data tab lists all ${data.length} data file(s)`);
  check(ev.every(x => !page.includes('<b>' + x.name + '</b>')), 'no evidence on the Data tab');
  check(!notes || page.includes('Incident notes</span>'), 'notes are labelled Incident notes');
  check(!notes || /fact\(s\)<\/b> from \d+ line/.test(page), 'notes show their fact count');

  if (notes) {
    win.dtFacts(notes.id); await sleep(2500);
    page = tabc();
    check(page.includes('What the customer did'), 'show facts: grouped by kind');
    check(/line \d+(, \d+)*/.test(page), 'show facts: each with its line');
  }

  win.setTab('evidence'); await sleep(1500);
  page = tabc();
  check(data.every(x => !page.includes('<b>' + x.name + '</b>')), 'no data on the Evidence tab');
  check(page.includes('add them on the'), 'the Evidence tab points to Data');

  console.log(failures.length ? `FAILED: ${failures.length}` : 'ALL OK');
  process.exit(failures.length ? 1 : 0);
})();
