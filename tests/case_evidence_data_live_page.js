// Evidence and External data on the REAL page against a LIVE appliance, on a
// throwaway case it creates and deletes: add, list apart, edit on either tab,
// facts, Use in analysis, the report's two sections, download, delete.
//   node tests/case_evidence_data_live_page.js <path to cases.html>
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

// multipart uploads go through curl inside the container (the JSON relay cannot)
function upload(cid, local, fields) {
  const remote = '/tmp/evdt_' + path.basename(local);
  execFileSync('docker', ['cp', local, CONTAINER + ':' + remote]);
  const args = ['exec', CONTAINER, 'curl', '-s', '-X', 'POST', `http://127.0.0.1:5001/api/cases/${cid}/files`,
    '-F', 'file=@' + remote];
  for (const [k, v] of Object.entries(fields)) args.push('-F', `${k}=${v}`);
  return JSON.parse(execFileSync('docker', args, { encoding: 'utf8' }));
}

(async () => {
  const failures = [];
  const check = (ok, why) => { if (!ok) failures.push(why); console.log((ok ? '  ok   ' : '  FAIL ') + why); };
  const tmp = fs.mkdtempSync(path.join(require('os').tmpdir(), 'evdt-'));
  const w = (n, b) => { const p = path.join(tmp, n); fs.writeFileSync(p, b); return p; };
  // a 1x1 PNG, a mail, a small EDR export and a short customer chat -- all synthetic
  const png = w('popup.png', Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==', 'base64'));
  const eml = w('mail.eml', 'From: it@acme.example\nSubject: odd prompt\n\nA user saw a prompt on WS01.\n');
  const csv = w('edr.csv', 'Timestamp,DeviceName,AccountName,FileName,ProcessCommandLine,RemoteIP,Severity,Title\n'
    + '2026-10-01T10:05:00Z,WS01,jdoe,mimi.exe,mimi.exe sekurlsa::logonpasswords,185.220.101.4,High,Credential dumping\n');
  const chat = w('chat.txt', '[09:12] Dana: payroll has been down since 08:30 on Oct 3\n'
    + '[09:20] Ron: our IT guy reimaged WS01 on Oct 3 at 10:00 before calling you\n');

  const cid = JSON.parse(call('POST', '/api/cases', { name: 'evdt-probe-' + Date.now() }).text).case_id;
  console.log('probe case:', cid);
  try {
    const pic = upload(cid, png, { name: 'Popup', description: 'the prompt on screen', source: 'other', source_other: 'customer' });
    const mail = upload(cid, eml, { name: 'IT mail', description: 'what IT saw', source: 'other', source_other: 'e-mail' });
    const log = upload(cid, csv, { name: 'EDR export', description: 'Defender CSV', data_type: 'edr' });
    const notes = upload(cid, chat, { name: 'Call with IT', description: 'Teams chat', data_type: 'notes' });
    check(!pic.data_type && !mail.data_type && log.data_type === 'edr' && notes.data_type === 'notes', 'four files added');
    const info = () => JSON.parse(call('GET', '/api/cases/' + cid).text);
    for (let i = 0; i < 60; i++) {                        // the log and the notes are read in the background
      const fs_ = info().case_files || [];
      if (fs_.filter(x => x.data_type).every(x => x.log && ['completed', 'failed'].includes(x.log.status))) break;
      await sleep(2000);
    }
    const byId = id => (info().case_files || []).find(x => x.id === id);
    check(byId(log.id).log.status === 'completed' && byId(log.id).log.alerts >= 1, 'the EDR export was read with its alert');
    check(byId(notes.id).log.status === 'completed', `the notes were read (${byId(notes.id).log.facts} fact(s))`);

    const dom = boot(null, cid), win = dom.window;
    win.confirm = () => true;
    await new Promise(r => win.addEventListener('load', r));
    await sleep(2500);
    const tabc = () => win.document.querySelector('#tabc').innerHTML;
    const tabEl = win.document.querySelector('[data-tab="data"]');
    check(tabEl && tabEl.textContent === 'External data', 'the tab is called External data');

    // ---- Evidence
    win.setTab('evidence'); await sleep(1500);
    let page = tabc();
    check(page.includes('<b>Popup</b>') && page.includes('<b>IT mail</b>'), 'Evidence lists the two evidence items');
    check(!page.includes('<b>EDR export</b>') && !page.includes('<b>Call with IT</b>'), 'Evidence lists no external data');
    check(page.includes(`/files/${pic.id}?inline=1`), 'the picture shows as a thumbnail');
    check(page.includes('2 item(s)'), 'the Evidence count is evidence only');
    win.evEditToggle(pic.id); await sleep(300);
    win.document.getElementById('eve-desc').value = 'the prompt, edited';
    win.document.getElementById('eve-srcother').value = 'customer';
    win.evSaveEdit(pic.id); await sleep(2000);
    check(byId(pic.id).description === 'the prompt, edited', 'an evidence edit is saved');
    check(win.eval('tab') === 'evidence' && tabc().includes('the prompt, edited'), 'and the Evidence tab shows it');

    // ---- External data
    win.setTab('data'); await sleep(1500);
    page = tabc();
    check(page.includes('<b>EDR export</b>') && page.includes('<b>Call with IT</b>'), 'External data lists both files');
    check(!page.includes('<b>Popup</b>'), 'External data lists no evidence');
    check(page.includes('Log data · EDR alerts') && page.includes('Incident notes</span>'), 'each labelled by kind');
    win.evEditToggle(log.id); await sleep(300);
    check(tabc().includes('<b>EDR export</b>') && !tabc().includes('<b>Popup</b>'),
      'edit on External data stays on External data');
    win.document.getElementById('eve-desc').value = 'Defender CSV, edited';
    win.document.getElementById('eve-srcother').value = 'Defender';
    win.evSaveEdit(log.id); await sleep(2000);
    check(byId(log.id).description === 'Defender CSV, edited', 'an external-data edit is saved');
    check(tabc().includes('Defender CSV, edited') && !tabc().includes('<b>Popup</b>'), 'and External data shows it');
    if (byId(notes.id).log.facts) {
      win.dtFacts(notes.id); await sleep(2500);
      check(tabc().includes('What the customer did') || tabc().includes('Impact'), 'the notes show their facts');
    }
    win.evUseInAnalysis(log.id, false); await sleep(1500);
    check(byId(log.id).ai === false, 'Use in analysis switched off');

    // ---- Report
    win.evToggleInclude(cid, true); await sleep(1500);
    check(info().include_evidence === true, 'Include evidence in the report switched on');
    const rep = JSON.parse(call('POST', '/api/cases/' + cid + '/report', { use_llm: false }).text);
    const md = rep.report_md || rep.report || JSON.parse(call('GET', '/api/cases/' + cid + '/report').text).report_md || '';
    const evSec = md.slice(md.indexOf('## Evidence attached'));
    const dataSec = md.indexOf('## External data') >= 0 ? md.slice(md.indexOf('## External data'), md.indexOf('## Evidence attached')) : '';
    check(md.includes('## Evidence attached') && evSec.includes('**Popup**') && evSec.includes(`](evidence:${pic.id})`),
      'the report lists the evidence with its picture');
    check(!evSec.includes('EDR export') && !evSec.includes('Call with IT'), 'the evidence section holds no external data');
    check(dataSec.includes('**Call with IT**') && !dataSec.includes('**EDR export**'),
      'External data lists the notes, not the switched-off export');
    win.evToggleInclude(cid, false); await sleep(1500);
    const md2 = JSON.parse(call('POST', '/api/cases/' + cid + '/report', { use_llm: false }).text);
    const m2 = md2.report_md || JSON.parse(call('GET', '/api/cases/' + cid + '/report').text).report_md || '';
    check(!m2.includes('## Evidence attached') && m2.includes('## External data'),
      'evidence switched off: its section goes, External data stays');

    // ---- Files and delete
    check(call('GET', `/api/cases/${cid}/files/${mail.id}`).status === 200, 'evidence downloads');
    check(call('GET', `/api/cases/${cid}/files/${pic.id}?inline=1`).status === 200, 'the picture opens inline');
    win.setTab('evidence'); await sleep(800);
    win.evDel(mail.id); await sleep(2000);
    check(!byId(mail.id) && !tabc().includes('<b>IT mail</b>'), 'evidence deleted');
    win.setTab('data'); await sleep(800);
    win.evDel(log.id); await sleep(2000);
    check(!byId(log.id) && !tabc().includes('<b>EDR export</b>'), 'external data deleted');
  } finally {
    const del = call('DELETE', '/api/cases/' + cid);
    console.log('probe case deleted:', del.status);
  }
  console.log(failures.length ? `FAILED: ${failures.length}` : 'ALL OK');
  process.exit(failures.length ? 1 : 0);
})();
