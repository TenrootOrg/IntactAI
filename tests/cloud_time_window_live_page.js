// AWS + Azure scan pages, driven for real: the partials' markup, the vendored flatpickr,
// js/components/cloud-datepickers.js and Alpine, with GETs relayed to the live backend.
// "Start scan" is intercepted (nothing starts): this checks what the page SENDS.
// Built when both pages moved to the Case Analysis-style time window (2026-10-26) --
// before, the picker sent {type, value}, which no backend reader understood.
//   NODE_PATH=<dir with jsdom@24>/node_modules node tests/cloud_time_window_live_page.js modules/nginx/html
const fs = require('fs'), path = require('path');
const { execFileSync } = require('child_process');
const { JSDOM, VirtualConsole } = require('jsdom');
const HTML = process.argv[2];
const relay = `import json, os, sys, urllib.request, urllib.error
req = urllib.request.Request("http://127.0.0.1:5001" + os.environ["P"])
try:
    r = urllib.request.urlopen(req, timeout=60); out, code = r.read(), r.status
except urllib.error.HTTPError as e:
    out, code = e.read(), e.code
sys.stdout.write(json.dumps({"status": code, "text": out.decode("utf-8", "replace")}))`;
fs.writeFileSync('/tmp/cloud_tw_relay.py', relay);
execFileSync('docker', ['cp', '/tmp/cloud_tw_relay.py', 'intact_backend:/tmp/cloud_tw_relay.py']);
const get = p => {
  const out = execFileSync('docker', ['exec', '-e', 'P=' + p, 'intact_backend', 'python3', '/tmp/cloud_tw_relay.py'],
                           { encoding: 'utf8', maxBuffer: 64 << 20 });
  return JSON.parse(out.slice(out.indexOf('{')));
};

const errors = [], sent = [], alerts = [];
const vc = new VirtualConsole();
vc.on('error', e => errors.push(String(e && e.message || e)));
vc.on('jsdomError', e => errors.push('jsdom: ' + e.message));
const part = n => fs.readFileSync(path.join(HTML, 'partials', n + '.html'), 'utf8');
const dom = new JSDOM(`<!doctype html><body>${part('aws')}${part('azure')}</body>`,
                      { runScripts: 'outside-only', pretendToBeVisual: true, virtualConsole: vc, url: 'https://intact.local/' });
const w = dom.window;
w.fetch = async (p, opt) => {
  const method = (opt && opt.method) || 'GET';
  if (method !== 'GET') {
    sent.push({ path: p, body: JSON.parse(opt.body || '{}') });
    return { ok: true, status: 200, json: async () => ({ run_id: 'test_run' }) };
  }
  const r = get(p);
  return { ok: r.status < 400, status: r.status, json: async () => JSON.parse(r.text), text: async () => r.text };
};
w.alert = m => alerts.push(String(m));
w.confirm = () => false;
w.document.addEventListener('alpine:init', () => {
  w.Alpine.store('app', { currentTab: 'cloud-aws', switchTab(t) { this.currentTab = t; } });
});
for (const f of ['vendor/flatpickr/flatpickr.min.js', 'js/components/tab-reset.js',
                 'js/components/cloud-datepickers.js', 'js/alpine.min.js'])
  w.eval(fs.readFileSync(path.join(HTML, f), 'utf8'));

const sleep = ms => new Promise(r => setTimeout(r, ms));
const waitFor = async (fn, ms = 8000) => { const end = Date.now() + ms; while (Date.now() < end) { if (fn()) return true; await sleep(50); } return fn(); };
const $ = s => w.document.querySelector(s);
const fails = [];
const check = (ok, what) => { console.log((ok ? 'ok   ' : 'FAIL ') + what); if (!ok) fails.push(what); };
const button = label => [...w.document.querySelectorAll('button')].find(b => b.textContent.includes(label));
const utc = ms => new Date(ms).toISOString().slice(0, 16);

async function start(label) {
  const before = sent.length, a = alerts.length;
  const b = button(label);
  b.disabled = false;                       // Azure's button waits for live credentials
  b.click();
  await waitFor(() => sent.length > before || alerts.length > a, 3000);
  return { body: sent.length > before ? sent[sent.length - 1].body : null, alert: alerts.length > a ? alerts[alerts.length - 1] : null };
}

(async () => {
  await waitFor(() => w.Alpine && w.Alpine.store('app'));
  for (const [p, label, tab] of [['aws', 'Start AWS scan', 'cloud-aws'], ['azure', 'Start Microsoft 365 Scan', 'cloud-azure']]) {
    console.log(`--- ${p}`);
    w.Alpine.store('app').currentTab = tab;
    // Azure opens on "targeted", which needs a user or IP: pick tenant-wide, as an operator would.
    if (p === 'azure') { $('input[name="azure-scope"][value="tenant_wide"]').click(); await sleep(50); }
    const s = $(`#${p}-tw-start`), e = $(`#${p}-tw-end`);
    await waitFor(() => s && s._flatpickr && e._flatpickr);
    check(s && e, 'two fields: Time window — start / end');
    check(!!(s && s._flatpickr && e._flatpickr), 'both are flatpickr calendars');
    check(s._flatpickr.config.enableTime && s._flatpickr.config.time_24hr && s._flatpickr.config.minuteIncrement === 5
          && s._flatpickr.config.allowInput, 'same calendar options as Case Analysis (date + time, 24 h, 5 min, typing allowed)');
    check(!!s._flatpickr.calendarContainer.querySelector('.flatpickr-time'), 'the calendar shows the time inline');
    const now = Date.now();
    check(s.value.slice(0, 13) === utc(now - 24 * 3600e3).slice(0, 13), `start prefilled to 24 h ago (UTC): ${s.value}`);
    check(e.value === '', 'end empty = up to now');
    check(!w.document.body.textContent.includes('Custom range'), 'old preset dropdown gone');

    let r = await start(label);
    check(r.body && r.body.time_filter.mode === 'between' && r.body.time_filter.enabled === true
          && r.body.time_filter.start_datetime === s.value + 'Z' && r.body.time_filter.end_datetime === '',
          'default: sends the prefilled start and an open end: ' + JSON.stringify(r.body && r.body.time_filter));

    s._flatpickr.setDate('2026-10-19T00:00:00', true);
    e._flatpickr.setDate('2026-10-25T18:35:00', true);
    r = await start(label);
    check(r.body && r.body.time_filter.start_datetime === '2026-10-19T00:00:00Z'
          && r.body.time_filter.end_datetime === '2026-10-25T18:35:00Z',
          'picked in the calendar: ' + JSON.stringify(r.body && r.body.time_filter));

    s.value = '2026-10-20T08:15';
    e.value = '';
    r = await start(label);
    check(r.body && r.body.time_filter.start_datetime === '2026-10-20T08:15:00Z' && r.body.time_filter.end_datetime === '',
          'typed by hand (no seconds): ' + JSON.stringify(r.body && r.body.time_filter));

    s.value = '2026-10-25T10:00:00'; e.value = '2026-10-24T10:00:00';
    r = await start(label);
    check(!r.body && /after the start/.test(r.alert || ''), 'end before start: refused, nothing sent — ' + r.alert);

    s.value = ''; e.value = '';
    r = await start(label);
    check(!r.body && /start of the time window/.test(r.alert || ''), 'no start: refused — ' + r.alert);

    s.value = 'last week';
    r = await start(label);
    check(!r.body && /not a date and time/.test(r.alert || ''), 'not a date: refused — ' + r.alert);
  }
  const real = errors.filter(x => !/Could not parse CSS|Not implemented/.test(x));
  check(real.length === 0, 'no page errors' + (real.length ? ': ' + real.slice(0, 3).join(' | ') : ''));
  console.log(fails.length ? `${fails.length} FAILED` : 'ALL OK');
  process.exit(fails.length ? 1 : 0);
})();
