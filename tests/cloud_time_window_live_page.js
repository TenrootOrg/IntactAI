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

const errors = [], sent = [], alerts = [], saves = [];
// The regions the box keeps (PUT /api/aws/regions). Simulated here, so the test never
// changes the operator's real choice: undefined = whatever the live box says.
let boxRegions;
let boxTW = { hours: 720 };     // the saved AWS time window, simulated too (a month = the default)
const twSaves = [];
const part = n => fs.readFileSync(path.join(HTML, 'partials', n + '.html'), 'utf8');
function makePage(parts) {           // a fresh page load = a refresh
  const vc = new VirtualConsole();
  vc.on('error', e => errors.push(String(e && e.message || e)));
  vc.on('jsdomError', e => errors.push('jsdom: ' + e.message));
  const dom = new JSDOM(`<!doctype html><body>${parts.map(part).join('')}</body>`,
                        { runScripts: 'outside-only', pretendToBeVisual: true, virtualConsole: vc, url: 'https://intact.local/' });
  const w = dom.window;
  w.fetch = async (p, opt) => {
    const method = (opt && opt.method) || 'GET';
    if (method === 'PUT' && p === '/api/aws/time-window') {
      boxTW = JSON.parse(opt.body); twSaves.push(boxTW);
      return { ok: true, status: 200, json: async () => ({ time_window: boxTW }) };
    }
    if (method === 'PUT' && p === '/api/aws/regions') {
      boxRegions = JSON.parse(opt.body).regions; saves.push(boxRegions);
      return { ok: true, status: 200, json: async () => ({ regions: boxRegions }) };
    }
    if (method !== 'GET') {
      sent.push({ path: p, body: JSON.parse(opt.body || '{}') });
      return { ok: true, status: 200, json: async () => ({ run_id: 'test_run' }) };
    }
    const r = get(p);
    let text = r.text;
    if (p === '/api/aws/status') {
      const d = JSON.parse(text);
      if (boxRegions !== undefined) d.aws_credentials.regions = boxRegions;
      d.aws_credentials.time_window = boxTW;
      text = JSON.stringify(d);
    }
    return { ok: r.status < 400, status: r.status, json: async () => JSON.parse(text), text: async () => text };
  };
  w.alert = m => alerts.push(String(m));
  w.confirm = () => false;
  w.document.addEventListener('alpine:init', () => {
    w.Alpine.store('app', { currentTab: 'cloud-aws', switchTab(t) { this.currentTab = t; } });
  });
  for (const f of ['vendor/flatpickr/flatpickr.min.js', 'js/components/tab-reset.js',
                   'js/components/cloud-datepickers.js', 'js/alpine.min.js'])
    w.eval(fs.readFileSync(path.join(HTML, f), 'utf8'));
  return w;
}
const w = makePage(['aws', 'azure']);

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
    const defH = p === 'aws' ? 720 : 24;     // AWS: a month until changed; Azure: 24 h
    await waitFor(() => s.value.slice(0, 13) === utc(now - defH * 3600e3).slice(0, 13), 3000);
    check(s.value.slice(0, 13) === utc(now - defH * 3600e3).slice(0, 13), `start prefilled to ${defH} h ago (UTC): ${s.value}`);
    check(e.value === '', 'end empty = up to now');
    check(!w.document.body.textContent.includes('Custom range'), 'old preset dropdown gone');
    if (p === 'aws') {
      // Regions: a multi-select dropdown on this page only, remembered on the box (Settings has none).
      const want = JSON.parse(get('/api/aws/status').text).aws_credentials.regions || [];
      const dd = $('#aws-regions-dd'), chips = () => [...dd.querySelectorAll('span.inline-flex > span')].map(x => x.textContent);
      await waitFor(() => JSON.stringify(chips()) === JSON.stringify(want));
      check(want.length && JSON.stringify(chips()) === JSON.stringify(want), `opens with the regions remembered on the box: ${chips()}`);
      check(!dd.querySelector('input[type="text"]'), 'no text box to type regions into');
      const menu = dd.querySelector('[role="listbox"]');
      check(menu.style.display === 'none', 'dropdown closed until clicked');
      dd.querySelector('[role="button"]').click(); await sleep(50);
      check(menu.style.display !== 'none', 'click opens the dropdown');
      const boxes = [...menu.querySelectorAll('input[type="checkbox"]')];
      check(boxes.length >= 26, `${boxes.length} regions to choose from`);
      for (const r of ['eu-west-2', 'ap-southeast-2'])
        if (!chips().includes(r)) { boxes.find(x => x.value === r).click(); await sleep(30); }
      if (!chips().includes('us-east-1')) { boxes.find(x => x.value === 'us-east-1').click(); await sleep(30); }
      check(['eu-west-2', 'ap-southeast-2', 'us-east-1'].every(r => chips().includes(r)), 'several regions picked: ' + chips());
      const x = [...dd.querySelectorAll('button')].find(b => b.getAttribute('aria-label') === 'Remove ap-southeast-2');
      x.click(); await sleep(50);
      check(!chips().includes('ap-southeast-2') && !boxes.find(b => b.value === 'ap-southeast-2').checked, 'the × removes a region (and unticks it): ' + chips());
      const xb = [...dd.querySelectorAll('button')].find(b => b.getAttribute('aria-label') === 'Remove us-east-1');
      check(xb && xb.style.width === '24px' && xb.style.height === '24px', 'the × is a 24×24 click target');
      await waitFor(() => saves.length && JSON.stringify(saves[saves.length - 1]) === JSON.stringify(chips()));
      check(JSON.stringify(saves[saves.length - 1]) === JSON.stringify(chips()), 'every change is saved on the box at once: ' + JSON.stringify(saves[saves.length - 1]));
      // Alpine ignores an outside click on an element with no size, and jsdom has no layout
      // (every offsetWidth is 0): give the dropdown the size a browser would.
      Object.defineProperty(dd, 'offsetWidth', { get: () => 400 });
      w.document.body.click();
      await waitFor(() => menu.style.display === 'none', 2000);   // x-transition: closes after its animation
      check(menu.style.display === 'none', 'a click outside closes the dropdown');
      const picked = chips();
      w.dispatchEvent(new w.CustomEvent('automation-tab-entered', { detail: 'cloud-aws' }));   // leave and come back
      await sleep(100);
      check(JSON.stringify(chips()) === JSON.stringify(picked), 'a tab switch keeps the picked regions: ' + chips());
      const r0 = await start(label);
      check(r0.body && JSON.stringify([...r0.body.regions].sort()) === JSON.stringify([...picked].sort()), 'the scan sends them: ' + JSON.stringify(r0.body && r0.body.regions));
      for (const r of chips()) { [...dd.querySelectorAll('button')].find(b => b.getAttribute('aria-label') === 'Remove ' + r).click(); await sleep(20); }
      check(chips().length === 0 && /Select regions/.test(dd.textContent), 'all removed: shows "Select regions…"');
      await waitFor(() => JSON.stringify(saves[saves.length - 1]) === '[]');
      check(JSON.stringify(saves[saves.length - 1]) === '[]', 'removing all is saved too: ' + JSON.stringify(saves[saves.length - 1]));
      // Refresh: a new page load must show what was left -- nothing -- not the old regions.
      const w2 = makePage(['aws']);
      await waitFor(() => w2.Alpine && w2.Alpine.$data && w2.document.querySelector('#aws-regions-dd') &&
                          w2.Alpine.$data(w2.document.querySelector('[data-automation-tab="cloud-aws"]')).awsRegionsLoaded);
      const dd2 = w2.document.querySelector('#aws-regions-dd');
      check(dd2.querySelectorAll('span.inline-flex').length === 0 && /Select regions/.test(dd2.textContent),
            'after a refresh the removed regions stay removed');
      boxRegions = ['eu-west-2', 'us-west-2'];
      const w3 = makePage(['aws']);
      await waitFor(() => w3.document.querySelectorAll('#aws-regions-dd span.inline-flex').length === 2);
      check([...w3.document.querySelectorAll('#aws-regions-dd span.inline-flex > span')].map(x => x.textContent).join() === 'eu-west-2,us-west-2',
            'after a refresh the page shows exactly the saved regions');

      const r1 = await start(label);
      check(!r1.body && /at least one region/.test(r1.alert || ''), 'no region: refused — ' + r1.alert);

      w.Alpine.$data($('[data-automation-tab="cloud-aws"]')).awsRegions = [...want]; await sleep(50);   // (simulated save)
      // Picking a blueprint takes its CloudTrail mode, severity floor, time range and cap.
      const comp = w.Alpine.$data($('[data-automation-tab="cloud-aws"]'));
      const bpSel = $('select[x-model="awsBlueprint"]');
      await waitFor(() => bpSel && [...bpSel.options].some(o => o.value === 'aws_full_investigation'));
      bpSel.value = 'aws_full_investigation'; bpSel.dispatchEvent(new w.Event('change')); await sleep(100);
      const before = $('#aws-tw-start').value;
      check(comp.awsCloudTrailMode === 'full' && comp.awsMinSeverity === 'informational' && comp.awsMaxEventsPerRegion === '10000',
            `Full Investigation: mode ${comp.awsCloudTrailMode}, severity ${comp.awsMinSeverity}, cap ${comp.awsMaxEventsPerRegion}`);
      check($('#aws-tw-start').value === before, 'a blueprint leaves the time window alone: ' + $('#aws-tw-start').value);
      const rb = await start(label);
      check(rb.body && rb.body.blueprint === 'aws_full_investigation' && rb.body.cloudtrail_mode === 'full' &&
            rb.body.min_severity === 'informational' && rb.body.max_events_per_region === 10000,
            'the scan sends the blueprint\'s settings: ' + JSON.stringify(rb.body && {m: rb.body.cloudtrail_mode, s: rb.body.min_severity, c: rb.body.max_events_per_region}));
      bpSel.value = 'aws_quick_triage'; bpSel.dispatchEvent(new w.Event('change')); await sleep(100);
      check(comp.awsCloudTrailMode === 'light' && comp.awsMinSeverity === 'low' && $('#aws-tw-start').value === before,
            `back to Quick Triage: ${comp.awsCloudTrailMode} / ${comp.awsMinSeverity} / ${$('#aws-tw-start').value}`);
      check(twSaves.length === 0, 'opening the page and switching blueprints saved no window: ' + JSON.stringify(twSaves));
      // The operator changes the window: remembered, and a refresh shows it.
      $('#aws-tw-start')._flatpickr.setDate('2026-09-01T00:00:00', true);
      $('#aws-tw-end')._flatpickr.setDate('2026-10-01T12:00:00', true);
      await waitFor(() => twSaves.length && twSaves[twSaves.length - 1].end);
      check(JSON.stringify(boxTW) === JSON.stringify({ start: '2026-09-01T00:00:00', end: '2026-10-01T12:00:00' }),
            'a fixed window is saved as its dates: ' + JSON.stringify(boxTW));
      const wf = makePage(['aws']);
      await waitFor(() => wf.document.querySelector('#aws-tw-end') && wf.document.querySelector('#aws-tw-end').value === '2026-10-01T12:00:00');
      check(wf.document.querySelector('#aws-tw-start').value === '2026-09-01T00:00:00' &&
            wf.document.querySelector('#aws-tw-end').value === '2026-10-01T12:00:00', 'after a refresh the fixed window is back');
      $('#aws-tw-end')._flatpickr.clear(true);
      $('#aws-tw-start')._flatpickr.setDate('2025-09-01T10:49:00', true);
      await waitFor(() => twSaves.length && twSaves[twSaves.length - 1].start === '2025-09-01T10:49:00' && !twSaves[twSaves.length - 1].end);
      check(JSON.stringify(boxTW) === JSON.stringify({ start: '2025-09-01T10:49:00', end: '' }),
            'an open end is saved exactly as set (start kept, end = up to now): ' + JSON.stringify(boxTW));
      const wr = makePage(['aws']);
      await waitFor(() => wr.document.querySelector('#aws-tw-start') && wr.document.querySelector('#aws-tw-start').value === '2025-09-01T10:49:00');
      check(wr.document.querySelector('#aws-tw-start').value === '2025-09-01T10:49:00' && wr.document.querySelector('#aws-tw-end').value === '',
            'after a refresh the exact start is back: ' + wr.document.querySelector('#aws-tw-start').value);
      const txt = $('[data-automation-tab="cloud-aws"]').textContent;
      check(!/Custom SIGMA Rules|Upload rule/.test(txt), 'no Custom SIGMA Rules panel');
      check(!/Default region/.test(txt), 'no "Default region" from the old Settings field');
    }

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
