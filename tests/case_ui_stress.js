// Every tab, every state, every payload shape — EXECUTED, not read.
//
// Two bugs in one day got through static tests and died on first execution: a
// renderer that threw ReferenceError on every draw while a report generated, and
// deferred writes painting a stale tab over a newer one. Both were invisible to
// checks that only read the file. So this drives the REAL page in a real DOM
// against a REAL backend and tries to break it:
//
//   A  every tab, in every order — content must match the underline
//   B  every ordered PAIR of tabs, with the first one's response slowed —
//      a late answer must never paint over the tab now on screen
//   C  the case payload mutilated field by field (missing, null, NaN, wrong
//      type) — every tab must still draw
//   D  the same, with a report generating, which is the state that hid the
//      ReferenceError
//
// drawTab catches a throwing renderer and writes "could not be drawn", so ANY
// renderer that throws is detectable from the outside: that string on screen is
// a failure here.
//
//   node tests/case_ui_stress.js <cases.html> <case id>
const fs = require('fs'), path = require('path');
const { execFileSync } = require('child_process');
const { JSDOM, VirtualConsole } = require('jsdom');

const PAGE = process.argv[2], CID = process.argv[3];
const DIR = path.dirname(PAGE), CONTAINER = process.env.INTACT_BACKEND || 'intact_backend';
const TABS = ['report', 'chat', 'timeline', 'identities', 'risk', 'config', 'log'];

function call(method, p, body) {
  const env = { ...process.env, M: method, P: p, BODY: body ? JSON.stringify(body) : '' };
  const out = execFileSync('docker', ['exec', '-i', '-e', 'M', '-e', 'P', '-e', 'BODY',
    CONTAINER, 'python3', '/tmp/api_call.py'],
    { env, encoding: 'utf8', maxBuffer: 256 * 1024 * 1024 });
  return JSON.parse(out.slice(out.indexOf('{')));
}

// One real fetch of every endpoint the page uses, replayed from memory — so the
// fuzzing below is fast and the appliance is hit once, not thousands of times.
const cache = new Map();
function cached(p) {
  if (!cache.has(p)) cache.set(p, call('GET', p, null));
  return cache.get(p);
}

const html = fs.readFileSync(PAGE, 'utf8')
  .replace(/<script src="([^"]+)"><\/script>/g, (m, src) => {
    const f = path.join(DIR, src.split('?')[0]);
    return fs.existsSync(f) ? `<script>${fs.readFileSync(f, 'utf8')}</script>` : '';
  }).replace(/<link[^>]+stylesheet[^>]*>/g, '');

function boot({ mutate = null, slow = null } = {}) {
  const errors = [];
  const vc = new VirtualConsole();
  vc.on('jsdomError', e => errors.push(String(e.message).split('\n')[0]));
  const dom = new JSDOM(html, {
    url: 'http://localhost/cases.html?embed=1&view=analysis',
    runScripts: 'dangerously', pretendToBeVisual: true, virtualConsole: vc,
    beforeParse(win) {
      win.localStorage.setItem('activeCaseId', CID);
      win.scrollTo = () => {};
      win.fetch = (p, opt) => {
        const method = (opt && opt.method) || 'GET';
        if (method !== 'GET') return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve({}) });
        const r = cached(p);
        const res = {
          ok: r.status < 400, status: r.status, text: () => Promise.resolve(r.text),
          json: () => { let j = JSON.parse(r.text); if (mutate) j = mutate(p, j) ?? j; return Promise.resolve(j); },
        };
        if (slow && slow.test(p)) return new Promise(z => setTimeout(() => z(res), 2000));
        return Promise.resolve(res);
      };
    },
  });
  return { dom, win: dom.window, errors };
}

const sleep = ms => new Promise(r => setTimeout(r, ms));
const failures = [];
const fail = why => { failures.push(why); console.log('  FAIL  ' + why); };

function inspect(win) {
  const box = win.document.querySelector('#tabc');
  const on = [...win.document.querySelectorAll('.tabs .tab')]
             .filter(e => e.classList.contains('on')).map(e => e.dataset.tab);
  return { html: (box && box.innerHTML) || '', stamped: box && box.dataset.tab,
           underline: on.join(','), broken: /could not be drawn/.test((box && box.innerHTML) || '') };
}

(async () => {
  // ---- A: every tab draws, and matches its underline ----------------------
  console.log('A. every tab draws');
  {
    const { dom, win, errors } = boot();
    await new Promise(r => win.addEventListener('load', r));
    await sleep(2500);
    for (const t of TABS) {
      win.setTab(t);
      await sleep(1200);
      const s = inspect(win);
      if (s.broken) fail(`tab "${t}" could not be drawn`);
      else if (!s.html) fail(`tab "${t}" drew nothing`);
      if (s.underline !== t) fail(`tab "${t}": underline says "${s.underline}"`);
      if (s.stamped && s.stamped !== t) fail(`tab "${t}": #tabc is showing "${s.stamped}"`);
    }
    if (errors.length) fail(`uncaught page errors: ${[...new Set(errors)].join(' | ')}`);
    win.close();
  }

  // ---- B: a slow tab must not paint over the next one ---------------------
  console.log('B. slow tab, then switch away');
  for (const [first, slow] of [['identities', /\/identities$/], ['risk', /\/risk$/],
                               ['timeline', /\/timeline$/]]) {
    const { win, errors } = boot({ slow });
    await new Promise(r => win.addEventListener('load', r));
    await sleep(2500);
    for (const second of TABS.filter(t => t !== first)) {
      win.setTab(first);
      await sleep(150);                 // leave before the slow call answers
      win.setTab(second);
      await sleep(2600);                // the slow answer lands in here
      const s = inspect(win);
      if (s.stamped && s.stamped !== second)
        fail(`${first} -> ${second}: the ${s.stamped} response painted over ${second}`);
      if (s.broken) fail(`${first} -> ${second}: "${second}" could not be drawn`);
    }
    if (errors.length) fail(`uncaught page errors (slow ${first}): ${[...new Set(errors)].join(' | ')}`);
    win.close();
  }

  // ---- C/D: mutilate the case payload, with and without a generation ------
  const FIELDS = ['time_window', 'counts', 'min_severity', 'masking', 'max_entities',
                  'max_identities', 'fusion_modules', 'report_altitude', 'llm_status',
                  'report_phase', 'report_generating_elapsed_s', 'report_phase_elapsed_s',
                  'fused_at', 'report_written_at', 'dispositions', 'token_ab',
                  'cost_estimate', 'modules_catalog', 'name', 'stale_run_ids'];
  const BREAK = { 'missing': undefined, 'null': null, 'NaN': NaN,
                  'wrong type': '### not what you expected ###' };
  for (const generating of [false, true]) {
    console.log(`${generating ? 'D' : 'C'}. mutilated payload${generating ? ', report generating' : ''}`);
    for (const field of FIELDS) {
      for (const [label, value] of Object.entries(BREAK)) {
        const mutate = (p, j) => {
          if (!/\/api\/cases\/[^/]+$/.test(p)) return j;
          if (value === undefined) delete j[field]; else j[field] = value;
          if (generating) { j.report_generating = true; j.report_phase = j.report_phase || 'narrative'; }
          return j;
        };
        const { win, errors } = boot({ mutate });
        await new Promise(r => win.addEventListener('load', r));
        await sleep(1500);
        for (const t of TABS) {
          win.setTab(t);
          await sleep(250);
          const s = inspect(win);
          if (s.broken) fail(`${field} ${label}${generating ? ' + generating' : ''}: tab "${t}" could not be drawn`);
        }
        if (errors.length)
          fail(`${field} ${label}${generating ? ' + generating' : ''}: ${[...new Set(errors)][0]}`);
        win.close();
      }
    }
  }

  console.log();
  if (failures.length) { console.error(`FAIL — ${failures.length} problem(s)`); process.exit(1); }
  console.log(`no failures: ${TABS.length} tabs × ${FIELDS.length} fields × ${Object.keys(BREAK).length} breakages, `
              + `with and without a generation, plus every slow-tab switch`);
})();
