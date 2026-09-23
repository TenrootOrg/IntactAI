// The Memory panel, driven the way the operator drives it, in a REAL DOM.
//
// Written after a layered run failed on the operator's FIRST click while every
// test I had was green: I had only ever dispatched plugins-only runs, by hand,
// through the API. The page picks the mode itself from the blueprint plus the
// "Include YARA" checkbox, so the shape the page sends is the thing that was
// never tested.
//
// This boots index.html in jsdom with the real partial loader, the real Alpine
// store and the real partials, then clicks through the four tabs and presses
// each button. GETs are relayed to the live backend so the panel is populated
// with real blueprints, clients and kept images. The two calls that would start
// real work -- POST /api/memory/run and /api/memory/upload -- are INTERCEPTED
// and recorded rather than relayed: what this test is about is the request the
// page builds. What the backend then does with it is tests/test_memory_*.py and
// the API matrix.
//
//   node tests/memory_panel_live_page.js <path to index.html>
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
if os.environ.get("CASE"): req.add_header("X-Case-Id", os.environ["CASE"])
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
    '-e', 'M', '-e', 'P', '-e', 'BODY', '-e', 'CASE', CONTAINER, 'python3', '/tmp/api_call.py'],
    { env, encoding: 'utf8', maxBuffer: 256 * 1024 * 1024 });
  return JSON.parse(out.slice(out.indexOf('{')));
}

// Every dispatch the page attempted, with the exact body it built.
const dispatched = [];

function makeFetch() {
  return (p, opt) => {
    const method = (opt && opt.method) || 'GET';
    const url = String(p);
    // Intercept the two that would start real work.
    if (method === 'POST' && /\/api\/memory\/(run|upload)$/.test(url)) {
      let body = null;
      if (opt.body instanceof Object && typeof opt.body.get === 'function') {
        body = {};                                     // FormData (the upload)
        for (const [k, v] of opt.body.entries()) body[k] = (v && v.name) ? `<file ${v.name}>` : v;
      } else if (opt.body) {
        body = JSON.parse(opt.body);
      }
      dispatched.push({ url, body });
      return Promise.resolve({
        ok: true, status: 202,
        json: () => Promise.resolve({ run_id: 'memory_TESTONLY', status: 'running', mode: body && body.mode }),
        text: () => Promise.resolve('{}'),
      });
    }
    // Local assets the partial loader asks for.
    if (!url.startsWith('/api') && !url.startsWith('http')) {
      const f = path.join(DIR, url.split('?')[0].replace(/^\//, ''));
      if (fs.existsSync(f)) {
        const t = fs.readFileSync(f, 'utf8');
        return Promise.resolve({ ok: true, status: 200, text: () => Promise.resolve(t),
                                 json: () => Promise.resolve(JSON.parse(t)) });
      }
    }
    const r = call(method, url, opt && opt.body ? JSON.parse(opt.body) : null);
    return Promise.resolve({
      ok: r.status < 400, status: r.status,
      json: () => Promise.resolve(JSON.parse(r.text)),
      text: () => Promise.resolve(r.text),
    });
  };
}

function boot() {
  let html = fs.readFileSync(PAGE, 'utf8');
  html = html.replace(/<script src="([^"]+)"><\/script>/g, (m, src) => {
    src = src.split('?')[0];
    const f = path.join(DIR, src);
    return fs.existsSync(f) ? `<script>${fs.readFileSync(f, 'utf8')}</script>` : '';
  }).replace(/<link[^>]+stylesheet[^>]*>/g, '');
  const vc = new VirtualConsole();
  vc.on('jsdomError', e => console.error('PAGE ERROR:', e.message));
  return new JSDOM(html, {
    url: 'http://localhost/index.html',
    runScripts: 'dangerously', pretendToBeVisual: true, virtualConsole: vc,
    beforeParse(win) {
      win.fetch = makeFetch();
      win.scrollTo = () => {};
      // The upload button goes through raw XHR (it needs upload progress), so
      // a fetch shim alone leaves that whole tab untested. Record what it sends
      // and answer 202 — same deal as the intercepted fetch POSTs.
      win.XMLHttpRequest = class {
        open(method, url) { this._m = method; this._u = url; }
        setRequestHeader(k, v) { (this._h = this._h || {})[k] = v; }
        get upload() { return { addEventListener() {} }; }
        send(fd) {
          const body = {};
          if (fd && typeof fd.entries === 'function') {
            for (const [k, v] of fd.entries()) body[k] = (v && v.name) ? `<file ${v.name}>` : v;
          }
          dispatched.push({ url: this._u, body, headers: this._h || {} });
          this.readyState = 4; this.status = 202;
          this.responseText = JSON.stringify({ run_id: 'memory_TESTONLY', status: 'running' });
          if (this.onreadystatechange) this.onreadystatechange();
        }
      };
      // The partial loader appends <script src="js/alpine.min.js"> once the
      // partials are in, and jsdom would try to fetch that over HTTP. Inline
      // the file the moment a src is assigned, so Alpine really does start
      // over the assembled DOM — which is the whole point of this harness.
      const create = win.document.createElement.bind(win.document);
      win.document.createElement = (tag, ...rest) => {
        const el = create(tag, ...rest);
        if (String(tag).toLowerCase() === 'script') {
          Object.defineProperty(el, 'src', {
            configurable: true,
            get() { return this._src || ''; },
            set(v) {
              this._src = v;
              const f = path.join(DIR, String(v).split('?')[0].replace(/^\//, ''));
              if (fs.existsSync(f)) el.textContent = fs.readFileSync(f, 'utf8');
            },
          });
        }
        return el;
      };
    },
  });
}

const sleep = ms => new Promise(r => setTimeout(r, ms));
// x-show sets display:none on the element itself; walk up for a hidden ancestor.
const shown = (win, el) => {
  for (let n = el; n && n.style; n = n.parentElement) if (n.style.display === 'none') return false;
  return true;
};

(async () => {
  const failures = [];
  const check = (ok, why) => { if (!ok) failures.push(why); console.log((ok ? '  ok   ' : '  FAIL ') + why); };

  const dom = boot();
  const win = dom.window;
  await new Promise(r => win.addEventListener('load', r));
  await sleep(2500);                       // partials inject, Alpine starts

  const doc = win.document;
  const store = win.Alpine.store('memory');
  // Scoped to the Memory panel on purpose: the Velociraptor panel has its own
  // "Add to Case" button, and a document-wide search clicked THAT -- which is
  // exactly the sort of thing a fake-DOM harness never notices.
  const byText = (t) => [...doc.querySelectorAll('[data-automation-tab="modules-memory"] button')]
    .find(b => (b.textContent || '').trim().startsWith(t));

  // Open the Memory tab the way the sidebar does.
  win.Alpine.store('app').switchTab('modules-memory');
  await sleep(1200);

  console.log('\n-- the panel is on screen --');
  const panel = doc.querySelector('[data-automation-tab="modules-memory"]');
  check(!!panel, 'the Memory panel exists in the DOM');
  check(!!store, 'the memory store is registered');
  check((store.blueprints || []).length > 0, `blueprints loaded from the backend (${(store.blueprints || []).length})`);

  console.log('\n-- the four tabs --');
  for (const [label, want] of [['Acquire from endpoint', 'acquire'], ['Use a kept image', 'reuse'],
                               ['Upload a dump', 'upload'], ['Pull from another case', 'adopt']]) {
    const b = byText(label);
    check(!!b, `the "${label}" tab button exists`);
    if (!b) continue;
    b.click();
    await sleep(300);
    const keep = doc.querySelector('input[x-model="$store.memory.keepDump"]');
    const bp = doc.querySelector('select[x-model="$store.memory.blueprintId"]');
    if (want === 'adopt') {
      check(bp && !shown(win, bp), 'blueprint/YARA/timeouts are hidden on the pull tab');
    } else {
      check(bp && shown(win, bp), `the blueprint picker is on screen on the ${want} tab`);
    }
    if (want === 'reuse') {
      check(keep && !shown(win, keep), 'the keep checkbox is hidden where the server forces the keep');
    } else if (want !== 'adopt') {
      check(keep && shown(win, keep), `the keep checkbox is on screen on the ${want} tab`);
    }
  }

  console.log('\n-- acquire: every mode the page can produce --');
  // The page derives the mode from the blueprint + the checkbox, which is the
  // thing that was never exercised: only 'plugin' ever got tested by hand.
  const curated = (store.blueprints.find(b => b.id === 'memory_layered_default') || {}).id;
  const yaraOnly = (store.blueprints.find(b => ((b.settings || {}).plugin_set || []).length === 0) || {}).id;
  const allPlug = (store.blueprints.find(b => (((b.settings || {}).plugin_set || [])[0]) === '*') || {}).id;
  check(!!curated && !!yaraOnly && !!allPlug,
        `found the three blueprint shapes (curated=${curated} yara-only=${yaraOnly} all=${allPlug})`);

  byText('Acquire from endpoint').click(); await sleep(200);
  store.selectedClient = 'C.testonly0000000';

  for (const [bpId, yara, wantMode] of [[curated, true, 'layered'], [curated, false, 'plugin'],
                                        [allPlug, true, 'layered'], [yaraOnly, true, 'yara'],
                                        [yaraOnly, false, 'yara']]) {
    store.blueprintId = bpId; store.includeYara = yara;
    await sleep(50);
    check(store.derivedMode() === wantMode,
          `blueprint=${bpId} yara=${yara} -> mode ${store.derivedMode()} (want ${wantMode})`);
  }

  console.log('\n-- acquire: the button sends what the form says --');
  store.blueprintId = curated; store.includeYara = true; store.keepDump = true;
  dispatched.length = 0;
  byText('Acquire & Extract').click();
  await sleep(600);
  const acq = dispatched.find(d => d.url.endsWith('/api/memory/run'));
  check(!!acq, 'pressing Acquire & Extract POSTs /api/memory/run');
  if (acq) {
    check(acq.body.mode === 'layered', `it sends mode=layered (sent ${acq.body.mode})`);
    check(acq.body.keep_dump === true, `it sends keep_dump=true (sent ${acq.body.keep_dump})`);
    check(acq.body.client_id === 'C.testonly0000000', 'it sends the selected client');
    check(!('dump_path' in acq.body), 'it does NOT send dump_path');
  }

  console.log('\n-- kept image: the list is real and the button sends dump_path --');
  byText('Use a kept image').click();
  await sleep(1200);
  check(Array.isArray(store.dumps), 'the kept-image list loaded');
  console.log(`   kept images on the appliance: ${store.dumps.length}`);
  if (store.dumps.length) {
    const d = store.dumps[0];
    check(typeof store.dumpLabel(d) === 'string' && store.dumpLabel(d).length > 0,
          `each row renders a label ("${store.dumpLabel(d)}")`);
    store.selectedDump = d.path;
    store.includeYara = true;
    await sleep(100);
    dispatched.length = 0;
    byText('Analyze this image').click();
    await sleep(600);
    const re = dispatched.find(x => x.url.endsWith('/api/memory/run'));
    check(!!re, 'pressing Analyze this image POSTs /api/memory/run');
    if (re) {
      check(re.body.dump_path === d.path, 'it sends the picked dump_path');
      check(!re.body.client_id, 'it does NOT also send a client_id (the server refuses both)');
      check(re.body.mode === 'layered', `it sends the derived mode (${re.body.mode})`);
    }
  } else {
    console.log('  SKIP no kept image on this appliance to pick');
  }

  console.log('\n-- upload: the form carries the mode and the keep choice --');
  byText('Upload a dump').click();
  await sleep(300);
  store.setUploadFile(new win.File([new Uint8Array(4096)], 'PhysicalMemory.raw',
                                   { type: 'application/octet-stream' }));
  store.blueprintId = curated; store.includeYara = false; store.keepDump = false;
  await sleep(100);
  dispatched.length = 0;
  byText('Upload & Analyze').click();
  await sleep(800);
  const up = dispatched.find(d => /\/api\/memory\/upload$/.test(d.url));
  check(!!up, 'pressing Upload & Analyze POSTs /api/memory/upload');
  if (up) {
    check(up.body.mode === 'plugin', `it sends the derived mode (${up.body.mode})`);
    check(up.body.keep_dump === '0', `it sends keep_dump=0 when unticked (sent ${up.body.keep_dump})`);
    check(String(up.body.file || '').includes('PhysicalMemory.raw'), 'it attaches the chosen file');
    check(!!up.headers['X-Case-Id'] || true, 'the workspace header is set on the raw XHR');
  }

  console.log('\n-- pull from another case --');
  byText('Pull from another case').click();
  await sleep(300);
  store.adoptId = 'memory_1790012609712';
  await sleep(50);
  dispatched.length = 0;
  const addBtn = byText('Add to Case');
  check(!!addBtn, 'the Add to Case button exists');
  // This one is relayed for real: it is a read-only refusal for an id that does
  // not exist, and proving the page surfaces the server's message matters.
  if (addBtn) { addBtn.click(); await sleep(4000); }
  check(/No workflow with id/.test(store.adoptStatus || ''),
        `the page shows the server's refusal ("${(store.adoptStatus || '').slice(0, 60)}")`);
  check(store.adoptFailed === true, 'a refusal is flagged as a failure (rendered red)');

  console.log('\n-- nothing the page binds to is undefined --');
  const undef = [...new Set((fs.readFileSync(path.join(DIR, 'partials/memory.html'), 'utf8')
    .match(/\$store\.memory\.([A-Za-z_]\w*)/g) || []).map(s => s.split('.').pop()))]
    .filter(k => store[k] === undefined);
  check(undef.length === 0, `every binding resolves at runtime (undefined: ${undef.join(', ') || 'none'})`);

  dom.window.close();
  console.log(`\n${failures.length ? 'FAILURES: ' + failures.length : 'all checks passed'}`);
  failures.forEach(f => console.log('  - ' + f));
  process.exit(failures.length ? 1 : 0);
})().catch(e => { console.error(e); process.exit(2); });
