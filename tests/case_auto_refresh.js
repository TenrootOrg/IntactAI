// A fuse that finishes must reach the screen with no reload and no click.
//
// The page used to poll ONLY while a report was generating, and only once the
// Analysis tab had been drawn during it. So the one case that refreshed itself
// was a report this browser had started -- and that made it look like the rule.
// Every other fuse (another operator's Refusion, the automatic re-fuse after new
// data lands, a disposition or timeline edit in a second tab) left the case
// showing the PREVIOUS report until somebody reloaded.
//
// This drives the REAL page in a real DOM against a LIVE backend, starts a fuse
// from OUTSIDE the browser -- the case the old poll could not see -- and checks
// the view catches up on its own. It also checks the other half: a background
// refresh must never land on top of someone typing.
//
// Needs a running appliance; the python wrapper skips without one. Works on a
// throwaway case it creates and deletes.
//
//   node tests/case_auto_refresh.js <path to cases.html>
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
  const out = execFileSync('docker', ['exec', '-i',
    '-e', 'M', '-e', 'P', '-e', 'BODY', CONTAINER, 'python3', '/tmp/api_call.py'],
    { env, encoding: 'utf8', maxBuffer: 256 * 1024 * 1024 });
  return JSON.parse(out.slice(out.indexOf('{')));
}

function boot(activeCase) {
  let html = fs.readFileSync(PAGE, 'utf8')
    .replace(/<script src="([^"]+)"><\/script>/g, (m, src) => {
      const f = path.join(DIR, src.split('?')[0]);
      return fs.existsSync(f) ? `<script>${fs.readFileSync(f, 'utf8')}</script>` : '';
    }).replace(/<link[^>]+stylesheet[^>]*>/g, '');
  const vc = new VirtualConsole();
  vc.on('jsdomError', e => console.error('PAGE ERROR:', e.message));
  return new JSDOM(html, {
    url: 'http://localhost/cases.html?embed=1&view=analysis',
    runScripts: 'dangerously', pretendToBeVisual: true, virtualConsole: vc,
    beforeParse(win) {
      win.localStorage.setItem('activeCaseId', activeCase);
      win.scrollTo = () => {};
      win.fetch = (p, opt) => {
        const r = call((opt && opt.method) || 'GET', p,
                       opt && opt.body ? JSON.parse(opt.body) : null);
        return Promise.resolve({ ok: r.status < 400, status: r.status,
                                 json: () => Promise.resolve(JSON.parse(r.text)),
                                 text: () => Promise.resolve(r.text) });
      };
    },
  });
}

const sleep = ms => new Promise(r => setTimeout(r, ms));
// The poll runs on a 5s interval, and each tick relays through docker exec, so
// give it a couple of cycles before calling it a failure.
async function waitFor(fn, ms = 30000) {
  const until = Date.now() + ms;
  while (Date.now() < until) { if (fn()) return true; await sleep(1000); }
  return false;
}

(async () => {
  const failures = [];
  const check = (ok, why) => { if (!ok) failures.push(why); console.log((ok ? '  ok   ' : '  FAIL ') + why); };

  const name = 'refresh-probe-' + Date.now();
  const cid = JSON.parse(call('POST', '/api/cases', { name }).text).case_id;
  console.log('probe case:', cid, name);
  let dom;
  try {
    // one fuse first, so the case has a fused_at to move
    call('POST', `/api/cases/${cid}/rescan`, { trigger: 'refusion' });

    dom = boot(cid);
    const win = dom.window;
    await new Promise(r => win.addEventListener('load', r));

    // `curInfo` is a `let`, so it is not a window property. showCase IS -- a
    // top-level function declaration -- and every refresh goes through it, so
    // wrapping it is how the test sees what the page is rendering.
    const seen = [];
    const realShowCase = win.showCase;
    win.showCase = (id, info, rep) => {
      if (id === cid && info) seen.push(info.fused_at);
      return realShowCase(id, info, rep);
    };
    // A fuse that changed only the fused data (no new report) updates in place
    // through _quietFuseRefresh instead of reloading the case: watch both.
    const realQuiet = win._quietFuseRefresh;
    win._quietFuseRefresh = (info) => {
      if (info && info.case_id === cid) seen.push(info.fused_at);
      return realQuiet(info);
    };
    const onScreen = () => seen.length ? seen[seen.length - 1] : undefined;

    await sleep(2500);
    check(seen.length > 0, 'the case is on screen');
    const before = onScreen();
    console.log('  fused_at on screen:', before);
    check(!!before, 'the case payload carries fused_at (the poll compares it)');

    // 1. A FUSE STARTED OUTSIDE THIS BROWSER. Nothing on the page asked for it
    //    and nothing on the page is generating -- exactly the case the old poll
    //    could not see.
    call('POST', `/api/cases/${cid}/rescan`, { trigger: 'refusion' });
    const after = JSON.parse(call('GET', '/api/cases/' + cid).text).fused_at;
    check(after !== before, `the fuse moved fused_at server-side (${before} -> ${after})`);
    const caught = await waitFor(() => onScreen() === after);
    check(caught, `the open case refreshed itself with no click (on screen: ${onScreen()})`);

    // 2. ...but not on top of someone typing.
    win.setTab('config');
    await sleep(1500);
    const box = win.document.querySelector('#cf-cust');
    check(!!box, 'the Configuration rail is available for the typing check');
    if (box) {
      box.value = 'half typed';
      box.focus();
      check(win.operatorIsTyping() === true, 'a focused field with text counts as typing');
      const held = onScreen();
      call('POST', `/api/cases/${cid}/rescan`, { trigger: 'refusion' });
      await sleep(12000);                      // ~2 poll ticks
      check(onScreen() === held,
        `a fuse finishing must NOT redraw the page under a half-typed field (on screen: ${onScreen()})`);
      check(win.document.querySelector('#cf-cust').value === 'half typed',
        'the typed text is still there');

      // 3. ...and the moment they stop, it catches up on its own.
      box.value = '';
      box.blur();
      const latest = JSON.parse(call('GET', '/api/cases/' + cid).text).fused_at;
      const resumed = await waitFor(() => onScreen() === latest);
      check(resumed, `the deferred refresh lands once the field is free (on screen: ${onScreen()})`);
    }
    win.close();
  } finally {
    call('DELETE', '/api/cases/' + cid);
    console.log('probe case deleted');
  }

  if (failures.length) { console.error('\nFAIL (' + failures.length + ')'); process.exit(1); }
  console.log('\nall good');
})();
