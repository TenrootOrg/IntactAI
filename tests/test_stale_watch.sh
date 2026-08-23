#!/usr/bin/env bash
# The case view must notice new data on its own -- and must do NOTHING else.
#
# The banner, the staleness fields and the Refusion/Rescan buttons all existed
# already; nothing re-checked them, so an analyst sitting on the Risk tab found
# out that runs had landed only by reloading the page. The watcher added here
# closes that, and the whole design constraint is what it must NOT do:
#
#   - never fuse (a fuse rebuilds the graph -- 33s for 9 hosts / 18,749 entities
#     on the live box -- and re-ranks every finding under whoever is reading it);
#   - never call render(), which rebuilds #main.innerHTML and would remount every
#     tab, losing scroll, expanded rows and a half-typed chat message;
#   - never stack requests behind a slow backend;
#   - never clear a banner it could not verify, so a transient error cannot claim
#     the data is current when it is not;
#   - never poll at all once the operator unticks the setting -- that checkbox is
#     the escape hatch, so it has to genuinely stop the thing.
#
# The REAL functions are lifted out of cases.html and executed, so this cannot
# drift from what ships. Node is not on an appliance, so this skips there.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="${ROOT}/modules/nginx/html/cases.html"

fails=0

# ---- static: things that must be true even where node is absent --------------
grep -q 'id="stalebar"' "$SRC" \
  || { echo "  FAIL no #stalebar container — the watcher has nothing to update in place"; fails=$((fails+1)); }
grep -q 'function staleBar(info)' "$SRC" \
  || { echo "  FAIL staleBar() is gone — the banner is back inside render()"; fails=$((fails+1)); }
grep -q 'id="cf-autocheck"' "$SRC" \
  || { echo "  FAIL the 'watch for new data' checkbox is missing from the config rail"; fails=$((fails+1)); }
grep -q 'auto_check_new_data' "${ROOT}/modules/backend/routes/case_routes.py" \
  || { echo "  FAIL the backend does not serve auto_check_new_data"; fails=$((fails+1)); }
grep -q '"auto_check_new_data" in cfg' "${ROOT}/modules/backend/services/fusion/store.py" \
  || { echo "  FAIL set_analysis_config does not persist auto_check_new_data"; fails=$((fails+1)); }

# The watcher must never reach for a fuse. Checked on the function bodies only,
# with comments stripped -- prose about fusing is fine, a call is not.
python3 - "$SRC" <<'PY' || fails=$((fails+1))
import re, sys
s = open(sys.argv[1], encoding="utf-8").read()
body = ""
for name in ("stopStaleWatch", "startStaleWatch", "staleTick"):
    m = re.search(r"function %s\([^)]*\)\{.*?\n\}" % name, s, re.S)
    if not m:
        sys.exit("  FAIL %s not found in cases.html" % name)
    body += m.group(0) + "\n"
code = "\n".join(l.split("//", 1)[0] for l in body.splitlines())
for forbidden in ("/rescan", "doRefusion(", "doRescanLLM(", "render(", "drawTab("):
    if forbidden in code:
        sys.exit("  FAIL the watcher calls %s — it must only update the banner" % forbidden)
PY

if ! command -v node >/dev/null 2>&1; then
    echo "  SKIP no node on this host — the watcher behaviour is checked where node exists"
    exit $(( fails > 0 ? 1 : 0 ))
fi

tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
python3 - "$SRC" "$tmp/w.js" <<'PY'
import re, sys
s = open(sys.argv[1], encoding="utf-8").read()
out = []
for pat in (r"const STALE_POLL_MS = \d+;",
            r"let _staleInFlight = false;",
            r"function staleBar\(info\)\{.*?\n\}",
            r"function stopStaleWatch\(\)\{.*?\n\}",
            r"function startStaleWatch\(id\)\{.*?\n\}",
            r"function staleTick\(id\)\{.*?\n\}"):
    m = re.search(pat, s, re.S)
    if not m:
        sys.exit("could not extract %r from cases.html" % pat)
    out.append(m.group(0))
open(sys.argv[2], "w", encoding="utf-8").write("\n".join(out))
PY
[[ -s "$tmp/w.js" ]] || { echo "  FAIL could not extract the watcher"; exit 1; }

node - "$tmp/w.js" <<'JS' || fails=$((fails+1))
const fs = require('fs');
const src = fs.readFileSync(process.argv[2], 'utf8');

let bad = 0;
const ok   = w => console.log('  ok   ' + w);
const fail = (w, d) => { console.log('  FAIL ' + w + (d ? '\n       ' + d : '')); bad++; };

// ---- a minimal, honest harness -------------------------------------------
// setInterval is captured rather than run, so each test drives ticks by hand and
// nothing depends on wall-clock timing.
function harness(opts){
  const env = {
    bar: { innerHTML: '' },
    hidden: false,
    fetches: 0,
    inflight: [],
    renderCalls: 0,
    timer: null,
    curInfo: Object.assign({
      case_id: 'case_1', is_stale: false, data_stale: 0, report_dirty: false,
      auto_check_new_data: true, min_severity: 'medium', master_prompt: 'KEEP ME'
    }, opts.info || {})
  };
  const ctx = {
    $: s => (s === '#stalebar' ? (env.barGone ? null : env.bar) : null),
    document: { hidden: false },
    window: {},
    curInfo: env.curInfo,
    console,
    clearInterval: () => { env.timer = null; },
    setInterval: (fn, ms) => { env.timer = { fn, ms }; return env.timer; },
    fetch: (url) => {
      env.fetches++;
      return new Promise((res, rej) => {
        env.inflight.push({ url, res, rej });
      });
    },
    render: () => { env.renderCalls++; }
  };
  Object.defineProperty(ctx.document, 'hidden', { get: () => env.hidden });
  const fn = new Function('$','document','window','curInfo','console','clearInterval',
                          'setInterval','fetch','render',
    src + '; return {startStaleWatch, stopStaleWatch, staleTick, staleBar, ' +
          'get timer(){return null;}};');
  env.api = fn(ctx.$, ctx.document, ctx.window, ctx.curInfo, ctx.console,
               ctx.clearInterval, ctx.setInterval, ctx.fetch, ctx.render);
  env.ctx = ctx;
  return env;
}
const settle = () => new Promise(r => setImmediate(() => setImmediate(r)));
const respond = (env, body, okFlag) => {
  const c = env.inflight.shift();
  c.res({ ok: okFlag !== false, json: () => Promise.resolve(body) });
  return settle();
};

(async () => {

  // 1. opted out -> no timer at all
  {
    const e = harness({ info: { auto_check_new_data: false } });
    e.api.startStaleWatch('case_1');
    if (e.ctx.window._staleTimer) fail('unticking the setting stops the polling');
    else ok('unticking the setting stops the polling');
  }

  // 2. default (absent) reads as ON
  {
    const e = harness({});
    delete e.curInfo.auto_check_new_data;
    e.api.startStaleWatch('case_1');
    if (e.ctx.window._staleTimer) ok('an absent setting polls (legacy cases stay covered)');
    else fail('an absent setting polls (legacy cases stay covered)');
  }

  // 3. 0 -> non-zero raises the banner, and touches nothing else
  {
    const e = harness({});
    e.api.staleTick('case_1');
    await respond(e, { case_id: 'case_1', is_stale: true, data_stale: 3, report_dirty: false });
    if (!/3 new run\(s\)/.test(e.bar.innerHTML)) fail('new runs raise the banner', e.bar.innerHTML.slice(0,90));
    else if (e.renderCalls !== 0) fail('new runs raise the banner', 'it called render()');
    else if (e.curInfo.master_prompt !== 'KEEP ME') fail('new runs raise the banner', 'it clobbered rail config');
    else ok('new runs raise the banner without re-rendering or touching config');
  }

  // 4. a failed read leaves the banner exactly as it was
  {
    const e = harness({ info: { is_stale: true, data_stale: 2 } });
    e.bar.innerHTML = 'EXISTING BANNER';
    e.api.staleTick('case_1');
    await respond(e, null, false);                       // HTTP 500
    if (e.bar.innerHTML !== 'EXISTING BANNER') fail('a failed read leaves the banner alone', e.bar.innerHTML);
    else ok('a failed read leaves the banner alone');
  }

  // 5. a rejected fetch is swallowed and the watcher recovers
  {
    const e = harness({});
    e.api.staleTick('case_1');
    e.inflight.shift().rej(new Error('network down'));
    await settle();
    e.api.staleTick('case_1');                            // must not be wedged
    if (e.fetches !== 2) fail('a network error does not wedge the watcher', 'fetches=' + e.fetches);
    else ok('a network error does not wedge the watcher');
  }

  // 6. no stacking while a tick is in flight
  {
    const e = harness({});
    e.api.staleTick('case_1');
    e.api.staleTick('case_1');
    e.api.staleTick('case_1');
    if (e.fetches !== 1) fail('a slow backend cannot stack requests', 'fetches=' + e.fetches);
    else {
      await respond(e, { case_id: 'case_1', is_stale: false, data_stale: 0 });
      e.api.staleTick('case_1');
      if (e.fetches !== 2) fail('the watcher resumes after a tick completes', 'fetches=' + e.fetches);
      else ok('a slow backend cannot stack requests, and the watcher resumes after');
    }
  }

  // 7. a backgrounded browser tab is not polled
  {
    const e = harness({});
    e.hidden = true;
    e.api.staleTick('case_1');
    if (e.fetches !== 0) fail('a hidden tab is not polled');
    else ok('a hidden tab is not polled');
  }

  // 8. the view went away -> stop, never leak a timer
  {
    const e = harness({});
    e.api.startStaleWatch('case_1');
    e.barGone = true;
    e.api.staleTick('case_1');
    if (e.fetches !== 0) fail('leaving the case view stops the poll', 'it still fetched');
    else if (e.ctx.window._staleTimer) fail('leaving the case view stops the poll', 'timer left running');
    else ok('leaving the case view stops the poll');
  }

  // 9. a reply for a different case is ignored (open A, switch to B, A replies)
  {
    const e = harness({});
    e.bar.innerHTML = '';
    e.api.staleTick('case_1');
    await respond(e, { case_id: 'case_OTHER', is_stale: true, data_stale: 9 });
    if (e.bar.innerHTML !== '') fail('a reply for another case is ignored', e.bar.innerHTML.slice(0,80));
    else ok('a reply for another case is ignored');
  }

  // 10. staleBar itself: no banner when nothing is stale
  {
    const e = harness({});
    if (e.api.staleBar({ is_stale: false }) !== '') fail('no banner when the case is current');
    else if (e.api.staleBar(null) !== '') fail('no banner for a missing info');
    else ok('no banner when the case is current');
  }

  // 11. report_dirty alone still offers Rescan but not Refusion
  {
    const e = harness({});
    const h = e.api.staleBar({ is_stale: true, data_stale: 0, report_dirty: true, case_id: 'c' });
    if (/doRefusion/.test(h)) fail('report-only staleness does not offer Refusion');
    else if (!/doRescanLLM/.test(h)) fail('report-only staleness offers Rescan');
    else ok('report-only staleness offers Rescan, not Refusion');
  }

  process.exit(bad ? 1 : 0);
})();
JS

# ---- the manual escape hatch must work from every tab ------------------------
# The banner's Refusion / Rescan buttons sit above #tabc and are visible on every
# tab, but the #cf-* inputs _railCfg() reads are written into #tabc by
# renderConfig() -- so they exist ONLY while Configuration is open, and a case
# opens on 'report'. _railCfg() hit `$('#cf-logo').files` on null and threw before
# any request was made; doRefusion's try/catch wraps only the api() call, so the
# rejection escaped with no toast and no error and the buttons silently did
# nothing. That is the manual fallback the whole design leans on.
python3 - "$SRC" "$tmp/rail.js" <<'PY'
import re, sys
s = open(sys.argv[1], encoding="utf-8").read()
m = re.search(r"async function _railCfg\(\)\{.*?\n\}", s, re.S)
if not m:
    sys.exit("could not find _railCfg in cases.html")
open(sys.argv[2], "w", encoding="utf-8").write(m.group(0))
PY

node - "$tmp/rail.js" <<'JS' || fails=$((fails+1))
const fs = require('fs');
const src = fs.readFileSync(process.argv[2], 'utf8');
let bad = 0;
const ok   = w => console.log('  ok   ' + w);
const fail = (w, d) => { console.log('  FAIL ' + w + (d ? '\n       ' + d : '')); bad++; };

const build = (lookup, all) => {
  const doc = { querySelector: lookup, querySelectorAll: all || (() => []) };
  return new Function('$','_fileToDataUrl','_hostExc','document',
    src + '; return _railCfg;')(lookup, async () => null, new Set(), doc);
};

(async () => {
  // Configuration tab NOT mounted -- every #cf-* lookup is null.
  try {
    const cfg = await build(() => null)();
    if (Object.keys(cfg).length !== 0)
      fail('an unmounted rail posts nothing', JSON.stringify(cfg).slice(0, 120));
    else
      ok('an unmounted rail posts {} instead of throwing (Refusion works off-tab)');
  } catch (e) {
    fail('an unmounted rail posts nothing', 'threw ' + e.message);
  }

  // Mounted -- the normal path must be untouched by that guard.
  const vals = {'#cf-logo':{files:[]},'#cf-start':{value:'2026-08-01'},'#cf-end':{value:''},
    '#cf-sev':{value:'high'},'#cf-aud':{value:'both'},'#cf-cust':{value:'Acme'},
    '#cf-tlp':{value:'AMBER'},'#cf-mp':{value:'steer'},'#cf-maxent':{value:'500000'},
    '#cf-maxident':{value:''},'#cf-airgap':{checked:true},'#cf-autocheck':{checked:false},
    '#cf-mask':{checked:false},'#cf-maskpat':{value:''}};
  try {
    const cfg = await build(s => vals[s] || null,
                            () => [{dataset:{mod:'memory'}}])();
    if (cfg.min_severity !== 'high') fail('a mounted rail is read in full', 'min_severity=' + cfg.min_severity);
    else if (cfg.air_gap_analysis !== true) fail('a mounted rail is read in full', 'air_gap lost');
    else if (cfg.auto_check_new_data !== false) fail('the checkbox round-trips', 'auto_check=' + cfg.auto_check_new_data);
    else if (cfg.master_prompt !== 'steer') fail('a mounted rail is read in full', 'master_prompt lost');
    else ok('a mounted rail is still read in full, checkbox included');
  } catch (e) {
    fail('a mounted rail is still read in full', 'threw ' + e.message);
  }
  process.exit(bad ? 1 : 0);
})();
JS

exit $(( fails > 0 ? 1 : 0 ))
