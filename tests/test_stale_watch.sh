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
# Three checkboxes were REMOVED from the Configuration rail on purpose. Each was a
# decision an operator had no basis to make, and each read as broken when it did
# nothing visible:
#   cf-autofuse  folding new data in is what the product does
#   cf-autocheck one cheap read every 20s that redraws nothing
#   cf-airgap    on a box with no model the report was deterministic either way,
#                so ticking or unticking it changed nothing the operator could see
for box in cf-autofuse cf-autocheck cf-airgap; do
    grep -q "id=\"$box\"" "$SRC" \
      && { echo "  FAIL the $box checkbox is back — that decision was reversed"; fails=$((fails+1)); }
done
grep -q '"auto_fuse" in cfg' "${ROOT}/modules/backend/services/fusion/store.py" \
  || { echo "  FAIL set_analysis_config no longer honours auto_fuse (the support escape hatch)"; fails=$((fails+1)); }
# Tab ORDER is a deliberate decision (investigative order, not build order) and is
# invisible to every test that only checks a tab renders — so it is pinned here.
# The landing tab must also be the FIRST tab: it was 'report' while Configuration
# sat leftmost, so the tab you land on was not the tab that looked selected.
python3 - "$SRC" <<'PY' || fails=$((fails+1))
import re, sys
s = open(sys.argv[1], encoding="utf-8").read()
order = re.findall(r'data-tab="([a-z]+)"', s)
want = ["report", "chat", "timeline", "identities", "risk", "config", "log"]
if order != want:
    sys.exit("  FAIL tab order is %s, expected %s" % (order, want))
m = re.search(r"let sel=null, tab='([a-z]+)'", s)
if not m:
    sys.exit("  FAIL could not find the landing tab")
if m.group(1) != order[0]:
    sys.exit("  FAIL landing tab is %r but the first tab is %r — they must agree"
             % (m.group(1), order[0]))
# every tab must have somewhere to dispatch to
d = re.search(r"function drawTab\(md\)\{.*?\n\}", s, re.S)
if not d:
    sys.exit("  FAIL drawTab not found")
for t in order:
    if t not in d.group(0) and t != "report":     # report is drawTab's else branch
        sys.exit("  FAIL tab %r has no renderer in drawTab" % t)
PY

grep -q '"fused_run_ids": list(' "${ROOT}/modules/backend/routes/case_routes.py" \
  || { echo "  FAIL the case payload does not carry fused_run_ids — the UI cannot detect a background fuse"; fails=$((fails+1)); }
grep -q 'air_gap_analysis' "${ROOT}/modules/backend/services/fusion/store.py" \
  && { echo "  FAIL air_gap_analysis is back in store.py — it is no longer a case setting"; fails=$((fails+1)); }

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

# The bar above the tabs must not offer Refusion. New data is folded in
# automatically, so there is nothing there for the operator to trigger; the only
# deliberate action left is generating a fresh report. Manual Refusion still
# exists, in Configuration.
m = re.search(r"function staleBar\(info\)\{.*?\n\}", s, re.S)
if not m:
    sys.exit("  FAIL staleBar not found")
if "doRefusion" in m.group(0):
    sys.exit("  FAIL staleBar offers Refusion — that moved to Configuration")
if "doRescanLLM" not in m.group(0):
    sys.exit("  FAIL staleBar no longer offers a new report")
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
      min_severity: 'medium', master_prompt: 'KEEP ME'
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

  // 1. the poll is unconditional — there is no setting to switch it off
  {
    const e = harness({});
    e.api.startStaleWatch('case_1');
    if (e.ctx.window._staleTimer) ok('the poll runs without needing a setting');
    else fail('the poll runs without needing a setting');
  }

  // 2. and a legacy case carrying the removed key is still polled
  {
    const e = harness({ info: { auto_check_new_data: false } });
    e.api.startStaleWatch('case_1');
    if (e.ctx.window._staleTimer) ok('a stored, now-removed opt-out no longer suppresses it');
    else fail('a stored, now-removed opt-out no longer suppresses it', 'the dead key still gates the poll');
  }

  // 3. 0 -> non-zero raises the banner, and touches nothing else
  {
    const e = harness({});
    e.api.staleTick('case_1');
    await respond(e, { case_id: 'case_1', is_stale: true, data_stale: 3, report_dirty: false });
    if (!/3 new runs<\/b> landed/.test(e.bar.innerHTML)) fail('new runs raise the banner', e.bar.innerHTML.slice(0,90));
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

  // 11a. a background fuse changed the stored graph -> offer a reload, redraw nothing
  {
    const e = harness({});
    e.ctx.window._renderedFused = 'runA';
    e.api.staleTick('case_1');
    await respond(e, { case_id: 'case_1', is_stale: false, data_stale: 0,
                       fused_run_ids: ['runA', 'runB'] });
    if (!/Show new data/.test(e.bar.innerHTML))
      fail('a background fuse offers a reload', e.bar.innerHTML.slice(0, 100) || '(empty)');
    else if (e.renderCalls !== 0)
      fail('a background fuse offers a reload', 'it redrew the view itself');
    else ok('a background fuse offers a reload instead of redrawing');
  }

  // 11b. the same fused set must NOT claim a background refresh
  {
    const e = harness({});
    e.ctx.window._renderedFused = 'runA';
    e.api.staleTick('case_1');
    await respond(e, { case_id: 'case_1', is_stale: false, data_stale: 0,
                       fused_run_ids: ['runA'] });
    if (/Show new data/.test(e.bar.innerHTML))
      fail('an unchanged graph does not claim a refresh', e.bar.innerHTML.slice(0, 90));
    else ok('an unchanged graph does not claim a refresh');
  }

  // 11c. a case that has never been rendered must not false-positive
  {
    const e = harness({});
    e.ctx.window._renderedFused = '';
    e.api.staleTick('case_1');
    await respond(e, { case_id: 'case_1', is_stale: true, data_stale: 1,
                       fused_run_ids: ['runA'] });
    if (/Show new data/.test(e.bar.innerHTML))
      fail('a first render does not claim a background refresh', e.bar.innerHTML.slice(0, 90));
    else if (!/1 new run<\/b> landed/.test(e.bar.innerHTML))
      fail('a first render still shows the normal stale banner', e.bar.innerHTML.slice(0, 90));
    else ok('a first render shows the stale banner, not a false refresh');
  }

  // 11d. the reload button reloads THIS case and nothing else fuses
  {
    const e = harness({});
    const h = e.api.staleBar({ bg_refreshed: true, case_id: 'case_9' });
    if (!/openCase\('case_9'\)/.test(h)) fail('the reload button reloads this case', h.slice(0, 120));
    else if (/doRefusion/.test(h)) fail('the reload button must not re-fuse', 'it offers Refusion');
    else ok('the reload button reloads the case and does not re-fuse');
  }

  // 11d2. the bar must name the RIGHT cause. It read "You've made changes (triage
  // / timeline validations)" unconditionally, which became wrong more often than
  // right once fusion went automatic: the usual reason the report is behind is now
  // new data folded in while nobody touched triage at all.
  {
    const e = harness({});
    const txt = st => e.api.staleBar(st).replace(/<[^>]+>/g, '').replace(/&amp;/g, '&');

    // new data fused, nobody triaged -> must NOT assert that they made changes
    const auto = txt({ is_stale: 1, data_stale: 0, report_stale: 2, report_dirty: true, case_id: 'c' });
    if (!/2 runs of new data/.test(auto)) fail('new data is named as the cause', auto.slice(0, 110));
    else if (/your triage \/ timeline validations have changed/.test(auto))
      fail('new data is named as the cause', 'it asserts triage that may not have happened');
    else if (!/any triage \/ timeline changes/.test(auto))
      fail('new data is named as the cause', 'triage is not even hedged');
    else ok('new data is named, and triage only hedged (report_dirty is not proof)');

    // no new runs -> the only thing that can have re-fused is triage
    const tri = txt({ is_stale: 1, data_stale: 0, report_stale: 0, report_dirty: true, case_id: 'c' });
    if (!/triage \/ timeline validations have changed/.test(tri))
      fail('triage-only is named as such', tri.slice(0, 110));
    else if (/new data/.test(tri))
      fail('triage-only is named as such', 'it claims new data with report_stale=0');
    else ok('triage-only says triage, and does not invent new data');

    // pluralisation, since these strings are read by customers
    const one = txt({ is_stale: 1, data_stale: 0, report_stale: 1, report_dirty: true, case_id: 'c' });
    if (/1 runs|1 run\(s\)/.test(one)) fail('it says "1 run", not "1 runs"', one.slice(0, 90));
    else if (!/1 run of new data has been fused/.test(one))
      fail('it says "1 run", not "1 runs"', one.slice(0, 90));
    else ok('singular and plural both read correctly');

    const landing = txt({ is_stale: 1, data_stale: 1, report_stale: 1, case_id: 'c' });
    if (!/1 new run landed and is being folded in/.test(landing))
      fail('the landing message agrees in number', landing.slice(0, 90));
    else ok('the landing message agrees in number');
  }

  // 11e. no banner state may offer Refusion
  {
    const e = harness({});
    const states = [
      { is_stale: true, data_stale: 3, case_id: 'c' },
      { is_stale: true, data_stale: 0, report_dirty: true, case_id: 'c' },
      { is_stale: true, data_stale: 0, report_dirty: false, case_id: 'c' },
      { bg_refreshed: true, case_id: 'c' },
    ];
    const offending = states.filter(st => /doRefusion/.test(e.api.staleBar(st)));
    if (offending.length) fail('no banner state offers Refusion', JSON.stringify(offending[0]));
    else ok('no banner state offers Refusion (it lives in Configuration)');
  }

  // 12. report_dirty alone still offers Rescan but not Refusion
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
    '#cf-maxident':{value:''},
    '#cf-mask':{checked:false},'#cf-maskpat':{value:''}};
  try {
    const cfg = await build(s => vals[s] || null,
                            () => [{dataset:{mod:'memory'}}])();
    if (cfg.min_severity !== 'high') fail('a mounted rail is read in full', 'min_severity=' + cfg.min_severity);
    else if (cfg.master_prompt !== 'steer') fail('a mounted rail is read in full', 'master_prompt lost');
    else if ('air_gap_analysis' in cfg) fail('the rail no longer posts removed settings', 'air_gap_analysis is back');
    else if ('auto_check_new_data' in cfg) fail('the rail no longer posts removed settings', 'auto_check_new_data is back');
    else ok('a mounted rail is still read in full, and posts no removed settings');
  } catch (e) {
    fail('a mounted rail is still read in full', 'threw ' + e.message);
  }
  process.exit(bad ? 1 : 0);
})();
JS

exit $(( fails > 0 ? 1 : 0 ))
