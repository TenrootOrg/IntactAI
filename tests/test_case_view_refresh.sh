#!/usr/bin/env bash
# The case view refreshes itself. There is nothing left to tell the operator.
#
# THIS FILE USED TO TEST THE OPPOSITE. The case view polled GET /api/cases/<id>
# every 20s and raised a banner -- "3 new runs landed", "the report & chat are
# not up to date", "new data was folded in, reload to see it" -- and this suite
# pinned every message and everything the poller must not do.
#
# All of it existed because parts of a case could silently fall behind. None of
# them can any more:
#   - a member run landing rebuilds the graph AND regenerates the report on its
#     own (services/fusion/autofuse.py), so the numbers and the words move
#     together;
#   - a triage, timeline or identity edit re-fuses in the same request that made
#     it, so it is current before the response is written.
# A banner announcing something the product already did, with a button that
# repeats it, is worse than no banner: the measured outcome was operators
# reading a report that was behind its own data because nobody pressed it.
#
# So the assertions below are the inverse. The staleness UI must be GONE -- and,
# the part that actually bites, gone COMPLETELY: doRefusion() called staleTick()
# from outside the watcher, so removing only the watcher would leave a
# ReferenceError that kills the manual Refusion path this same file tests at the
# bottom.
#
# What stayed: tab order, the checkboxes that were deliberately removed, the
# support escape hatches, and _railCfg -- none of which were ever about
# staleness, and all of which are still load-bearing.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="${ROOT}/modules/nginx/html/cases.html"
fails=0

# ---- static: things that must be true even where node is absent --------------
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

# ---- the staleness UI is gone, and nothing still reaches for it ---------------
python3 - "$SRC" <<'ZPY' || fails=$((fails+1))
import re, sys
s = open(sys.argv[1], encoding="utf-8").read()
# Comments are stripped first: the note explaining WHY the watcher was removed
# names every one of these, and a naive grep matches the explanation.
code = "\n".join(l.split("//", 1)[0] for l in s.splitlines())
for gone in ("staleBar", "staleTick", "startStaleWatch", "stopStaleWatch",
             "STALE_POLL_MS", "_staleInFlight", "bg_refreshed",
             "_renderedFused", 'id="stalebar"'):
    if gone in code:
        sys.exit("  FAIL %s is back in cases.html -- the staleness banner returned"
                 % gone)
# The removal must be total. A definition removed while a CALL survives is the
# worse of the two outcomes: the page parses, and then throws at the moment the
# operator clicks the thing that calls it.
if re.search(r"setInterval\s*\(\s*\(\s*\)\s*=>\s*stale", code):
    sys.exit("  FAIL a staleness poll is still armed")
ZPY

# The banner is replaced by the report regenerating itself. If that stops
# happening this file's whole argument collapses, so it is asserted here too.
AF="${ROOT}/modules/backend/services/fusion/autofuse.py"
grep -q '_regenerate_report(case_id, d)' "$AF" \
  || { echo "  FAIL an automatic fuse no longer regenerates the report -- the banner was removed on the promise that it would"; fails=$((fails+1)); }
grep -q 'def _report_enabled' "$AF" \
  || { echo "  FAIL the auto_report escape hatch is gone -- narration is the half that spends money"; fails=$((fails+1)); }
# The FUSE half must stay free and fast; only the separate report step may narrate.
python3 - "$AF" <<'ZPY' || fails=$((fails+1))
import re, sys
s = open(sys.argv[1], encoding="utf-8").read()
m = re.search(r"store\.fuse_case\((.*?)\)", s, re.S)
if not m or "allow_llm=False" not in m.group(1):
    sys.exit("  FAIL the automatic fuse no longer forbids the LLM -- narration is a "
             "separate step so the graph rebuild cannot be held up by a provider")
ZPY

if ! command -v node >/dev/null 2>&1; then
    echo "  SKIP no node on this host — _railCfg is exercised where node exists"
    exit $(( fails > 0 ? 1 : 0 ))
fi
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT

# ---- the manual escape hatch must work from every tab ------------------------
# Refusion / Rescan are reached from the Configuration rail, but the #cf-* inputs
# _railCfg() reads are written into #tabc by
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
