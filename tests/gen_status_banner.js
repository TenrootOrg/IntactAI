// The "generating…" banner must RENDER, for every shape the server can send.
//
// It was rewritten to take elapsed SECONDS from the server instead of a
// timestamp to subtract from the browser clock — and one line kept the old
// parameter name, `startedAt`. That threw ReferenceError every time the banner
// drew, which is only ever while a report is generating. renderReport died with
// it, #tabc kept whatever tab was there before, and the operator saw the Log
// sitting under the Analysis underline. Static tests all passed: nothing ever
// CALLED the function.
//
//   node tests/gen_status_banner.js <repo root>
const fs = require('fs'), path = require('path'), assert = require('assert');
const root = process.argv[2];
const html = fs.readFileSync(path.join(root, 'modules/nginx/html/cases.html'), 'utf8');
const a = html.indexOf('function genStatusHtml('), b = html.indexOf('function stopReportGenPoll(', a);
assert.ok(a !== -1 && b > a, 'could not slice genStatusHtml');
const genStatusHtml = new Function('esc', html.slice(a, b) + '\n; return genStatusHtml;')
                      (s => String(s == null ? '' : s));

const failures = [];
const check = (ok, why) => { if (!ok) failures.push(why); };

// Every shape /api/cases/<id> can produce: absent while a job is starting,
// numeric once measured, null on an unparseable stamp — and each phase.
for (const elapsed of [null, undefined, 0, 1, 42, 125, 600, 86400, NaN, 'x'])
  for (const phase of [null, undefined, 'narrative', 'advisory', 'checklist'])
    for (const pe of [null, 0, 30, NaN]) {
      let out;
      try { out = genStatusHtml(elapsed, phase, pe); }
      catch (e) { check(false, `threw for (${elapsed}, ${phase}, ${pe}): ${e.message}`); continue; }
      check(typeof out === 'string' && out.includes('agbanner'),
        `produced no banner for (${elapsed}, ${phase}, ${pe})`);
    }

// ...and says the right thing.
check(/starting…/.test(genStatusHtml(null, 'narrative', null)),
  'with no elapsed figure yet the banner should say "starting…"');
check(/just started/.test(genStatusHtml(20, 'narrative', 20)),
  '20s in, the banner should say "just started"');
check(/running 10 min/.test(genStatusHtml(600, 'narrative', 600)),
  '600s in, the banner should say "running 10 min"');
check(/Report ready/.test(genStatusHtml(600, 'checklist', 30)),
  'the checklist phase means the report is already readable — say so');
check(!/NaN|undefined|Infinity/.test(genStatusHtml(NaN, 'narrative', NaN)),
  'a missing figure must never reach the screen as NaN/undefined');

if (failures.length) {
  console.error('FAIL:\n  - ' + failures.slice(0, 10).join('\n  - ')
                + (failures.length > 10 ? `\n  …and ${failures.length - 10} more` : ''));
  process.exit(1);
}
console.log('generating banner: renders for every server input, and reads correctly');
