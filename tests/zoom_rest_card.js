// Drives the REAL _ztRest from cases.html (see test_zoom_rest_card.py).
const fs = require('fs'), path = require('path'), assert = require('assert');
const html = fs.readFileSync(path.join(__dirname, '..', 'modules/nginx/html/cases.html'), 'utf8');
const grab = name => { const i = html.indexOf('function ' + name + '('); assert(i >= 0, name);
  let d = 0, j = html.indexOf('{', i); for (; j < html.length; j++) { if (html[j] === '{') d++; else if (html[j] === '}' && --d === 0) break; }
  return html.slice(i, j + 1); };
const esc = s => String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const _scopeDates = w => (w || {}).start + ' – ' + (w || {}).end;
eval(grab('_ztRest') + '\nglobal._ztRest=_ztRest;');

const w = (s, e, n, sev) => ({ window: { start: s, end: e }, host_labels: ['A', 'B'].slice(0, n), finding_count: n * 2, severity: sev });
const t = { rollup: true, rollup_windows: 3, finding_count: 6,
            windows: [w('2024-01-01', '2024-01-02', 1, 'low'), w('2024-02-01', '2024-02-02', 2, 'medium'), w('2024-03-01', '2024-03-02', 1, 'high')] };
const out = _ztRest('case_1', t, 6);
assert(!/Accounting row|Not a scope/.test(out), 'the old internal wording is gone');
assert(/Ranked below the phases above/.test(out), 'says what the windows are');
assert(/<summary>Show the 3 window\(s\)<\/summary>/.test(out), 'opens on demand');
assert.strictEqual((out.match(/applyZoomRest\('case_1',6,\d\)/g) || []).length, 3, 'one Analyze per window');
assert(/applyZoomRest\('case_1',6,2\)/.test(out));
assert(/2024-02-01 – 2024-02-02/.test(out) && /2 host\(s\) · 4 detection\(s\)/.test(out));
assert(!/more \(the oldest/.test(out), 'nothing more to say when all are listed');

const capped = _ztRest('case_1', Object.assign({}, t, { rollup_windows: 250 }), 6);
assert(/…and 247 more \(the oldest 3 are listed\)/.test(capped), 'a capped list says so');

const bare = _ztRest('case_1', { rollup: true, rollup_windows: 5, finding_count: 9 }, 6);   // an older backend: no list
assert(/Ranked below/.test(bare) && !/<details/.test(bare) && !/Open the list/.test(bare), 'no list, no promise of one');
console.log('ok');
