// Renders the Analysis tab's "template report" banner for every situation an
// operator can meet, from the REAL cases.html functions and the REAL backend
// messages (passed in as JSON by test_air_gap_banner.py), and checks each one
// tells a single, consistent story. Prints every rendered banner so a person
// can read them all in one place: `node tests/air_gap_banner.js <root> <json>`.
const fs = require('fs'), path = require('path'), assert = require('assert');
const [root, msgsJson] = process.argv.slice(2);
const html = fs.readFileSync(path.join(root, 'modules/nginx/html/cases.html'), 'utf8');
const pick = (start, end) => html.slice(html.indexOf(start), html.indexOf(end));
const code = pick('function reportAirGap(md, ls){', 'function renderReport(info){');
const esc = s => (s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const { reportAirGap, airGapBanner } = new Function('esc', code + '; return {reportAirGap, airGapBanner};')(esc);
const msgs = JSON.parse(msgsJson);            // {code: [problem, fix]}

const TEMPLATE = 'body\n\n---\n_Deterministic report — no model configured._\n';
const OLD_BG   = 'body\n\n---\n_Deterministic report — no live narration was requested._\n';
const NEW_BG   = 'body\n\n---\n_Deterministic report — the AI model was not used for this automatic report._\n';
const NARRATED = 'body\n\n---\n_Narrative by live LLM; fact tables deterministic._\n';
const text = h => h.replace(/<[^>]+>/g, '').replace(/&amp;/g, '&').replace(/\s+\n/g, '\n').split('\n').map(l => l.trim()).filter(Boolean);

const cases = [];
for (const [c, [reason, fix]] of Object.entries(msgs))
  cases.push({ name: `live check failed: ${c}`, md: TEMPLATE, ls: { available: false, code: c, reason, fix } });
// The same messages as the report's own closing tag records them (llm_sim joins
// "problem fix"), read back when the live check gives no answer.
for (const [c, [reason, fix]] of Object.entries(msgs))
  cases.push({ name: `report tag only: ${c}`, md: `body\n\n---\n_Deterministic report — ${reason} ${fix}_\n`, ls: null,
               wantProblem: reason });
cases.push({ name: 'model connected now', md: TEMPLATE, ls: { available: true } });
cases.push({ name: 'no live answer, old background report', md: OLD_BG, ls: null });
cases.push({ name: 'no live answer, new background report', md: NEW_BG, ls: null });
cases.push({ name: 'old report tag, unsplittable', md: 'body\n\n---\n_Deterministic report — The LLM API key was rejected — it looks invalid or outdated. Update it in Settings._\n', ls: null, legacy: true });

let failures = [];
for (const k of cases) {
  const lines = text(airGapBanner(reportAirGap(k.md, k.ls)));
  console.log(`\n[${k.name}]\n  ` + lines.join('\n  '));
  const all = lines.join(' ');
  const check = (ok, why) => { if (!ok) failures.push(`${k.name}: ${why} -> ${JSON.stringify(lines)}`); };
  check(lines.length === 3, 'banner must be exactly title, problem, fix');
  check(lines[0] === '📝 Offline report — written from the case evidence, without an AI model', 'one title for every case');
  check((all.match(/Regenerate report/g) || []).length === 1, 'says how to retry exactly once');
  check(!/undefined|null|\.\.|narrat|deterministic/i.test(all) && (k.legacy || !/LLM/.test(all)), 'no broken or internal wording');
  check((all.match(/try again/gi) || []).length <= 1, 'says "try again" at most once');
  if (k.ls && k.ls.available === true)
    check(!/Settings|API key|not|cannot|no /i.test(lines.slice(1).join(' ')), 'a connected model must not be described as missing');
  else
    check(!/connected now/i.test(all), 'a failing model must not be described as connected');
  if (k.ls && k.ls.reason) check(lines[1] === k.ls.reason, 'shows the backend problem verbatim');
  if (k.wantProblem) check(lines[1].startsWith(k.wantProblem), 'splits the tag back into the backend problem');
}
assert.strictEqual(airGapBanner(reportAirGap(NARRATED, { available: false, reason: 'x' })), '', 'narrated report: no banner');
if (failures.length) { console.error('\nFAIL\n' + failures.join('\n')); process.exit(1); }
console.log(`\nair-gap banner: ${cases.length} situations render one consistent story`);
