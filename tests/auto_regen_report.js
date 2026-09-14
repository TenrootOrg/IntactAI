// Drives the REAL shouldAutoRegen / maybeAutoRegen from cases.html with the page
// globals stubbed. `node tests/auto_regen_report.js <root>`
const fs = require('fs'), path = require('path');
const html = fs.readFileSync(path.join(process.argv[2], 'modules/nginx/html/cases.html'), 'utf8');
const code = html.slice(html.indexOf('function shouldAutoRegen('), html.indexOf('function renderReport(info){'));

const TEMPLATE_NO_MODEL = 'r\n\n---\n_Deterministic report — No AI model is selected. Choose one in Settings ▸ Agentic, then try again._\n';
const TEMPLATE_KEY = 'r\n\n---\n_Deterministic report — The AI provider rejected the API key. Enter a valid key in Settings ▸ Agentic, then try again._\n';
const BACKGROUND_NEW = 'r\n\n---\n_Deterministic report — the AI model was not used for this automatic report._\n';
const BACKGROUND_OLD = 'r\n\n---\n_Deterministic report — no live narration was requested._\n';
const NARRATED = 'r\n\n---\n_Narrative by live LLM; fact tables deterministic._\n';
const LIVE_OK = { available: true, code: 'ok', checked_live: true };
const CONFIG_OK = { available: true, code: 'ok' };            // from the case payload: never probed

function page(over = {}) {
  const store = new Map();
  const ctx = {
    curInfo: { case_id: 'A', _fresh: true, report_generating: false, llm_status: LIVE_OK },
    tab: 'report',
    window: { _md: TEMPLATE_NO_MODEL },
    regens: [],
    toast() {},
    regenReport(id) { ctx.regens.push(id); },
    sessionStorage: over.brokenStorage
      ? { getItem() { throw new Error('denied'); }, setItem() { throw new Error('denied'); } }
      : { getItem: k => store.has(k) ? store.get(k) : null, setItem: (k, v) => store.set(k, v) },
  };
  if (over.info === null) ctx.curInfo = null;
  else if (over.info) Object.assign(ctx.curInfo, over.info);
  if (over.md !== undefined) ctx.window._md = over.md;
  if (over.tab) ctx.tab = over.tab;
  const fns = new Function('ctx', 'with (ctx) { ' + code + '; return { shouldAutoRegen, maybeAutoRegen }; }')(ctx);
  return Object.assign(ctx, fns);
}

const fails = [];
const expect = (name, over, want, times = 1) => {
  const p = page(over);
  for (let i = 0; i < times; i++) p.maybeAutoRegen();
  const got = p.regens.length;
  console.log(`${got === want ? 'ok  ' : 'FAIL'} ${name}: ${got} regeneration(s)`);
  if (got !== want) fails.push(name);
};

expect('template (no model) + model connected now', {}, 1);
expect('template (key rejected) + model connected now', { md: TEMPLATE_KEY }, 1);
expect('opening the case again in the same tab does not repeat it', {}, 1, 3);
expect('storage blocked: still only once', { brokenStorage: true }, 1, 3);
expect('model set per config: starts at once, without waiting for the probe', { info: { llm_status: CONFIG_OK } }, 1);
expect('last live probe failed (carried in the case payload)', { info: { llm_status: { available: false, code: 'invalid_key', checked_live: false } } }, 0);
expect('model still not reachable', { info: { llm_status: { available: false, code: 'invalid_key', checked_live: true } } }, 0);
expect('background-fuse template (nothing switched)', { md: BACKGROUND_NEW }, 0);
expect('old background-fuse template', { md: BACKGROUND_OLD }, 0);
expect('report already written by the AI', { md: NARRATED }, 0);
expect('a report is already generating', { info: { report_generating: true } }, 0);
expect('case switch turned off', { info: { auto_regen_report: false } }, 0);
expect('not on the Analysis tab', { tab: 'timeline' }, 0);
expect('remembered view, server not answered yet', { info: { _fresh: false } }, 0);
expect('no case open', { info: null }, 0);

// Only the case on screen: another case in the same tab still gets its own one try.
const p = page();
p.maybeAutoRegen(); p.curInfo = { case_id: 'B', _fresh: true, llm_status: LIVE_OK }; p.maybeAutoRegen(); p.maybeAutoRegen();
const ok = JSON.stringify(p.regens) === '["A","B"]';
console.log(`${ok ? 'ok  ' : 'FAIL'} each case on screen is regenerated once, only when it is open: ${JSON.stringify(p.regens)}`);
if (!ok) fails.push('per-case');

if (fails.length) { console.error('\nFAILED: ' + fails.join('; ')); process.exit(1); }
console.log('\nauto-regenerate: all rules hold');
