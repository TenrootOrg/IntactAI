// Drives the REAL _usd/_aiBudgetLine/_aiCostHtml from cases.html (see test_case_ai_cost.py).
const fs = require('fs'), path = require('path'), assert = require('assert');
const html = fs.readFileSync(path.join(__dirname, '..', 'modules/nginx/html/cases.html'), 'utf8');
const grab = name => { const i = html.indexOf('function ' + name + '('); assert(i >= 0, name);
  let d = 0, j = html.indexOf('{', i); for (; j < html.length; j++) { if (html[j] === '{') d++; else if (html[j] === '}' && --d === 0) break; }
  return html.slice(i, j + 1); };
const esc = s => String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
eval(['_usd', '_aiBudgetLine', '_aiCostHtml', '_aiCostChip'].map(grab).join('\n') +
     '\nglobal._usd=_usd; global._aiBudgetLine=_aiBudgetLine; global._aiCostHtml=_aiCostHtml; global._aiCostChip=_aiCostChip;');

// the page's existing money format (also the cost badge's)
assert.strictEqual(_usd(1.5), '$1.50');
assert.strictEqual(_usd(0.0042), '$0.0042', 'a tiny call still shows a price');

// header warning: nothing below 80%, amber from 80, red at 100
const d = (cost, budget) => ({ cost_usd: cost, budget_usd: budget, used_pct: budget ? 100 * cost / budget : null });
assert.strictEqual(_aiBudgetLine(d(7, 10)), '');
assert.strictEqual(_aiBudgetLine(d(7, null)), '', 'no budget, no warning');
assert(/\$8\.00 of \$10\.00 used \(80%\)/.test(_aiBudgetLine(d(8, 10))));
assert(/used up: \$10\.50 of \$10\.00.*No new AI calls/.test(_aiBudgetLine(d(10.5, 10))));

// configuration block
const empty = _aiCostHtml({ calls: 0, budget_usd: 5 });
assert(/no AI calls recorded/.test(empty) && /Budget \$5\.00\./.test(empty));
assert(!/Settings/.test(html.slice(html.indexOf('function _aiCostHtml('), html.indexOf('function loadAiCost('))),
       'no platform-wide default any more: each case has its own budget');
const full = _aiCostHtml({ calls: 3, cost_usd: 1.75, estimated_usd: 1.0, since: '2026-11-22T10:00:00Z',
                           budget_usd: 5, used_pct: 35,
                           by_source: [{ name: 'chat', calls: 2, cost_usd: 1.25 }, { name: 'report', calls: 1, cost_usd: 0.5 }],
                           by_model: [{ name: '<m>', calls: 3, cost_usd: 1.75 }] });
assert(/AI cost: <b>\$1\.75<\/b> across 3 call\(s\) since 2026-11-22 · \$1\.00 of it estimated\./.test(full));
assert(/Budget \$5\.00 — 35% used\./.test(full));
assert(/chat <span[^>]*>· 2 call\(s\)<\/span><\/span><span>\$1\.25/.test(full), 'by source');
assert(/&lt;m&gt;/.test(full) && !/<m>/.test(full), 'names are escaped');
assert(/No budget set\./.test(_aiCostHtml({ calls: 1, cost_usd: 0.1, estimated_usd: 0, by_source: [], by_model: [] })));

// Case Management: each case's cost on its card (the list carries ai_cost_usd)
assert.strictEqual(_aiCostChip({}), '', 'the Analysis header has no list cost: no chip');
assert(/AI: \$0\.430 \(no limit\)/.test(_aiCostChip({ ai_cost_usd: 0.43 })));
assert(/AI: \$0\.00 \(no limit\)/.test(_aiCostChip({ ai_cost_usd: 0 })) || /AI: \$0\.0000/.test(_aiCostChip({ ai_cost_usd: 0 })));
assert(/var\(--muted\).*AI: \$1\.00 \/ \$5\.00/.test(_aiCostChip({ ai_cost_usd: 1, ai_budget_usd: 5 })));
assert(/var\(--high\)/.test(_aiCostChip({ ai_cost_usd: 4, ai_budget_usd: 5 })), 'amber from 80%');
assert(/var\(--crit\)/.test(_aiCostChip({ ai_cost_usd: 5, ai_budget_usd: 5 })), 'red when used up');
console.log('ok');
