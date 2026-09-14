// Runs the REAL blueprints-forensics.js against a fake page and checks what the
// Collection and Hunt start requests send. `node <file> <root>`
const fs = require('fs'), path = require('path'), assert = require('assert');
const src = fs.readFileSync(path.join(process.argv[2], 'modules/nginx/html/js/blueprints-forensics.js'), 'utf8');

function page(mode) {
  const els = {};
  const el = (id, extra = {}) => (els[id] = Object.assign({ id, value: '', textContent: '', innerHTML: '', className: '',
    classList: { add() {}, remove() {} }, checked: false }, extra));
  el('forensics-blueprint-select', { value: 'bp1' });
  el('forensics-mode-ai', { className: mode === 'ai' ? 'border-purple-500' : '' });
  el('forensics-mode-raw', { className: mode === 'raw' ? 'border-blue-500' : '' });
  ['forensics-bp-expiry', 'forensics-bp-timeout', 'forensics-bp-cpu', 'forensics-artifact-count', 'forensics-blueprint-info',
   'forensics-bp-description', 'forensics-status', 'forensics-per-artifact-toggle'].forEach(id => el(id));
  el('forensics-collection-time', { value: '30' });
  const sent = [], alerts = [];
  const blueprint = { id: 'bp1', name: 'QuickWins', artifacts: ['A.B'], settings: { hunt_expiry: 720, timeout: 3600, cpu_limit: 50 } };
  const ctx = {
    document: { getElementById: id => els[id] || null, querySelectorAll: () => [], addEventListener() {}, querySelector: () => null },
    ClientManager: class { constructor() {} getSelected() { return ['C.1']; } load() { return Promise.resolve(); } },
    getBlueprintById: async () => blueprint, loadBlueprints: async () => [blueprint],
    fetch: async (url, opt) => { sent.push({ url, body: JSON.parse(opt.body) }); return { ok: true, json: async () => ({ run_id: 'r1' }) }; },
    alert: m => alerts.push(m), setTimeout: () => 0, window: {}, Alpine: undefined, console,
  };
  const names = Object.keys(ctx);
  const api = new Function(...names, src + '; return { onForensicsBlueprintChange, startForensicsCollection, resetForensicsRunSettings };')
    (...names.map(n => ctx[n]));
  return { els, sent, alerts, api };
}

(async () => {
  // 1. choosing a blueprint fills the fields with its defaults
  {
    const p = page('ai');
    await p.api.onForensicsBlueprintChange('bp1');
    assert.deepStrictEqual([p.els['forensics-bp-expiry'].value, p.els['forensics-bp-timeout'].value, p.els['forensics-bp-cpu'].value], [720, 3600, 50]);
  }
  // 2. Collection sends the edited timeout + CPU, and no expiry
  {
    const p = page('ai');
    await p.api.onForensicsBlueprintChange('bp1');
    p.els['forensics-bp-timeout'].value = '1800'; p.els['forensics-bp-cpu'].value = '25';
    await p.api.startForensicsCollection();
    assert.strictEqual(p.sent[0].url, '/api/agentic/run');
    assert.strictEqual(p.sent[0].body.timeout_seconds, 1800);
    assert.strictEqual(p.sent[0].body.cpu_limit, 25);
    assert.ok(!('expire_minutes' in p.sent[0].body), 'a collection has no expiry');
  }
  // 3. Hunt sends all three edited values
  {
    const p = page('raw');
    await p.api.onForensicsBlueprintChange('bp1');
    p.els['forensics-bp-expiry'].value = '90'; p.els['forensics-bp-timeout'].value = '600'; p.els['forensics-bp-cpu'].value = '10';
    await p.api.startForensicsCollection();
    assert.strictEqual(p.sent[0].url, '/api/velociraptor/bestpractice');
    assert.deepStrictEqual([p.sent[0].body.expire_minutes, p.sent[0].body.timeout_seconds, p.sent[0].body.cpu_limit], [90, 600, 10]);
  }
  // 4. untouched fields send the blueprint defaults
  {
    const p = page('raw');
    await p.api.onForensicsBlueprintChange('bp1');
    await p.api.startForensicsCollection();
    assert.deepStrictEqual([p.sent[0].body.expire_minutes, p.sent[0].body.timeout_seconds, p.sent[0].body.cpu_limit], [720, 3600, 50]);
  }
  // 5. an invalid value is refused on the page, nothing is sent
  for (const [id, bad] of [['forensics-bp-cpu', '150'], ['forensics-bp-timeout', '10'], ['forensics-bp-cpu', '2.5'], ['forensics-bp-timeout', 'abc']]) {
    const p = page('ai');
    await p.api.onForensicsBlueprintChange('bp1');
    p.els[id].value = bad;
    await p.api.startForensicsCollection();
    assert.strictEqual(p.sent.length, 0, `${id}=${bad} must not be sent`);
    assert.ok(p.alerts.length === 1 && /between/.test(p.alerts[0]), `${id}=${bad} explains the range`);
  }
  // 6. reset restores the blueprint defaults; a new blueprint replaces them
  {
    const p = page('ai');
    await p.api.onForensicsBlueprintChange('bp1');
    p.els['forensics-bp-cpu'].value = '5';
    p.api.resetForensicsRunSettings();
    assert.strictEqual(p.els['forensics-bp-cpu'].value, 50);
  }
  console.log('forensics run settings: all checks pass');
})().catch(e => { console.error('FAIL:', e.message); process.exit(1); });
