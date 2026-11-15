"""Blueprint/scheduler Save guards and the read-only default card (QA F13, D9).

F13: a double-click on "Save Blueprint" / "Save Schedule" POSTed twice and made
two identical rows (a duplicate schedule runs every hunt twice). D9: default
cards offer Duplicate, not Edit, and Duplicate opens the create form pre-filled.

The real blueprints.js / scheduler.js run under node in a vm with a tolerant DOM
stub (jsdom is not installed here); fetch resolves late so the second click
lands while the first save is in flight. Skipped where node is unavailable.
"""

import os
import shutil
import subprocess
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
JS = os.path.join(ROOT, "modules/nginx/html/js")

HARNESS = r"""
const fs = require('fs'), vm = require('vm'), assert = require('assert');
const [bpSrc, schedSrc] = process.argv.slice(-2).map(p => fs.readFileSync(p, 'utf8'));

function context(values) {
  const els = {};
  const el = id => els[id] || (els[id] = {
    value: values[id] ?? '', checked: false, textContent: '', innerHTML: '', style: {}, dataset: {},
    options: [], parentElement: null,
    classList: { add() {}, remove() {}, toggle() {}, contains: () => false },
    addEventListener() {}, appendChild() {}, querySelector: () => null, querySelectorAll: () => [],
  });
  const writes = [];
  const ctx = {
    console, setTimeout, clearTimeout, setInterval, clearInterval, alerts: [], writes, els,
    document: {
      getElementById: el,
      querySelectorAll: s => s === '.blueprint-artifact-cb:checked' ? [{ value: 'A' }] : [],
      querySelector: () => null, addEventListener() {},
    },
    alert: m => ctx.alerts.push(m), confirm: () => true, escapeHtml: s => String(s ?? ''),
    initForensicsTab() {}, addEventListener() {},
    ClientManager: class { constructor() { this.totalClients = 0; } getSelected() { return []; }
                           confirmMany() { return true; } load() {} },
    fetch: (url, opts = {}) => {
      if (opts.method && opts.method !== 'GET') writes.push(opts.method + ' ' + url);
      const body = /\/api\/blueprints\/velociraptor\/velo_default$/.test(url)
        ? { id: 'velo_default', name: 'Velo', is_default: true, artifacts: ['A'], settings: {} }
        : { blueprints: [], jobs: [], success: true, blueprint: {} };
      return new Promise(r => setTimeout(() => r({ ok: true, json: async () => body }), 30));
    },
  };
  ctx.window = ctx;
  vm.createContext(ctx);
  return ctx;
}

(async () => {
  // Blueprint Save: two clicks while the first POST is in flight -> one POST.
  const b = context({ 'blueprint-name': 'Mine', 'blueprint-edit-id': '' });
  vm.runInContext(bpSrc, b);
  vm.runInContext("window.currentBlueprintEditType = 'velociraptor'", b);
  await Promise.all([vm.runInContext('saveBlueprintFromModal()', b), vm.runInContext('saveBlueprintFromModal()', b)]);
  assert.deepStrictEqual(b.writes, ['POST /api/blueprints/velociraptor'], 'double click: ' + b.writes);
  await vm.runInContext('saveBlueprintFromModal()', b);   // guard released after the save
  assert.strictEqual(b.writes.length, 2, 'a later Save must still work');

  // Default card: Duplicate with the hint, no Edit, no Delete. Custom: Edit + Delete.
  const card = bp => vm.runInContext('renderBlueprintCard(' + JSON.stringify(bp) + ')', b);
  const def = card({ id: 'velo_default', name: 'Velo', is_default: true, _type: 'velociraptor', _actualType: 'velociraptor' });
  assert.ok(!/>Edit</.test(def) && !/>Delete</.test(def), 'default card offers Edit/Delete');
  assert.ok(/>Duplicate</.test(def) && /cannot be edited/.test(def), 'default card lacks Duplicate + hint');
  const cus = card({ id: 'custom_1', name: 'Mine', is_default: false, _type: 'velociraptor', _actualType: 'velociraptor' });
  assert.ok(/>Edit</.test(cus) && />Delete</.test(cus), 'custom card lost Edit/Delete');

  // Duplicate opens the create form: no edit id, "(copy)" name, Save POSTs.
  await vm.runInContext("editBlueprint('velo_default', 'velociraptor', true)", b);
  assert.strictEqual(b.els['blueprint-edit-id'].value, '');
  assert.strictEqual(b.els['blueprint-name'].value, 'Velo (copy)');
  assert.ok(/^Duplicate/.test(b.els['blueprint-modal-title'].textContent));

  // Schedule Save: same double click -> one POST.
  const s = context({ 'schedule-name': 'n', 'schedule-blueprint-type': 'velociraptor',
                      'schedule-blueprint-select': 'velo_default', 'schedule-edit-id': '' });
  vm.runInContext(schedSrc, s);
  await Promise.all([vm.runInContext('saveScheduleFromModal()', s), vm.runInContext('saveScheduleFromModal()', s)]);
  assert.deepStrictEqual(s.writes, ['POST /api/scheduler/jobs'], 'double click: ' + s.writes);
  await vm.runInContext('saveScheduleFromModal()', s);
  assert.strictEqual(s.writes.length, 2, 'a later Save must still work');
  assert.deepStrictEqual([b.alerts, s.alerts], [[], []]);
  console.log('ok');
})().catch(e => { console.error(e.stack || e.message); process.exit(1); });
"""


class SaveGuardsAndDefaultCard(unittest.TestCase):
    @unittest.skipIf(shutil.which("node") is None, "node is not installed")
    def test_real_scripts(self):
        r = subprocess.run(["node", "-e", HARNESS, "--",
                            os.path.join(JS, "blueprints.js"), os.path.join(JS, "scheduler.js")],
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(0, r.returncode, r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
