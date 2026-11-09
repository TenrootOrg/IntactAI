// Runs the REAL upload.js / blueprints-forensics.js / reset functions against
// fake pages and checks the busy flags and buttons come back after a System
// guard block, a Stop and a success. `node <file> <root>`
const fs = require('fs'), path = require('path'), assert = require('assert');
const root = process.argv[2];
const read = rel => fs.readFileSync(path.join(root, 'modules/nginx/html', rel), 'utf8');

// Pull one top-level `function name(...) {...}` out of a page script.
function fnSrc(src, name) {
  const start = src.indexOf(`function ${name}(`);
  assert.ok(start >= 0, `${name} not found`);
  const end = src.indexOf('\n}\n', start);
  return src.slice(start, end + 2);
}

function fakeEl(id) {
  const cls = new Set();
  return { id, disabled: false, value: 'x', textContent: '', style: { width: '40%' },
    classList: { add: (...c) => c.forEach(x => cls.add(x)), remove: (...c) => c.forEach(x => cls.delete(x)), has: c => cls.has(c) } };
}

function loadUploader(blockResult) {
  let last = null;
  class FakeUpload {
    constructor(file, opts) { this.opts = opts; this.url = ''; this.aborted = null; last = this; }
    findPreviousUploads() { return Promise.resolve([]); }
    start() {}
    abort(del) { this.aborted = del; }
  }
  const win = { ActiveCase: { blockIfSystem: async () => blockResult, get: () => 'c1' } };
  const ctx = { tus: { Upload: FakeUpload }, window: win, document: { getElementById: () => null }, console: { log() {}, error() {} },
                location: {} };
  const names = Object.keys(ctx);
  new Function(...names, read('js/upload.js'))(...names.map(n => ctx[n]));
  return { TusUploader: win.TusUploader, lastUpload: () => last };
}

const tick = () => new Promise(r => setTimeout(r, 0));

(async () => {
  // 1. System guard block calls onCancel (memory clears `uploading`)
  {
    const { TusUploader } = loadUploader(true);
    let cancelled = 0;
    new TusUploader({ purpose: 'memory', onCancel: () => cancelled++ }).upload({ name: 'a.raw' });
    await tick();
    assert.strictEqual(cancelled, 1, 'a blocked upload must fire onCancel');
  }
  // 2. registered as soon as tusd gives the url; Stop aborts and fires onCancel
  {
    const { TusUploader, lastUpload } = loadUploader(false);
    let cancelled = 0;
    new TusUploader({ purpose: 'memory', onCancel: () => cancelled++ }).upload({ name: 'a.raw' });
    await tick();
    const up = lastUpload();
    up.url = 'https://x/api/uploads/abc123';
    up.opts.onUploadUrlAvailable();
    assert.ok(TusUploader._active.has('abc123'), 'registered before the first progress event');
    assert.ok(TusUploader.abortUpload('abc123'));
    assert.strictEqual(up.aborted, true);
    assert.strictEqual(cancelled, 1, 'Stop must fire onCancel');
    assert.ok(!TusUploader._active.has('abc123'));
  }
  // 3. memory store: its uploaders wire onCancel to the busy flags
  {
    const mem = read('js/memory.js');
    assert.match(mem, /onCancel: \(\) => \{ this\.symUploading = false;/);
    assert.match(mem, /onCancel: \(\) => \{ this\.uploading = false; \}/);
  }
  // 4. Timesketch reset re-enables the Upload button
  {
    const els = {};
    ['ts-upload-progress', 'ts-upload-bar', 'ts-dropzone-text', 'ts-kape-file', 'ts-upload-btn'].forEach(id => els[id] = fakeEl(id));
    els['ts-upload-btn'].disabled = true;
    els['ts-upload-btn'].classList.add('opacity-50', 'cursor-not-allowed');
    new Function('document', 'let tsSelectedFile = {};' + fnSrc(read('js/timesketch.js'), 'resetTimesketchUpload') + '; resetTimesketchUpload();')
      ({ getElementById: id => els[id] || null });
    const b = els['ts-upload-btn'];
    assert.strictEqual(b.disabled, false, 'Upload button re-enabled');
    assert.ok(!b.classList.has('opacity-50') && !b.classList.has('cursor-not-allowed'));
  }
  // 5. Velociraptor reset hides the progress box the partial actually has
  {
    const part = read('partials/velociraptor.html');
    const ids = ['offline-upload-progress', 'offline-upload-bar', 'offline-import-btn', 'offline-dropzone-text', 'offline-import-file'];
    ids.forEach(id => assert.ok(part.includes(`id="${id}"`), `partial has #${id}`));
    const els = {}; ids.forEach(id => els[id] = fakeEl(id));
    els['offline-import-btn'].disabled = true;
    new Function('document', 'let selectedImportFile = {};' + fnSrc(read('js/velociraptor.js'), 'resetOfflineImport') + '; resetOfflineImport();')
      ({ getElementById: id => els[id] || null });
    assert.ok(els['offline-upload-progress'].classList.has('hidden'), 'progress box hidden');
    assert.strictEqual(els['offline-upload-bar'].style.width, '0%');
    assert.strictEqual(els['offline-import-btn'].disabled, false);
  }
  // 6. Forensics Start: mode comes from the argument, double-click sends one request
  {
    const els = {};
    const el = (id, extra = {}) => (els[id] = Object.assign({ id, value: '', textContent: '', innerHTML: '', className: '',
      disabled: false, classList: { add() {}, remove() {} }, checked: false }, extra));
    el('forensics-blueprint-select', { value: 'bp1' });
    // Tabs styled the "wrong" way round: the mode must not come from CSS.
    el('forensics-mode-ai', { className: 'border-blue-500' });
    el('forensics-mode-raw', { className: 'border-purple-500' });
    el('forensics-start-btn');
    ['forensics-bp-expiry', 'forensics-bp-timeout', 'forensics-bp-cpu', 'forensics-artifact-count', 'forensics-blueprint-info',
     'forensics-bp-description', 'forensics-status', 'forensics-per-artifact-toggle'].forEach(id => el(id));
    el('forensics-collection-time', { value: '30' });
    const sent = [];
    let release;
    const gate = new Promise(r => { release = r; });
    const blueprint = { id: 'bp1', name: 'Q', artifacts: ['A.B'], settings: { hunt_expiry: 720, timeout: 3600, cpu_limit: 50 } };
    const ctx = {
      document: { getElementById: id => els[id] || null, querySelectorAll: () => [], addEventListener() {}, querySelector: () => null },
      ClientManager: class { getSelected() { return ['C.1']; } confirmMany() { return true; } load() { return Promise.resolve(); } },
      getBlueprintById: async () => blueprint, loadBlueprints: async () => [blueprint],
      fetch: async (url) => { sent.push(url); await gate; return { ok: true, json: async () => ({ run_id: 'r1' }) }; },
      alert: () => {}, setTimeout: () => 0, window: { addEventListener() {} }, Alpine: undefined, console,
    };
    const names = Object.keys(ctx);
    const api = new Function(...names, read('js/blueprints-forensics.js') + '; return { startForensicsCollection };')(...names.map(n => ctx[n]));
    const a = api.startForensicsCollection('ai');
    const b = api.startForensicsCollection('ai');
    assert.strictEqual(els['forensics-start-btn'].disabled, true, 'button disabled while starting');
    await tick(); await tick();
    release(); await a; await b;
    assert.deepStrictEqual(sent, ['/api/agentic/run'], 'one collection, from the argument not the CSS');
    assert.strictEqual(els['forensics-start-btn'].disabled, false, 'button back after the request');
    await api.startForensicsCollection('raw');
    assert.deepStrictEqual(sent, ['/api/agentic/run', '/api/velociraptor/bestpractice']);
    assert.match(read('partials/velociraptor.html'), /id="forensics-start-btn" @click="startForensicsCollection\(forensicsMode\)"/);
  }
  console.log('uploadsui frontend: all checks pass');
})().catch(e => { console.error('FAIL:', e.message); process.exit(1); });
