// The REAL ClientManager with the scheduler's options: offline clients are listed
// and say, in red, that a scheduled run will not work for them while offline.
// Other pages (no offlineNote) are unchanged. `node <file> <root>`
const fs = require('fs'), path = require('path'), assert = require('assert');
const src = fs.readFileSync(path.join(process.argv[2], 'modules/nginx/html/js/utils/client-manager.js'), 'utf8');

function el() {
  return { innerHTML: '', className: '', children: [], addEventListener() {}, querySelector: () => null, parentNode: null };
}
async function build(opts, clients) {
  const container = el();
  container.parentNode = { insertBefore: () => {} };
  const doc = { getElementById: id => (id === 'list' ? container : null), createElement: () => el() };
  const fetch = async () => ({ ok: true, json: async () => ({ items: clients, total: clients.length }) });
  const escapeHtml = s => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  const window = {};
  new Function('document', 'fetch', 'escapeHtml', 'window', src)(doc, fetch, escapeHtml, window);
  const m = new window.ClientManager('list', 'cb', opts);
  await m.load();
  return container.innerHTML;
}
const now = Date.now() * 1000;
const clients = [
  { client_id: 'C.on', hostname: 'ONLINE-PC', os: 'windows', labels: [], last_seen_at: now },
  { client_id: 'C.off', hostname: 'OFFLINE-PC', os: 'windows', labels: [], last_seen_at: 1 },
];
const NOTE = 'Offline now: the scheduled run will not work for this client unless it is online when the schedule runs.';

(async () => {
  // the scheduler's settings (js/scheduler.js)
  const sched = await build({ onlineOnly: false, offlineNote: NOTE }, clients);
  assert(sched.includes('ONLINE-PC') && sched.includes('OFFLINE-PC'), 'offline clients must be listed');
  assert.strictEqual(sched.split(NOTE).length - 1, 1, 'the red note is on the offline row only');
  assert(sched.includes('color:#f87171'), 'the note is red');

  // every other picker keeps its default: online only, no note
  const other = await build({}, clients);
  assert(other.includes('ONLINE-PC') && !other.includes('OFFLINE-PC'), 'default stays online only');
  assert(!other.includes('Offline now'), 'no note without the option');

  // and the scheduler really is built with those settings
  const sj = fs.readFileSync(path.join(process.argv[2], 'modules/nginx/html/js/scheduler.js'), 'utf8');
  const ctor = sj.slice(sj.indexOf("const schedulerClientManager = new ClientManager("));
  assert(/onlineOnly:\s*false/.test(ctor.slice(0, 400)) && ctor.slice(0, 400).includes(NOTE), 'scheduler options');
  console.log('ok');
})().catch(e => { console.error(e.message); process.exit(1); });
