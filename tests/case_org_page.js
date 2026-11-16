// The real js/active-case.js (and client-manager.js) in jsdom: the Velociraptor
// org follows the active case. No page picks one: the cookie mirrors the case's
// org, the top bar shows it, a module page shows it read-only, and a client list
// tied to another case (the schedule form) asks for THAT case's fleet.
// `node <file> <root>`; exit 77 = no jsdom.
const fs = require('fs'), path = require('path'), assert = require('assert');
let JSDOM;
try { ({ JSDOM } = require('jsdom')); } catch (e) { process.exit(77); }

const html = path.join(process.argv[2], 'modules/nginx/html/js');
const ac = fs.readFileSync(path.join(html, 'active-case.js'), 'utf8');
const cmSrc = fs.readFileSync(path.join(html, 'utils/client-manager.js'), 'utf8');
const tick = () => new Promise(r => setTimeout(r, 120));

(async () => {
  const dom = new JSDOM('<div id="bar"></div><div class="velo-org-slot" data-hint="Imports land here."></div><div id="list"></div>',
                        { url: 'https://intact.local/', runScripts: 'outside-only' });
  const w = dom.window;
  const sent = [];
  const cases = [{ case_id: 'c-def', name: 'Default', is_default: true, velo_org: 'root' },
                 { case_id: 'c-acme', name: 'Acme IR', velo_org: 'OFM5G' }];
  w.fetch = async (url, init) => {
    const h = new w.Headers((init && init.headers) || {});
    sent.push({ url: String(url), caseId: h.get('X-Case-Id') });
    const body = String(url).startsWith('/api/cases') ? { cases }
      : String(url).startsWith('/api/velociraptor/orgs') ? { orgs: [{ id: 'root', name: 'root' }, { id: 'OFM5G', name: 'Acme' }] }
      : String(url).startsWith('/api/clients') ? { total: 0, items: [] } : {};
    return { ok: true, status: 200, json: async () => body, clone() { return this; } };
  };
  w.escapeHtml = s => String(s);
  w.localStorage.setItem('activeCaseId', 'c-acme');
  let changed = 0;
  w.addEventListener('velo-org-changed', () => { changed++; });
  w.eval(ac);
  w.eval(cmSrc);

  // the top bar: the case, and its org next to it
  await w.ActiveCase.renderCaseSelector(w.document.getElementById('bar'));
  await tick();
  assert.match(w.document.cookie, /intact_case=c-acme/, 'the cookie names the case, never an org: ' + w.document.cookie);
  assert.doesNotMatch(w.document.cookie, /velo_org=/, 'the old per-page org cookie is gone');
  assert.strictEqual(w.VeloOrg.get(), 'OFM5G', 'the case\'s org, for display and the GUI link');
  assert.ok(changed >= 1, 'pages hear about it (client lists reload)');
  const org = w.document.querySelector('#bar .ac-org');
  assert.ok(org, 'the top bar shows the org');
  assert.strictEqual(org.querySelector('b').textContent, 'Acme (OFM5G)');
  assert.ok(!w.document.querySelector('#bar select.velo-org-select'), 'no org dropdown in the top bar');

  // the DASHBOARD top bar (js/components/workspace-bar.js): "Case: X  Org: Y"
  const wsb = w.document.createElement('div'); wsb.id = 'workspace-bar'; w.document.body.appendChild(wsb);
  w.eval(fs.readFileSync(path.join(html, 'components/workspace-bar.js'), 'utf8'));
  await w.renderTopWorkspace(wsb);
  await tick();
  assert.match(wsb.textContent, /Case:\s*Acme IR/);
  const orgA = wsb.querySelector('#ws-org-link'), caseA = wsb.querySelector('#ws-link');
  assert.strictEqual(orgA.textContent, 'Acme (OFM5G)', 'the org next to the case');
  assert.strictEqual(orgA.getAttribute('style'), caseA.getAttribute('style'), 'the org looks the same as the case');
  assert.strictEqual(orgA.getAttribute('href'), '#cases', 'it opens Case Management, where the org is set');

  // a module page: read-only, never a picker
  const slot = w.document.querySelector('.velo-org-slot');
  assert.ok(!slot.querySelector('select'), 'no org dropdown on a module page');
  assert.match(slot.textContent, /Velociraptor org: Acme \(OFM5G\)/);
  assert.match(slot.textContent, /Imports land here\./);
  assert.ok(!('set' in w.VeloOrg), 'nothing can pick an org any more');

  // every /api fetch carries the case; the backend takes the org from it
  sent.length = 0;
  await w.fetch('/api/anything');
  assert.strictEqual(sent[0].caseId, 'c-acme');

  // another case: the org moves with it
  w.ActiveCase.set('c-def');
  await tick();
  assert.match(w.document.cookie, /intact_case=c-def/, 'the cookie follows: ' + w.document.cookie);
  assert.strictEqual(w.VeloOrg.get(), 'root', 'back to root');
  assert.match(slot.textContent, /Velociraptor org: root/, 'the label follows');

  // a client list tied to its own case asks for that case's fleet
  sent.length = 0;
  const cm = new w.ClientManager('list', 'cb', { caseId: () => 'c-acme' });
  await cm.load();
  const req = sent.find(s => s.url.startsWith('/api/clients'));
  assert.strictEqual(req.caseId, 'c-acme', 'explicit case wins over the active one');
  console.log('ok');
})().catch(e => { console.error(e && e.stack || e); process.exit(1); });
