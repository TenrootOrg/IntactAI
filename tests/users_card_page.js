// Settings -> Users from the REAL partials/settings.html markup, js/active-case.js
// (the fetch hook), js/access.js (role hiding, re-auth prompt, toast),
// js/components/users-card.js and Alpine, in jsdom with a mocked backend:
//   - an Operator never sees the card and never asks for /api/users;
//   - an Admin's own row, the Super-admin's row and a fellow Admin's row have
//     no actions; rows below get Disable/Enable + Reset password;
//   - Add user goes through the 403 reauth_required -> password prompt ->
//     /api/auth/reauth -> one retry, then shows the one-time password ONCE;
//   - a 403 forbidden on a change becomes a toast;
//   - only the Super-admin sees Transfer Super-admin;
//   - the MFA column (On/Off, "required" for an Admin row that is off) and
//     Reset 2-step only on rows you may manage that have it on.
// `node <file> <root>`; exit 77 = no jsdom.
const fs = require('fs'), path = require('path'), assert = require('assert');
let JSDOM;
try { ({ JSDOM } = require('jsdom')); } catch (e) { process.exit(77); }

const html = path.join(process.argv[2], 'modules/nginx/html');
const read = f => fs.readFileSync(path.join(html, f), 'utf8');
const sleep = ms => new Promise(r => setTimeout(r, ms));
const settings = read('partials/settings.html');
const panel = settings.slice(settings.indexOf('<!-- Users Tab'), settings.indexOf('<!-- Logs Tab'));
assert.ok(panel.includes('usersCard()'), 'Users panel found in settings.html');

const ROLES = [['readonly', 'Read-only'], ['operator', 'Operator'], ['admin', 'Admin'], ['superadmin', 'Super-admin']];
const RANK = { readonly: 0, operator: 1, admin: 2, superadmin: 3 };
const USERS = [
  { username: 'root', role: 'superadmin', enabled: true, temp_password_pending: false, last_login: 1764000000, mfa_enabled: true },
  { username: 'alice', role: 'admin', enabled: true, temp_password_pending: false, last_login: 1764000000, mfa_enabled: true },
  { username: 'bob', role: 'admin', enabled: true, temp_password_pending: false, last_login: null, mfa_enabled: false },
  { username: 'carol', role: 'operator', enabled: true, temp_password_pending: true, last_login: null, mfa_enabled: true },
  { username: 'dave', role: 'readonly', enabled: false, temp_password_pending: false, last_login: null, mfa_enabled: false },
];
const TEMP = 'Xq7-temp-pw-ONCE-abcdef12';

async function page(me, role) {
  const can = { write: RANK[role] >= 1, settings: RANK[role] >= 2, users: RANK[role] >= 2,
                host: role === 'superadmin', tools: [] };
  const dom = new JSDOM(`<!DOCTYPE html><html><head></head><body><div x-data="{ settingsTab: 'users' }">${panel}</div></body></html>`,
                        { url: 'https://intact.local/', runScripts: 'outside-only', pretendToBeVisual: true });
  const w = dom.window, calls = [], toasts = [];
  let reauthed = false;
  const reply = (status, body) => ({ ok: status < 300, status, headers: new w.Headers(),
                                     json: async () => body, clone() { return this; } });
  w.fetch = async (url, init) => {
    const method = (init && init.method) || 'GET';
    calls.push(method + ' ' + url);
    if (url === '/api/auth/status')
      return reply(200, { mode: 'login', authenticated: true, user: me, role, role_label: role, can });
    if (url === '/api/users' && method === 'GET')
      return reply(200, { users: USERS, me, roles: ROLES.map(([r, label]) =>
        ({ role: r, label, grantable: r !== 'superadmin' && RANK[role] > RANK[r] })) });
    if (url === '/api/auth/reauth') {
      if (JSON.parse(init.body).password !== 'right') return reply(401, { error: 'invalid_credentials', message: 'Password is incorrect.' });
      reauthed = true;
      return reply(200, { success: true });
    }
    if (url === '/api/users' && method === 'POST') {
      if (!reauthed) return reply(403, { error: 'reauth_required', message: 'Enter your password again to continue.' });
      return reply(200, { success: true, username: JSON.parse(init.body).username, temporary_password: TEMP, expires_hours: 24 });
    }
    if (url.endsWith('/reset-mfa') && method === 'POST') return reply(200, { success: true });
    if (url.startsWith('/api/users/') && method === 'PATCH')
      return reply(403, { error: 'forbidden', message: 'You can only change users with a role below your own.' });
    return reply(404, {});
  };
  w.confirm = () => true;
  w.addEventListener('show-toast', e => toasts.push(e.detail));
  // The page's 401 redirect must never fire here (a wrong re-auth password is a 401).
  for (const f of ['js/active-case.js', 'js/access.js', 'js/components/users-card.js', 'js/alpine.min.js'])
    w.eval(read(f));
  await sleep(150);
  const d = w.document;
  const card = d.getElementById('users-card');
  const row = name => d.querySelector(`tr[data-user="${name}"]`);
  const buttons = name => [...row(name).querySelectorAll('button')].map(b => b.textContent.trim());
  const shown = el => w.getComputedStyle(el).display !== 'none';
  // The MFA cell: the visible text only (the "required" hint is x-show).
  const mfa = name => [...row(name).querySelectorAll('td')[3].querySelectorAll('span')]
    .filter(shown).map(s => s.textContent.trim()).join(' ');
  return { w, d, card, row, buttons, shown, calls, toasts, mfa };
}

const type = (w, el, value) => { el.value = value; el.dispatchEvent(new w.Event('input', { bubbles: true })); };

(async () => {
  // --- Operator: no card, no call -----------------------------------------
  const op = await page('olga', 'operator');
  assert.strictEqual(op.d.documentElement.getAttribute('data-can-users'), '0');
  assert.ok(!op.shown(op.card), 'the Users card is hidden for an Operator');
  assert.ok(!op.calls.includes('GET /api/users'), 'an Operator never asks for /api/users: ' + op.calls);

  // --- Admin ----------------------------------------------------------------
  const ad = await page('alice', 'admin');
  assert.ok(ad.shown(ad.card), 'the Users card shows for an Admin');
  assert.ok(ad.calls.includes('GET /api/users'));
  for (const name of ['root', 'alice', 'bob'])
    assert.deepStrictEqual(ad.buttons(name), [], `${name}: no actions on this row`);
  assert.ok(!ad.row('root').querySelector('select') && !ad.row('alice').querySelector('select'), 'no role select on own/Super-admin rows');
  assert.deepStrictEqual(ad.buttons('carol'), ['Disable', 'Reset password', 'Reset 2-step'], 'Reset 2-step: managed and on');
  assert.deepStrictEqual(ad.buttons('dave'), ['Enable', 'Reset password']);
  assert.deepStrictEqual([...ad.row('carol').querySelectorAll('select option')].map(o => o.value), ['readonly', 'operator'],
                         'role change offers only grantable roles');
  assert.ok(/one-time password pending/.test(ad.row('carol').textContent));
  assert.deepStrictEqual([...ad.card.querySelectorAll('thead th')].map(t => t.textContent.trim()),
                         ['Name', 'Role', 'Status', 'MFA', 'Last login', '']);
  assert.strictEqual(ad.mfa('root'), 'On');
  assert.strictEqual(ad.mfa('bob'), 'Off · required', 'an Admin without two-step login: required');
  assert.strictEqual(ad.mfa('carol'), 'On');
  assert.strictEqual(ad.mfa('dave'), 'Off', 'a Read-only user: no hint');
  assert.ok(/Disabled/.test(ad.row('dave').textContent));
  assert.ok(!ad.shown(ad.d.querySelector('#users-card h4').parentNode), 'an Admin sees no Transfer Super-admin');
  assert.deepStrictEqual([...ad.card.querySelector('form select').options].map(o => o.value), ['readonly', 'operator'],
                         'Add user offers only grantable roles');
  assert.ok(!/delete/i.test(ad.card.textContent.replace(/deleted/g, '')), 'there is no delete button');

  // Add user: 403 reauth_required -> prompt -> wrong, then right -> one retry -> one-time password.
  const form = ad.card.querySelector('form');
  type(ad.w, form.querySelector('input'), 'eve');
  await sleep(20);
  form.querySelector('button[type=submit]').click();
  await sleep(50);
  const dlg = ad.d.getElementById('reauth-dialog');
  assert.ok(dlg, 'the password prompt opened on 403 reauth_required');
  const pw = dlg.querySelector('input[type=password]');
  pw.value = 'wrong';
  dlg.querySelector('button[type=submit]').click();
  await sleep(50);
  assert.ok(ad.d.getElementById('reauth-dialog'), 'a wrong password keeps the prompt open');
  assert.ok(/incorrect/.test(dlg.querySelector('.reauth-err').textContent));
  pw.value = 'right';
  dlg.querySelector('button[type=submit]').click();
  await sleep(100);
  assert.ok(!ad.d.getElementById('reauth-dialog'), 'the prompt closed');
  assert.strictEqual(ad.calls.filter(c => c === 'POST /api/users').length, 2, 'the request was retried exactly once: ' + ad.calls);
  const otp = ad.d.getElementById('otp-value');
  assert.ok(ad.shown(otp.closest('[role=dialog]')), 'the one-time password dialog is open');
  assert.strictEqual(otp.textContent, TEMP);
  assert.strictEqual(ad.d.getElementById('otp-note').textContent,
                     'Give this to eve. It works for 24 hours, and only to choose their own password.');
  [...otp.closest('[role=dialog]').querySelectorAll('button')].find(b => b.textContent.trim() === 'Done').click();
  await sleep(30);
  assert.ok(!ad.d.body.textContent.includes(TEMP), 'the one-time password is gone once closed');

  // A refused change: a toast, not an inline error, no redirect.
  ad.row('carol').querySelector('button').click();     // Disable -> PATCH -> 403 forbidden
  await sleep(80);
  assert.deepStrictEqual(ad.toasts.map(t => t.message), ['You can only change users with a role below your own.']);

  // Reset 2-step: a confirm that says what happens, then the POST.
  let asked = '';
  ad.w.confirm = m => { asked = m; return true; };
  [...ad.row('carol').querySelectorAll('button')].find(b => b.textContent.trim() === 'Reset 2-step').click();
  await sleep(80);
  assert.ok(/set it up again at their next sign-in/.test(asked), asked);
  assert.ok(ad.calls.includes('POST /api/users/carol/reset-mfa'), ad.calls);

  // --- Super-admin ----------------------------------------------------------
  const sa = await page('root', 'superadmin');
  assert.ok(sa.shown(sa.d.querySelector('#users-card h4').parentNode), 'the Super-admin sees Transfer Super-admin');
  assert.deepStrictEqual(sa.buttons('root'), [], 'no actions on your own row');
  assert.deepStrictEqual(sa.buttons('alice'), ['Disable', 'Reset password', 'Reset 2-step'], 'a Super-admin manages Admins');
  assert.deepStrictEqual(sa.buttons('bob'), ['Disable', 'Reset password'], 'no Reset 2-step while it is off');
  assert.deepStrictEqual([...sa.d.querySelectorAll('#users-card h4 ~ form select option')].map(o => o.value).filter(Boolean),
                         ['alice', 'bob'], 'transfer targets: enabled Admins only');
  console.log('ok');
})().catch(e => { console.error(e.stack || e.message); process.exit(1); });
