// Two-step login (TOTP) screens in jsdom against a mocked backend:
//   - the REAL login.html, its own scripts running, with js/show-password.js
//     and the vendored js/vendor/qrcode.js inlined where the page loads them:
//     password -> mfa_required -> code step; a wrong code stays; a right code
//     signs in; mfa_expired goes back to the password; a recovery code works
//     and must_change then opens change-password; must_enroll opens the setup
//     screen with a QR <svg>, the secret in groups of 4 and, after confirm, the
//     10 recovery codes ONCE (Continue only once "saved" is ticked);
//     the clock warning shows at 120 s skew and not at 10 s;
//   - the dashboard user menu from index.html with js/active-case.js,
//     js/access.js and Alpine: status must_enroll and a 403
//     mfa_enroll_required both go to login.html?mfa=setup; the re-auth prompt
//     asks for the code when two-step login is on; "Turn off" only when the
//     role does not require it.
// Navigation is not implemented in jsdom, so location.replace/reload in the
// sources are rewritten to a recorder (__nav) before they run.
// `node <file> <root>`; exit 77 = no jsdom.
const fs = require('fs'), path = require('path'), assert = require('assert');
let JSDOM, VirtualConsole;
try { ({ JSDOM, VirtualConsole } = require('jsdom')); } catch (e) { process.exit(77); }

const html = path.join(process.argv[2], 'modules/nginx/html');
const read = f => fs.readFileSync(path.join(html, f), 'utf8');
const sleep = ms => new Promise(r => setTimeout(r, ms));
const navs = src => src.replace(/(?:window\.top\.)?location\.(replace|reload)\(/g, '__nav(');
const SECRET = 'JBSWY3DPEHPK3PXP';
const CODES = Array.from({ length: 10 }, (_, i) => `abcd-ef${i}g-h${i}`);
// A promise that never settles (a dialog nobody closed) would drain the event
// loop and exit 0 without a word: count that as a failure.
let finished = false;
process.on('beforeExit', () => { if (!finished) { console.error('stalled before the end'); process.exit(1); } });
const quiet = () => { const vc = new VirtualConsole(); vc.on('error', () => {}); return vc; };

function visible(w, el) {
  for (; el && el.nodeType === 1; el = el.parentNode)
    if (w.getComputedStyle(el).display === 'none') return false;
  return true;
}
function reply(w, status, body) {
  return { ok: status < 300, status, headers: new w.Headers(), json: async () => body, clone() { return this; } };
}

// login.html with `backend(url, method, body)` -> [status, body].
async function login(backend) {
  let src = read('login.html');
  for (const f of ['js/show-password.js', 'js/vendor/qrcode.js']) {
    const tag = new RegExp(`<script src="${f.replace(/[./]/g, '\\$&')}\\?v=\\d+"></script>`);
    assert.ok(tag.test(src), `login.html loads ${f}`);
    src = src.replace(tag, () => `<script>${read(f)}</script>`);
  }
  const calls = [], nav = [], blobs = [];
  const dom = new JSDOM(navs(src), {
    url: 'https://intact.local/login.html' + (backend.query || ''), runScripts: 'dangerously',
    pretendToBeVisual: true, virtualConsole: quiet(),
    beforeParse(w) {
      w.__nav = u => nav.push(u === undefined ? 'reload' : u);
      w.fetch = async (url, init) => {
        const method = (init && init.method) || 'GET';
        const body = init && init.body ? JSON.parse(init.body) : null;
        calls.push({ url, method, body });
        const [status, b] = backend(url, method, body);
        return reply(w, status, b);
      };
      const B = w.Blob;
      w.Blob = function (parts, opt) { blobs.push(parts.join('')); return new B(parts, opt); };
      w.URL.createObjectURL = () => 'blob:https://intact.local/x';
      w.URL.revokeObjectURL = () => {};
      const click = w.HTMLAnchorElement.prototype.click;   // a download link would navigate
      w.HTMLAnchorElement.prototype.click = function () { if (this.download) blobs.push('clicked:' + this.download); else click.call(this); };
    },
  });
  await sleep(60);
  const w = dom.window, d = w.document, $ = id => d.getElementById(id);
  const shown = id => visible(w, $(id));
  const submit = async (id, ms) => { $(id).click(); await sleep(ms || 40); };
  return { w, d, $, shown, submit, calls, nav, blobs };
}

const now = () => Math.floor(Date.now() / 1000);
const unauth = skew => [200, { mode: 'login', authenticated: false, server_time: now() - skew }];

(async () => {
  // --- password -> code step -> wrong code stays -> right code signs in -------
  {
    let signedIn = false;
    const p = await login((url, m, b) => {
      if (url === '/api/auth/status') return signedIn
        ? [200, { mode: 'login', authenticated: true, user: 'alice', role: 'admin', mfa_enabled: true, server_time: now() }]
        : unauth(10);
      if (url === '/api/auth/login') return [200, { success: true, mfa_required: true }];
      if (url === '/api/auth/mfa') {
        if (b.code !== '123456') return [401, { error: 'invalid_code', message: 'That code is not right.' }];
        signedIn = true;
        return [200, { success: true, user: 'alice', role: 'admin', must_change: false }];
      }
      return [404, {}];
    });
    assert.ok(p.shown('loginForm') && !p.shown('mfaForm'), 'the password step first');
    p.$('username').value = 'alice';
    p.$('password').value = 'pw';
    await p.submit('submitBtn');
    assert.ok(!p.shown('loginForm') && p.shown('mfaForm'), 'mfa_required opens the code step');
    const code = p.$('mfaCode');
    assert.strictEqual(code.getAttribute('autocomplete'), 'one-time-code');
    assert.strictEqual(code.getAttribute('inputmode'), 'numeric');
    assert.ok(!p.shown('clockWarn'), 'no clock warning at 10 s skew');
    assert.deepStrictEqual(p.nav, [], 'not signed in yet');

    code.value = '000000';
    await p.submit('mfaBtn');
    assert.ok(p.shown('mfaForm') && p.shown('mfaError'), 'a wrong code stays on the code step');
    assert.strictEqual(p.$('mfaError').textContent, 'That code is not right.');
    assert.strictEqual(code.value, '', 'the wrong code is cleared');
    assert.deepStrictEqual(p.nav, []);

    code.value = '123 456';
    await p.submit('mfaBtn', 80);
    assert.deepStrictEqual(p.calls.filter(c => c.url === '/api/auth/mfa').map(c => c.body),
                           [{ code: "000000" }, { code: "123456" }], "codes sent without spaces: " + JSON.stringify(p.calls));
    assert.deepStrictEqual(p.nav, ['/'], 'a right code goes to the dashboard');
  }

  // --- clock warning at 120 s on the code step ---------------------------------
  {
    const p = await login((url) => {
      if (url === '/api/auth/status') return unauth(120);
      if (url === '/api/auth/login') return [200, { success: true, mfa_required: true }];
      return [404, {}];
    });
    p.$('password').value = 'pw';
    await p.submit('submitBtn');
    assert.ok(p.shown('clockWarn'), 'the clock warning shows at 120 s skew');
    const t = p.$('clockWarn').textContent;
    assert.ok(t.includes("This computer's clock and the appliance's clock differ by 2 minutes"), t);
    assert.ok(t.includes("codes may be refused. Ask an administrator to check the appliance's time."), t);
    assert.ok(/Appliance time: .+\./.test(t), 'the appliance time is shown: ' + t);
  }

  // --- mfa_expired -> back to the password ----------------------------------------
  {
    const p = await login((url) => {
      if (url === '/api/auth/status') return unauth(0);
      if (url === '/api/auth/login') return [200, { success: true, mfa_required: true }];
      if (url === '/api/auth/mfa') return [401, { error: 'mfa_expired', message: 'Too slow. Sign in again.' }];
      return [404, {}];
    });
    p.$('password').value = 'pw';
    await p.submit('submitBtn');
    p.$('mfaCode').value = '123456';
    await p.submit('mfaBtn');
    assert.ok(p.shown('loginForm') && !p.shown('mfaForm'), 'mfa_expired is back on the password step');
    assert.strictEqual(p.$('error').textContent, 'Too slow. Sign in again.');
    assert.strictEqual(p.$('password').value, '');
    assert.ok(!p.$('submitBtn').disabled, 'Sign in works again');
  }

  // --- recovery code; locked stays; must_change after it ---------------------------
  {
    let n = 0;
    const p = await login((url, m, b) => {
      if (url === '/api/auth/status') return unauth(0);
      if (url === '/api/auth/login') return [200, { success: true, mfa_required: true }];
      if (url === '/api/auth/mfa') {
        if (n++ === 0) return [429, { error: 'locked', message: 'Too many wrong codes. Wait 5 minutes.' }];
        return b.recovery_code === 'abcd-efgh-12' ? [200, { success: true, user: 'u', role: 'operator', must_change: true }]
                                                   : [401, { error: 'invalid_code', message: 'no' }];
      }
      return [404, {}];
    });
    p.$('password').value = 'one-time-pw';
    await p.submit('submitBtn');
    p.$('mfaToggle').click();
    assert.ok(p.shown('mfaRecBox') && !p.shown('mfaCodeBox'), 'the toggle swaps in the recovery code field');
    assert.strictEqual(p.$('mfaToggle').textContent, 'Use a code from the app instead');
    p.$('recoveryCode').value = ' abcd-efgh-12 ';
    await p.submit('mfaBtn');
    assert.ok(p.shown('mfaForm'), 'locked stays on the code step');
    assert.strictEqual(p.$('mfaError').textContent, 'Too many wrong codes. Wait 5 minutes.');
    p.$('recoveryCode').value = ' abcd-efgh-12 ';
    await p.submit('mfaBtn', 80);
    assert.deepStrictEqual(p.calls.filter(c => c.url === '/api/auth/mfa').pop().body, { recovery_code: 'abcd-efgh-12' });
    assert.ok(p.shown('changeForm') && !p.shown('mfaForm'), 'must_change opens change-password');
    assert.strictEqual(p.$('current').value, 'one-time-pw', 'with the password already typed');
    assert.deepStrictEqual(p.nav, []);
  }

  // --- forced setup: QR + secret, wrong code, recovery codes once ------------------
  {
    let enrolled = false, setups = 0;
    const p = await login((url, m, b) => {
      if (url === '/api/auth/status') return [200, { mode: 'login', authenticated: true, user: 'alice', role: 'admin',
        mfa_enabled: enrolled, mfa_required: true, must_enroll: !enrolled, server_time: now() - 120 }];
      if (url === '/api/auth/mfa/setup') {
        setups++;
        return [200, { success: true, secret: SECRET, issuer: 'Intact.AI', account: 'alice',
                       otpauth_uri: `otpauth://totp/Intact.AI:alice?secret=${SECRET}&issuer=Intact.AI` }];
      }
      if (url === '/api/auth/mfa/confirm') {
        if (b.code !== '654321') return [401, { error: 'invalid_code', message: 'That code is not right.' }];
        enrolled = true;
        return [200, { success: true, recovery_codes: CODES }];
      }
      return [404, {}];
    });
    assert.ok(p.shown('setupBox') && !p.shown('loginForm'), 'must_enroll opens the setup screen');
    assert.strictEqual(setups, 1);
    assert.ok(p.shown('mustEnroll'));
    assert.strictEqual(p.$('mustEnroll').textContent.trim(), 'Your role requires two-step login. Set it up to continue.');
    assert.ok(p.shown('setupLogout') && !p.shown('setupCancel'), 'forced: Log out, no Cancel');
    const svg = p.d.querySelector('#qr svg');
    assert.ok(svg, 'a QR <svg> is drawn locally');
    assert.ok(/^M\d/.test(svg.querySelector('path').getAttribute('d')), 'with modules in it');
    assert.strictEqual(p.$('mfaSecret').textContent, 'JBSW Y3DP EHPK 3PXP', 'the secret in groups of 4');
    assert.strictEqual(p.$('mfaAccount').textContent, 'alice');
    assert.ok(p.shown('clockWarn'), 'the clock warning shows on the setup screen at 120 s skew');
    assert.ok(/offline/.test(p.$('setupStep').textContent) && /Aegis/.test(p.$('setupStep').textContent));

    p.$('confirmCode').value = '111111';
    await p.submit('confirmBtn');
    assert.ok(p.shown('setupError') && !p.shown('codesStep'), 'a wrong code stays');
    p.$('confirmCode').value = '654321';
    await p.submit('confirmBtn');
    assert.ok(p.shown('codesStep') && !p.shown('setupStep'), 'the recovery codes replace the QR');
    assert.deepStrictEqual(p.$('recoveryCodes').textContent.split('\n'), CODES);
    assert.ok(!p.shown('setupLogout') && !p.shown('setupCancel'), 'Continue is the only way on');

    p.$('downloadCodes').click();
    assert.ok(p.blobs[0].includes(CODES.join('\n')), 'the .txt holds the codes');
    assert.strictEqual(p.blobs[1], 'clicked:intact-recovery-codes.txt');

    assert.ok(p.$('codesDone').disabled, 'Continue waits for "I have saved these codes"');
    p.$('savedCodes').click();
    assert.ok(!p.$('codesDone').disabled);
    p.$('codesDone').click();
    assert.ok(!p.d.body.textContent.includes(CODES[0]), 'the codes are gone once past');
    assert.deepStrictEqual(p.nav, ['/']);
  }

  // --- voluntary setup (?mfa=setup) ---------------------------------------------------
  {
    const p = await login(Object.assign((url) => {
      if (url === '/api/auth/status') return [200, { mode: 'login', authenticated: true, user: 'olga', role: 'operator',
        mfa_enabled: false, mfa_required: false, must_enroll: false, server_time: now() - 10 }];
      if (url === '/api/auth/mfa/setup') return [200, { success: true, secret: SECRET, account: 'olga', otpauth_uri: 'otpauth://totp/x?secret=' + SECRET }];
      return [404, {}];
    }, { query: '?mfa=setup' }));
    assert.ok(p.shown('setupBox') && !p.shown('mustEnroll'), '?mfa=setup opens setup without the forced message');
    assert.ok(p.shown('setupCancel') && !p.shown('setupLogout'));
    assert.ok(!p.shown('clockWarn'), 'no clock warning at 10 s skew');
  }

  // --- dashboard: user menu, hook, re-auth with code --------------------------------
  const idx = read('index.html');
  const menu = idx.slice(idx.indexOf('<!-- Who is signed in, and the way out'), idx.indexOf('<!-- Platform version'));
  assert.ok(menu.includes('IntactAccess.logout()'), 'user menu found in index.html');
  async function dash(st, backend) {
    const dom = new JSDOM(`<!DOCTYPE html><html><head></head><body>${menu}</body></html>`,
                          { url: 'https://intact.local/', runScripts: 'outside-only', pretendToBeVisual: true, virtualConsole: quiet() });
    const w = dom.window, calls = [], nav = [];
    w.Response = Response;          // jsdom has none; every browser does
    w.__nav = u => nav.push(u === undefined ? 'reload' : u);
    w.fetch = async (url, init) => {
      const method = (init && init.method) || 'GET';
      const body = init && init.body ? JSON.parse(init.body) : null;
      calls.push({ url, method, body });
      if (url === '/api/auth/status') return reply(w, 200, Object.assign({ mode: 'login', authenticated: true, can: {} }, st));
      const [s, b] = (backend || (() => [404, {}]))(url, method, body);
      return reply(w, s, b);
    };
    w.document.addEventListener('alpine:init', () => w.Alpine.store('app', { sidebarCollapsed: false }));
    for (const f of ['js/active-case.js', 'js/access.js', 'js/alpine.min.js']) w.eval(navs(read(f)));
    await sleep(120);
    // The menu itself is closed; which of its entries would show when opened.
    const items = () => [...w.document.querySelectorAll('[role=menu] > *')]
      .filter(e => w.getComputedStyle(e).display !== 'none').map(e => e.textContent.trim());
    return { w, d: w.document, calls, nav, items };
  }

  {
    // GETs closed to the role (status.gets) are answered here, never sent:
    // background loads a role cannot see stay out of the audit log.
    const gets = { closed: ['^/api/system/data\\-location$', '^/api/cases/[^/]+$'], open: ['^/api/cases/export$'] };
    const g = await dash({ user: 'rita', role: 'readonly', role_label: 'Read-only', gets },
                         (url, method) => [200, { url, method }]);
    let r = await g.w.fetch('/api/system/data-location?x=1');
    assert.strictEqual(r.status, 403, 'a closed GET gets the same 403 the server sends');
    assert.strictEqual((await r.json()).error, 'forbidden');
    assert.strictEqual((await g.w.fetch('/api/system/data-location', { method: 'POST' })).status, 200, 'writes are sent');
    assert.strictEqual((await g.w.fetch('/api/cases/export')).status, 200, 'an open route matching too: sent');
    assert.strictEqual((await g.w.fetch('/api/memory/dumps')).status, 200, 'unlisted paths are sent');
    assert.deepStrictEqual(g.calls.filter(c => c.url !== '/api/auth/status').map(c => c.url + ' ' + c.method),
      ['/api/system/data-location POST', '/api/cases/export GET', '/api/memory/dumps GET']);
  }
  {
    const g = await dash({ user: 'alice', role: 'admin', role_label: 'Admin', mfa_enabled: false, mfa_required: true, must_enroll: true });
    assert.deepStrictEqual(g.nav, ['/login.html?mfa=setup'], 'status must_enroll goes to the setup screen');
  }
  {
    const g = await dash({ user: 'olga', role: 'operator', role_label: 'Operator', mfa_enabled: false, mfa_required: false },
                         () => [403, { error: 'mfa_enroll_required', message: 'Set up two-step login first.' }]);
    assert.deepStrictEqual(g.items(), ['Change password', 'Two-step login', 'API tokens', 'Log out'], 'off: the setup link');
    assert.strictEqual(g.d.querySelector('a[href="/login.html?mfa=setup"]').textContent, 'Two-step login');
    await g.w.fetch('/api/cases');
    await sleep(30);
    assert.deepStrictEqual(g.nav, ['/login.html?mfa=setup'], '403 mfa_enroll_required goes to the setup screen');
  }
  {
    const g = await dash({ user: 'root', role: 'superadmin', role_label: 'Super-admin', mfa_enabled: true, mfa_required: true });
    assert.deepStrictEqual(g.items(), ['Change password', 'Two-step login: on', 'API tokens', 'Log out'], 'required: no Turn off');
  }
  {
    let reauthed = false;
    const g = await dash({ user: 'olga', role: 'operator', role_label: 'Operator', mfa_enabled: true, mfa_required: false },
      (url, m, b) => {
        if (url === '/api/auth/reauth') {
          if (b.password !== 'right') return [401, { error: 'invalid_credentials', message: 'Password is incorrect.' }];
          if (b.code !== '123456') return [401, { error: 'invalid_code', message: 'The code is not right.' }];
          reauthed = true;
          return [200, { success: true }];
        }
        if (url === '/api/thing') return reauthed ? [200, { ok: 1 }] : [403, { error: 'reauth_required' }];
        if (url === '/api/auth/mfa/disable') return b.code === '222222' ? [200, { success: true }] : [401, { error: 'invalid_code' }];
        return [404, {}];
      });
    assert.deepStrictEqual(g.items(), ['Change password', 'Two-step login: on', 'Turn off two-step login', 'API tokens', 'Log out']);

    const done = g.w.fetch('/api/thing', { method: 'POST' });
    await sleep(30);
    const dlg = g.d.getElementById('reauth-dialog');
    assert.ok(dlg && dlg.querySelector('.reauth-code'), 'the re-auth prompt asks for the code');
    dlg.querySelector('input[type=password]').value = 'right';
    dlg.querySelector('.reauth-code').value = '000000';
    dlg.querySelector('button[type=submit]').click();
    await sleep(30);
    assert.ok(g.d.getElementById('reauth-dialog'), 'a wrong code keeps the prompt open');
    assert.strictEqual(dlg.querySelector('.reauth-err').textContent, 'The code is not right.');
    assert.strictEqual(dlg.querySelector('.reauth-code').value, '', 'the wrong code is cleared');
    dlg.querySelector('.reauth-code').value = '123456';
    dlg.querySelector('button[type=submit]').click();
    const r = await done;
    assert.strictEqual(r.status, 200, 'retried once after the prompt');
    assert.deepStrictEqual(g.calls.filter(c => c.url === '/api/auth/reauth').map(c => c.body),
                           [{ password: 'right', code: '000000' }, { password: 'right', code: '123456' }]);
    assert.strictEqual(g.calls.filter(c => c.url === '/api/thing').length, 2);

    [...g.d.querySelectorAll('[role=menu] button')].find(b => b.textContent.includes('Turn off')).click();
    await sleep(20);
    const off = g.d.getElementById('mfa-off-dialog');
    assert.ok(off && off.querySelector('.reauth-code'), 'Turn off asks for password and code');
    off.querySelector('input[type=password]').value = 'pw';
    off.querySelector('.reauth-code').value = '222222';
    off.querySelector('button[type=submit]').click();
    await sleep(30);
    assert.deepStrictEqual(g.calls.filter(c => c.url === '/api/auth/mfa/disable').map(c => c.body), [{ password: 'pw', code: '222222' }]);
    assert.deepStrictEqual(g.nav, ['reload'], 'the page redraws once it is off');
  }
  {
    // Two-step login off: the re-auth prompt stays password-only.
    const g = await dash({ user: 'olga', role: 'operator', role_label: 'Operator', mfa_enabled: false, mfa_required: false },
                         () => [403, { error: 'reauth_required' }]);
    g.w.fetch('/api/thing', { method: 'POST' });
    await sleep(30);
    const dlg = g.d.getElementById('reauth-dialog');
    assert.ok(dlg && !dlg.querySelector('.reauth-code'), 'no code field without two-step login');
  }
  finished = true;
  console.log('ok');
})().catch(e => { console.error(e.stack || e.message); process.exit(1); });
