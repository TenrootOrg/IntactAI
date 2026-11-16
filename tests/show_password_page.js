// The real setup.html and login.html in jsdom, their own scripts running, with
// js/show-password.js inlined where the page loads it: every password field gets
// a Show/Hide toggle that flips it, never submits, and is hidden again on submit.
// `node <file> <root>`; exit 77 = no jsdom.
const fs = require('fs'), path = require('path'), assert = require('assert');
let JSDOM;
try { ({ JSDOM } = require('jsdom')); } catch (e) { process.exit(77); }

const html = path.join(process.argv[2], 'modules/nginx/html');
const toggle = fs.readFileSync(path.join(html, 'js/show-password.js'), 'utf8');

async function page(name, wantIds) {
  let src = fs.readFileSync(path.join(html, name), 'utf8');
  const tag = /<script src="js\/show-password\.js\?v=\d+"><\/script>/;
  assert.ok(tag.test(src), `${name} loads js/show-password.js`);
  src = src.replace(tag, () => `<script>${toggle}</script>`);
  const posts = [];
  const dom = new JSDOM(src, {
    url: 'https://intact.local/' + name, runScripts: 'dangerously',
    beforeParse(w) {
      w.fetch = async (url, init) => {
        if (init && init.method === 'POST') posts.push(String(url));
        return { ok: true, status: 200, json: async () => ({ mode: name === 'setup.html' ? 'setup' : 'login', authenticated: false }) };
      };
    },
  });
  await new Promise(r => setTimeout(r, 50));
  const d = dom.window.document;
  const fields = [...d.querySelectorAll('input')].filter(i => i.dataset.pwToggle);
  assert.deepStrictEqual(fields.map(i => i.id).sort(), [...wantIds].sort(), `${name}: every password field has a toggle`);
  for (const input of fields) {
    const btn = input.parentNode.querySelector('button.pw-toggle');
    assert.ok(btn, `${input.id}: a toggle sits in the field`);
    assert.strictEqual(btn.type, 'button', `${input.id}: the toggle never submits`);
    assert.strictEqual(input.type, 'password');
    btn.click();
    assert.strictEqual(input.type, 'text', `${input.id}: Show reveals it`);
    assert.strictEqual(btn.textContent, 'Hide');
    assert.strictEqual(btn.getAttribute('aria-pressed'), 'true');
    btn.click();
    assert.strictEqual(input.type, 'password', `${input.id}: Hide masks it again`);
    assert.strictEqual(btn.getAttribute('aria-label'), 'Show password');
  }
  assert.deepStrictEqual(posts, [], `${name}: clicking the toggles sent nothing`);
  // Revealed, then submitted: back to a password field.
  const first = fields[0];
  first.parentNode.querySelector('button.pw-toggle').click();
  first.form.dispatchEvent(new dom.window.Event('submit', { cancelable: true, bubbles: true }));
  assert.strictEqual(first.type, 'password', `${name}: submit hides it again`);
}

(async () => {
  await page('setup.html', ['password', 'confirm']);
  await page('login.html', ['password', 'current', 'newpw', 'confirmpw']);
  console.log('ok');
})().catch(e => { console.error(e && e.stack || e); process.exit(1); });
