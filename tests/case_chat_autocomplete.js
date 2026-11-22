// Drives the REAL _acTerms/_acMatch from cases.html (see test_case_chat_autocomplete.py).
const fs = require('fs'), path = require('path'), assert = require('assert');
const html = fs.readFileSync(path.join(__dirname, '..', 'modules/nginx/html/cases.html'), 'utf8');
const grab = name => { const i = html.indexOf('function ' + name + '('); assert(i >= 0, name);
  let d = 0, j = html.indexOf('{', i); for (; j < html.length; j++) { if (html[j] === '{') d++; else if (html[j] === '}' && --d === 0) break; }
  return html.slice(i, j + 1); };
eval(grab('_acTerms') + '\n' + grab('_acMatch') + '\nglobal._acTerms=_acTerms; global._acMatch=_acMatch;');

// names come from the case's own payloads: visible hosts first, then identities
const names = _acTerms(
  { hosts: [{ host: 'WIN-DC01.corp.local' }, { host: 'web-01' }, { host: 'hidden-host', hidden: true },
            { host: 'excluded-host', excluded: true }, { host: 'AWS account …2114' }] },
  { identities: [{ name: 'alice', names: ['Alice.Smith'], accounts: [{ label: 'alice' }, { label: 'svc_backup' }] },
                 { name: 'Yaniv-Intact-Test', accounts: [{ label: 'yaniv-intact-test' }] }] });
assert.deepStrictEqual(names, ['WIN-DC01.corp.local', 'web-01', 'alice', 'Alice.Smith', 'svc_backup', 'Yaniv-Intact-Test']);
assert.deepStrictEqual(_acTerms({}, {}), [], 'an empty case suggests nothing');

const m = t => _acMatch(names, t);
assert.strictEqual(m('what did win-d'), 'C01.corp.local', 'case-insensitive prefix of the last word');
assert.strictEqual(m('is svc'), '_backup');
assert.strictEqual(m('CORP\\ali'), 'ce', 'after DOMAIN\\ only the user part');
assert.strictEqual(m('w'), '', 'two letters at least');
assert.strictEqual(m('alice '), '', 'nothing after a space');
assert.strictEqual(m('alice'), '', 'a complete name needs nothing');
assert.strictEqual(m('host (web'), '-01', 'after a bracket');
assert.strictEqual(m('nothing-like-this'), '');
assert.strictEqual(m(''), '');
console.log('ok');
