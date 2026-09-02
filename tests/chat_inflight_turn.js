// Regression harness for the chat turn that is IN FLIGHT.
//
// Reported live: ask a question, switch to the Log tab, come back -- the
// question is gone and only the answer is there. The cause is a three-step
// sequence, not a typo:
//
//   1. the backend persists the question and the answer TOGETHER, atomically,
//      and only once the model has answered. Between asking and answering the
//      question exists in the browser tab and nowhere else.
//   2. leaving and re-entering the Chat tab reloads the history from the
//      server, which does not have that question yet -- so it is wiped.
//   3. the answer then arrives, finds no placeholder to replace, and is
//      appended on its own: an answer to a question no longer on screen.
//
// This evaluates the REAL function bodies out of cases.html rather than a
// re-implementation, so it cannot pass while the shipped page is broken.
//
//   node tests/chat_inflight_turn.js [repo-root]
const fs = require('fs');
const path = require('path');
const ROOT = process.argv[2] || path.join(__dirname, '..');
const html = fs.readFileSync(path.join(ROOT, 'modules/nginx/html/cases.html'), 'utf8');

function grab(name){
  const i = html.indexOf('function ' + name + '(');
  if (i < 0) throw new Error('not found: ' + name);
  let d = 0, started = false;
  for (let j = i; j < html.length; j++){
    if (html[j] === '{'){ d++; started = true; }
    else if (html[j] === '}'){ d--; if (started && d === 0) return html.slice(i, j+1); }
  }
  throw new Error('unbalanced: ' + name);
}

const QUESTION = 'who is the most malicious user';
let chatHist = [], _pendingQ = null, _asking = false;
let serverHistory = [];

const drawMsgs = () => {};
const $ = (sel) => (sel === '#q' ? {value: ' ' + QUESTION + ' '} : {disabled:false, textContent:''});
const api = () => Promise.resolve({messages: serverHistory});
global.fetch = () => Promise.resolve({
  ok: true, status: 200, text: async () => JSON.stringify({answer: 'THE ANSWER'})});

eval(grab('reattachPendingTurn'));
eval(grab('ask'));

const shape = () => chatHist.map(m => m.role + ':' + (m.pending ? 'PENDING' : m.content));

(async () => {
  let fail = 0;
  const check = (label, got, want) => {
    const ok = JSON.stringify(got) === JSON.stringify(want);
    console.log((ok ? '  PASS  ' : '  FAIL  ') + label);
    if (!ok){ fail++;
      console.log('        got : ' + JSON.stringify(got));
      console.log('        want: ' + JSON.stringify(want)); }
  };

  ask('case_1');
  check('the question appears when asked',
        shape(), ['user:' + QUESTION, 'assistant:PENDING']);

  // Switch to Log and back: history reloads from a server that has not yet
  // been told about this turn.
  chatHist = serverHistory.map(m => ({role: m.role, content: m.content}));
  reattachPendingTurn();
  check('the question survives leaving and re-entering the tab',
        shape(), ['user:' + QUESTION, 'assistant:PENDING']);

  // The answer lands; the backend has now stored the pair.
  serverHistory = [{role:'user', content: QUESTION},
                   {role:'assistant', content:'THE ANSWER'}];
  await new Promise(r => setTimeout(r, 20));
  check('the answer stays paired with its question',
        shape(), ['user:' + QUESTION, 'assistant:THE ANSWER']);
  check('the in-flight flag is cleared', _asking, false);
  check('the in-flight question is cleared', _pendingQ, null);

  if (fail) { console.log(`\n${fail} check(s) failed`); process.exit(1); }
  process.exit(0);
})();
