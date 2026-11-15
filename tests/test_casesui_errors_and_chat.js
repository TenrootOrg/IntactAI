// Case page: error replies must not read as success, and a chat turn must stay
// in the case it was asked in.
//
// api() is fetch().then(r=>r.json()) and never looks at the status, so a 500
// arrives as {error}. That used to toast "Refusion complete." / "Report
// generation started.", and on the 5 s case poll an {error} (case deleted in
// another tab) read as "the report changed": a reload and a toast every tick.
//
// The chat's in-flight turn was a set of globals with no case id: ask in A,
// open B, and B showed A's "thinking…", then A's answer, then A's history.
//
// Evaluates the REAL function bodies out of cases.html (no live box needed).
//
//   node tests/test_casesui_errors_and_chat.js [repo-root]
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

// ---- page stubs ------------------------------------------------------------
let els = {}, chatMounted = true, toasts = [], apiImpl = () => Promise.resolve({});
const $ = (sel) => {
  if (sel === '#msgs' && !chatMounted) return null;
  return els[sel] || (els[sel] = {value:'', innerHTML:'', disabled:false, textContent:'',
                                  addEventListener(){}, style:{}, dataset:{}});
};
const api = (p, o) => apiImpl(p, o);
const toast = (m) => toasts.push(m);
const escape = s => s, mdToHtml = s => s;
const lastToast = () => toasts[toasts.length - 1] || '';
const flush = () => new Promise(r => setTimeout(r, 10));

// doRefusion / regenReport / pollReportGen
let curInfo = null, tab = 'report', refreshed = [], intervals = [];
let _genPoll = null, _genPollCase = null, _genPhase = null, _cfgDirty = false;
const _noHostSelected = () => false, _railCfg = async () => ({});
const _applyCfgLocally = () => {}, setTab = () => {}, logRefresh = () => {};
const openCase = () => {}, drawTab = () => {}, patchReportStatus = () => {};
const _quietFuseRefresh = () => {}, operatorIsTyping = () => false;
const backgroundRefresh = (id, msg) => { refreshed.push(msg); if (msg) toast(msg); return true; };
const setInterval = (fn) => { intervals.push(fn); return intervals.length; };
const clearInterval = () => {};

// chat
let chatHist = [], _pendingQ = null, _asking = false, _askCase = null, _chatCase = null;
const SHOW_INVESTIGATE = false;

for (const f of ['doRefusion', 'regenReport', 'stopReportGenPoll', 'pollReportGen',
                 'renderChat', 'reattachPendingTurn', 'ask', 'drawMsgs'])
  eval((f === 'doRefusion' ? 'async ' : '') + grab(f));

(async () => {
  let fail = 0;
  const check = (label, got, want) => {
    const ok = JSON.stringify(got) === JSON.stringify(want);
    console.log((ok ? '  PASS  ' : '  FAIL  ') + label);
    if (!ok){ fail++;
      console.log('        got : ' + JSON.stringify(got));
      console.log('        want: ' + JSON.stringify(want)); }
  };

  // ---- F2: refusion ----
  apiImpl = () => Promise.resolve({error: 'fuse crashed'});
  await doRefusion('A');
  check('a crashed rescan (500 {error}) shows the failed toast', lastToast(),
        'Refusion failed. See the Log for details.');
  apiImpl = () => Promise.resolve({error: 'busy', busy: true});
  await doRefusion('A');
  check('a busy rescan (409) is still not a failure', lastToast(),
        'This case is already being re-fused. Please try again shortly.');
  apiImpl = () => Promise.resolve({status: 'rescanned', entities: 3});
  await doRefusion('A');
  check('a good rescan still says complete', lastToast(),
        'Refusion complete. Data, risk and timeline are up to date.');

  // ---- F2: report POST ----
  apiImpl = () => Promise.resolve({error: 'synthesis failed'});
  regenReport('A', false); await flush();
  check('a failed report POST shows the failed toast', lastToast(),
        'Report generation could not be started. Please try again.');
  apiImpl = () => Promise.resolve({error: 'already', busy: true});
  regenReport('A', false); await flush();
  check('a busy report POST says one is already running', lastToast(),
        'A report is already being generated. It will appear here when it is ready.');

  // ---- F2: poll tick ----
  curInfo = {case_id: 'P', report_written_at: '2026-11-01T00:00:00'};
  refreshed = []; toasts = [];
  apiImpl = () => Promise.resolve({error: 'case not found'});
  pollReportGen('P'); await flush(); intervals[intervals.length - 1](); await flush();
  check('an error body on a poll tick reloads nothing and toasts nothing',
        [refreshed, toasts], [[], []]);
  apiImpl = () => Promise.resolve({report_written_at: '2026-11-02T00:00:00'});
  intervals[intervals.length - 1](); await flush();
  check('a real new report on a tick still refreshes', refreshed, ['The report has been updated.']);

  // ---- F9: chat turn stays in its case ----
  const server = {A: [{role:'user', content:'old A q'}, {role:'assistant', content:'old A a'}],
                  B: [{role:'user', content:'old B q'}, {role:'assistant', content:'old B a'}]};
  let getDelay = {};
  apiImpl = (p) => {
    const id = p.split('/')[3];
    const reply = () => ({messages: server[id].slice()});
    return getDelay[id] ? getDelay[id].then(reply) : Promise.resolve(reply());
  };
  let posts = 0, resolveA;
  global.fetch = () => { posts++; return new Promise(r => { resolveA = r; }); };
  const mount = async (id) => { delete els['#askbtn']; delete els['#msgs']; chatMounted = true;
                                renderChat(id); await flush(); };
  const shape = () => chatHist.map(m => m.role + ':' + (m.pending ? 'PENDING' : m.content));

  await mount('A');
  $('#q').value = 'QA';
  ask('A');
  check('asking in A shows the pending turn in A', shape(),
        ['user:old A q', 'assistant:old A a', 'user:QA', 'assistant:PENDING']);

  await mount('B');
  check('B shows only B while A is in flight', shape(), ['user:old B q', 'assistant:old B a']);
  check("B's Ask button is not stuck on Asking…", [$('#askbtn').disabled, $('#askbtn').textContent],
        [false, '']);

  toasts = [];
  $('#q').value = 'QB';
  ask('B');
  check('asking in B while A is in flight says why instead of doing nothing',
        [posts, /another case/.test(lastToast())], [1, true]);

  server.A.push({role:'user', content:'QA'}, {role:'assistant', content:'ANS A'});
  resolveA({ok: true, status: 200, text: async () => JSON.stringify({answer: 'ANS A'})});
  await flush(); await flush();
  check("A's answer does not land in B", shape(), ['user:old B q', 'assistant:old B a']);
  check("B's screen has none of A's turn", /QA|ANS A/.test($('#msgs').innerHTML), false);
  check('the in-flight flag is cleared', [_asking, _pendingQ, _askCase], [false, null, null]);

  await mount('A');
  check('reopening A shows the pair', shape().slice(-2), ['user:QA', 'assistant:ANS A']);

  // The answer lands while another tab of the same case is drawn (no #msgs).
  $('#q').value = 'QA2';
  ask('A');
  chatMounted = false;
  server.A.push({role:'user', content:'QA2'}, {role:'assistant', content:'ANS A2'});
  resolveA({ok: true, status: 200, text: async () => JSON.stringify({answer: 'ANS A2'})});
  await flush(); await flush();
  check('an answer with the chat tab not drawn is kept, not turned into a fake network error',
        [shape().slice(-2), shape().some(s => /Could not reach/.test(s))],
        [['user:QA2', 'assistant:ANS A2'], false]);

  // A slow GET for A must not overwrite B, opened after it.
  let releaseA; getDelay.A = new Promise(r => { releaseA = r; });
  delete els['#msgs']; chatMounted = true; renderChat('A');
  await mount('B');
  releaseA(); await flush();
  check("a late history GET for A does not replace B's", shape(), ['user:old B q', 'assistant:old B a']);

  if (fail) { console.log(`\n${fail} check(s) failed`); process.exit(1); }
  process.exit(0);
})().catch(e => { console.error(e); process.exit(1); });
