// Case page followers (F10): the evidence follower must survive a failed poll,
// and the Log follower must not poll while the dashboard hides the iframe.
//
// _evFollow used to .catch(()=>{}) without rescheduling (a backend restart left
// "reading…" stuck), and an {error} reply set case_files to [] (empty list).
// logFollow's 4 s interval kept GETting /log from the hidden x-show iframe.
//
// Evaluates the REAL function bodies out of cases.html (no live box needed).
//
//   node tests/test_casesui2_followers.js [repo-root]
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

// ---- page stubs: timers are captured, never fire on their own ----
let timeouts = [], intervals = [];
const setTimeout = (fn, ms) => { timeouts.push({fn, ms}); return timeouts.length; };
const clearTimeout = () => {};
const setInterval = (fn, ms) => { intervals.push({fn, ms}); return intervals.length; };
const clearInterval = () => {};
const window = {}, document = {hidden: false};
let curInfo = null, tab = 'data', apiImpl = () => Promise.resolve({}), apiCalls = 0, rendered = 0, logCalls = 0;
const api = (p) => { apiCalls++; return apiImpl(p); };
const renderEvidence = () => rendered++, renderData = () => rendered++;
const logRefresh = () => logCalls++;
const flush = () => new Promise(r => global.setTimeout(r, 10));

for (const f of ['_evList', '_evFollow', 'logFollow']) eval(grab(f));

const busyFile = {id: 'f1', name: 'a.evtx', data_type: 'evtx', log: {status: 'running'}};

(async () => {
  let fail = 0;
  const check = (label, got, want) => {
    const ok = JSON.stringify(got) === JSON.stringify(want);
    console.log((ok ? '  PASS  ' : '  FAIL  ') + label);
    if (!ok){ fail++;
      console.log('        got : ' + JSON.stringify(got));
      console.log('        want: ' + JSON.stringify(want)); }
  };
  const fire = async () => { const t = timeouts.shift(); t.fn(); await flush(); };

  // ---- evidence follower: rejected fetch ----
  curInfo = {case_id: 'A', case_files: [busyFile]};
  timeouts = [];
  _evFollow();
  check('a busy log file schedules a poll in 4 s', timeouts.map(t => t.ms), [4000]);
  apiImpl = () => Promise.reject(new Error('backend down'));
  await fire();
  check('a failed poll schedules a retry (slower)', timeouts.map(t => t.ms), [15000]);
  check('the list is kept after a failed poll', curInfo.case_files.length, 1);

  // ---- evidence follower: {error} JSON ----
  apiImpl = () => Promise.resolve({error: 'restarting'});
  await fire();
  check('an {error} reply does not blank the list', curInfo.case_files.length, 1);
  check('an {error} reply schedules a retry', timeouts.map(t => t.ms), [15000]);

  // ---- a reply that is neither the case nor {error}: keep the list, stop ----
  timeouts = [];
  curInfo = {case_id: 'A', case_files: [busyFile]};
  _evFollow();
  apiImpl = () => Promise.resolve({rows: []});
  await fire();
  check('an unrecognised reply keeps the list', curInfo.case_files.length, 1);
  check('an unrecognised reply does not loop', timeouts.length, 0);
  _evFollow();
  apiImpl = () => Promise.resolve({error: 'restarting'});
  await fire();

  // ---- recovery: a good reply renders and the done file ends the follow ----
  apiImpl = () => Promise.resolve({case_files: [{...busyFile, log: {status: 'done'}}]});
  rendered = 0;
  await fire();
  check('a good reply after the outage renders the list', rendered, 1);
  check('the follow stops once nothing is reading', timeouts.length, 0);

  // ---- a failed poll after switching case does not follow the old case ----
  curInfo = {case_id: 'A', case_files: [busyFile]};
  _evFollow();
  apiImpl = () => Promise.reject(new Error('x'));
  const t = timeouts.shift();
  curInfo = {case_id: 'B', case_files: []};
  t.fn(); await flush();
  check('a failed poll for a case left behind does not retry', timeouts.length, 0);

  // ---- log follower skips ticks while the iframe is hidden ----
  tab = 'log'; intervals = [];
  logFollow(true);
  check('log follow starts a 4 s interval', intervals.map(i => i.ms), [4000]);
  const tick = intervals[0].fn;
  window.frameElement = {getClientRects: () => []};          // x-show display:none
  logCalls = 0; tick();
  check('no /log fetch while the iframe is hidden', logCalls, 0);
  window.frameElement = {getClientRects: () => [{}]};        // shown again
  tick();
  check('polling resumes once the iframe is visible', logCalls, 1);
  document.hidden = true; tick();
  check('no /log fetch while the browser tab is hidden', logCalls, 1);
  document.hidden = false; delete window.frameElement; tick();
  check('standalone page (no frame) still polls', logCalls, 2);

  console.log(fail ? `\n${fail} FAILED` : '\nall passed');
  process.exit(fail ? 1 : 0);
})();
