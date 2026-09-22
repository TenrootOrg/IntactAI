// A timeline row is one line with "more" on click, like the evidence under it.
// QA: a recurring detection ("… 2 [T1027, T1059.001] · ×2 · HOST-A, HOST-B")
// wrapped onto two lines, so one entry read as two. Drives the page's own
// mdToHtml (sliced from cases.html) — the clamp itself needs a real layout.
const fs = require('fs');
const src = fs.readFileSync(process.argv[2], 'utf8');
const start = src.indexOf('function mdToHtml(md){');
let depth = 0, end = start;
for (let i = src.indexOf('{', start); i < src.length; i++) {
  if (src[i] === '{') depth++;
  else if (src[i] === '}' && --depth === 0) { end = i + 1; break; }
}
const escape = s => String(s).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const inlineSrc = src.slice(src.indexOf('function inline(s){'), src.indexOf('\n', src.indexOf('function inline(s){')));
const mdToHtml = new Function('escape', inlineSrc + '\n' + src.slice(start, end) + '; return mdToHtml;')(escape);
const html = mdToHtml([
  '- `2026-09-01T09:13:38Z → 2026-09-01T11:54:46Z` · **[high]** SIGMA: Potential PowerShell Command Line Obfuscation `[T1027, T1059.001]` · ×2 · DESKTOP-16OJFO6, DESKTOP-566AT85',
  '    - User: Administrator · Command: powershell -enc …',
  '- A narrative bullet that is not an event',
].join('\n'));
let bad = 0;
const check = (ok, what) => { console.log((ok ? '  ok   ' : '  FAIL ') + what); if (!ok) bad++; };
check(/<li class="ev"><code>2026-09-01/.test(html), 'a timeline row is marked ev');
check(/<li class="sub">User: Administrator/.test(html), 'its evidence stays sub');
check(/<li>A narrative bullet/.test(html), 'a prose bullet is never clamped');
check(/\.md li\.ev\.clip\{max-height/.test(src) && /querySelectorAll\('\.md li\.sub, \.md li\.ev'\)/.test(src),
      'the clamp and its click cover timeline rows');
process.exit(bad ? 1 : 0);
