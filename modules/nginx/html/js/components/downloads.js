/* Downloads tab helpers — extracted from inline <script> blocks in index.html.
 *
 *  - copyBlock: copy the command inside a code block, with an icon that flips to
 *    a checkmark on success (and selects the text as a fallback on failure).
 *  - Legacy-binary availability: grey out download buttons whose bundled
 *    binary isn't on disk yet.
 *
 *  Loaded as a plain (non-module) script, so these stay window-global for the
 *  inline onclick handlers.
 */

const _DL_ICON_COPY =
    '<svg xmlns="http://www.w3.org/2000/svg" class="w-4 h-4" fill="none" viewBox="0 0 24 24" ' +
    'stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' +
    '<rect x="9" y="9" width="11" height="11" rx="2"/>' +
    '<path d="M5 15V5a2 2 0 0 1 2-2h10"/></svg>';
const _DL_ICON_CHECK =
    '<svg xmlns="http://www.w3.org/2000/svg" class="w-4 h-4" fill="none" viewBox="0 0 24 24" ' +
    'stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">' +
    '<path d="M20 6 9 17l-5-5"/></svg>';

// Legacy execCommand path — the reliable fallback when the async Clipboard API
// isn't available. The old code used navigator.clipboard.writeText() with NO
// fallback and NO .catch(): on a non-secure context (plain HTTP, or a
// self-signed HTTPS the browser treats as insecure) it failed SILENTLY, so the
// copy button did nothing (the bug QA reported).
function _dlLegacyCopy(text) {
    try {
        const ta = document.createElement('textarea');
        ta.value = text;
        ta.setAttribute('readonly', '');
        ta.style.position = 'fixed';
        ta.style.top = '-1000px';
        ta.style.opacity = '0';
        document.body.appendChild(ta);
        ta.focus();
        ta.select();
        ta.setSelectionRange(0, text.length);
        const ok = document.execCommand('copy');
        document.body.removeChild(ta);
        return ok;
    } catch (e) {
        return false;
    }
}

function _dlCopy(text) {
    if (navigator.clipboard && navigator.clipboard.writeText && window.isSecureContext) {
        return navigator.clipboard.writeText(text)
            .then(() => true)
            .catch(() => _dlLegacyCopy(text));   // permission denied / not focused
    }
    return Promise.resolve(_dlLegacyCopy(text));
}

// Copy the command in the code block this button sits in, with icon feedback.
if (!window.copyBlock) {
    window.copyBlock = function (btn) {
        const wrap = btn.closest('.dl-cmd');
        const pre = wrap && wrap.querySelector('pre');
        if (!pre) return;
        const text = pre.textContent;
        Promise.resolve(_dlCopy(text)).then((ok) => {
            btn.innerHTML = ok ? _DL_ICON_CHECK : _DL_ICON_COPY;
            btn.classList.toggle('text-green-400', ok);
            btn.classList.toggle('text-red-400', !ok);
            btn.title = ok ? 'Copied!' : 'Copy blocked — text selected, press Ctrl/Cmd+C';
            if (!ok) {
                // Select the command so the operator can copy manually.
                const range = document.createRange();
                range.selectNodeContents(pre);
                const sel = window.getSelection();
                sel.removeAllRanges();
                sel.addRange(range);
            }
            setTimeout(() => {
                btn.innerHTML = _DL_ICON_COPY;
                btn.classList.remove('text-green-400', 'text-red-400');
                btn.title = 'Copy';
            }, 1500);
        });
    };
}

// Paint the copy icon into every code-block button once the partial is injected.
function _dlPaintCopyIcons() {
    document.querySelectorAll('.dl-cmd button[data-copy]').forEach((b) => {
        if (!b.innerHTML.trim()) b.innerHTML = _DL_ICON_COPY;
    });
}

// Grey out + disable each download button whose bundled binary isn't on disk
// yet (re-run install.sh to fix).
(function checkLegacyBinaries() {
    const run = () => {
        _dlPaintCopyIcons();
        fetch('/api/clients/legacy/status').then(r => r.json()).then(s => {
            if (!s || s.error) return;
            const grey = (btn, ready) => {
                if (!btn) return;
                if (!ready) {
                    btn.classList.add('opacity-50', 'cursor-not-allowed');
                    btn.removeAttribute('href');
                    btn.title = 'Bundled binary not present — re-run install.sh.';
                }
            };
            grey(document.getElementById('dl-legacy-btn'), s.binaries?.['windows-amd64']?.available);
            grey(document.getElementById('dl-legacy-linux-btn'), s.binaries?.['linux-amd64']?.available);
            grey(document.getElementById('dl-musl-btn'), s.modern_musl?.available);
        }).catch(() => {});
    };
    // The Downloads tab lives in partials/downloads.html, so its buttons only
    // exist after the partial-loader injects them — wait for that event.
    document.addEventListener('partials:ready', run);
})();
