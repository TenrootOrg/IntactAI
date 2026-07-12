/* Downloads tab helpers — extracted from inline <script> blocks in index.html.
 *
 *  - copyWinCmd / copyLinuxCmd: copy a hidden <template> command body to the
 *    clipboard (called from onclick= in the Downloads tab).
 *  - toggleCmd: expand/collapse the FULL command under a row (the on-row
 *    preview is often a truncated summary, so operators need the real body).
 *  - Legacy-binary availability: grey out download buttons whose bundled
 *    binary isn't on disk yet.
 *
 *  Loaded as a plain (non-module) script, so these stay window-global for the
 *  inline onclick handlers.
 */

// Decode a <template>'s HTML-escaped body back into the literal command text.
function _dlDecodeTpl(tpl) {
    // textContent already gives the unescaped text for a <template>'s content,
    // and preserves newlines / &&, unlike a manual entity replace.
    return (tpl.content && tpl.content.textContent != null)
        ? tpl.content.textContent
        : tpl.textContent;
}

// Robust clipboard copy with a graceful fallback + real feedback.
// The old code called navigator.clipboard.writeText() with NO fallback and NO
// .catch(): on a non-secure context (plain HTTP, or self-signed HTTPS that the
// browser treats as insecure) navigator.clipboard is undefined / rejects, so
// the copy failed SILENTLY — the button did nothing. Now we fall back to the
// legacy execCommand('copy') path and always tell the operator what happened.
function _dlCopyText(text, btn) {
    const orig = btn.getAttribute('data-orig') || btn.textContent;
    btn.setAttribute('data-orig', orig);
    const flash = (msg, ok, ms) => {
        btn.textContent = msg;
        btn.classList.toggle('bg-green-600', ok);
        btn.classList.toggle('bg-red-600', !ok);
        setTimeout(() => {
            btn.textContent = orig;
            btn.classList.remove('bg-green-600', 'bg-red-600');
        }, ms);
    };

    const legacyCopy = () => {
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
            flash(ok ? 'Copied!' : 'Press Ctrl+C', ok, ok ? 1200 : 2500);
        } catch (e) {
            flash('Press Ctrl+C', false, 2500);
        }
    };

    if (navigator.clipboard && navigator.clipboard.writeText && window.isSecureContext) {
        navigator.clipboard.writeText(text)
            .then(() => flash('Copied!', true, 1200))
            .catch(legacyCopy);   // permission denied / not focused → fall back
    } else {
        legacyCopy();             // no async clipboard in this context
    }
}

function _dlCopyFromTpl(btn, tplId) {
    const tpl = document.getElementById(tplId);
    if (!tpl) return;
    _dlCopyText(_dlDecodeTpl(tpl), btn);
}

if (!window.copyWinCmd)   window.copyWinCmd   = function (btn, tplId) { _dlCopyFromTpl(btn, tplId); };
if (!window.copyLinuxCmd) window.copyLinuxCmd = function (btn, tplId) { _dlCopyFromTpl(btn, tplId); };

// Expand / collapse the full command for a row. Injects a <pre> right after the
// row (inside the same panel) showing the real, un-truncated, multi-line body.
if (!window.toggleCmd) {
    window.toggleCmd = function (btn, tplId) {
        const tpl = document.getElementById(tplId);
        if (!tpl) return;
        const row = btn.closest('.justify-between');   // only the row has justify-between
        if (!row) return;

        const existing = row.nextElementSibling;
        if (existing && existing.hasAttribute && existing.hasAttribute('data-cmd-full')) {
            existing.remove();
            btn.setAttribute('aria-expanded', 'false');
            btn.title = 'Show full command';
            btn.innerHTML = '&#9662;';   // ▾
            return;
        }

        const pre = document.createElement('pre');
        pre.setAttribute('data-cmd-full', '');
        pre.className = 'text-gray-200 text-xs font-mono whitespace-pre-wrap break-words ' +
                        'bg-black/50 border border-gray-700 rounded p-2 mt-1 overflow-x-auto select-text';
        pre.textContent = _dlDecodeTpl(tpl);
        row.parentNode.insertBefore(pre, row.nextSibling);
        btn.setAttribute('aria-expanded', 'true');
        btn.title = 'Hide full command';
        btn.innerHTML = '&#9652;';       // ▴
    };
}

// Grey out + disable each button whose bundled binary isn't on disk yet
// (re-run install.sh to fix).
(function checkLegacyBinaries() {
    const run = () => {
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
    // The Downloads tab now lives in partials/downloads.html, so its buttons
    // only exist after the partial-loader injects them — wait for that event.
    document.addEventListener('partials:ready', run);
})();
