/* Downloads tab helpers — extracted from inline <script> blocks in index.html.
 *
 *  - copyWinCmd / copyLinuxCmd: copy a hidden <template> command body to the
 *    clipboard (called from onclick= in the Downloads tab).
 *  - Legacy-binary availability: grey out download buttons whose bundled
 *    binary isn't on disk yet.
 *
 *  Loaded as a plain (non-module) script, so these stay window-global for the
 *  inline onclick handlers.
 */

if (!window.copyWinCmd) {
    window.copyWinCmd = function (btn, tplId) {
        const tpl = document.getElementById(tplId);
        if (!tpl) return;
        const text = tpl.innerHTML
            .replace(/&lt;/g, '<')
            .replace(/&gt;/g, '>')
            .replace(/&amp;/g, '&');
        navigator.clipboard.writeText(text).then(() => {
            const orig = btn.textContent;
            btn.textContent = 'Copied!';
            setTimeout(() => { btn.textContent = orig; }, 1200);
        });
    };
}

if (!window.copyLinuxCmd) {
    window.copyLinuxCmd = function (btn, tplId) {
        const tpl = document.getElementById(tplId);
        if (!tpl) return;
        const text = tpl.innerHTML
            .replace(/&lt;/g, '<')
            .replace(/&gt;/g, '>')
            .replace(/&amp;/g, '&');
        navigator.clipboard.writeText(text).then(() => {
            const orig = btn.textContent;
            btn.textContent = 'Copied!';
            setTimeout(() => { btn.textContent = orig; }, 1200);
        });
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
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', run);
    } else {
        run();
    }
})();
