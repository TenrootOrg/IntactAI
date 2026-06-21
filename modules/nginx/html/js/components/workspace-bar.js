/* Active-workspace top bar — extracted from inline <script> in index.html.
 * Renders the active case name into #workspace-bar and keeps it in sync when
 * the Case Management view (separate frame) changes the active workspace.
 */

function escWs(s) {
    return (s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

async function renderTopWorkspace(bar) {
    const { id, cases } = await window.ActiveCase.ensureActiveCase();
    const active = (cases || []).find(c => c.case_id === id);
    const name = active ? (active.name || active.case_id) : '—';
    bar.innerHTML =
        `<span style="font-size:12px;color:#8b949e">Workspace:</span>
         <a href="#cases" id="ws-link" style="color:#58a6ff;font-weight:600">${escWs(name)}</a>
         <span style="font-size:12px;color:#8b949e">· manage ▸</span>`;
    bar.querySelector('#ws-link').addEventListener('click', function (e) {
        e.preventDefault();
        if (window.Alpine) Alpine.store('app').switchTab('cases');
    });
}

(function initWorkspaceBar() {
    const run = async () => {
        const bar = document.getElementById('workspace-bar');
        if (bar && window.ActiveCase) {
            await renderTopWorkspace(bar);
            // Refresh the name when the Case Management view changes the active
            // workspace — localStorage fires 'storage' cross-frame.
            window.addEventListener('storage', function (e) {
                if (e.key === 'activeCaseId') renderTopWorkspace(bar);
            });
        }
    };
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', run);
    } else {
        run();
    }
})();
