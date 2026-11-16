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
    const org = (active && active.velo_org) || 'root';
    bar.innerHTML =
        `<span style="font-size:12px;color:#8b949e">Case:</span>
         <a href="#cases" id="ws-link" style="color:#58a6ff;font-weight:600">${escWs(name)}</a>
         <span style="font-size:12px;color:#8b949e;margin-left:8px">Org:</span>
         <a href="#cases" id="ws-org-link" style="color:#58a6ff;font-weight:600" title="The case's Velociraptor org: everything this case does in Velociraptor runs there. Change it by editing the case.">${escWs(org)}</a>`;
    if (window.VeloOrg) window.VeloOrg.nameOf(org).then(n => {
        const a = bar.querySelector('#ws-org-link'); if (a) a.textContent = n;
    });
    // Both open Case Management: the org is set on the case there.
    bar.querySelectorAll('#ws-link, #ws-org-link').forEach(el => el.addEventListener('click', function (e) {
        e.preventDefault();
        if (window.Alpine) Alpine.store('app').switchTab('cases');
    }));
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
            // Same-tab changes (e.g. ActiveCase auto-switching a module launch
            // from System -> Default) don't fire 'storage'; ActiveCase.set()
            // dispatches this instead. Keep the bar in sync so the operator sees
            // the workspace they were moved to.
            window.addEventListener('active-case-changed', function () {
                renderTopWorkspace(bar);
            });
            // The case's org was edited (Case Management saves -> re-sync).
            window.addEventListener('velo-org-changed', function () {
                renderTopWorkspace(bar);
            });
        }
    };
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', run);
    } else {
        run();
    }
})();
