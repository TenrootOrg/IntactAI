// Engagement Report — bundles N completed workflow runs (agentic /
// aws_scan / azure_scan) into one customer-facing IR markdown
// deliverable.
//
// UX flow (workflows-page driven):
//   1. Operator checks the box next to each eligible row in the
//      Workflows table.
//   2. A selection bar appears above the table showing count +
//      "Generate Engagement Report" button.
//   3. Clicking Generate opens the compose modal: pick a name,
//      override per-source section assignments, add notes.
//   4. Generate dispatches the build; the modal closes; a new
//      `engagement_report` workflow row appears in the same table
//      with progress bar and Download / Interactive buttons.
//
// Endpoints used: /api/engagement/generate (backend already shipped).

document.addEventListener('alpine:init', () => {
    Alpine.store('engagement', {
        // The set of run_ids the operator has ticked in the table.
        // Stored as plain array (so Alpine reactivity sees mutations).
        selectedRunIds: [],
        // Per-run section assignment: {run_id: 'Endpoints' | 'AWS' | 'Azure' | 'Other'}
        // Defaults are auto-assigned from automation_type on first toggle;
        // operator can override per row inside the compose modal.
        sectionByRun: {},
        // Cache of run rows we've seen (id -> row), so the compose modal
        // has the name/type even if the operator scrolls past the row.
        runsById: {},

        composeOpen: false,
        name: '',
        notes: '',
        // Operator-controlled engagement metadata. These default to the
        // same values the backend used to hardcode (TLP=AMBER, audience
        // mixed, English) so blank-form behaviour matches the old build
        // exactly. Logo override is a data URL; empty falls back to the
        // embedded Tenroot brand.
        tlp: 'AMBER',
        customerName: '',
        audience: 'both',
        language: 'en',
        logoB64: '',
        logoName: '',
        generating: false,
        status: '',
        statusLevel: 'info',

        // ──────────────────────────────────────────────────────────────
        // Predicates + helpers
        // ──────────────────────────────────────────────────────────────

        // Only rows that produce an LLM-written report are eligible.
        // Mirrors the predicate the existing "Report" download button
        // uses in the workflow row template — agentic runs always
        // generate one when status=completed, but AWS/Azure scans
        // emit a row marked `llm_enabled: false` (no LLM ran) which
        // has no report content to feed the engagement builder.
        // Those rows show the orange "LLM disabled" chip — and they
        // get no checkbox here.
        isEligible(run) {
            if (!run || run.status !== 'completed') return false;
            if (run.type === 'agentic') return true;
            if (run.type === 'aws_scan' || run.type === 'azure_scan') {
                const d = run.details || {};
                return d.has_report === true && d.llm_enabled !== false;
            }
            if (run.type === 'cve_scan') {
                // CVE Scan doesn't run an LLM; eligibility is whether
                // it produced the short markdown summary + findings.json
                // (both come from save_report + findings.json write in
                // services/cve_scan/pipeline.py).
                const d = run.details || {};
                return d.has_report === true;
            }
            return false;
        },

        isSelected(runId) {
            return this.selectedRunIds.includes(runId);
        },

        // Default section for a given automation_type. Operator can
        // Every automation_type maps to exactly one canonical
        // section, decided by its data source. Agentic = Velociraptor
        // endpoint forensics (whether single-host, multi-host, or
        // multi-host with a DC), so it always lands in the Endpoints
        // section. The LLM surfaces any AD-specific findings inside
        // that section.
        _defaultSection(run) {
            const t = run.type || run.automation_type;
            switch (t) {
                case 'agentic':    return 'Endpoints';
                case 'aws_scan':   return 'AWS';
                case 'azure_scan': return 'Azure';
                case 'cve_scan':   return 'Vulnerabilities';
                default:           return 'Other';
            }
        },

        setSection(runId, section) {
            this.sectionByRun[runId] = section;
        },

        toggle(run) {
            const id = run.id;
            if (this.isSelected(id)) {
                this.remove(id);
                return;
            }
            this.runsById[id] = {
                run_id: id,
                name: run.name || id,
                automation_type: run.type,
                details: run.details || {},
            };
            this.selectedRunIds.push(id);
            // Default must run AFTER runsById is set so the agentic
            // heuristic can inspect details.hostnames.
            this.sectionByRun[id] = this._defaultSection(this.runsById[id]);
        },

        // No row is operator-choosable — each automation_type has
        // exactly one section. Pin them here so the payload to the
        // backend is always correct regardless of any state quirk.
        sectionFor(runId) {
            const run = this.runsById[runId];
            if (run) {
                if (run.automation_type === 'agentic')    return 'Endpoints';
                if (run.automation_type === 'aws_scan')   return 'AWS';
                if (run.automation_type === 'azure_scan') return 'Azure';
                if (run.automation_type === 'cve_scan')   return 'Vulnerabilities';
            }
            return this.sectionByRun[runId] || 'Other';
        },

        remove(runId) {
            this.selectedRunIds = this.selectedRunIds.filter(id => id !== runId);
            delete this.sectionByRun[runId];
            delete this.runsById[runId];
        },

        clearSelection() {
            this.selectedRunIds = [];
            this.sectionByRun = {};
            this.runsById = {};
        },

        // Computed: detail rows used by the compose modal. Each entry
        // pairs the run_id with whatever name/type we cached at toggle
        // time, so the modal works even if the runs list has rolled.
        get selectedDetails() {
            return this.selectedRunIds.map(id => this.runsById[id] || { run_id: id, name: id, automation_type: 'unknown' });
        },

        // ──────────────────────────────────────────────────────────────
        // Compose modal lifecycle
        // ──────────────────────────────────────────────────────────────

        openComposeModal() {
            if (this.selectedRunIds.length === 0) return;
            this.composeOpen = true;
            this.status = '';
            // Default the name if blank — operator can replace.
            if (!this.name) {
                const today = new Date().toISOString().slice(0, 10);
                this.name = `IR Engagement — ${today}`;
            }
        },

        closeComposeModal() {
            this.composeOpen = false;
        },

        // ──────────────────────────────────────────────────────────────
        // Dispatch the build
        // ──────────────────────────────────────────────────────────────
        //
        // POST then immediately close — the build runs in the backend
        // worker thread and the operator monitors progress via the
        // workflow row on the dashboard (which already polls). No need
        // for a duplicate progress UI inside the modal.

        async generate() {
            if (this.generating) return;
            if (this.selectedRunIds.length === 0) {
                this._setStatus('No workflows selected.', 'error');
                return;
            }
            const name = (this.name || '').trim() || `IR Engagement — ${new Date().toISOString().slice(0, 10)}`;
            const sources = this.selectedRunIds.map(id => ({
                run_id: id,
                section: this.sectionByRun[id] || 'Other',
            }));
            this.generating = true;
            this._setStatus('Dispatching build…', 'info');
            try {
                const r = await fetch('/api/engagement/generate', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        name,
                        sources,
                        notes: this.notes || '',
                        tlp: this.tlp || 'AMBER',
                        customer_name: this.customerName || '',
                        audience: this.audience || 'both',
                        language: this.language || 'en',
                        customer_logo_b64: this.logoB64 || '',
                    }),
                });
                const data = await r.json();
                if (!r.ok) throw new Error(data.error || `HTTP ${r.status}`);
                // Success — close modal + clear state. The new
                // engagement_report row picks up the live progress bar
                // on the dashboard.
                this.composeOpen = false;
                this.clearSelection();
                this.name = '';
                this.notes = '';
                this.customerName = '';
                this.logoB64 = '';
                this.logoName = '';
                if (Alpine.store('workflows')?.load) Alpine.store('workflows').load();
            } catch (e) {
                this._setStatus(`Build failed: ${e.message}`, 'error');
            } finally {
                this.generating = false;
            }
        },


        // File-picker handler for the logo upload field. Reads the
        // chosen file as a base64 data URL ready to drop into the
        // dispatch payload — backend stores the data URL verbatim and
        // the PDF renderer embeds it directly into <img src="…">.
        async onLogoSelected(event) {
            const file = event?.target?.files?.[0];
            if (!file) {
                this.logoB64 = '';
                this.logoName = '';
                return;
            }
            // 1.5 MiB hard cap — the backend cap is 2 MiB on the
            // already-encoded payload (~1.5 MiB raw). Keep them in sync.
            if (file.size > 1_500_000) {
                this._setStatus('Logo too large (>1.5 MB). Pick a smaller image.', 'error');
                event.target.value = '';
                return;
            }
            try {
                const reader = new FileReader();
                const dataUrl = await new Promise((resolve, reject) => {
                    reader.onerror = () => reject(reader.error);
                    reader.onload = () => resolve(reader.result);
                    reader.readAsDataURL(file);
                });
                this.logoB64 = dataUrl || '';
                this.logoName = file.name || '';
            } catch (e) {
                this._setStatus(`Could not read logo file: ${e.message}`, 'error');
            }
        },

        clearLogo() {
            this.logoB64 = '';
            this.logoName = '';
        },

        _setStatus(text, level) {
            this.status = text || '';
            this.statusLevel = level || 'info';
        },
    });
});
