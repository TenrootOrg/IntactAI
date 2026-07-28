/**
 * Reset an automation tab to its defaults when the operator returns to it.
 *
 * Tabs are shown/hidden with x-show, never destroyed, so every panel keeps
 * whatever the last run left behind: the "Collection started! Run ID: … —
 * Redirecting to Workflows…" banner, a half-filled form, a client selection
 * that no longer matches the filter. Coming back to Velociraptor showed the
 * PREVIOUS run's message as if it had just happened — worst case the operator
 * reads a stale run id and goes hunting for the wrong workflow.
 *
 * Why a snapshot instead of a written-out reset() per page: the defaults would
 * then live in two places (the x-data literal / store literal, and the reset),
 * and they drift the first time someone adds a field and forgets the second
 * copy — silently, because a field that fails to reset looks exactly like a
 * field the operator filled in.  Here the defaults ARE the snapshot, taken
 * once at arm time before any interaction, so a new field is covered for free.
 *
 * Caches are exempt via `keep`. Blueprint lists, client lists and similar are
 * expensive to refetch and are not "input the operator left behind", so
 * wiping them would turn every tab switch into a reload.
 *
 * Usage:
 *   TabReset.arm($data, 'cloud-aws', { keep: ['awsBlueprints'] })   // x-init
 *   TabReset.arm(Alpine.store('memory'), 'modules-memory', {...})   // stores
 */
(function () {
    'use strict';

    function snapshot(obj, keep) {
        const snap = {};
        for (const [k, v] of Object.entries(obj)) {
            if (typeof v === 'function') continue;      // methods, not state
            if (k.startsWith('$')) continue;            // Alpine magics
            if (keep.has(k)) continue;                  // caches
            // Structured-clone the value so later mutation of an array/object
            // in place (items.push(...)) cannot corrupt the pristine copy.
            try {
                snap[k] = (v === null || typeof v !== 'object')
                    ? v : JSON.parse(JSON.stringify(v));
            } catch (e) {
                // Non-serialisable (File handles, DOM nodes, AbortController).
                // null is the right reset for those — they are per-run objects.
                snap[k] = null;
            }
        }
        return snap;
    }

    window.TabReset = {
        /**
         * Take the defaults now, and restore them whenever `tab` is entered.
         * Call once, at init — arming twice would snapshot state the operator
         * has already touched and make THAT the new "default".
         */
        arm(target, tab, opts) {
            if (!target || target.__tabResetArmed) return;
            const keep = new Set((opts && opts.keep) || []);
            const defaults = snapshot(target, keep);
            target.__tabResetArmed = true;

            window.addEventListener('automation-tab-entered', (ev) => {
                if (ev.detail !== tab) return;
                for (const [k, v] of Object.entries(defaults)) {
                    target[k] = (v === null || typeof v !== 'object')
                        ? v : JSON.parse(JSON.stringify(v));
                }
            });
        },
    };
})();
