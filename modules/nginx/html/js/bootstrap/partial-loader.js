/* Partial loader — assembles index.html from partials/*.html, then starts Alpine.
 *
 * Why: index.html is a thin shell with <div data-partial="NAME"></div>
 * placeholders. This loader fetches each partial and swaps it in (outerHTML), so
 * the partial's own root <div x-show=...> lands exactly where the placeholder was.
 * Alpine is started ONLY AFTER all partials are injected (alpine.min.js is NOT in
 * <head> anymore) so it walks a DOM that already contains every tab — the existing
 * x-show tab logic keeps working unchanged, no Alpine.initTree needed.
 *
 * Events:
 *   - 'partials:ready'      dispatched once all partials are injected (before Alpine).
 *   - 'alpine:initialized'  Alpine's own event, fired after it starts.
 * Code that touches partial DOM listens for 'partials:ready'; code that needs the
 * Alpine stores listens for 'alpine:initialized'.
 */
(function () {
    // Tabs that live in partials/. One file per tab panel in <main>.
    const PARTIALS = [
        'cases', 'case-analysis', 'dashboard', 'workflows', 'downloads',
        'velociraptor', 'timesketch', 'cve', 'memory', 'blueprints',
        'scheduler', 'aws', 'azure', 'settings',
    ];

    async function injectAll() {
        await Promise.all(PARTIALS.map(async (name) => {
            const ph = document.querySelector(`[data-partial="${name}"]`);
            if (!ph) return;
            try {
                const res = await fetch(`partials/${name}.html`);
                if (!res.ok) throw new Error('HTTP ' + res.status);
                ph.outerHTML = await res.text();
            } catch (e) {
                console.error(`[partials] failed to load "${name}":`, e);
                ph.innerHTML = `<div class="p-6 text-red-400">Failed to load the ${name} panel.</div>`;
            }
        }));
    }

    function start() {
        injectAll().then(() => {
            document.dispatchEvent(new CustomEvent('partials:ready'));
            // Start Alpine now that every partial is in the DOM.
            const s = document.createElement('script');
            s.src = 'js/alpine.min.js?v=1';
            document.head.appendChild(s);
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', start);
    } else {
        start();
    }
})();
