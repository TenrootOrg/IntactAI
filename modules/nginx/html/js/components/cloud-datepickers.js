/* AWS + Azure date-range pickers (flatpickr) — extracted from inline <script>
 * in index.html. These stay window-global: the cloud tabs call the init,
 * sync and getCloudCustomDates functions from x-init / onchange / their
 * Alpine startScan methods.
 *
 * Both tabs render the same widget — a readonly date input, an hour <select>,
 * and a hidden input holding the combined UTC value — under a `<cloud>-` id
 * prefix. Everything below is therefore written once and takes the prefix as
 * an argument; only two flatpickr options actually differ per cloud.
 */

const cloudFp = { aws: {}, azure: {} };

/** Write "<date>T<hour>:00:00Z" into the hidden field for one edge of a range. */
function syncCloudDateTime(cloud, edge) {
    const dateEl = document.getElementById(`${cloud}-date-${edge}`);
    const hourEl = document.getElementById(`${cloud}-time-${edge}-hour`);
    const hiddenEl = document.getElementById(`${cloud}-time-${edge}`);
    if (dateEl?.value && hourEl && hiddenEl) {
        hiddenEl.value = `${dateEl.value}T${hourEl.value}:00:00Z`;
    }
}

function initCloudDatePickers(cloud) {
    if (typeof flatpickr === 'undefined') return;
    const startEl = document.getElementById(`${cloud}-date-start`);
    const endEl = document.getElementById(`${cloud}-date-end`);
    if (!startEl || !endEl) return;

    // Destroy-and-recreate rather than "skip if already made": the pickers are
    // built inside the setTimeout below, so a second call within 50ms would
    // otherwise slip past an "already initialised" guard and double-bind.
    const fp = cloudFp[cloud];
    fp.start?.destroy();
    fp.end?.destroy();
    fp.start = fp.end = null;

    const config = {
        dateFormat: 'Y-m-d',
        allowInput: false,
        // `document.body` is read here, not at load time, so this file stays
        // safe to include from <head>.
        ...(cloud === 'aws'
            ? { maxDate: 'today', theme: 'dark' }
            : { disableMobile: true, clickOpens: true, appendTo: document.body }),
    };

    setTimeout(() => {
        fp.start = flatpickr(startEl, {
            ...config,
            onChange: (dates) => {
                syncCloudDateTime(cloud, 'start');
                if (fp.end && dates[0]) fp.end.set('minDate', dates[0]);
            },
        });
        fp.end = flatpickr(endEl, {
            ...config,
            onChange: (dates) => {
                syncCloudDateTime(cloud, 'end');
                if (fp.start && dates[0]) fp.start.set('maxDate', dates[0]);
            },
        });
    }, 50);
}

function getCloudCustomDates(cloud) {
    return {
        start: document.getElementById(`${cloud}-time-start`)?.value || '',
        end: document.getElementById(`${cloud}-time-end`)?.value || '',
    };
}
