/* AWS + Azure scan time window: the same two date+time fields as Case Analysis
 * (Configuration -> Time window). Values are UTC, "YYYY-MM-DDTHH:MM:SS"; an empty
 * end means "up to now". The pages call initCloudTimeWindow(prefix) from x-init
 * and cloudTimeFilter(prefix) when the scan starts.
 *
 * Before 2026-10-26 these pages had a preset dropdown + date box + hour box and
 * sent {type, value}, a shape no backend reader understood: the picker did nothing.
 */

const CLOUD_TW_DEFAULT_HOURS = 24;   // the window a fresh page starts with

function _cloudTwUtc(ms) {
    return new Date(ms).toISOString().slice(0, 16) + ':00';
}

function initCloudTimeWindow(prefix) {
    const start = document.getElementById(prefix + '-tw-start');
    const end = document.getElementById(prefix + '-tw-end');
    if (!start || !end) return;
    if (!start.value) start.value = _cloudTwUtc(Date.now() - CLOUD_TW_DEFAULT_HOURS * 3600e3);
    if (typeof flatpickr === 'undefined' || start._flatpickr) return;
    // Same options as the Case Analysis time window.
    const fp = { enableTime: true, time_24hr: true, dateFormat: 'Y-m-d\\TH:i:S', minuteIncrement: 5, allowInput: true };
    flatpickr(start, fp);
    flatpickr(end, fp);
}

const _CLOUD_TW_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2})?$/;

/* {filter} for the scan request, or {error} to show the operator. */
function cloudTimeFilter(prefix) {
    const v = id => ((document.getElementById(prefix + id) || {}).value || '').trim().replace(/Z$/, '');
    const start = v('-tw-start'), end = v('-tw-end');
    if (!start) return { error: 'Pick the start of the time window.' };
    if (!_CLOUD_TW_RE.test(start)) return { error: 'The start "' + start + '" is not a date and time (YYYY-MM-DDTHH:MM).' };
    if (end && !_CLOUD_TW_RE.test(end)) return { error: 'The end "' + end + '" is not a date and time (YYYY-MM-DDTHH:MM).' };
    const z = s => (s.length === 16 ? s + ':00' : s) + 'Z';
    if (end && z(end) <= z(start)) return { error: 'The end of the time window must be after the start.' };
    return { filter: { enabled: true, mode: 'between', start_datetime: z(start), end_datetime: end ? z(end) : '' } };
}
