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

/* defaultHours: the window a fresh page shows. onUserChange: called when the OPERATOR
   changes either field (picked, typed or cleared) -- never for a value set in code. */
function initCloudTimeWindow(prefix, defaultHours, onUserChange) {
    const start = document.getElementById(prefix + '-tw-start');
    const end = document.getElementById(prefix + '-tw-end');
    if (!start || !end) return;
    const hours = defaultHours > 0 ? defaultHours : CLOUD_TW_DEFAULT_HOURS;
    if (!start.value) start.value = _cloudTwUtc(Date.now() - hours * 3600e3);   // local-clock-ok: an editable default, not a duration
    if (typeof flatpickr === 'undefined' || start._flatpickr) return;
    // Same options as the Case Analysis time window.
    // Saved on every way the operator can change it. onChange alone missed TYPED edits:
    // a typed date is committed when the calendar closes, silently (no onChange), so
    // it was never saved and came back as the old window on the next load (2026-10-26,
    // reproduced in Chromium). The callback dedupes, so firing twice is harmless.
    const changed = () => { if (typeof onUserChange === 'function') setTimeout(onUserChange, 0); };
    const fp = { enableTime: true, time_24hr: true, dateFormat: 'Y-m-d\\TH:i:S', minuteIncrement: 5, allowInput: true,
                 onChange: changed, onClose: changed };
    flatpickr(start, fp);
    flatpickr(end, fp);
    start.addEventListener('blur', changed);
    end.addEventListener('blur', changed);
}

/* Show a saved window: {hours} = the last N hours (end open), {start, end} = fixed. */
function setCloudTimeWindow(prefix, tw) {
    const start = document.getElementById(prefix + '-tw-start');
    const end = document.getElementById(prefix + '-tw-end');
    if (!start || !end || !tw) return;
    const s = tw.hours > 0 ? _cloudTwUtc(Date.now() - tw.hours * 3600e3)   // local-clock-ok: a rolling window's start, not a duration
            : String(tw.start || '').replace(/Z$/, '');
    const e = tw.hours > 0 ? '' : String(tw.end || '').replace(/Z$/, '');   // '' = up to now
    if (!s) return;
    if (start._flatpickr) start._flatpickr.setDate(s, false); else start.value = s;
    if (end._flatpickr) { if (e) end._flatpickr.setDate(e, false); else end._flatpickr.clear(false); } else end.value = e;
}

/* What to remember: exactly what the operator set (an empty end stays "up to now").
   Only the untouched default rolls ({hours}). Turning a typed start into "the last N
   hours" moved it forward every day -- not what was typed (2026-10-26).
   null while the fields do not hold a valid window. */
function cloudTimeWindowToSave(prefix) {
    const tw = cloudTimeFilter(prefix);
    if (tw.error) return null;
    const f = tw.filter;
    return { start: f.start_datetime.replace(/Z$/, ''), end: f.end_datetime.replace(/Z$/, '') };
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
