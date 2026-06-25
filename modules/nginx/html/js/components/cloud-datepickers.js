/* AWS + Azure date-range pickers (flatpickr) — extracted from inline <script>
 * in index.html. These stay window-global: the cloud tabs call the init,
 * update and getAzureCustomDates functions from x-init / @change / their
 * Alpine startScan methods.
 */

// ---- Azure date pickers --------------------------------------------------
let azureFpStart = null, azureFpEnd = null;

function initAzureDatePickers() {
    if (typeof flatpickr === 'undefined') return;
    const startEl = document.getElementById('azure-date-start');
    const endEl = document.getElementById('azure-date-end');
    if (!startEl || !endEl) return;

    if (azureFpStart) { azureFpStart.destroy(); azureFpStart = null; }
    if (azureFpEnd) { azureFpEnd.destroy(); azureFpEnd = null; }

    const config = {
        dateFormat: 'Y-m-d',
        disableMobile: true,
        allowInput: false,
        clickOpens: true,
        appendTo: document.body,
    };

    setTimeout(() => {
        azureFpStart = flatpickr(startEl, {
            ...config,
            onChange: (dates) => {
                updateAzureStartDateTime();
                if (azureFpEnd && dates[0]) azureFpEnd.set('minDate', dates[0]);
            },
        });
        azureFpEnd = flatpickr(endEl, {
            ...config,
            onChange: (dates) => {
                updateAzureEndDateTime();
                if (azureFpStart && dates[0]) azureFpStart.set('maxDate', dates[0]);
            },
        });
    }, 50);
}

function updateAzureStartDateTime() {
    const dateEl = document.getElementById('azure-date-start');
    const hourEl = document.getElementById('azure-time-start-hour');
    const hiddenEl = document.getElementById('azure-time-start');
    if (dateEl?.value && hourEl && hiddenEl) {
        hiddenEl.value = dateEl.value + 'T' + hourEl.value + ':00:00Z';
    }
}

function updateAzureEndDateTime() {
    const dateEl = document.getElementById('azure-date-end');
    const hourEl = document.getElementById('azure-time-end-hour');
    const hiddenEl = document.getElementById('azure-time-end');
    if (dateEl?.value && hourEl && hiddenEl) {
        hiddenEl.value = dateEl.value + 'T' + hourEl.value + ':00:00Z';
    }
}

function getAzureCustomDates() {
    return {
        start: document.getElementById('azure-time-start')?.value || '',
        end: document.getElementById('azure-time-end')?.value || '',
    };
}

// ---- AWS date pickers (mirror of the Azure pair) -------------------------
let awsFpStart = null, awsFpEnd = null;

function initAwsDatePickers() {
    const startEl = document.getElementById('aws-date-start');
    const endEl = document.getElementById('aws-date-end');
    if (!startEl || !endEl || typeof flatpickr === 'undefined') return;
    if (awsFpStart && awsFpEnd) return; // already initialised

    const config = {
        dateFormat: 'Y-m-d',
        allowInput: false,
        maxDate: 'today',
        theme: 'dark',
    };
    setTimeout(() => {
        awsFpStart = flatpickr(startEl, {
            ...config,
            onChange: (dates) => { updateAwsStartDateTime(); if (awsFpEnd && dates[0]) awsFpEnd.set('minDate', dates[0]); },
        });
        awsFpEnd = flatpickr(endEl, {
            ...config,
            onChange: (dates) => { updateAwsEndDateTime(); if (awsFpStart && dates[0]) awsFpStart.set('maxDate', dates[0]); },
        });
    }, 50);
}

function updateAwsStartDateTime() {
    const dateEl = document.getElementById('aws-date-start');
    const hourEl = document.getElementById('aws-time-start-hour');
    const hiddenEl = document.getElementById('aws-time-start');
    if (dateEl?.value && hourEl && hiddenEl) {
        hiddenEl.value = dateEl.value + 'T' + hourEl.value + ':00:00Z';
    }
}

function updateAwsEndDateTime() {
    const dateEl = document.getElementById('aws-date-end');
    const hourEl = document.getElementById('aws-time-end-hour');
    const hiddenEl = document.getElementById('aws-time-end');
    if (dateEl?.value && hourEl && hiddenEl) {
        hiddenEl.value = dateEl.value + 'T' + hourEl.value + ':00:00Z';
    }
}
