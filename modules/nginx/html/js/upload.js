/**
 * Resumable Upload Component using tus protocol
 *
 * Provides unified upload functionality for:
 * - Velociraptor offline collector import
 * - Timesketch KAPE file upload
 *
 * Features:
 * - Resumable uploads (survives page refresh, connection drops)
 * - Progress tracking with speed calculation
 * - Automatic retry on failure
 * - Drag and drop support
 */

class TusUploader {
    /**
     * Create a new TusUploader instance
     * @param {Object} options Configuration options
     * @param {string} options.purpose - Upload purpose: 'velociraptor' or 'timesketch'
     * @param {Object} options.metadata - Additional metadata to send with upload
     * @param {Function} options.onProgress - Progress callback: (info) => {}
     * @param {Function} options.onSuccess - Success callback: (upload) => {}
     * @param {Function} options.onError - Error callback: (error) => {}
     */
    constructor(options = {}) {
        this.endpoint = '/api/uploads/';
        this.purpose = options.purpose || 'velociraptor';
        this.metadata = options.metadata || {};
        this.onProgress = options.onProgress || (() => {});
        this.onSuccess = options.onSuccess || (() => {});
        this.onError = options.onError || (() => {});

        this.currentUpload = null;
        this._startTime = null;
        this._lastBytes = 0;
        this._lastTime = null;
        this._speedHistory = [];
    }

    /**
     * Start or resume an upload
     * @param {File} file The file to upload
     * @returns {Object} tus Upload instance
     */
    upload(file) {
        if (!file) {
            this.onError(new Error('No file provided'));
            return null;
        }

        // Check if tus library is loaded
        if (typeof tus === 'undefined') {
            this.onError(new Error('tus library not loaded. Include tus-js-client before upload.js'));
            return null;
        }

        // PROACTIVE System-workspace guard. tus uploads (velociraptor offline
        // collector, timesketch import) are MODULE work: the backend creates the
        // run server-side AFTER the upload completes, so when the active workspace
        // is System it rejects the run with a 409 the browser never sees — the
        // import just silently does nothing. Block up front with a clear alert,
        // BEFORE wasting time uploading a (possibly large) collection ZIP.
        if (window.ActiveCase && window.ActiveCase.blockIfSystem) {
            window.ActiveCase.blockIfSystem(
                'This import runs against an investigation workspace, not System. ' +
                'Switch to or create an investigation workspace first, then re-import.'
            ).then((blocked) => { if (!blocked) this._beginUpload(file); });
            return null;
        }
        this._beginUpload(file);
        return null;
    }

    /** Start the actual tus upload (after the System-workspace guard passes). */
    _beginUpload(file) {
        this._startTime = Date.now();
        this._lastTime = this._startTime;
        this._lastBytes = 0;
        this._speedHistory = [];

        const uploadMetadata = {
            filename: file.name,
            filetype: file.type || 'application/zip',
            purpose: this.purpose,
            // Tag the upload to the browser's active workspace. tus uses its own
            // XHR (bypassing the window.fetch X-Case-Id hook), so the case must
            // ride in the upload metadata for the tusd hook to tag the run.
            case_id: (window.ActiveCase && window.ActiveCase.get && window.ActiveCase.get()) || '',
            ...this.metadata
        };

        console.log('[TusUploader] Starting upload:', file.name);
        console.log('[TusUploader] Metadata:', uploadMetadata);

        const upload = new tus.Upload(file, {
            endpoint: this.endpoint,
            retryDelays: [0, 1000, 3000, 5000, 10000],
            chunkSize: 5 * 1024 * 1024, // 5MB chunks
            metadata: uploadMetadata,

            onError: (error) => {
                console.error('[TusUploader] Upload error:', error);
                this.onError(error);
            },

            onProgress: (bytesUploaded, bytesTotal) => {
                const percentage = ((bytesUploaded / bytesTotal) * 100).toFixed(1);
                const speed = this._calculateSpeed(bytesUploaded);
                const eta = this._calculateETA(bytesUploaded, bytesTotal, speed);

                this.onProgress({
                    bytesUploaded,
                    bytesTotal,
                    percentage: parseFloat(percentage),
                    speed,
                    speedFormatted: this._formatSpeed(speed),
                    eta,
                    etaFormatted: this._formatETA(eta)
                });
            },

            onSuccess: () => {
                console.log('[TusUploader] Upload complete:', upload.url);
                this.onSuccess(upload);
            },

            onShouldRetry: (err, retryAttempt, options) => {
                console.log(`[TusUploader] Retry attempt ${retryAttempt}:`, err.message);
                // Never retry an auth failure. nginx gates /api/uploads/ with
                // auth_request, so once the session expires EVERY subsequent
                // PATCH is a 401 — retrying just spins until the retry budget
                // runs out and reports a misleading network error. onAfterResponse
                // redirects to the login page instead.
                const status = err && err.originalResponse && err.originalResponse.getStatus
                    ? err.originalResponse.getStatus() : 0;
                if (status === 401 || status === 403) return false;
                // Retry on network errors
                return true;
            },

            onAfterResponse: (req, res) => {
                // Log response for debugging
                const status = res.getStatus();
                if (status >= 400) {
                    console.error(`[TusUploader] Server error: ${status}`);
                }
                // tus uses XMLHttpRequest, so it never passes through the
                // window.fetch 401 hook in js/active-case.js. nginx gates
                // /api/uploads/ with auth_request, so an expired session turns
                // every PATCH into a 302 to the login page — which onShouldRetry
                // above would happily retry forever. Bounce to the login page
                // instead of spinning.
                if (status === 401 || status === 403) {
                    console.error('[TusUploader] Session expired mid-upload — redirecting to login');
                    try { location.replace('/login.html?reason=expired'); }
                    catch (e) { location.href = '/login.html?reason=expired'; }
                }
            }
        });

        // Check for previous uploads to resume
        upload.findPreviousUploads().then((previousUploads) => {
            if (previousUploads.length > 0) {
                const prev = previousUploads[0];
                console.log('[TusUploader] Found previous upload, resuming from:', prev.uploadUrl);
                upload.resumeFromPreviousUpload(prev);
            }
            upload.start();
        }).catch((err) => {
            console.log('[TusUploader] No previous uploads found, starting fresh');
            upload.start();
        });

        this.currentUpload = upload;
        return upload;
    }

    /**
     * Abort the current upload
     */
    abort() {
        if (this.currentUpload) {
            console.log('[TusUploader] Aborting upload');
            this.currentUpload.abort();
            this.currentUpload = null;
        }
    }

    /**
     * Calculate upload speed in bytes per second
     */
    _calculateSpeed(bytesUploaded) {
        const now = Date.now();
        const timeDiff = (now - this._lastTime) / 1000; // seconds

        if (timeDiff < 0.5) {
            // Return last known speed if time diff too small
            return this._speedHistory.length > 0
                ? this._speedHistory[this._speedHistory.length - 1]
                : 0;
        }

        const bytesDiff = bytesUploaded - this._lastBytes;
        const speed = bytesDiff / timeDiff;

        // Keep rolling average of last 5 speed samples
        this._speedHistory.push(speed);
        if (this._speedHistory.length > 5) {
            this._speedHistory.shift();
        }

        this._lastBytes = bytesUploaded;
        this._lastTime = now;

        // Return average speed
        const avgSpeed = this._speedHistory.reduce((a, b) => a + b, 0) / this._speedHistory.length;
        return Math.max(0, avgSpeed);
    }

    /**
     * Calculate estimated time remaining in seconds
     */
    _calculateETA(bytesUploaded, bytesTotal, speed) {
        if (speed <= 0) return Infinity;
        const remaining = bytesTotal - bytesUploaded;
        return remaining / speed;
    }

    /**
     * Format speed for display
     */
    _formatSpeed(bytesPerSecond) {
        if (bytesPerSecond < 1024) {
            return `${bytesPerSecond.toFixed(0)} B/s`;
        } else if (bytesPerSecond < 1024 * 1024) {
            return `${(bytesPerSecond / 1024).toFixed(1)} KB/s`;
        } else {
            return `${(bytesPerSecond / 1024 / 1024).toFixed(1)} MB/s`;
        }
    }

    /**
     * Format ETA for display
     */
    _formatETA(seconds) {
        if (!isFinite(seconds) || seconds < 0) {
            return 'calculating...';
        }

        if (seconds < 60) {
            return `${Math.ceil(seconds)}s`;
        } else if (seconds < 3600) {
            const mins = Math.floor(seconds / 60);
            const secs = Math.ceil(seconds % 60);
            return `${mins}m ${secs}s`;
        } else {
            const hours = Math.floor(seconds / 3600);
            const mins = Math.floor((seconds % 3600) / 60);
            return `${hours}h ${mins}m`;
        }
    }
}

/**
 * Format bytes for display
 * @param {number} bytes Number of bytes
 * @returns {string} Formatted string (e.g., "1.5 MB")
 */
function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

/**
 * Initialize a drag-and-drop zone
 * @param {string} dropzoneId ID of the dropzone element
 * @param {string} fileInputId ID of the hidden file input
 * @param {Function} onFileSelected Callback when file is selected: (file) => {}
 */
function initDropzone(dropzoneId, fileInputId, onFileSelected) {
    const dropzone = document.getElementById(dropzoneId);
    const fileInput = document.getElementById(fileInputId);

    if (!dropzone || !fileInput) {
        console.error('[Dropzone] Elements not found:', dropzoneId, fileInputId);
        return;
    }

    // Click to browse
    dropzone.addEventListener('click', () => fileInput.click());

    // Drag events
    dropzone.addEventListener('dragover', (e) => {
        e.preventDefault();
        e.stopPropagation();
        dropzone.classList.add('border-purple-500', 'bg-purple-500/10');
    });

    dropzone.addEventListener('dragleave', (e) => {
        e.preventDefault();
        e.stopPropagation();
        dropzone.classList.remove('border-purple-500', 'bg-purple-500/10');
    });

    dropzone.addEventListener('drop', (e) => {
        e.preventDefault();
        e.stopPropagation();
        dropzone.classList.remove('border-purple-500', 'bg-purple-500/10');

        const files = e.dataTransfer.files;
        if (files.length > 0) {
            fileInput.files = files;
            if (onFileSelected) {
                onFileSelected(files[0]);
            }
        }
    });

    // File input change
    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
            if (onFileSelected) {
                onFileSelected(e.target.files[0]);
            }
        }
    });
}

// Export for use in other modules
window.TusUploader = TusUploader;
window.formatBytes = formatBytes;
window.initDropzone = initDropzone;
