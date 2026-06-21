// Global shim functions kept on window for inline onclick= handlers + DOMContentLoaded helpers.
// Global config for compatibility
window.currentConfig = null;
function getConfig() {
    return window.currentConfig || window.defaultConfig;
}

// Legacy function compatibility for onclick handlers in HTML
function switchTab(tabName) {
    Alpine.store('app').switchTab(tabName);
}

function toggleModulesDropdown() {
    Alpine.store('app').toggleModules();
}

function loadWorkflows() {
    Alpine.store('workflows').load();
}

function viewWorkflowLogs(runId) {
    Alpine.store('workflows').viewLogs(runId);
}

function closeLogModal() {
    Alpine.store('workflows').closeModal();
}

function loadSettings() {
    Alpine.store('settings').load();
}

function runSystemMaintenance() {
    Alpine.store('settings').runMaintenance();
}

function checkAllServices() {
    Alpine.store('services').checkAll();
}

function loadClientCount() {
    Alpine.store('services').loadClients();
}

function refreshAll() {
    Alpine.store('services').checkAll();
    Alpine.store('services').loadClients();
}

// Settings form init (legacy compatibility)
function initSettingsForm() {
    // Now handled by Alpine x-model bindings
}
