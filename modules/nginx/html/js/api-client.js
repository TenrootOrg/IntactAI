/**
 * API Client - Reusable fetch wrappers for Intact.AI Dashboard
 *
 * This module provides simple helper functions to reduce code duplication
 * in API calls. Existing code can gradually adopt these helpers.
 *
 * Usage:
 *   const data = await api.get('/api/clients');
 *   const result = await api.post('/api/agentic/run', { client_ids: [...] });
 *   const success = await api.delete('/api/blueprints/velociraptor/123');
 */

const api = {
    /**
     * GET request - returns parsed JSON or null on error
     */
    async get(endpoint) {
        try {
            const response = await fetch(endpoint);
            if (!response.ok) {
                console.error(`API GET ${endpoint} failed:`, response.status);
                return null;
            }
            return await response.json();
        } catch (error) {
            console.error(`API GET ${endpoint} error:`, error);
            return null;
        }
    },

    /**
     * POST request with JSON body - returns parsed JSON or null on error
     */
    async post(endpoint, data) {
        try {
            const response = await fetch(endpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data)
            });
            const result = await response.json();
            if (!response.ok) {
                console.error(`API POST ${endpoint} failed:`, result.error || response.status);
                return { error: result.error || 'Request failed', _status: response.status };
            }
            return result;
        } catch (error) {
            console.error(`API POST ${endpoint} error:`, error);
            return { error: error.message, _status: 0 };
        }
    },

    /**
     * PUT request with JSON body - returns parsed JSON or null on error
     */
    async put(endpoint, data) {
        try {
            const response = await fetch(endpoint, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data)
            });
            const result = await response.json();
            if (!response.ok) {
                console.error(`API PUT ${endpoint} failed:`, result.error || response.status);
                return { error: result.error || 'Request failed', _status: response.status };
            }
            return result;
        } catch (error) {
            console.error(`API PUT ${endpoint} error:`, error);
            return { error: error.message, _status: 0 };
        }
    },

    /**
     * DELETE request - returns parsed JSON or null on error
     */
    async delete(endpoint) {
        try {
            const response = await fetch(endpoint, { method: 'DELETE' });
            const result = await response.json();
            if (!response.ok) {
                console.error(`API DELETE ${endpoint} failed:`, result.error || response.status);
                return { error: result.error || 'Request failed', _status: response.status };
            }
            return result;
        } catch (error) {
            console.error(`API DELETE ${endpoint} error:`, error);
            return { error: error.message, _status: 0 };
        }
    },

    /**
     * Check if response is an error
     */
    isError(result) {
        return result === null || (result && result.error);
    },

    /**
     * Get error message from result
     */
    getError(result) {
        if (result === null) return 'Request failed';
        return result.error || 'Unknown error';
    }
};

// Make available globally
window.api = api;
