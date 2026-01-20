/**
 * Standardized API response utilities.
 *
 * All API endpoints should use these helpers to ensure consistent response format:
 * {
 *   status: 'success' | 'fail' | 'error',
 *   message: string,
 *   data?: T,
 *   errors?: unknown
 * }
 */

export type ApiStatus = 'success' | 'fail' | 'error';

export interface ApiResponseFormat<T = unknown> {
    status: ApiStatus;
    message: string;
    data?: T;
    errors?: unknown;
}

/**
 * Helper functions to create standardized API responses.
 *
 * - `success`: For 2xx responses with optional data
 * - `fail`: For 4xx client errors (validation, auth, not found)
 * - `error`: For 5xx server errors
 */
export const ApiResponse = {
    /**
     * Create a success response (2xx)
     */
    success<T>(message: string, data?: T): ApiResponseFormat<T> {
        const response: ApiResponseFormat<T> = {
            status: 'success',
            message,
        };
        if (data !== undefined) {
            response.data = data;
        }
        return response;
    },

    /**
     * Create a fail response (4xx client errors)
     */
    fail(message: string, errors?: unknown): ApiResponseFormat {
        const response: ApiResponseFormat = {
            status: 'fail',
            message,
        };
        if (errors !== undefined) {
            response.errors = errors;
        }
        return response;
    },

    /**
     * Create an error response (5xx server errors)
     */
    error(message: string): ApiResponseFormat {
        return {
            status: 'error',
            message,
        };
    },
};
