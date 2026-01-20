/**
 * Authentication-related constants.
 * Centralized configuration for cookies and token settings.
 */

/** Cookie expiration time in milliseconds (7 days) */
export const REFRESH_TOKEN_COOKIE_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;

/** Standard cookie options for refresh token */
export const REFRESH_TOKEN_COOKIE_OPTIONS = {
    httpOnly: true,
    secure: process.env['NODE_ENV'] === 'production',
    sameSite: 'strict' as const,
    maxAge: REFRESH_TOKEN_COOKIE_MAX_AGE_MS,
};

/** Cookie options for clearing the refresh token */
export const REFRESH_TOKEN_CLEAR_OPTIONS = {
    httpOnly: true,
    secure: process.env['NODE_ENV'] === 'production',
    sameSite: 'strict' as const,
};

/** CSRF token cookie name */
export const CSRF_COOKIE_NAME = 'csrf-token';

/** CSRF header name */
export const CSRF_HEADER_NAME = 'x-csrf-token';

/** CSRF cookie max age in milliseconds (1 hour) */
export const CSRF_COOKIE_MAX_AGE_MS = 60 * 60 * 1000;
