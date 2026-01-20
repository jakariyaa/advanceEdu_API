import { Request, Response, NextFunction } from 'express';
import crypto from 'crypto';
import { ApiError } from './error-handler';
import {
    CSRF_COOKIE_NAME,
    CSRF_HEADER_NAME,
    CSRF_COOKIE_MAX_AGE_MS,
} from '../../modules/auth/auth.constants';

/**
 * Routes exempt from CSRF protection.
 * Auth routes are exempt because they use credentials or HttpOnly cookies.
 */
const CSRF_EXEMPT_PATHS = [
    '/auth/login',
    '/auth/register',
    '/auth/refresh',
    '/auth/logout',
    '/auth/logout-all',
];

/**
 * CSRF Protection Middleware using Double Submit Cookie pattern.
 * 
 * For GET/HEAD/OPTIONS requests: generates and sets a CSRF token cookie.
 * For state-changing requests (POST/PUT/DELETE/PATCH): validates the token.
 * 
 * The client must:
 * 1. Read the csrf-token cookie value
 * 2. Send it in the x-csrf-token header for state-changing requests
 */
export const csrfProtection = (req: Request, res: Response, next: NextFunction): void => {
    // Skip CSRF protection in development mode for easier local testing
    if (process.env['NODE_ENV'] === 'development') {
        return next();
    }

    const safeMethodsRegex = /^(GET|HEAD|OPTIONS)$/i;

    if (safeMethodsRegex.test(req.method)) {
        if (!req.cookies[CSRF_COOKIE_NAME]) {
            const token = crypto.randomBytes(32).toString('hex');
            res.cookie(CSRF_COOKIE_NAME, token, {
                httpOnly: false,
                secure: process.env['NODE_ENV'] === 'production',
                sameSite: 'strict',
                maxAge: CSRF_COOKIE_MAX_AGE_MS,
            });
        }
        return next();
    }

    if (CSRF_EXEMPT_PATHS.includes(req.path)) {
        return next();
    }

    const cookieToken = req.cookies[CSRF_COOKIE_NAME];
    const headerToken = req.headers[CSRF_HEADER_NAME];

    if (!cookieToken || !headerToken) {
        throw new ApiError(403, 'CSRF token missing');
    }

    if (cookieToken !== headerToken) {
        throw new ApiError(403, 'CSRF token mismatch');
    }

    next();
};

