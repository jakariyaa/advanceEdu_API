import rateLimit from 'express-rate-limit';
import { logger } from '../lib/logger';

export const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per windowMs
    standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
    legacyHeaders: false, // Disable the `X-RateLimit-*` headers
    handler: (req, res, _next, options) => {
        logger.warn(`Rate limit exceeded for IP ${req.ip}`);
        res.status(options.statusCode).json({
            status: 'fail',
            message: 'Too many requests, please try again later.',
        });
    },
});

export const authLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 5, // Limit each IP to 5 create account requests per hour
    message: 'Too many accounts created from this IP, please try again after an hour',
    handler: (req, res, _next, options) => {
        logger.warn(`Auth rate limit exceeded for IP ${req.ip}`);
        res.status(options.statusCode).json({
            status: 'fail',
            message: 'Too many login attempts, please try again later.',
        });
    },
});

