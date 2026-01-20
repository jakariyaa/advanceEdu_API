import rateLimit from 'express-rate-limit';
import { logger } from '../lib/logger';

export const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 100,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    handler: (req, res, _next, options) => {
        logger.warn(`Rate limit exceeded for IP ${req.ip}`);
        res.status(options.statusCode).json({
            status: 'fail',
            message: 'Too many requests, please try again later.',
        });
    },
});

export const authLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    limit: 5,
    message: 'Too many accounts created from this IP, please try again after an hour',
    handler: (req, res, _next, options) => {
        logger.warn(`Auth rate limit exceeded for IP ${req.ip}`);
        res.status(options.statusCode).json({
            status: 'fail',
            message: 'Too many login attempts, please try again later.',
        });
    },
});

