import { Request, Response, NextFunction } from 'express';
import { logger } from '../lib/logger';
import { ZodError } from 'zod';
import { Prisma } from '../../generated/prisma/client';

export class ApiError extends Error {
    statusCode: number;

    constructor(statusCode: number, message: string) {
        super(message);
        this.statusCode = statusCode;
        this.name = 'ApiError';
        Error.captureStackTrace(this, this.constructor);
    }
}

import { ApiResponseFormat } from '../lib/api-response';

type ErrorResponse = Omit<ApiResponseFormat, 'data'> & { data?: never };

export const errorHandler = (
    err: Error,
    req: Request,
    res: Response,
    _next: NextFunction
): void => {
    const sanitizeBody = (body: Record<string, unknown>): Record<string, unknown> => {
        const sensitiveFields = [
            'password', 'token', 'secret', 'key', 'authorization', 'apiKey', 'api_key',
            'refreshToken', 'accessToken', 'creditCard', 'ssn', 'cvv'
        ];
        const sanitized = { ...body };

        for (const field of sensitiveFields) {
            if (field in sanitized) {
                sanitized[field] = '[REDACTED]';
            }
        }

        return sanitized;
    };

    const errorInfo = {
        name: err.name,
        message: err.message,
        stack: err.stack,
        req: {
            method: req.method,
            url: req.url,
            body: req.body ? sanitizeBody(req.body as Record<string, unknown>) : undefined,
        },
    };

    logger.error(errorInfo, `[${err.name}] ${err.message}`);

    if (err instanceof ApiError) {
        const response: ErrorResponse = {
            status: err.statusCode >= 500 ? 'error' : 'fail',
            message: err.message,
        };
        res.status(err.statusCode).json(response);
        return;
    }

    if (err instanceof ZodError) {
        const response: ErrorResponse = {
            status: 'fail',
            message: 'Validation Error',
            errors: err.issues.map(issue => ({
                field: issue.path.join('.'),
                message: issue.message,
            })),
        };
        res.status(400).json(response);
        return;
    }

    if (err instanceof Prisma.PrismaClientKnownRequestError) {
        const prismaErr = err as Prisma.PrismaClientKnownRequestError;
        if (prismaErr.code === 'P2002') {
            const response: ErrorResponse = {
                status: 'fail',
                message: 'Resource already exists',
            };
            res.status(409).json(response);
            return;
        }
        if (prismaErr.code === 'P2025') {
            const response: ErrorResponse = {
                status: 'fail',
                message: 'Resource not found',
            };
            res.status(404).json(response);
            return;
        }
    }

    if (err instanceof Prisma.PrismaClientValidationError) {
        const response: ErrorResponse = {
            status: 'fail',
            message: 'Database validation error',
        };
        res.status(400).json(response);
        return;
    }

    if (err instanceof Prisma.PrismaClientInitializationError) {
        const response: ErrorResponse = {
            status: 'error',
            message: 'Database connection error',
        };
        logger.fatal({ err }, 'Database connection failed');
        res.status(503).json(response);
        return;
    }

    const response: ErrorResponse = {
        status: 'error',
        message: process.env['NODE_ENV'] === 'development' ? err.message : 'Internal Server Error',
    };
    res.status(500).json(response);
};


