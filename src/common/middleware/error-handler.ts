import { Request, Response, NextFunction } from 'express';
import { logger } from '../lib/logger';
import { ZodError } from 'zod';
import { Prisma } from '@prisma/client';

export class ApiError extends Error {
    statusCode: number;

    constructor(statusCode: number, message: string) {
        super(message);
        this.statusCode = statusCode;
        Error.captureStackTrace(this, this.constructor);
    }
}

export const errorHandler = (
    err: Error,
    _req: Request,
    res: Response,
    _next: NextFunction
) => {
    logger.error(err);

    if (err instanceof ApiError) {
        return res.status(err.statusCode).json({
            status: err.statusCode >= 400 && err.statusCode < 500 ? 'fail' : 'error',
            message: err.message,
        });
    }

    if (err instanceof ZodError) {
        return res.status(400).json({
            status: 'fail',
            message: 'Validation Error',
            errors: err.issues,
        });
    }

    if (err instanceof Prisma.PrismaClientKnownRequestError) {
        if (err.code === 'P2002') {
            return res.status(409).json({
                status: 'fail',
                message: 'Resource already exists',
            });
        }
    }

    return res.status(500).json({
        status: 'error',
        message: 'Internal Server Error',
    });
};
