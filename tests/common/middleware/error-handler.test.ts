/* eslint-disable @typescript-eslint/no-explicit-any */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { errorHandler, ApiError } from '../../../src/common/middleware/error-handler';
import { Request, Response } from 'express';
import { ZodError } from 'zod';
import { Prisma } from '../../../src/generated/prisma/client';

describe('ErrorHandler', () => {
    let req: Partial<Request>;
    let res: Partial<Response>;
    let next: any;

    beforeEach(() => {
        req = {
            method: 'GET',
            url: '/test',
            body: {},
        };
        res = {
            status: vi.fn().mockReturnThis(),
            json: vi.fn(),
        };
        next = vi.fn();
    });

    it('should_handle_api_error', () => {
        const error = new ApiError(418, 'I am a teapot');
        errorHandler(error, req as Request, res as Response, next);

        expect(res.status).toHaveBeenCalledWith(418);
        expect(res.json).toHaveBeenCalledWith({
            status: 'fail',
            message: 'I am a teapot',
        });
    });

    it('should_handle_zod_validation_error', () => {
        const zodError = new ZodError([{
            code: 'invalid_type',
            expected: 'string',
            received: 'number',
            path: ['name'],
            message: 'Expected string, received number',
        }]);

        errorHandler(zodError, req as Request, res as Response, next);

        expect(res.status).toHaveBeenCalledWith(400);
        expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
            status: 'fail',
            message: 'Validation Error',
        }));
    });

    it('should_handle_prisma_unique_constraint_error', () => {
        const prismaError = new Prisma.PrismaClientKnownRequestError('Unique constraint', {
            code: 'P2002',
            clientVersion: '5.0.0',
        });

        errorHandler(prismaError, req as Request, res as Response, next);

        expect(res.status).toHaveBeenCalledWith(409);
        expect(res.json).toHaveBeenCalledWith({
            status: 'fail',
            message: 'Resource already exists',
        });
    });

    it('should_handle_prisma_not_found_error', () => {
        const prismaError = new Prisma.PrismaClientKnownRequestError('Not found', {
            code: 'P2025',
            clientVersion: '5.0.0',
        });

        errorHandler(prismaError, req as Request, res as Response, next);

        expect(res.status).toHaveBeenCalledWith(404);
        expect(res.json).toHaveBeenCalledWith({
            status: 'fail',
            message: 'Resource not found',
        });
    });

    it('should_handle_generic_error_as_500', () => {
        const error = new Error('Something exploded');
        errorHandler(error, req as Request, res as Response, next);

        expect(res.status).toHaveBeenCalledWith(500);
        expect(res.json).toHaveBeenCalledWith({
            status: 'error',
            message: 'Internal Server Error',
        });
    });
});
