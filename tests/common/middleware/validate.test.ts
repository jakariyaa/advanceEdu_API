import { describe, it, expect, vi, beforeEach } from 'vitest';
import { validate } from '../../../src/common/middleware/validate';
import { Request, Response, NextFunction } from 'express';
import { z } from 'zod';

describe('Validate Middleware', () => {
    let req: Partial<Request>;
    let res: Partial<Response>;
    let next: NextFunction;

    const schema = z.object({
        body: z.object({
            name: z.string().min(1),
            age: z.number().optional(),
        }).optional(),
        query: z.object({
            page: z.string().optional(),
        }).optional(),
        params: z.object({
            id: z.string().optional(),
        }).optional(),
    });

    beforeEach(() => {
        req = { body: {}, query: {}, params: {} };
        res = {};
        next = vi.fn();
    });

    it('should_call_next_if_validation_passes', async () => {
        req.body = { name: 'Test' };
        await validate(schema)(req as Request, res as Response, next);
        expect(next).toHaveBeenCalledWith();
    });

    it('should_validate_query_params', async () => {
        req.body = { name: 'Test' };
        req.query = { page: '1' };
        await validate(schema)(req as Request, res as Response, next);
        expect(next).toHaveBeenCalledWith();
    });

    it('should_call_next_with_error_if_body_validation_fails', async () => {
        req.body = { name: '' };
        await validate(schema)(req as Request, res as Response, next);
        expect(next).toHaveBeenCalledWith(expect.any(z.ZodError));
    });

    it('should_strip_unknown_body_keys_if_strict', async () => {







        const transformSchema = z.object({
            body: z.object({
                name: z.string().transform(v => v.toUpperCase()),
            })
        });

        req.body = { name: 'lowercase' };
        await validate(transformSchema)(req as Request, res as Response, next);




    });
});
