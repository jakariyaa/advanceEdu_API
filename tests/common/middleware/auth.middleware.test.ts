/* eslint-disable @typescript-eslint/no-explicit-any */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { authenticate } from '../../../src/common/middleware/auth.middleware';
import { Request, Response, NextFunction } from 'express';
import { tokenService } from '../../../src/common/lib/token.service';
import { prisma } from '../../../src/common/lib/prisma';


vi.mock('../../../src/common/lib/token.service');
vi.mock('../../../src/common/lib/prisma', () => ({
    prisma: {
        user: {
            findUnique: vi.fn(),
        },
    },
}));

describe('Auth Middleware', () => {
    let req: Partial<Request>;
    let res: Partial<Response>;
    let next: NextFunction;

    beforeEach(() => {
        req = {
            headers: {},
        };
        res = {};
        next = vi.fn();
        vi.clearAllMocks();
    });

    it('should_call_next_with_401_if_authorization_header_is_missing', async () => {
        await authenticate(req as Request, res as Response, next);

        expect(next).toHaveBeenCalledWith(expect.objectContaining({
            statusCode: 401,
            message: 'Unauthorized'
        }));
    });

    it('should_call_next_with_401_if_token_format_is_invalid', async () => {
        req.headers = { authorization: 'InvalidFormat token' };
        await authenticate(req as Request, res as Response, next);

        expect(next).toHaveBeenCalledWith(expect.objectContaining({
            statusCode: 401,
            message: 'Unauthorized'
        }));
    });

    it('should_call_next_with_401_if_token_verification_fails', async () => {
        req.headers = { authorization: 'Bearer invalid-token' };
        (tokenService.verifyAccessToken as any).mockImplementation(() => {
            throw new Error('Invalid token');
        });

        await authenticate(req as Request, res as Response, next);

        expect(next).toHaveBeenCalledWith(expect.objectContaining({
            statusCode: 401,
            message: 'Invalid or expired token'
        }));
    });

    it('should_call_next_with_401_if_user_not_found', async () => {
        req.headers = { authorization: 'Bearer valid-token' };
        (tokenService.verifyAccessToken as any).mockReturnValue({ userId: 999 });
        (prisma.user.findUnique as any).mockResolvedValue(null);

        await authenticate(req as Request, res as Response, next);

        expect(next).toHaveBeenCalledWith(expect.objectContaining({
            statusCode: 401
        }));
    });

    it('should_call_next_if_authentication_succeeds', async () => {
        req.headers = { authorization: 'Bearer valid-token' };
        const mockUser = { id: 1, email: 'test@example.com', role: 'USER', name: null, stripeId: null };

        (tokenService.verifyAccessToken as any).mockReturnValue({ userId: 1 });
        (prisma.user.findUnique as any).mockResolvedValue(mockUser);

        await authenticate(req as Request, res as Response, next);

        expect(next).toHaveBeenCalledWith();
        expect((req as any).user).toEqual({
            userId: 1,
            email: 'test@example.com',
            role: 'USER',
            name: null,
            stripeId: null
        });
    });
});
