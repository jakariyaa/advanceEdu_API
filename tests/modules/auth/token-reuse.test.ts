/* eslint-disable @typescript-eslint/no-explicit-any */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import request from 'supertest';
import app from '../../../src/app';
import { prisma } from '../../../src/common/lib/prisma';
import { DeepMockProxy } from 'vitest-mock-extended';
import { PrismaClient } from '../../../src/generated/prisma/client';
import bcrypt from 'bcrypt';


vi.mock('../../../src/common/lib/prisma', async () => {
    const { mockDeep } = await import('vitest-mock-extended');
    return {
        __esModule: true,
        prisma: mockDeep<PrismaClient>(),
    };
});

const prismaMock = prisma as unknown as DeepMockProxy<PrismaClient>;

describe('Token Reuse Detection (Mocked)', () => {

    beforeEach(() => {
        vi.clearAllMocks();
    });

    it('should_detect_token_reuse_and_revoke_all_sessions', async () => {

        const user = {
            id: 1,
            email: 'reuse-test@example.com',
            password: 'hashed_password',
            role: 'USER',
            name: 'Reuse Test User',
            stripeId: null,
            createdAt: new Date(),
            updatedAt: new Date(),
        };


        prismaMock.user.findUnique.mockResolvedValue(user as any);
        (bcrypt.compare as any) = vi.fn().mockResolvedValue(true);
        prismaMock.refreshToken.create.mockResolvedValue({
            id: 1,
            token: 'hashed_refresh_token_1',
            userId: 1,
            familyId: 'family_1',
            isUsed: false,
            expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
            createdAt: new Date(),
        } as any);

        const loginRes = await request(app)
            .post('/api/auth/login')
            .send({ email: user.email, password: 'password123' });

        expect(loginRes.status).toBe(200);

        const cookies = loginRes.headers['set-cookie'];
        expect(cookies).toBeDefined();
        const refreshTokenCookie = (Array.isArray(cookies) ? cookies : [cookies as string]).find((c: string) => c.startsWith('refreshToken='));
        expect(refreshTokenCookie).toBeDefined();


        prismaMock.refreshToken.findUnique.mockResolvedValueOnce({
            id: 1,
            token: expect.any(String),
            userId: 1,
            familyId: 'family_1',
            isUsed: false,
            expiresAt: new Date(Date.now() + 100000),
            user: user,
        } as any);


        prismaMock.refreshToken.update.mockResolvedValue({} as any);


        prismaMock.refreshToken.create.mockResolvedValue({
            id: 2,
            token: 'hashed_refresh_token_2',
            userId: 1,
            familyId: 'family_1',
            isUsed: false,
            expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
            createdAt: new Date(),
        } as any);

        const refreshRes1 = await request(app)
            .post('/api/auth/refresh')
            .set('Cookie', cookies);

        expect(refreshRes1.status).toBe(200);
        const tokens2 = refreshRes1.body.data;
        const _refreshToken2 = tokens2.refreshToken;




        prismaMock.refreshToken.findUnique.mockResolvedValueOnce({
            id: 1,
            token: expect.any(String),
            userId: 1,
            familyId: 'family_1',
            isUsed: true,
            expiresAt: new Date(Date.now() + 100000),
            user: user,
        } as any);


        prismaMock.refreshToken.deleteMany.mockResolvedValue({ count: 1 } as any);

        const reuseRes = await request(app)
            .post('/api/auth/refresh')
            .set('Cookie', cookies);



        expect(reuseRes.status).not.toBe(200);


        expect(prismaMock.refreshToken.deleteMany).toHaveBeenCalledWith({
            where: { familyId: 'family_1' },
        });
    });

    it('should_reject_expired_refresh_token', async () => {
        const user = {
            id: 1,
            email: 'expired-test@example.com',
            password: 'hashed_password',
            role: 'USER',
            name: 'Expired Test',
            stripeId: null,
            createdAt: new Date(),
            updatedAt: new Date(),
        };

        prismaMock.refreshToken.findUnique.mockResolvedValueOnce({
            id: 1,
            token: 'hashed_expired_token',
            userId: 1,
            familyId: 'family_expired',
            isUsed: false,
            expiresAt: new Date(Date.now() - 1000),
            user: user,
        } as never);

        prismaMock.refreshToken.delete.mockResolvedValue({} as never);

        const res = await request(app)
            .post('/api/auth/refresh')
            .set('Cookie', ['refreshToken=expired_token_value']);

        expect(res.status).toBe(401);
        expect(res.body.message).toContain('expired');
    });

    it('should_reject_when_refresh_token_not_found_in_database', async () => {
        prismaMock.refreshToken.findUnique.mockResolvedValueOnce(null);

        const res = await request(app)
            .post('/api/auth/refresh')
            .set('Cookie', ['refreshToken=unknown_token_value']);

        expect(res.status).toBe(401);
    });

    it('should_reject_when_no_refresh_token_cookie_provided', async () => {
        const res = await request(app)
            .post('/api/auth/refresh');

        expect(res.status).toBe(401);
        expect(res.body.message).toBe('Refresh token is required');
    });

    it('should_reject_reused_token_with_401', async () => {
        const res = await request(app)
            .post('/api/auth/refresh')
            .set('Cookie', ['refreshToken=reused_token_value']);

        expect(res.status).toBe(401);
    });
});
