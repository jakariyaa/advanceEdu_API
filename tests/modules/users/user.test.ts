/* eslint-disable @typescript-eslint/no-explicit-any */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import request from 'supertest';
import app from '../../../src/app';
import { prisma } from '../../../src/common/lib/prisma';
import { DeepMockProxy } from 'vitest-mock-extended';
import { PrismaClient } from '../../../src/generated/prisma/client';
import jwt from 'jsonwebtoken';

vi.mock('../../../src/common/lib/prisma', async () => {
    const { mockDeep } = await import('vitest-mock-extended');
    return {
        __esModule: true,
        prisma: mockDeep<PrismaClient>(),
    };
});

const prismaMock = prisma as unknown as DeepMockProxy<PrismaClient>;

describe('User Endpoints', () => {
    let token: string;
    const testJwtSecret = 'test-secret-min-32-chars-for-security';

    beforeEach(() => {
        vi.clearAllMocks();

        token = jwt.sign({ userId: 1, email: 'test@example.com', role: 'USER', type: 'access' }, testJwtSecret);
    });

    describe('GET /api/users/me', () => {
        it('should_return_current_user_profile', async () => {
            const user = {
                id: 1,
                email: 'test@example.com',
                password: 'hashed',
                name: 'Test User',
                stripeId: 'cus_123',
                createdAt: new Date(),
                updatedAt: new Date(),
            };

            prismaMock.user.findUnique.mockResolvedValue(user as any);

            const res = await request(app)
                .get('/api/users/me')
                .set('Authorization', `Bearer ${token}`);

            expect(res.status).toBe(200);
            expect(res.body.status).toBe('success');
            expect(res.body.data.user).toHaveProperty('id', 1);
            expect(res.body.data.user).toHaveProperty('email', 'test@example.com');
            expect(res.body.data.user).not.toHaveProperty('password');
        });

        it('should_return_401_if_unauthorized', async () => {
            const res = await request(app)
                .get('/api/users/me');

            expect(res.status).toBe(401);
        });

        it('should_return_401_if_user_not_found', async () => {
            prismaMock.user.findUnique.mockResolvedValue(null);

            const res = await request(app)
                .get('/api/users/me')
                .set('Authorization', `Bearer ${token}`);

            expect(res.status).toBe(401);
        });
    });
});
