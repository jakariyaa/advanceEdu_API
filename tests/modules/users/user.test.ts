import { describe, it, expect, vi, beforeEach } from 'vitest';
import request from 'supertest';
import app from '../../../src/app';
import { prisma } from '../../../src/common/lib/prisma';
import { mockDeep, DeepMockProxy } from 'vitest-mock-extended';
import { PrismaClient } from '@prisma/client';
import jwt from 'jsonwebtoken';

// Mock Prisma
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

    beforeEach(() => {
        vi.clearAllMocks();
        process.env.JWT_SECRET = 'test-secret';
        token = jwt.sign({ userId: 1, email: 'test@example.com' }, 'test-secret');
    });

    describe('GET /api/users/me', () => {
        it('should return current user profile', async () => {
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

        it('should return 401 if unauthorized', async () => {
            const res = await request(app)
                .get('/api/users/me');

            expect(res.status).toBe(401);
        });

        it('should return 401 if user not found', async () => {
            prismaMock.user.findUnique.mockResolvedValue(null);

            const res = await request(app)
                .get('/api/users/me')
                .set('Authorization', `Bearer ${token}`);

            expect(res.status).toBe(401);
        });
    });
});
