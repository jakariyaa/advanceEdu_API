import { describe, it, expect, vi, beforeEach } from 'vitest';
import request from 'supertest';
import app from '../../../src/app';
import { prisma } from '../../../src/common/lib/prisma';
import bcrypt from 'bcrypt';
import { mockDeep, DeepMockProxy } from 'vitest-mock-extended';
import { PrismaClient } from '@prisma/client';

// Mock Prisma
vi.mock('../../../src/common/lib/prisma', async () => {
    const { mockDeep } = await import('vitest-mock-extended');
    return {
        __esModule: true,
        prisma: mockDeep<PrismaClient>(),
    };
});

const prismaMock = prisma as unknown as DeepMockProxy<PrismaClient>;

// Mock Bcrypt
vi.mock('bcrypt', () => ({
    default: {
        compare: vi.fn(),
        hash: vi.fn().mockResolvedValue('hashed_password'),
    },
    compare: vi.fn(),
    hash: vi.fn().mockResolvedValue('hashed_password'),
}));

describe('Auth Endpoints', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        process.env.JWT_SECRET = 'test-secret-min-32-chars-for-security';
    });

    describe('POST /api/auth/register', () => {
        it('should register a new user successfully', async () => {
            const newUser = {
                email: 'test@example.com',
                password: 'password123',
                name: 'Test User',
            };

            // Mock prisma response
            prismaMock.user.findUnique.mockResolvedValue(null);
            prismaMock.user.create.mockResolvedValue({
                id: 1,
                ...newUser,
                password: 'hashed_password',
                createdAt: new Date(),
                updatedAt: new Date(),
                stripeId: null,
            } as never);

            const res = await request(app)
                .post('/api/auth/register')
                .send(newUser);

            expect(res.status).toBe(201);
            expect(res.body.status).toBe('success');
            expect(res.body.data.user).toHaveProperty('id');
            expect(res.body.data.user.email).toBe(newUser.email);
            expect(prismaMock.user.create).toHaveBeenCalled();
        });

        it('should register without optional name', async () => {
            const newUser = {
                email: 'noname@example.com',
                password: 'password123',
            };

            prismaMock.user.findUnique.mockResolvedValue(null);
            prismaMock.user.create.mockResolvedValue({
                id: 2,
                email: newUser.email,
                password: 'hashed_password',
                name: null,
                createdAt: new Date(),
                updatedAt: new Date(),
                stripeId: null,
            } as never);

            const res = await request(app)
                .post('/api/auth/register')
                .send(newUser);

            expect(res.status).toBe(201);
            expect(res.body.data.user.email).toBe(newUser.email);
        });

        it('should return 409 if email already exists', async () => {
            const existingUser = {
                email: 'exists@example.com',
                password: 'password123',
            };

            prismaMock.user.findUnique.mockResolvedValue({
                id: 1,
                email: existingUser.email,
                password: 'hashed',
                name: null,
                stripeId: null,
                createdAt: new Date(),
                updatedAt: new Date(),
            } as never);

            const res = await request(app)
                .post('/api/auth/register')
                .send(existingUser);

            expect(res.status).toBe(409);
            expect(res.body.status).toBe('fail');
        });

        it('should validate email format', async () => {
            const invalidUser = {
                email: 'not-an-email',
                password: 'password123',
            };

            const res = await request(app)
                .post('/api/auth/register')
                .send(invalidUser);

            expect(res.status).toBe(400);
            expect(res.body.status).toBe('fail');
        });

        it('should validate password length', async () => {
            const invalidUser = {
                email: 'valid@example.com',
                password: '123', // too short
            };

            const res = await request(app)
                .post('/api/auth/register')
                .send(invalidUser);

            expect(res.status).toBe(400);
        });
    });

    describe('POST /api/auth/login', () => {
        it('should login successfully with correct credentials', async () => {
            const loginData = {
                email: 'test@example.com',
                password: 'password123',
            };

            prismaMock.user.findUnique.mockResolvedValue({
                id: 1,
                email: loginData.email,
                password: 'hashed_password_from_db',
                name: 'Test User',
                stripeId: null,
                createdAt: new Date(),
                updatedAt: new Date(),
            } as never);

            (bcrypt.compare as ReturnType<typeof vi.fn>).mockResolvedValue(true as never);

            const res = await request(app)
                .post('/api/auth/login')
                .send(loginData);

            expect(res.status).toBe(200);
            expect(res.body.status).toBe('success');
            expect(res.body.data).toHaveProperty('token');
        });

        it('should fail with invalid password', async () => {
            const loginData = {
                email: 'test@example.com',
                password: 'wrongpassword',
            };

            prismaMock.user.findUnique.mockResolvedValue({
                id: 1,
                email: loginData.email,
                password: 'hashed_password',
                name: 'Test User',
                stripeId: null,
                createdAt: new Date(),
                updatedAt: new Date(),
            } as never);

            (bcrypt.compare as ReturnType<typeof vi.fn>).mockResolvedValue(false as never);

            const res = await request(app)
                .post('/api/auth/login')
                .send(loginData);

            expect(res.status).toBe(401);
        });

        it('should fail with non-existent email', async () => {
            const loginData = {
                email: 'nonexistent@example.com',
                password: 'password123',
            };

            prismaMock.user.findUnique.mockResolvedValue(null);

            const res = await request(app)
                .post('/api/auth/login')
                .send(loginData);

            expect(res.status).toBe(401);
        });

        it('should validate required fields', async () => {
            const res = await request(app)
                .post('/api/auth/login')
                .send({});

            expect(res.status).toBe(400);
        });
    });
});
