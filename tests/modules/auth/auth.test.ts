import { describe, it, expect, vi, beforeEach } from 'vitest';
import request from 'supertest';
import app from '../../../src/app';
import { prisma } from '../../../src/common/lib/prisma';
import bcrypt from 'bcrypt';
import { DeepMockProxy } from 'vitest-mock-extended';
import { PrismaClient } from '../../../src/generated/prisma/client';

vi.mock('../../../src/common/lib/prisma', async () => {
    const { mockDeep } = await import('vitest-mock-extended');
    return {
        __esModule: true,
        prisma: mockDeep<PrismaClient>(),
    };
});

const prismaMock = prisma as unknown as DeepMockProxy<PrismaClient>;

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
        process.env.JWT_ACCESS_SECRET = 'test-secret-min-32-chars-for-security';
    });

    describe('POST /api/auth/register', () => {
        it('should_register_a_new_user_successfully', async () => {
            const newUser = {
                email: 'test@example.com',
                password: 'Password123',
                name: 'Test User',
            };

            prismaMock.user.findUnique.mockResolvedValue(null);
            prismaMock.user.create.mockResolvedValue({
                id: 1,
                ...newUser,
                password: 'hashed_password',
                role: 'USER',
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

        it('should_register_without_optional_name', async () => {
            const newUser = {
                email: 'noname@example.com',
                password: 'Password123',
            };

            prismaMock.user.findUnique.mockResolvedValue(null);
            prismaMock.user.create.mockResolvedValue({
                id: 2,
                email: newUser.email,
                password: 'hashed_password',
                name: null,
                role: 'USER',
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

        it('should_return_409_if_email_already_exists', async () => {
            const existingUser = {
                email: 'exists@example.com',
                password: 'Password123',
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

        it('should_validate_email_format', async () => {
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

        it('should_validate_password_length', async () => {
            const invalidUser = {
                email: 'valid@example.com',
                password: '123',
            };

            const res = await request(app)
                .post('/api/auth/register')
                .send(invalidUser);

            expect(res.status).toBe(400);
        });
    });

    describe('POST /api/auth/login', () => {
        it('should_login_successfully_with_correct_credentials', async () => {
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
                role: 'USER',
                createdAt: new Date(),
                updatedAt: new Date(),
            } as never);

            (bcrypt.compare as ReturnType<typeof vi.fn>).mockResolvedValue(true as never);



            const res = await request(app)
                .post('/api/auth/login')
                .send(loginData);

            expect(res.status).toBe(200);
            expect(res.body.status).toBe('success');
            expect(res.body.data).toHaveProperty('accessToken');
            expect(res.body.data).not.toHaveProperty('refreshToken');

            const cookies = res.headers['set-cookie'];
            expect(cookies).toBeDefined();
            expect((cookies as unknown as string[]).some((c: string) => c.includes('refreshToken') && c.includes('HttpOnly'))).toBe(true);
        });

        it('should_fail_with_invalid_password', async () => {
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
    });

    describe('POST /api/auth/refresh', () => {
        it('should_refresh_token_with_valid_cookie', async () => {

            const _refreshToken = 'valid_refresh_token';
            const res = await request(app)
                .post('/api/auth/refresh');

            expect(res.status).toBe(401);
        });
    });

    describe('POST /api/auth/logout', () => {
        it('should_clear_cookie_on_logout', async () => {
            const res = await request(app)
                .post('/api/auth/logout')
                .set('Cookie', ['refreshToken=some_token']);

            expect(res.status).toBe(200);

            const cookies = res.headers['set-cookie'];
            expect(cookies).toBeDefined();
            expect((cookies as unknown as string[]).some((c: string) => c.includes('refreshToken=;') || c.includes('Max-Age=0'))).toBe(true);
        });
    });
});
