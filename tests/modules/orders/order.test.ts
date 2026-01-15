import { describe, it, expect, vi, beforeEach } from 'vitest';
import request from 'supertest';
import app from '../../../src/app';
import { prisma } from '../../../src/common/lib/prisma';
import { stripe } from '../../../src/common/lib/stripe';
import { mockDeep, DeepMockProxy } from 'vitest-mock-extended';
import { PrismaClient } from '@prisma/client';
import jwt from 'jsonwebtoken';

vi.mock('../../../src/common/lib/prisma', async () => {
    const { mockDeep } = await import('vitest-mock-extended');
    return {
        __esModule: true,
        prisma: mockDeep<PrismaClient>(),
    };
});

// Mock Stripe
vi.mock('../../../src/common/lib/stripe', () => ({
    stripe: {
        checkout: {
            sessions: {
                create: vi.fn(),
            },
        },
    },
}));

const prismaMock = prisma as unknown as DeepMockProxy<PrismaClient>;

describe('Order Endpoints', () => {
    let token: string;

    beforeEach(() => {
        vi.clearAllMocks();
        process.env.JWT_SECRET = 'test-secret';
        process.env.API_BASE_URL = 'http://test.com';
        token = jwt.sign({ userId: 1, email: 'user@example.com' }, 'test-secret');
    });

    describe('POST /api/orders', () => {
        it('should create order and checkout session', async () => {
            const orderInput = {
                items: [
                    { productId: 1, quantity: 2 },
                ],
            };

            const product = { id: 1, name: 'P1', price: 1000, currency: 'usd', isActive: true, description: 'Test product' };
            const user = { id: 1, email: 'user@example.com', stripeId: 'cus_123', name: 'Test User', password: 'hashed', createdAt: new Date(), updatedAt: new Date() };

            prismaMock.user.findUnique.mockResolvedValue(user as never);
            prismaMock.product.findUnique.mockResolvedValue(product as never);
            prismaMock.product.findMany.mockResolvedValue([product] as never);

            // Order creation mock
            prismaMock.order.create.mockResolvedValue({
                id: 1,
                userId: 1,
                status: 'PENDING',
                totalAmount: 2000,
                currency: 'usd',
                createdAt: new Date(),
                updatedAt: new Date(),
                stripeSessionId: null,
                stripePaymentId: null,
                items: [{ id: 1, orderId: 1, productId: 1, quantity: 2, price: 1000, product }],
                user: user
            } as never);

            prismaMock.order.update.mockResolvedValue({} as never);

            // Stripe session mock
            (stripe.checkout.sessions.create as ReturnType<typeof vi.fn>).mockResolvedValue({
                id: 'cs_test_123',
                url: 'https://checkout.stripe.com/test',
            });

            const res = await request(app)
                .post('/api/orders')
                .set('Authorization', `Bearer ${token}`)
                .send(orderInput);

            expect(res.status).toBe(201);
            expect(res.body.status).toBe('success');
            expect(res.body.data).toHaveProperty('sessionId', 'cs_test_123');
            expect(res.body.data).toHaveProperty('url');
            expect(prismaMock.order.create).toHaveBeenCalled();
        });

        it('should return 400 for invalid/inactive product', async () => {
            const orderInput = {
                items: [
                    { productId: 999, quantity: 1 },
                ],
            };

            const user = { id: 1, email: 'user@example.com', stripeId: 'cus_123', name: 'Test User', password: 'hashed', createdAt: new Date(), updatedAt: new Date() };

            prismaMock.user.findUnique.mockResolvedValue(user as never);
            prismaMock.product.findMany.mockResolvedValue([] as never);

            const res = await request(app)
                .post('/api/orders')
                .set('Authorization', `Bearer ${token}`)
                .send(orderInput);

            expect(res.status).toBe(400);
            expect(res.body.message).toContain('invalid or inactive');
        });

        it('should return 401 without auth token', async () => {
            const res = await request(app)
                .post('/api/orders')
                .send({ items: [{ productId: 1, quantity: 1 }] });

            expect(res.status).toBe(401);
        });

        it('should return 400 for invalid input', async () => {
            const res = await request(app)
                .post('/api/orders')
                .set('Authorization', `Bearer ${token}`)
                .send({ items: [] });

            expect(res.status).toBe(400);
        });
    });
});
