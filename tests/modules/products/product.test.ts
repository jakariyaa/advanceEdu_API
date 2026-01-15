import { describe, it, expect, vi, beforeEach } from 'vitest';
import request from 'supertest';
import app from '../../../src/app';
import { prisma } from '../../../src/common/lib/prisma';
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

const prismaMock = prisma as unknown as DeepMockProxy<PrismaClient>;

describe('Product Endpoints', () => {
    let token: string;

    beforeEach(() => {
        vi.clearAllMocks();
        process.env.JWT_SECRET = 'test-secret';
        token = jwt.sign({ userId: 1, email: 'admin@example.com' }, 'test-secret');
    });

    describe('GET /api/products', () => {
        it('should return list of active products', async () => {
            const products = [
                { id: 1, name: 'P1', price: 100, isActive: true, createdAt: new Date(), updatedAt: new Date() },
                { id: 2, name: 'P2', price: 200, isActive: true, createdAt: new Date(), updatedAt: new Date() },
            ];

            prismaMock.product.findMany.mockResolvedValue(products as any);

            const res = await request(app).get('/api/products');

            expect(res.status).toBe(200);
            expect(res.body.status).toBe('success');
            expect(res.body.data.products).toHaveLength(2);
            expect(prismaMock.product.findMany).toHaveBeenCalledWith({
                where: { isActive: true },
                orderBy: { createdAt: 'desc' },
            });
        });
    });

    describe('GET /api/products/:id', () => {
        it('should return product details', async () => {
            const product = { id: 1, name: 'P1', price: 100, isActive: true, createdAt: new Date(), updatedAt: new Date() };
            prismaMock.product.findUnique.mockResolvedValue(product as any);

            const res = await request(app).get('/api/products/1');

            expect(res.status).toBe(200);
            expect(res.body.data.product).toHaveProperty('id', 1);
        });

        it('should return 404 if not found', async () => {
            prismaMock.product.findUnique.mockResolvedValue(null);
            const res = await request(app).get('/api/products/999');
            expect(res.status).toBe(404);
        });
    });

    describe('POST /api/products', () => {
        it('should create product if authenticated', async () => {
            const newProduct = {
                name: 'New Product',
                price: 1000,
                currency: 'usd',
            };

            prismaMock.product.create.mockResolvedValue({
                id: 3,
                ...newProduct,
                description: null,
                stripeId: null,
                isActive: true,
                createdAt: new Date(),
                updatedAt: new Date(),
            } as any);

            // Assuming user finding for auth middleware
            prismaMock.user.findUnique.mockResolvedValue({ id: 1, email: 'admin@example.com' } as any);

            const res = await request(app)
                .post('/api/products')
                .set('Authorization', `Bearer ${token}`)
                .send(newProduct);

            expect(res.status).toBe(201);
            expect(res.body.status).toBe('success');
            expect(prismaMock.product.create).toHaveBeenCalled();
        });

        it('should fail if unauthenticated', async () => {
            const res = await request(app).post('/api/products').send({});
            expect(res.status).toBe(401);
        });

        it('should validate input', async () => {
            prismaMock.user.findUnique.mockResolvedValue({ id: 1 } as any);
            const res = await request(app)
                .post('/api/products')
                .set('Authorization', `Bearer ${token}`)
                .send({ name: '' }); // Invalid

            expect(res.status).toBe(400);
        });
    });
});
