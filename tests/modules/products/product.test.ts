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

describe('Product Endpoints', () => {
    const testJwtSecret = 'test-secret-min-32-chars-for-security';

    beforeEach(() => {
        vi.clearAllMocks();

    });

    describe('GET /api/products', () => {
        it('should_return_list_of_active_products', async () => {
            const products = [
                { id: 1, name: 'P1', price: 100, isActive: true, createdAt: new Date(), updatedAt: new Date() },
                { id: 2, name: 'P2', price: 200, isActive: true, createdAt: new Date(), updatedAt: new Date() },
            ];

            prismaMock.product.findMany.mockResolvedValue(products as any);
            prismaMock.product.count.mockResolvedValue(2);

            const res = await request(app).get('/api/products');

            expect(res.status).toBe(200);
            expect(res.body.status).toBe('success');
            expect(res.body.data.products).toHaveLength(2);
            expect(res.body.data.pagination).toBeDefined();
            expect(prismaMock.product.findMany).toHaveBeenCalledWith({
                where: { isActive: true },
                orderBy: { createdAt: 'desc' },
                skip: 0,
                take: 20,
            });
        });
    });

    describe('GET /api/products/:id', () => {
        it('should_return_product_details', async () => {
            const product = { id: 1, name: 'P1', price: 100, isActive: true, createdAt: new Date(), updatedAt: new Date() };
            prismaMock.product.findUnique.mockResolvedValue(product as any);

            const res = await request(app).get('/api/products/1');

            expect(res.status).toBe(200);
            expect(res.body.data.product).toHaveProperty('id', 1);
        });

        it('should_return_404_if_not_found', async () => {
            prismaMock.product.findUnique.mockResolvedValue(null);
            const res = await request(app).get('/api/products/999');
            expect(res.status).toBe(404);
        });
    });

    describe('POST /api/products', () => {
        let userToken: string;

        beforeEach(() => {
            userToken = jwt.sign({ userId: 2, email: 'user@example.com', role: 'USER', type: 'access' }, testJwtSecret);
        });

        it('should_create_product_if_authenticated_user', async () => {
            const newProduct = {
                name: 'New Product',
                price: 1000,
                currency: 'usd',
            };

            prismaMock.product.create.mockResolvedValue({
                id: 3,
                ...newProduct,
                ...newProduct,
                userId: 2,
                description: null,
                stripeId: null,
                isActive: true,
                createdAt: new Date(),
                updatedAt: new Date(),
            } as any);

            prismaMock.user.findUnique.mockResolvedValue({ id: 2, email: 'user@example.com', role: 'USER' } as any);

            const res = await request(app)
                .post('/api/products')
                .set('Authorization', `Bearer ${userToken}`)
                .send(newProduct);

            expect(res.status).toBe(201);
            expect(res.body.status).toBe('success');
            expect(prismaMock.product.create).toHaveBeenCalledWith(expect.objectContaining({
                data: expect.objectContaining({
                    userId: 2,
                    name: 'New Product'
                })
            }));
        });

        it('should_fail_if_unauthenticated', async () => {
            const res = await request(app).post('/api/products').send({});
            expect(res.status).toBe(401);
        });

        it('should_validate_input', async () => {
            prismaMock.user.findUnique.mockResolvedValue({ id: 2, role: 'USER' } as any);
            const res = await request(app)
                .post('/api/products')
                .set('Authorization', `Bearer ${userToken}`)
                .send({ name: '' });

            expect(res.status).toBe(400);
        });
    });

    describe('PATCH /api/products/:id', () => {
        let ownerToken: string;
        let otherUserToken: string;

        beforeEach(() => {
            ownerToken = jwt.sign({ userId: 2, email: 'owner@example.com', role: 'USER', type: 'access' }, testJwtSecret);
            otherUserToken = jwt.sign({ userId: 3, email: 'other@example.com', role: 'USER', type: 'access' }, testJwtSecret);
        });

        it('should_update_product_if_owner', async () => {
            prismaMock.product.findUnique.mockResolvedValue({
                id: 1,
                userId: 2,
                name: 'Old Name',
                price: 100,
                description: 'Desc',
                isActive: true
            } as any);

            prismaMock.product.update.mockResolvedValue({
                id: 1,
                userId: 2,
                name: 'New Name',
                price: 100,
                description: 'Desc',
                isActive: true,
                createdAt: new Date(),
                updatedAt: new Date(),
                currency: 'usd',
                stripeId: null
            } as any);

            prismaMock.user.findUnique.mockResolvedValue({ id: 2, email: 'owner@example.com', role: 'USER' } as any);

            const res = await request(app)
                .patch('/api/products/1')
                .set('Authorization', `Bearer ${ownerToken}`)
                .send({ name: 'New Name' });

            expect(res.status).toBe(200);
            expect(prismaMock.product.update).toHaveBeenCalled();
        });

        it('should_fail_update_if_not_owner', async () => {
            prismaMock.product.findUnique.mockResolvedValue({
                id: 1,
                userId: 2,
                name: 'Old Name'
            } as any);

            prismaMock.user.findUnique.mockResolvedValue({ id: 3, email: 'other@example.com', role: 'USER' } as any);

            const res = await request(app)
                .patch('/api/products/1')
                .set('Authorization', `Bearer ${otherUserToken}`)
                .send({ name: 'Hacked Name' });

            expect(res.status).toBe(403);
            expect(prismaMock.product.update).not.toHaveBeenCalled();
        });

        it('should_fail_update_if_unauthenticated', async () => {
            const res = await request(app).patch('/api/products/1').send({ name: 'New' });
            expect(res.status).toBe(401);
        });
    });

    describe('DELETE /api/products/:id', () => {
        let adminToken: string;
        let userToken: string;

        beforeEach(() => {
            adminToken = jwt.sign({ userId: 1, email: 'admin@example.com', role: 'ADMIN', type: 'access' }, testJwtSecret);
            userToken = jwt.sign({ userId: 2, email: 'user@example.com', role: 'USER', type: 'access' }, testJwtSecret);
        });

        it('should_delete_product_if_admin', async () => {
            prismaMock.product.findUnique.mockResolvedValue({ id: 1, userId: 2 } as any);
            prismaMock.product.delete.mockResolvedValue({ id: 1 } as any);
            prismaMock.user.findUnique.mockResolvedValue({ id: 1, role: 'ADMIN' } as any);

            const res = await request(app)
                .delete('/api/products/1')
                .set('Authorization', `Bearer ${adminToken}`);

            expect(res.status).toBe(204);
            expect(prismaMock.product.delete).toHaveBeenCalledWith({ where: { id: 1 } });
        });

        it('should_fail_delete_if_not_admin', async () => {
            prismaMock.user.findUnique.mockResolvedValue({ id: 2, role: 'USER' } as any);

            const res = await request(app)
                .delete('/api/products/1')
                .set('Authorization', `Bearer ${userToken}`);

            expect(res.status).toBe(403);
            expect(prismaMock.product.delete).not.toHaveBeenCalled();
        });
    });
});

// Added update test cases
