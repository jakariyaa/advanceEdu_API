import { describe, it, expect, vi, beforeEach } from 'vitest';
import request from 'supertest';
import app from '../../../src/app';
import { prisma } from '../../../src/common/lib/prisma';
import { stripe } from '../../../src/common/lib/stripe';
import { mockDeep, DeepMockProxy } from 'vitest-mock-extended';
import { PrismaClient } from '@prisma/client';

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
        webhooks: {
            constructEvent: vi.fn(),
        },
    },
}));

const prismaMock = prisma as unknown as DeepMockProxy<PrismaClient>;

describe('Webhook Endpoints', () => {

    beforeEach(() => {
        vi.clearAllMocks();
        process.env.STRIPE_WEBHOOK_SECRET = 'whsec_test';
    });

    describe('POST /api/webhooks/stripe', () => {
        it('should handle checkout.session.completed', async () => {
            const payload = {
                id: 'evt_123',
                type: 'checkout.session.completed',
                data: {
                    object: {
                        id: 'cs_test_123',
                        payment_intent: 'pi_123',
                        metadata: { orderId: '1' },
                    },
                },
            };

            (stripe.webhooks.constructEvent as ReturnType<typeof vi.fn>).mockReturnValue(payload);
            prismaMock.order.update.mockResolvedValue({} as never);

            const res = await request(app)
                .post('/api/webhooks/stripe')
                .set('stripe-signature', 'valid_signature')
                .send(payload);

            expect(res.status).toBe(200);
            expect(res.body).toEqual({ received: true });
            expect(prismaMock.order.update).toHaveBeenCalledWith({
                where: { id: 1 },
                data: { status: 'PAID', stripePaymentId: 'pi_123' },
            });
        });

        it('should handle checkout.session.expired', async () => {
            const payload = {
                id: 'evt_456',
                type: 'checkout.session.expired',
                data: {
                    object: {
                        id: 'cs_test_456',
                        metadata: { orderId: '2' },
                    },
                },
            };

            (stripe.webhooks.constructEvent as ReturnType<typeof vi.fn>).mockReturnValue(payload);
            prismaMock.order.update.mockResolvedValue({} as never);

            const res = await request(app)
                .post('/api/webhooks/stripe')
                .set('stripe-signature', 'valid_signature')
                .send(payload);

            expect(res.status).toBe(200);
            expect(res.body).toEqual({ received: true });
            expect(prismaMock.order.update).toHaveBeenCalledWith({
                where: { id: 2 },
                data: { status: 'CANCELLED' },
            });
        });

        it('should handle unhandled event types gracefully', async () => {
            const payload = {
                id: 'evt_789',
                type: 'some.other.event',
                data: { object: {} },
            };

            (stripe.webhooks.constructEvent as ReturnType<typeof vi.fn>).mockReturnValue(payload);

            const res = await request(app)
                .post('/api/webhooks/stripe')
                .set('stripe-signature', 'valid_signature')
                .send(payload);

            expect(res.status).toBe(200);
            expect(res.body).toEqual({ received: true });
        });

        it('should handle session with no orderId in metadata', async () => {
            const payload = {
                id: 'evt_no_order',
                type: 'checkout.session.completed',
                data: {
                    object: {
                        id: 'cs_test_no_order',
                        metadata: {},
                    },
                },
            };

            (stripe.webhooks.constructEvent as ReturnType<typeof vi.fn>).mockReturnValue(payload);

            const res = await request(app)
                .post('/api/webhooks/stripe')
                .set('stripe-signature', 'valid_signature')
                .send(payload);

            expect(res.status).toBe(200);
            expect(prismaMock.order.update).not.toHaveBeenCalled();
        });

        it('should return 400 for missing stripe-signature', async () => {
            const res = await request(app)
                .post('/api/webhooks/stripe')
                .send({});

            expect(res.status).toBe(400);
            expect(res.text).toContain('Missing stripe-signature header');
        });

        it('should return 400 for invalid signature', async () => {
            (stripe.webhooks.constructEvent as ReturnType<typeof vi.fn>).mockImplementation(() => {
                throw new Error('Invalid signature');
            });

            const res = await request(app)
                .post('/api/webhooks/stripe')
                .set('stripe-signature', 'invalid')
                .send({});

            expect(res.status).toBe(400);
        });
    });
});
