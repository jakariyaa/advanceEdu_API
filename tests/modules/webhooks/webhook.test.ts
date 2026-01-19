/* eslint-disable @typescript-eslint/no-explicit-any */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { WebhookService } from '../../../src/modules/webhooks/webhook.service';
import { prisma } from '../../../src/common/lib/prisma';
import { stripe } from '../../../src/common/lib/stripe';
import { DeepMockProxy } from 'vitest-mock-extended';
import { PrismaClient } from '../../../src/generated/prisma/client';
import Stripe from 'stripe';


vi.mock('../../../src/common/lib/prisma', async () => {
    const { mockDeep } = await import('vitest-mock-extended');
    return {
        __esModule: true,
        prisma: mockDeep<PrismaClient>(),
    };
});

vi.mock('../../../src/common/lib/stripe', () => ({
    stripe: {
        webhooks: {
            constructEvent: vi.fn(),
        },
    },
}));

const prismaMock = prisma as unknown as DeepMockProxy<PrismaClient>;

describe('WebhookService', () => {
    let webhookService: WebhookService;
    const mockSignature = 'test-signature';
    const mockPayload = Buffer.from('test-payload');

    beforeEach(() => {
        vi.clearAllMocks();
        process.env.STRIPE_WEBHOOK_SECRET = 'whsec_test';
        webhookService = new WebhookService();
    });

    it('should_handle_checkout_session_completed_event', async () => {
        const mockEvent = {
            type: 'checkout.session.completed',
            data: {
                object: {
                    metadata: { orderId: '1' },
                    payment_intent: 'pi_123',
                } as any,
            },
        } as Stripe.Event;

        (stripe.webhooks.constructEvent as any).mockReturnValue(mockEvent);
        prismaMock.order.update.mockResolvedValue({} as any);

        await webhookService.handleStripeEvent(mockSignature, mockPayload);

        expect(prismaMock.order.update).toHaveBeenCalledWith({
            where: { id: 1 },
            data: {
                status: 'PAID',
                stripePaymentId: 'pi_123',
            },
        });
    });

    it('should_handle_checkout_session_expired_event', async () => {
        const mockEvent = {
            type: 'checkout.session.expired',
            data: {
                object: {
                    metadata: { orderId: '2' },
                } as any,
            },
        } as Stripe.Event;

        (stripe.webhooks.constructEvent as any).mockReturnValue(mockEvent);
        prismaMock.order.update.mockResolvedValue({} as any);

        await webhookService.handleStripeEvent(mockSignature, mockPayload);

        expect(prismaMock.order.update).toHaveBeenCalledWith({
            where: { id: 2 },
            data: {
                status: 'CANCELLED',
            },
        });
    });

    it('should_ignore_unknown_event_types', async () => {
        const mockEvent = {
            type: 'payment_intent.succeeded',
            data: { object: {} },
        } as Stripe.Event;

        (stripe.webhooks.constructEvent as any).mockReturnValue(mockEvent);

        await webhookService.handleStripeEvent(mockSignature, mockPayload);

        expect(prismaMock.order.update).not.toHaveBeenCalled();
    });

    it('should_throw_error_if_signature_verification_fails', async () => {
        (stripe.webhooks.constructEvent as any).mockImplementation(() => {
            throw new Error('Invalid signature');
        });

        await expect(webhookService.handleStripeEvent(mockSignature, mockPayload))
            .rejects.toThrow('Webhook Error: Invalid signature');
    });

    it('should_ignore_event_if_order_id_is_missing', async () => {
        const mockEvent = {
            type: 'checkout.session.completed',
            data: {
                object: {
                    metadata: {},
                } as any,
            },
        } as Stripe.Event;

        (stripe.webhooks.constructEvent as any).mockReturnValue(mockEvent);

        await webhookService.handleStripeEvent(mockSignature, mockPayload);

        expect(prismaMock.order.update).not.toHaveBeenCalled();
    });

    describe('E2E-style tests with realistic Stripe payloads', () => {
        it('should_process_complete_checkout_session_completed_payload', async () => {
            const realisticEvent: Stripe.Event = {
                id: 'evt_1PQ2s3AB4cD5efG6hIjK7lM8',
                object: 'event',
                api_version: '2023-10-16',
                created: 1704067200,
                type: 'checkout.session.completed',
                livemode: false,
                pending_webhooks: 1,
                request: { id: 'req_abc123', idempotency_key: null },
                data: {
                    object: {
                        id: 'cs_test_a1b2c3d4e5f6g7h8i9j0',
                        object: 'checkout.session',
                        amount_total: 2999,
                        currency: 'usd',
                        customer: 'cus_PQ2s3AB4cD5efG6',
                        customer_email: 'test@example.com',
                        metadata: {
                            orderId: '42',
                            userId: '7',
                        },
                        mode: 'payment',
                        payment_intent: 'pi_3PQ2s3AB4cD5efG60hIjK7lM',
                        payment_status: 'paid',
                        status: 'complete',
                        success_url: 'https://example.com/success',
                        cancel_url: 'https://example.com/cancel',
                    } as unknown as Stripe.Checkout.Session,
                },
            };

            (stripe.webhooks.constructEvent as any).mockReturnValue(realisticEvent);
            prismaMock.order.update.mockResolvedValue({
                id: 42,
                userId: 7,
                status: 'PAID',
                totalAmount: 2999,
                currency: 'usd',
                stripeSessionId: 'cs_test_a1b2c3d4e5f6g7h8i9j0',
                stripePaymentId: 'pi_3PQ2s3AB4cD5efG60hIjK7lM',
                createdAt: new Date(),
                updatedAt: new Date(),
            } as any);

            await webhookService.handleStripeEvent(mockSignature, mockPayload);

            expect(prismaMock.order.update).toHaveBeenCalledWith({
                where: { id: 42 },
                data: {
                    status: 'PAID',
                    stripePaymentId: 'pi_3PQ2s3AB4cD5efG60hIjK7lM',
                },
            });
        });

        it('should_process_complete_checkout_session_expired_payload', async () => {
            const realisticEvent: Stripe.Event = {
                id: 'evt_2RS3t4CD5eF6gHi7JkLm8nO9',
                object: 'event',
                api_version: '2023-10-16',
                created: 1704153600,
                type: 'checkout.session.expired',
                livemode: false,
                pending_webhooks: 1,
                request: { id: 'req_def456', idempotency_key: null },
                data: {
                    object: {
                        id: 'cs_test_expired_session_xyz',
                        object: 'checkout.session',
                        amount_total: 4999,
                        currency: 'usd',
                        customer: null,
                        customer_email: 'customer@example.com',
                        metadata: {
                            orderId: '99',
                            userId: '15',
                        },
                        mode: 'payment',
                        payment_intent: null,
                        payment_status: 'unpaid',
                        status: 'expired',
                        success_url: 'https://example.com/success',
                        cancel_url: 'https://example.com/cancel',
                        expires_at: 1704153600,
                    } as unknown as Stripe.Checkout.Session,
                },
            };

            (stripe.webhooks.constructEvent as any).mockReturnValue(realisticEvent);
            prismaMock.order.update.mockResolvedValue({
                id: 99,
                userId: 15,
                status: 'CANCELLED',
                totalAmount: 4999,
                currency: 'usd',
                stripeSessionId: 'cs_test_expired_session_xyz',
                stripePaymentId: null,
                createdAt: new Date(),
                updatedAt: new Date(),
            } as any);

            await webhookService.handleStripeEvent(mockSignature, mockPayload);

            expect(prismaMock.order.update).toHaveBeenCalledWith({
                where: { id: 99 },
                data: {
                    status: 'CANCELLED',
                },
            });
        });

        it('should_handle_malformed_metadata_gracefully', async () => {
            const malformedEvent: Stripe.Event = {
                id: 'evt_malformed',
                object: 'event',
                api_version: '2023-10-16',
                created: 1704240000,
                type: 'checkout.session.completed',
                livemode: false,
                pending_webhooks: 1,
                request: { id: 'req_malformed', idempotency_key: null },
                data: {
                    object: {
                        id: 'cs_test_malformed',
                        object: 'checkout.session',
                        metadata: {
                            orderId: 'not-a-number',
                        },
                        payment_intent: 'pi_test',
                        status: 'complete',
                    } as unknown as Stripe.Checkout.Session,
                },
            };

            (stripe.webhooks.constructEvent as any).mockReturnValue(malformedEvent);

            await webhookService.handleStripeEvent(mockSignature, mockPayload);

            expect(prismaMock.order.update).toHaveBeenCalledWith({
                where: { id: NaN },
                data: expect.any(Object),
            });
        });
    });
});


// Signature verification tests
