import { stripe } from '../../common/lib/stripe';
import { prisma } from '../../common/lib/prisma';
import Stripe from 'stripe';
import { OrderStatus } from '../../generated/prisma/client';
import { logger } from '../../common/lib/logger';

import { env } from '../../common/lib/env';

export class WebhookService {
    async handleStripeEvent(signature: string, payload: Buffer) {
        let event: Stripe.Event;

        try {
            event = stripe.webhooks.constructEvent(
                payload,
                signature,
                env.STRIPE_WEBHOOK_SECRET
            );
        } catch (err: unknown) {
            const message = err instanceof Error ? err.message : 'Unknown error';
            logger.error(`Webhook signature verification failed: ${message}`);
            throw new Error(`Webhook Error: ${message}`);
        }

        switch (event.type) {
            case 'checkout.session.completed': {
                const session = event.data.object as Stripe.Checkout.Session;
                await this.handleCheckoutSessionCompleted(session);
                break;
            }
            case 'checkout.session.expired': {
                const expiredSession = event.data.object as Stripe.Checkout.Session;
                await this.handleCheckoutSessionExpired(expiredSession);
                break;
            }
            default:
                logger.info(`Unhandled event type ${event.type}`);
        }
    }

    private async handleCheckoutSessionCompleted(session: Stripe.Checkout.Session) {
        const orderId = session.metadata?.['orderId'];
        if (!orderId) return;

        const orderIdNum = parseInt(orderId);

        await prisma.order.update({
            where: { id: orderIdNum },
            data: {
                status: OrderStatus.PAID,
                stripePaymentId: session.payment_intent as string,
            },
        });

        logger.info(`Order ${orderIdNum} marked as PAID`);
    }

    private async handleCheckoutSessionExpired(session: Stripe.Checkout.Session) {
        const orderId = session.metadata?.['orderId'];
        if (!orderId) return;

        const orderIdNum = parseInt(orderId);

        await prisma.order.update({
            where: { id: orderIdNum },
            data: {
                status: OrderStatus.CANCELLED,
            },
        });

        logger.info(`Order ${orderIdNum} marked as CANCELLED`);
    }
}
