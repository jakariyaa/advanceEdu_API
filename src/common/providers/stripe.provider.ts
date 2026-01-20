import { PaymentProvider, CreateCheckoutSessionInput } from '../interfaces/payment.provider';
import { stripe } from '../lib/stripe';

export class StripeProvider implements PaymentProvider {
    async createCheckoutSession(input: CreateCheckoutSessionInput): Promise<{ sessionId: string; url: string | null }> {
        const session = await stripe.checkout.sessions.create({
            payment_method_types: ['card'],
            line_items: input.items.map(item => ({
                price_data: {
                    currency: item.currency,
                    product_data: {
                        name: item.name,
                        ...(item.description && { description: item.description }),
                    },
                    unit_amount: item.price,
                },
                quantity: item.quantity,
            })),
            mode: 'payment',
            success_url: input.successUrl.replace('{CHECKOUT_SESSION_ID}', '{CHECKOUT_SESSION_ID}'),
            cancel_url: input.cancelUrl,
            customer_email: input.userEmail,
            metadata: {
                orderId: input.orderId.toString(),
                userId: input.userId.toString(),
            },
        });

        return { sessionId: session.id, url: session.url };
    }
}
