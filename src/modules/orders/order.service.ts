import { prisma } from '../../common/lib/prisma';
import { stripe } from '../../common/lib/stripe';
import { ApiError } from '../../common/middleware/error-handler';
import { createOrderSchema } from './order.schema';
import { z } from 'zod';
import { OrderStatus } from '@prisma/client';

type CreateOrderInput = z.infer<typeof createOrderSchema>['body'];

export class OrderService {
    async createOrder(userId: number, data: CreateOrderInput) {
        const { items } = data;

        const productIds = items.map(i => i.productId);
        const products = await prisma.product.findMany({
            where: { id: { in: productIds }, isActive: true },
        });

        if (products.length !== items.length) {
            throw new ApiError(400, 'Some products are invalid or inactive');
        }

        let totalAmount = 0;
        const orderItemsData = items.map(item => {
            const product = products.find(p => p.id === item.productId)!;
            totalAmount += product.price * item.quantity;
            return {
                productId: item.productId,
                quantity: item.quantity,
                price: product.price,
            };
        });

        const order = await prisma.order.create({
            data: {
                userId,
                totalAmount,
                status: OrderStatus.PENDING,
                items: {
                    create: orderItemsData,
                },
            },
            include: {
                items: {
                    include: {
                        product: true,
                    },
                },
                user: true,
            },
        });

        const session = await stripe.checkout.sessions.create({
            payment_method_types: ['card'],
            line_items: order.items.map(item => ({
                price_data: {
                    currency: item.product.currency,
                    product_data: {
                        name: item.product.name,
                        ...(item.product.description && { description: item.product.description }),
                    },
                    unit_amount: item.price,
                },
                quantity: item.quantity,
            })),
            mode: 'payment',
            success_url: `${process.env['API_BASE_URL'] || 'http://localhost:3000'}/api/payment/success?session_id={CHECKOUT_SESSION_ID}`,
            cancel_url: `${process.env['API_BASE_URL'] || 'http://localhost:3000'}/api/payment/cancel`,
            customer_email: order.user.email,
            metadata: {
                orderId: order.id.toString(),
                userId: userId.toString(),
            },
        });

        await prisma.order.update({
            where: { id: order.id },
            data: { stripeSessionId: session.id },
        });

        return { order, sessionId: session.id, url: session.url };
    }
}
