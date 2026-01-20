import { env } from '../../common/lib/env';
import { ApiError } from '../../common/middleware/error-handler';
import { createOrderSchema } from './order.schema';
import { z } from 'zod';
import { OrderStatus, Product } from '../../generated/prisma/client';
import { OrderRepository } from './order.repository';
import { ProductRepository } from '../products/product.repository';
import { PaymentProvider } from '../../common/interfaces/payment.provider';
import { StripeProvider } from '../../common/providers/stripe.provider';

type CreateOrderInput = z.infer<typeof createOrderSchema>['body'];

export class OrderService {
    constructor(
        private readonly orderRepository: OrderRepository = new OrderRepository(),
        private readonly productRepository: ProductRepository = new ProductRepository(),
        private readonly paymentProvider: PaymentProvider = new StripeProvider()
    ) { }

    async createOrder(userId: number, data: CreateOrderInput) {
        const { items } = data;

        const productIds = items.map(i => i.productId);
        const products = await this.productRepository.findActiveByIds(productIds);

        if (products.length !== items.length) {
            throw new ApiError(400, 'Some products are invalid or inactive');
        }

        let totalAmount = 0;
        const orderItemsData = items.map(item => {
            const product = products.find((p: Product) => p.id === item.productId)!;
            totalAmount += product.price * item.quantity;
            return {
                productId: item.productId,
                quantity: item.quantity,
                price: product.price,
            };
        });

        const order = await this.orderRepository.create({
            userId,
            totalAmount,
            status: OrderStatus.PENDING,
            items: {
                create: orderItemsData,
            },
        });


        const paymentItems = order.items.map(item => ({
            name: item.product.name,
            ...(item.product.description ? { description: item.product.description } : {}),
            price: item.price,
            currency: item.product.currency,
            quantity: item.quantity,
        }));

        const { sessionId, url } = await this.paymentProvider.createCheckoutSession({
            orderId: order.id,
            userId,
            userEmail: order.user.email,
            items: paymentItems,
            successUrl: `${env.API_BASE_URL}/api/payment/success?session_id={CHECKOUT_SESSION_ID}`,
            cancelUrl: `${env.API_BASE_URL}/api/payment/cancel`,
        });

        await this.orderRepository.updateStripeSessionId(order.id, sessionId);

        return { order, sessionId, url };
    }
}
