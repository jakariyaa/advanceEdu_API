import { BaseRepository } from '../../common/repositories/base.repository';
import { Order, Prisma } from '../../generated/prisma/client';

export class OrderRepository extends BaseRepository {
    async create(data: Prisma.OrderUncheckedCreateInput): Promise<Prisma.OrderGetPayload<{ include: { items: { include: { product: true } }, user: true } }>> {
        return this.prisma.order.create({
            data,
            include: {
                items: {
                    include: {
                        product: true,
                    },
                },
                user: true,
            },
        });
    }

    async updateStripeSessionId(orderId: number, sessionId: string): Promise<Order> {
        return this.prisma.order.update({
            where: { id: orderId },
            data: { stripeSessionId: sessionId },
        });
    }

    async findById(id: number): Promise<Order | null> {
        return this.prisma.order.findUnique({
            where: { id },
            include: { items: true },
        });
    }
}
