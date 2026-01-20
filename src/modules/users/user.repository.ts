import { BaseRepository } from '../../common/repositories/base.repository';
import { User, Prisma } from '../../generated/prisma/client';

export class UserRepository extends BaseRepository {
    async findByEmail(email: string): Promise<User | null> {
        return this.prisma.user.findUnique({
            where: { email },
        });
    }

    async findById(id: number): Promise<User | null> {
        return this.prisma.user.findUnique({
            where: { id },
        });
    }

    async create(data: Prisma.UserCreateInput): Promise<User> {
        return this.prisma.user.create({
            data,
        });
    }

    async updateStripeId(userId: number, stripeId: string): Promise<User> {
        return this.prisma.user.update({
            where: { id: userId },
            data: { stripeId },
        });
    }
}
