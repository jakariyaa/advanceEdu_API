import { BaseRepository } from '../../common/repositories/base.repository';
import { Product, Prisma } from '../../generated/prisma/client';

export class ProductRepository extends BaseRepository {
    async findActiveByIds(ids: number[]): Promise<Product[]> {
        return this.prisma.product.findMany({
            where: {
                id: { in: ids },
                isActive: true,
            },
        });
    }

    async findAll(skip: number, take: number): Promise<Product[]> {
        return this.prisma.product.findMany({
            where: { isActive: true },
            orderBy: { createdAt: 'desc' },
            skip,
            take,
        });
    }

    async countActive(): Promise<number> {
        return this.prisma.product.count({
            where: { isActive: true },
        });
    }

    async findById(id: number): Promise<Product | null> {
        return this.prisma.product.findUnique({
            where: { id },
        });
    }

    async create(data: Prisma.ProductUncheckedCreateInput): Promise<Product> {
        return this.prisma.product.create({
            data,
        });
    }

    async update(id: number, data: Prisma.ProductUpdateInput): Promise<Product> {
        return this.prisma.product.update({
            where: { id },
            data,
        });
    }

    async delete(id: number): Promise<Product> {
        return this.prisma.product.delete({
            where: { id },
        });
    }
}
