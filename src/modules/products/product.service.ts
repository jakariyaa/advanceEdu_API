import { prisma } from '../../common/lib/prisma';
import { ApiError } from '../../common/middleware/error-handler';
import { createProductSchema } from './product.schema';
import { z } from 'zod';

type CreateProductInput = z.infer<typeof createProductSchema>['body'];

export class ProductService {
    async getAllProducts() {
        return prisma.product.findMany({
            where: { isActive: true },
            orderBy: { createdAt: 'desc' },
        });
    }

    async getProductById(id: number) {
        const product = await prisma.product.findUnique({
            where: { id },
        });

        if (!product) {
            throw new ApiError(404, 'Product not found');
        }

        return product;
    }

    async createProduct(data: CreateProductInput) {
        return prisma.product.create({
            data: {
                name: data.name,
                description: data.description ?? null,
                price: data.price,
                currency: data.currency,
            },
        });
    }
}
