import { ApiError } from '../../common/middleware/error-handler';
import { createProductSchema, updateProductSchema } from './product.schema';
import { z } from 'zod';
import { ProductRepository } from './product.repository';
import { Prisma } from '../../generated/prisma/client';

type CreateProductInput = z.infer<typeof createProductSchema>['body'];
type UpdateProductInput = z.infer<typeof updateProductSchema>['body'];

export class ProductService {
    constructor(
        private readonly productRepository: ProductRepository = new ProductRepository()
    ) { }

    async getAllProducts(page: number = 1, limit: number = 20) {
        const skip = (page - 1) * limit;

        const [products, total] = await Promise.all([
            this.productRepository.findAll(skip, limit),
            this.productRepository.countActive(),
        ]);

        return {
            products,
            pagination: {
                page,
                limit,
                total,
                totalPages: Math.ceil(total / limit),
            },
        };
    }

    async getProductById(id: number) {
        const product = await this.productRepository.findById(id);

        if (!product) {
            throw new ApiError(404, 'Product not found');
        }

        return product;
    }

    async createProduct(userId: number, data: CreateProductInput) {
        return this.productRepository.create({
            ...data,
            description: data.description ?? null,
            userId,
        });
    }

    async updateProduct(id: number, userId: number, data: UpdateProductInput) {
        const product = await this.productRepository.findById(id);

        if (!product) {
            throw new ApiError(404, 'Product not found');
        }

        if (product.userId !== userId) {
            throw new ApiError(403, 'You are not authorized to update this product');
        }

        const updateData: Prisma.ProductUpdateInput = {};
        if (data.name) updateData.name = data.name;
        if (data.price) updateData.price = data.price;
        if (data.currency) updateData.currency = data.currency;
        if (data.isActive !== undefined) updateData.isActive = data.isActive;
        updateData.description = data.description ?? product.description;

        return this.productRepository.update(id, updateData);
    }

    async deleteProduct(id: number) {
        const product = await this.productRepository.findById(id);

        if (!product) {
            throw new ApiError(404, 'Product not found');
        }

        return this.productRepository.delete(id);
    }
}
