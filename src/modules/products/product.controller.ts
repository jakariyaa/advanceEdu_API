import { Request, Response } from 'express';
import { ProductService } from './product.service';
import { asyncHandler } from '../../common/utils/async-handler';
import { ApiError } from '../../common/middleware/error-handler';

const productService = new ProductService();

export const getAllProducts = asyncHandler(async (req: Request, res: Response) => {
    const page = Math.max(1, parseInt(req.query['page'] as string) || 1);
    const limit = Math.min(100, Math.max(1, parseInt(req.query['limit'] as string) || 20));

    const result = await productService.getAllProducts(page, limit);
    res.status(200).json({
        status: 'success',
        message: 'Products retrieved successfully',
        data: result,
    });
});

export const getProductById = asyncHandler(async (req: Request, res: Response) => {
    const id = parseInt(req.params['id'] as string);
    const product = await productService.getProductById(id);
    res.status(200).json({
        status: 'success',
        message: 'Product retrieved successfully',
        data: { product },
    });
});

export const createProduct = asyncHandler(async (req: Request, res: Response) => {
    if (!req.user) {
        throw new ApiError(401, 'Authentication required');
    }
    const product = await productService.createProduct(req.user.userId, req.body);
    res.status(201).json({
        status: 'success',
        message: 'Product created successfully',
        data: { product },
    });
});

export const updateProduct = asyncHandler(async (req: Request, res: Response) => {
    if (!req.user) {
        throw new ApiError(401, 'Authentication required');
    }
    const id = parseInt(req.params['id'] as string);
    const product = await productService.updateProduct(id, req.user.userId, req.body);
    res.status(200).json({
        status: 'success',
        message: 'Product updated successfully',
        data: { product },
    });
});

export const deleteProduct = asyncHandler(async (req: Request, res: Response) => {
    const id = parseInt(req.params['id'] as string);
    await productService.deleteProduct(id);
    res.status(204).send();
});


