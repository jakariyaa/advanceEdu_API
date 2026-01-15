import { Request, Response } from 'express';
import { ProductService } from './product.service';
import { asyncHandler } from '../../common/utils/async-handler';

const productService = new ProductService();

export const getAllProducts = asyncHandler(async (_req: Request, res: Response) => {
    const products = await productService.getAllProducts();
    res.status(200).json({
        status: 'success',
        data: { products },
    });
});

export const getProductById = asyncHandler(async (req: Request, res: Response) => {
    const id = parseInt(req.params['id'] as string);
    const product = await productService.getProductById(id);
    res.status(200).json({
        status: 'success',
        data: { product },
    });
});

export const createProduct = asyncHandler(async (req: Request, res: Response) => {
    const product = await productService.createProduct(req.body);
    res.status(201).json({
        status: 'success',
        data: { product },
    });
});
