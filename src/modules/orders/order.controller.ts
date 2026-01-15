import { Request, Response } from 'express';
import { OrderService } from './order.service';
import { asyncHandler } from '../../common/utils/async-handler';
import { ApiError } from '../../common/middleware/error-handler';

const orderService = new OrderService();

export const createOrder = asyncHandler(async (req: Request, res: Response) => {
    if (!req.user?.userId) {
        throw new ApiError(401, 'Unauthorized');
    }

    const result = await orderService.createOrder(req.user.userId, req.body);
    res.status(201).json({
        status: 'success',
        data: result,
    });
});
