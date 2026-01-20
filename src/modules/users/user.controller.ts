import { Request, Response } from 'express';
import { UserService } from './user.service';
import { asyncHandler } from '../../common/utils/async-handler';
import { ApiError } from '../../common/middleware/error-handler';

const userService = new UserService();

export const getMe = asyncHandler(async (req: Request, res: Response) => {
    if (!req.user?.userId) {
        throw new ApiError(401, 'Unauthorized');
    }

    const result = await userService.getUserProfile(req.user.userId);
    res.status(200).json({
        status: 'success',
        message: 'User profile retrieved successfully',
        data: result,
    });
});
