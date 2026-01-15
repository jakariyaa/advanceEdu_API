import { Request, Response } from 'express';
import { AuthService } from './auth.service';
import { asyncHandler } from '../../common/utils/async-handler';

const authService = new AuthService();

export const register = asyncHandler(async (req: Request, res: Response) => {
    const result = await authService.register(req.body);
    res.status(201).json({
        status: 'success',
        data: result,
    });
});

export const login = asyncHandler(async (req: Request, res: Response) => {
    const result = await authService.login(req.body);
    res.status(200).json({
        status: 'success',
        data: result,
    });
});
