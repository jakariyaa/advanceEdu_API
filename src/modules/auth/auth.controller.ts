import { Request, Response } from 'express';
import { AuthService } from './auth.service';
import { asyncHandler } from '../../common/utils/async-handler';
import { ApiError } from '../../common/middleware/error-handler';
import { REFRESH_TOKEN_COOKIE_OPTIONS, REFRESH_TOKEN_CLEAR_OPTIONS } from './auth.constants';

const authService = new AuthService();

export const register = asyncHandler(async (req: Request, res: Response) => {
    const result = await authService.register(req.body);
    res.status(201).json({
        status: 'success',
        message: 'User registered successfully',
        data: result,
    });
});

export const login = asyncHandler(async (req: Request, res: Response) => {
    const result = await authService.login(req.body);

    res.cookie('refreshToken', result.tokens.refreshToken, REFRESH_TOKEN_COOKIE_OPTIONS);

    res.status(200).json({
        status: 'success',
        message: 'Login successful',
        data: {
            user: result.user,
            accessToken: result.tokens.accessToken,
            expiresIn: result.tokens.expiresIn,
        },
    });
});

export const refresh = asyncHandler(async (req: Request, res: Response) => {
    const refreshToken = req.cookies['refreshToken'];

    if (!refreshToken) {
        throw new ApiError(401, 'Refresh token is required');
    }

    const tokens = await authService.refreshTokens(refreshToken);

    res.cookie('refreshToken', tokens.refreshToken, REFRESH_TOKEN_COOKIE_OPTIONS);

    res.status(200).json({
        status: 'success',
        message: 'Token refreshed successfully',
        data: {
            accessToken: tokens.accessToken,
            expiresIn: tokens.expiresIn,
        },
    });
});

export const logout = asyncHandler(async (req: Request, res: Response) => {
    const refreshToken = req.cookies['refreshToken'];

    if (refreshToken) {
        await authService.logout(refreshToken);
    }

    res.clearCookie('refreshToken', REFRESH_TOKEN_CLEAR_OPTIONS);

    res.status(200).json({
        status: 'success',
        message: 'Logged out successfully',
    });
});

export const logoutAll = asyncHandler(async (req: Request, res: Response) => {
    if (!req.user) {
        throw new ApiError(401, 'Authentication required');
    }

    await authService.logoutAll(req.user.userId);
    res.status(200).json({
        status: 'success',
        message: 'Logged out from all devices',
    });
});

// Improved error handling
