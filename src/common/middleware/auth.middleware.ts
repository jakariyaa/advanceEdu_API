import { Request, Response, NextFunction } from 'express';
import { ApiError } from './error-handler';
import { prisma } from '../lib/prisma';
import { tokenService } from '../lib/token.service';

export const authenticate = async (
    req: Request,
    _res: Response,
    next: NextFunction
) => {
    try {
        const authHeader = req.headers.authorization;

        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            throw new ApiError(401, 'Unauthorized');
        }

        const token = authHeader.split(' ')[1];

        if (!token) {
            throw new ApiError(401, 'Unauthorized');
        }

        try {
            const decoded = tokenService.verifyAccessToken(token);

            const user = await prisma.user.findUnique({
                where: { id: decoded.userId },
            });

            if (!user) {
                throw new ApiError(401, 'User not found');
            }

            req.user = {
                userId: user.id,
                email: user.email,
                name: user.name ?? null,
                role: user.role,
                stripeId: user.stripeId ?? null
            };

            next();
        } catch {
            throw new ApiError(401, 'Invalid or expired token');
        }
    } catch (error) {
        next(error);
    }
};
