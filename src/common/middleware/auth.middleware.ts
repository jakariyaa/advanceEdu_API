import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { ApiError } from './error-handler';
import { prisma } from '../lib/prisma';

interface JwtPayload {
    userId: number;
    email: string;
}

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
            const jwtSecret = process.env['JWT_SECRET'];
            if (!jwtSecret) {
                throw new ApiError(500, 'JWT secret not configured');
            }

            const decoded = jwt.verify(token, jwtSecret) as unknown as JwtPayload;

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
                stripeId: user.stripeId ?? null
            };

            next();
        } catch (_error) {
            throw new ApiError(401, 'Invalid token');
        }
    } catch (error) {
        next(error);
    }
};
