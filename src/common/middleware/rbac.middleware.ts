import { Request, Response, NextFunction } from 'express';
import { Role } from '../../generated/prisma/client';
import { ApiError } from './error-handler';

/**
 * Middleware to require specific roles for accessing a route.
 * Must be used after the authenticate middleware.
 * 
 * @param roles - One or more roles that are allowed to access the route
 * @returns Express middleware function
 */
export const requireRole = (...roles: Role[]) => {
    return (req: Request, _res: Response, next: NextFunction): void => {
        if (!req.user) {
            throw new ApiError(401, 'Authentication required');
        }

        if (!roles.includes(req.user.role as Role)) {
            throw new ApiError(403, 'Insufficient permissions');
        }

        next();
    };
};
