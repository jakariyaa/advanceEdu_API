import { Role } from '../../generated/prisma/client';

declare global {
    namespace Express {
        interface Request {
            user?: {
                userId: number;
                email: string;
                name: string | null;
                role: Role;
                stripeId: string | null;
            };
        }
    }
}

// Standardized error response interface
