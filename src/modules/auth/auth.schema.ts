import { z } from 'zod';

export const registerSchema = z.object({
    body: z.object({
        email: z.email({ message: 'Invalid email format' }),
        password: z.string()
            .min(8, 'Password must be at least 8 characters')
            .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
            .regex(/[a-z]/, 'Password must contain at least one lowercase letter')
            .regex(/[0-9]/, 'Password must contain at least one number'),
        name: z.string().min(2).optional(),
    }),
});

export const loginSchema = z.object({
    body: z.object({
        email: z.email(),
        password: z.string(),
    }),
});

// Password complexity: min 8 chars, 1 number
