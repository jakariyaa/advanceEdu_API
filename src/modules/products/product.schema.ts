import { z } from 'zod';

export const createProductSchema = z.object({
    body: z.object({
        name: z.string().min(1),
        description: z.string().optional(),
        price: z.number().int().positive(),
        currency: z.string().default('usd'),
    }),
});

export const updateProductSchema = z.object({
    body: z.object({
        name: z.string().min(1).optional(),
        description: z.string().optional(),
        price: z.number().int().positive().optional(),
        currency: z.string().optional(),
        isActive: z.boolean().optional(),
    }),
});
