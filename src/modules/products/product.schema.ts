import { z } from 'zod';

export const createProductSchema = z.object({
    body: z.object({
        name: z.string().min(1),
        description: z.string().optional(),
        price: z.number().int().positive(), // in cents
        currency: z.string().default('usd'),
    }),
});
