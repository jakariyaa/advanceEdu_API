import { z } from 'zod';

export const createOrderSchema = z.object({
    body: z.object({
        items: z.array(z.object({
            productId: z.number().int().positive(),
            quantity: z.number().int().positive(),
        })).min(1),
    }),
});


