import { Router } from 'express';
import { createOrder } from './order.controller';
import { authenticate } from '../../common/middleware/auth.middleware';
import { validate } from '../../common/middleware/validate';
import { createOrderSchema } from './order.schema';

const router = Router();

router.post('/', authenticate, validate(createOrderSchema), createOrder);

export default router;
