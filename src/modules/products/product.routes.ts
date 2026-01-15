import { Router } from 'express';
import { getAllProducts, getProductById, createProduct } from './product.controller';
import { authenticate } from '../../common/middleware/auth.middleware';
import { validate } from '../../common/middleware/validate';
import { createProductSchema } from './product.schema';

const router = Router();

router.get('/', getAllProducts);
router.get('/:id', getProductById);
router.post('/', authenticate, validate(createProductSchema), createProduct);

export default router;
