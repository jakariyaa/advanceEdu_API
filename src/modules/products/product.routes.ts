import { Router } from 'express';
import { getAllProducts, getProductById, createProduct, updateProduct, deleteProduct } from './product.controller';
import { authenticate } from '../../common/middleware/auth.middleware';
import { requireRole } from '../../common/middleware/rbac.middleware';
import { validate } from '../../common/middleware/validate';
import { createProductSchema, updateProductSchema } from './product.schema';
import { Role } from '../../generated/prisma/client';

const router = Router();

router.get('/', getAllProducts);
router.get('/:id', getProductById);
router.post('/', authenticate, validate(createProductSchema), createProduct);
router.patch('/:id', authenticate, validate(updateProductSchema), updateProduct);
router.delete('/:id', authenticate, requireRole(Role.ADMIN), deleteProduct);

export default router;
