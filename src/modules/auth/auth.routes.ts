import { Router } from 'express';
import { register, login } from './auth.controller';
import { validate } from '../../common/middleware/validate';
import { registerSchema, loginSchema } from './auth.schema';
import { authLimiter } from '../../common/middleware/rate-limit';

const router = Router();

router.post('/register', authLimiter, validate(registerSchema), register);
router.post('/login', authLimiter, validate(loginSchema), login);

export default router;
