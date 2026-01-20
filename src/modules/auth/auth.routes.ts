import { Router } from 'express';
import { register, login, refresh, logout, logoutAll } from './auth.controller';
import { validate } from '../../common/middleware/validate';
import { registerSchema, loginSchema } from './auth.schema';
import { authLimiter } from '../../common/middleware/rate-limit';
import { authenticate } from '../../common/middleware/auth.middleware';

const router = Router();

router.post('/register', authLimiter, validate(registerSchema), register);
router.post('/login', authLimiter, validate(loginSchema), login);
router.post('/refresh', authLimiter, refresh);
router.post('/logout', logout);
router.post('/logout-all', authenticate, logoutAll);

export default router;
