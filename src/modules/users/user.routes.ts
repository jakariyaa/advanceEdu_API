import { Router } from 'express';
import { getMe } from './user.controller';
import { authenticate } from '../../common/middleware/auth.middleware';

const router = Router();

router.get('/me', authenticate, getMe);

export default router;
