import { Router } from 'express';
import { handleStripeWebhook } from './webhook.controller';

const router = Router();

router.post('/stripe', handleStripeWebhook);

export default router;
