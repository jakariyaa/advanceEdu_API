import { Router } from 'express';

const router = Router();

router.get('/success', (req, res) => {
    const sessionId = req.query['session_id'];
    res.status(200).json({
        status: 'success',
        message: 'Payment successful',
        data: {
            sessionId,
        },
    });
});

router.get('/cancel', (_req, res) => {
    res.status(200).json({
        status: 'success',
        message: 'Payment cancelled',
    });
});

export default router;
