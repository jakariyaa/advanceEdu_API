import { Request, Response } from 'express';
import { WebhookService } from './webhook.service';

const webhookService = new WebhookService();

export const handleStripeWebhook = async (req: Request, res: Response): Promise<void> => {
    const signature = req.headers['stripe-signature'] as string;

    if (!signature) {
        res.status(400).send('Missing stripe-signature header');
        return;
    }

    let rawBody: Buffer;
    if (Buffer.isBuffer(req.body)) {
        rawBody = req.body;
    } else if (typeof req.body === 'object') {
        rawBody = Buffer.from(JSON.stringify(req.body));
    } else if (typeof req.body === 'string') {
        rawBody = Buffer.from(req.body);
    } else {
        res.status(400).send('Unable to parse request body');
        return;
    }

    try {
        await webhookService.handleStripeEvent(signature, rawBody);
        res.json({ received: true });
    } catch (err: unknown) {
        const message = err instanceof Error ? err.message : 'Unknown error';
        res.status(400).send(message);
    }
};
