import { Request, Response } from 'express';
import { WebhookService } from './webhook.service';

const webhookService = new WebhookService();

export const handleStripeWebhook = async (req: Request, res: Response): Promise<void> => {
    const signature = req.headers['stripe-signature'] as string;

    if (!signature) {
        res.status(400).send('Missing stripe-signature header');
        return;
    }

    try {
        await webhookService.handleStripeEvent(signature, req.body);
        res.json({ received: true });
    } catch (err: unknown) {
        const message = err instanceof Error ? err.message : 'Unknown error';
        res.status(400).send(message);
    }
};
