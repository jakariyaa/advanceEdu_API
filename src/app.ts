import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import { pinoHttp } from 'pino-http';
import { logger } from './common/lib/logger';
import { errorHandler } from './common/middleware/error-handler';
import { limiter } from './common/middleware/rate-limit';
import routes from './routes';
import webhookRoutes from './modules/webhooks/webhook.routes';

const app = express();

app.use(helmet());
app.use(cors());
app.use(limiter);

app.use(pinoHttp({ logger }));

app.use('/api/webhooks', express.raw({ type: 'application/json' }), webhookRoutes);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use('/api', routes);

app.use(errorHandler);

export default app;
