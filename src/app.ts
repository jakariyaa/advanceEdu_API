import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import { pinoHttp } from 'pino-http';
import { logger } from './common/lib/logger';
import { errorHandler } from './common/middleware/error-handler';
import { csrfProtection } from './common/middleware/csrf.middleware';
import { limiter } from './common/middleware/rate-limit';
import routes from './routes';
import webhookRoutes from './modules/webhooks/webhook.routes';

import { corsOptions } from './config/cors';
import { helmetOptions } from './config/security';

const app = express();

app.use(helmet(helmetOptions));
app.use(cors(corsOptions));
app.use(cookieParser());
app.use(limiter);

app.use(pinoHttp({
    logger,
    autoLogging: true,
    quietReqLogger: false,
}));

app.use('/api/webhooks', express.raw({ type: 'application/json' }), webhookRoutes);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use('/api', csrfProtection, routes);

app.use(errorHandler);

export default app;

// Optimized imports

// Added health check endpoint
