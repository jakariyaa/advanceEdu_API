import { CorsOptions } from 'cors';
import { env } from '../common/lib/env';

const allowedOrigins = [env.FRONTEND_URL];

export const corsOptions: CorsOptions = {
    origin: (origin, callback) => {

        if (!origin && env.NODE_ENV === 'development') {
            return callback(null, true);
        }
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'x-csrf-token'],
};
