import { vi, beforeEach, afterEach } from 'vitest';


process.env.DATABASE_URL = 'postgresql://test:test@localhost:5432/testdb';
process.env.JWT_ACCESS_SECRET = 'test-secret-min-32-chars-for-security';
process.env.JWT_REFRESH_SECRET = 'test-refresh-secret-min-32-chars-for-security';
process.env.JWT_ACCESS_EXPIRES_IN = '15m';
process.env.JWT_REFRESH_EXPIRES_IN = '7d';
process.env.STRIPE_SECRET_KEY = 'sk_test_dummy_key_for_testing_only';
process.env.STRIPE_WEBHOOK_SECRET = 'whsec_test_dummy_webhook_secret';
process.env.PORT = '3000';
process.env.API_BASE_URL = 'http://localhost:3000';
process.env.NODE_ENV = 'test';
process.env.FRONTEND_URL = 'http://localhost:4000';


vi.mock('../src/common/middleware/rate-limit', () => ({
    limiter: (req: import('express').Request, res: import('express').Response, next: import('express').NextFunction) => next(),
    authLimiter: (req: import('express').Request, res: import('express').Response, next: import('express').NextFunction) => next(),
}));

vi.mock('../src/common/middleware/csrf.middleware', () => ({
    csrfProtection: (req: import('express').Request, res: import('express').Response, next: import('express').NextFunction) => next(),
}));


beforeEach(() => {
});

afterEach(() => {
});
