// Test setup file - runs before all tests
import { vi, beforeEach, afterEach } from 'vitest';

// Mock rate limiter to allow all requests in tests
vi.mock('../src/common/middleware/rate-limit', () => ({
    limiter: (req: import('express').Request, res: import('express').Response, next: import('express').NextFunction) => next(),
    authLimiter: (req: import('express').Request, res: import('express').Response, next: import('express').NextFunction) => next(),
}));

// Reset any mocks between tests
beforeEach(() => {
    // Setup code that runs before each test
    process.env.JWT_SECRET = 'test-secret-min-32-chars-for-security';
    process.env.NODE_ENV = 'test';
});

afterEach(() => {
    // Cleanup code that runs after each test
});
