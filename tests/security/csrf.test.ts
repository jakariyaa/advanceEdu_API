import { describe, it, expect, vi, beforeEach } from 'vitest';
import express from 'express';
import request from 'supertest';
import cookieParser from 'cookie-parser';
import { ApiError } from '../../src/common/middleware/error-handler';


vi.unmock('../../src/common/middleware/csrf.middleware');

import { csrfProtection } from '../../src/common/middleware/csrf.middleware';
import { CSRF_COOKIE_NAME, CSRF_HEADER_NAME } from '../../src/modules/auth/auth.constants';

describe('CSRF Protection Middleware', () => {
    let app: express.Application;

    beforeEach(() => {
        app = express();
        app.use(cookieParser());
        app.use(express.json());


        app.get('/api/protected', csrfProtection, (req, res) => {
            res.json({ message: 'success' });
        });

        app.post('/api/protected', csrfProtection, (req, res) => {
            res.json({ message: 'created' });
        });


        app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
            if (err instanceof ApiError) {
                return res.status(err.statusCode).json({ message: err.message });
            }
            res.status(500).json({ message: 'Internal Server Error' });
        });
    });

    it('should set CSRF cookie on GET request', async () => {
        const response = await request(app).get('/api/protected');
        expect(response.status).toBe(200);
        expect(response.headers['set-cookie']).toBeDefined();
        const cookies = response.headers['set-cookie'][0];
        expect(cookies).toContain(CSRF_COOKIE_NAME);
    });

    it('should fail POST request without CSRF token', async () => {
        const response = await request(app).post('/api/protected');
        expect(response.status).toBe(403);
        expect(response.body.message).toBe('CSRF token missing');
    });

    it('should fail POST request with mismatching tokens', async () => {

        const getResponse = await request(app).get('/api/protected');
        const cookie = getResponse.headers['set-cookie'][0];



        const token = cookie.split(';')[0].split('=')[1];

        const response = await request(app)
            .post('/api/protected')
            .set('Cookie', [`${CSRF_COOKIE_NAME}=${token}`])
            .set(CSRF_HEADER_NAME, 'wrong-token');

        expect(response.status).toBe(403);
        expect(response.body.message).toBe('CSRF token mismatch');
    });

    it('should pass POST request with matching tokens', async () => {

        const getResponse = await request(app).get('/api/protected');
        const cookie = getResponse.headers['set-cookie'][0];
        const token = cookie.split(';')[0].split('=')[1];

        const response = await request(app)
            .post('/api/protected')
            .set('Cookie', [`${CSRF_COOKIE_NAME}=${token}`])
            .set(CSRF_HEADER_NAME, token);

        expect(response.status).toBe(200);
        expect(response.body.message).toBe('created');
    });
});
