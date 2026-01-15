import app from './app';
import { logger } from './common/lib/logger';
import dotenv from 'dotenv';

dotenv.config();

const PORT = process.env['PORT'] || 4000;

const server = app.listen(PORT, () => {
    logger.info(`Server running on port ${PORT}`);
});

process.on('SIGTERM', () => {
    logger.info('SIGTERM signal received: closing HTTP server');
    server.close(() => {
        logger.info('HTTP server closed');
    });
});

export default server;
