import app from './app';
import { logger } from './common/lib/logger';
import { databaseService } from './common/services/database.service';
import { env } from './common/lib/env';

const PORT = env.PORT;

async function bootstrap(): Promise<void> {
    try {
        await databaseService.connect();

        const server = app.listen(PORT, () => {
            logger.info(`Server running on port ${PORT}`);
        });

        process.on('SIGTERM', async () => {
            logger.info('SIGTERM signal received: closing HTTP server');
            server.close(async () => {
                await databaseService.disconnect();
                logger.info('HTTP server closed');
                process.exit(0);
            });
        });

        process.on('SIGINT', async () => {
            logger.info('SIGINT signal received: closing HTTP server');
            server.close(async () => {
                await databaseService.disconnect();
                logger.info('HTTP server closed');
                process.exit(0);
            });
        });
    } catch (error) {
        logger.fatal({ err: error }, 'Failed to start server');
        process.exit(1);
    }
}

bootstrap();

// Integrated logger middleware
