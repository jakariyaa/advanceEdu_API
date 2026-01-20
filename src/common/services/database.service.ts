import { prisma } from '../lib/prisma';
import { logger } from '../lib/logger';

export class DatabaseService {
    async connect(): Promise<void> {
        try {
            await prisma.$connect();
            logger.info('Database connection established');
        } catch (error) {
            logger.fatal({ err: error }, 'Failed to connect to database');
            throw error;
        }
    }

    async disconnect(): Promise<void> {
        await prisma.$disconnect();
        logger.info('Database connection closed');
    }
}

export const databaseService = new DatabaseService();
