import { PrismaClient } from '../../generated/prisma/client';
import { PrismaPg } from '@prisma/adapter-pg';

import { env } from './env';

let connectionString = env.DATABASE_URL;




const isRemoteDb = !connectionString.includes('@localhost') && !connectionString.includes('@127.0.0.1');
const isProduction = env.NODE_ENV === 'production';

if (isRemoteDb && !isProduction) {

    if (connectionString.includes('sslmode=require')) {
        connectionString = connectionString.replace('sslmode=require', 'sslmode=no-verify');

        console.warn('[SECURITY] SSL certificate validation bypassed for development. Do not use in production.');
    } else if (!connectionString.includes('sslmode')) {
        const separator = connectionString.includes('?') ? '&' : '?';
        connectionString = `${connectionString}${separator}sslmode=no-verify`;
        console.warn('[SECURITY] SSL certificate validation bypassed for development. Do not use in production.');
    }
}

const adapter = new PrismaPg({ connectionString });

const globalForPrisma = global as unknown as { prisma: PrismaClient };

export const prisma = globalForPrisma.prisma || new PrismaClient({ adapter });

if (env.NODE_ENV !== 'production') globalForPrisma.prisma = prisma;


