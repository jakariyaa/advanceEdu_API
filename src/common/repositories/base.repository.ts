import { prisma } from '../lib/prisma';
import { PrismaClient } from '../../generated/prisma/client';

export abstract class BaseRepository {
    protected prisma: PrismaClient;

    constructor() {
        this.prisma = prisma;
    }
}
