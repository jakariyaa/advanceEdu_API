import pino, { LoggerOptions } from 'pino';

const isDev = process.env['NODE_ENV'] !== 'production';

const devOptions: LoggerOptions = {
    level: process.env['LOG_LEVEL'] || 'info',
    transport: {
        target: 'pino-pretty',
        options: {
            colorize: true,
            ignore: 'pid,hostname',
            translateTime: 'SYS:standard',
            sync: true,
        },
    },
};

const prodOptions: LoggerOptions = {
    level: process.env['LOG_LEVEL'] || 'info',
};

export const logger = pino(isDev ? devOptions : prodOptions);
