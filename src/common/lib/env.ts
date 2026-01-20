import 'dotenv/config';
import { z } from 'zod';

/**
 * Environment variable validation schema.
 * All required environment variables are validated at startup.
 * Provides clear error messages for missing or invalid configuration.
 */
const envSchema = z.object({
    DATABASE_URL: z.url({ message: 'DATABASE_URL must be a valid database connection URL' }),


    JWT_ACCESS_SECRET: z.string().min(32, 'JWT_ACCESS_SECRET must be at least 32 characters for security'),
    JWT_REFRESH_SECRET: z.string().min(32, 'JWT_REFRESH_SECRET must be at least 32 characters'),
    JWT_ACCESS_EXPIRES_IN: z.string().default('15m'),
    JWT_REFRESH_EXPIRES_IN: z.string().default('7d'),


    STRIPE_SECRET_KEY: z.string().startsWith('sk_', 'STRIPE_SECRET_KEY must start with sk_'),
    STRIPE_WEBHOOK_SECRET: z.string().startsWith('whsec_', 'STRIPE_WEBHOOK_SECRET must start with whsec_'),


    PORT: z.string().regex(/^\d+$/, 'PORT must be a number').default('3000').transform(Number),
    API_BASE_URL: z.url().default('http://localhost:3000'),
    NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),


    FRONTEND_URL: z.url().default('http://localhost:4000'),
});

/**
 * Validated environment variables.
 * Throws an error at startup if validation fails.
 */
function validateEnv() {
    const result = envSchema.safeParse(process.env);

    if (!result.success) {
        const errors = result.error.issues.map(issue => {
            return `  - ${issue.path.join('.')}: ${issue.message}`;
        }).join('\n');

        console.error('\nEnvironment validation failed:\n');
        console.error(errors);
        console.error('\nPlease check your .env file matches .env.example\n');

        throw new Error('Invalid environment configuration');
    }

    return result.data;
}

export const env = validateEnv();

export type Env = z.infer<typeof envSchema>;
