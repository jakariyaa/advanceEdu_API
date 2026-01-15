import { defineConfig } from 'vitest/config';

export default defineConfig({
    test: {
        include: ['**/*.{test,spec}.ts'],
        exclude: ['**/node_modules/**', '**/dist/**'],
        environment: 'node',
        globals: true,
        pool: 'forks',
        testTimeout: 10000,
        hookTimeout: 15000,
        reporters: ['default'],
        coverage: {
            provider: 'v8',
            enabled: false,
            reporter: ['text', 'json', 'html'],
            reportsDirectory: './coverage',
            include: ['src/**/*.ts'],
            exclude: [
                '**/*.test.ts',
                '**/*.spec.ts',
                'src/server.ts',
                'src/config/**',
            ],
            thresholds: {
                lines: 80,
                functions: 80,
                branches: 70,
                statements: 80,
            },
        },
        setupFiles: ['./tests/setup.ts'],
        clearMocks: true,
        restoreMocks: true,
    },
});
