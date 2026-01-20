/* eslint-disable @typescript-eslint/no-explicit-any */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { TokenService } from '../../../src/common/lib/token.service';
import { prisma } from '../../../src/common/lib/prisma';
import jwt from 'jsonwebtoken';
import { DeepMockProxy } from 'vitest-mock-extended';
import { PrismaClient } from '../../../src/generated/prisma/client';


vi.mock('../../../src/common/lib/prisma', async () => {
    const { mockDeep } = await import('vitest-mock-extended');
    return {
        __esModule: true,
        prisma: mockDeep<PrismaClient>(),
    };
});

const prismaMock = prisma as unknown as DeepMockProxy<PrismaClient>;

describe('TokenService Unit Tests', () => {
    let tokenService: TokenService;
    const mockUser = { id: 1, email: 'test@example.com', role: 'USER' };

    beforeEach(() => {
        vi.clearAllMocks();
        tokenService = new TokenService();
    });

    describe('generateTokenPair', () => {
        it('should_generate_valid_access_and_refresh_tokens', async () => {
            prismaMock.refreshToken.create.mockResolvedValue({} as any);

            const tokens = await tokenService.generateTokenPair(mockUser);

            expect(tokens.accessToken).toBeDefined();
            expect(tokens.refreshToken).toBeDefined();
            expect(tokens.expiresIn).toBeDefined();

            const decodedAccess = jwt.decode(tokens.accessToken) as any;
            expect(decodedAccess.userId).toBe(mockUser.id);
            expect(decodedAccess.type).toBe('access');

            const decodedRefresh = jwt.decode(tokens.refreshToken) as any;
            expect(decodedRefresh.userId).toBe(mockUser.id);
            expect(decodedRefresh.type).toBe('refresh');
            expect(decodedRefresh.familyId).toBeDefined();
        });

        it('should_propagate_family_id_if_provided', async () => {
            const familyId = 'existing-family-id';
            prismaMock.refreshToken.create.mockResolvedValue({} as any);

            const tokens = await tokenService.generateTokenPair(mockUser, familyId);

            const decodedRefresh = jwt.decode(tokens.refreshToken) as any;
            expect(decodedRefresh.familyId).toBe(familyId);
        });
    });

    describe('verifyAccessToken', () => {
        it('should_return_payload_for_valid_token', async () => {
            const tokens = await tokenService.generateTokenPair(mockUser);
            const payload = tokenService.verifyAccessToken(tokens.accessToken);
            expect(payload.userId).toBe(mockUser.id);
        });

        it('should_throw_error_for_invalid_signature', () => {
            const invalidToken = jwt.sign({ foo: 'bar' }, 'wrong-secret');
            expect(() => tokenService.verifyAccessToken(invalidToken)).toThrow();
        });

        it('should_throw_error_if_token_type_is_incorrect', async () => {

            const badTypeToken = jwt.sign(
                { ...mockUser, type: 'refresh' },
                process.env.JWT_ACCESS_SECRET || 'secret'
            );
            expect(() => tokenService.verifyAccessToken(badTypeToken)).toThrow('Invalid token type');
        });
    });

    describe('refreshTokens', () => {
        it('should_throw_error_if_token_is_malformed', async () => {
            await expect(tokenService.refreshTokens('malformed.token')).rejects.toThrow();
        });

        it('should_throw_error_if_token_type_is_not_refresh', async () => {
            const accessToken = jwt.sign(
                { ...mockUser, type: 'access' },
                process.env.JWT_REFRESH_SECRET || process.env.JWT_ACCESS_SECRET || 'secret'
            );
            await expect(tokenService.refreshTokens(accessToken)).rejects.toThrow('Invalid token type');
        });

        it('should_throw_error_if_token_not_found_in_db', async () => {

            const token = jwt.sign(
                { ...mockUser, type: 'refresh', tokenId: 'tid', familyId: 'fid' },
                process.env.JWT_REFRESH_SECRET || 'secret'
            );

            prismaMock.refreshToken.findUnique.mockResolvedValue(null);

            await expect(tokenService.refreshTokens(token)).rejects.toThrow('Refresh token not found');
        });

        it('should_detect_reuse_and_throw_security_alert', async () => {
            const token = jwt.sign(
                { ...mockUser, type: 'refresh', tokenId: 'tid', familyId: 'target-family' },
                process.env.JWT_REFRESH_SECRET || 'secret'
            );

            prismaMock.refreshToken.findUnique.mockResolvedValue({
                id: 1,
                isUsed: true,
                familyId: 'target-family',
                user: mockUser,
            } as any);

            await expect(tokenService.refreshTokens(token)).rejects.toThrow(/Security Alert/);

            expect(prismaMock.refreshToken.deleteMany).toHaveBeenCalledWith({
                where: { familyId: 'target-family' }
            });
        });

        it('should_throw_error_if_token_expired_in_db', async () => {
            const token = jwt.sign(
                { ...mockUser, type: 'refresh', tokenId: 'tid', familyId: 'fid' },
                process.env.JWT_REFRESH_SECRET || 'secret'
            );

            prismaMock.refreshToken.findUnique.mockResolvedValue({
                id: 1,
                isUsed: false,
                expiresAt: new Date(Date.now() - 1000),
                user: mockUser,
            } as any);

            await expect(tokenService.refreshTokens(token)).rejects.toThrow('Refresh token expired');
            expect(prismaMock.refreshToken.delete).toHaveBeenCalled();
        });
    });
});
