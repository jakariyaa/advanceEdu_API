import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { env } from '../lib/env';
import { prisma } from '../lib/prisma';
import type { StringValue } from 'ms';

export interface AccessTokenPayload {
    userId: number;
    email: string;
    role: string;
    type: 'access';
}

export interface RefreshTokenPayload {
    userId: number;
    tokenId: string;
    familyId: string;
    type: 'refresh';
}

export interface TokenPair {
    accessToken: string;
    refreshToken: string;
    expiresIn: number;
}

/**
 * Token service for generating and validating access/refresh tokens.
 * Implements industry-standard token rotation for refresh tokens.
 */
export class TokenService {
    private readonly accessSecret = env.JWT_ACCESS_SECRET;
    private readonly refreshSecret = env.JWT_REFRESH_SECRET;
    private readonly accessExpiresIn = env.JWT_ACCESS_EXPIRES_IN as StringValue;
    private readonly refreshExpiresIn = env.JWT_REFRESH_EXPIRES_IN as StringValue;

    /**
     * Generate access and refresh token pair.
     * Stores hashed refresh token in database.
     */
    async generateTokenPair(user: { id: number; email: string; role: string }, familyId?: string): Promise<TokenPair> {
        const tokenId = crypto.randomUUID();
        const currentFamilyId = familyId || crypto.randomUUID();


        const accessToken = jwt.sign(
            {
                userId: user.id,
                email: user.email,
                role: user.role,
                type: 'access',
            } as AccessTokenPayload,
            this.accessSecret,
            { expiresIn: this.accessExpiresIn }
        );


        const refreshToken = jwt.sign(
            {
                userId: user.id,
                tokenId,
                familyId: currentFamilyId,
                type: 'refresh',
            } as RefreshTokenPayload,
            this.refreshSecret,
            { expiresIn: this.refreshExpiresIn }
        );


        const hashedToken = this.hashToken(refreshToken);


        const expiresAt = this.calculateExpiry(this.refreshExpiresIn);


        await prisma.refreshToken.create({
            data: {
                token: hashedToken,
                userId: user.id,
                familyId: currentFamilyId,
                expiresAt,
            },
        });


        const decoded = jwt.decode(accessToken) as { exp: number; iat: number };
        const expiresIn = decoded.exp - decoded.iat;

        return { accessToken, refreshToken, expiresIn };
    }

    /**
     * Verify access token and return payload.
     */
    verifyAccessToken(token: string): AccessTokenPayload {
        const payload = jwt.verify(token, this.accessSecret) as AccessTokenPayload;

        if (payload.type !== 'access') {
            throw new Error('Invalid token type');
        }

        return payload;
    }

    /**
     * Refresh tokens with rotation and reuse detection.
     * If a used token is presented, revokes the entire token family.
     */
    async refreshTokens(refreshToken: string): Promise<TokenPair> {
        const payload = jwt.verify(refreshToken, this.refreshSecret) as RefreshTokenPayload;

        if (payload.type !== 'refresh') {
            throw new Error('Invalid token type');
        }


        const hashedToken = this.hashToken(refreshToken);
        const storedToken = await prisma.refreshToken.findUnique({
            where: { token: hashedToken },
            include: { user: true },
        });

        if (!storedToken) {




            throw new Error('Refresh token not found');
        }


        if (storedToken.isUsed) {


            await prisma.refreshToken.deleteMany({
                where: { familyId: storedToken.familyId },
            });
            throw new Error('Security Alert: Refresh token reuse detected. All sessions revoked.');
        }

        if (storedToken.expiresAt < new Date()) {
            await prisma.refreshToken.delete({ where: { id: storedToken.id } });
            throw new Error('Refresh token expired');
        }


        await prisma.refreshToken.update({
            where: { id: storedToken.id },
            data: { isUsed: true },
        });


        return this.generateTokenPair({
            id: storedToken.user.id,
            email: storedToken.user.email,
            role: storedToken.user.role,
        }, storedToken.familyId);
    }

    /**
     * Invalidate refresh token (logout).
     */
    async revokeRefreshToken(refreshToken: string): Promise<void> {
        const hashedToken = this.hashToken(refreshToken);

        await prisma.refreshToken.deleteMany({
            where: { token: hashedToken },
        });
    }

    /**
     * Invalidate all refresh tokens for a user.
     */
    async revokeAllUserTokens(userId: number): Promise<void> {
        await prisma.refreshToken.deleteMany({
            where: { userId },
        });
    }

    /**
     * Clean up expired tokens (call periodically).
     */
    async cleanupExpiredTokens(): Promise<number> {
        const result = await prisma.refreshToken.deleteMany({
            where: { expiresAt: { lt: new Date() } },
        });
        return result.count;
    }

    private hashToken(token: string): string {
        return crypto.createHash('sha256').update(token).digest('hex');
    }

    private calculateExpiry(duration: string): Date {
        const ms = this.parseDuration(duration);
        return new Date(Date.now() + ms);
    }

    private parseDuration(duration: string): number {
        const match = duration.match(/^(\d+)([smhd])$/);
        if (!match) {

            return 7 * 24 * 60 * 60 * 1000;
        }

        const value = parseInt(match[1] ?? '7', 10);
        const unit = match[2] ?? 'd';

        switch (unit) {
            case 's': return value * 1000;
            case 'm': return value * 60 * 1000;
            case 'h': return value * 60 * 60 * 1000;
            case 'd': return value * 24 * 60 * 60 * 1000;
            default: return 7 * 24 * 60 * 60 * 1000;
        }
    }
}

export const tokenService = new TokenService();
