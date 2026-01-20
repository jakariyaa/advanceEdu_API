import bcrypt from 'bcrypt';
import { ApiError } from '../../common/middleware/error-handler';
import { z } from 'zod';
import { registerSchema, loginSchema } from './auth.schema';
import { tokenService, TokenPair } from '../../common/lib/token.service';
import { UserRepository } from '../users/user.repository';

type RegisterInput = z.infer<typeof registerSchema>['body'];
type LoginInput = z.infer<typeof loginSchema>['body'];

export class AuthService {
    constructor(
        private readonly userRepository: UserRepository = new UserRepository()
    ) { }

    async register(data: RegisterInput) {
        const existingUser = await this.userRepository.findByEmail(data.email);

        if (existingUser) {
            throw new ApiError(409, 'User already exists');
        }

        const hashedPassword = await bcrypt.hash(data.password, 10);

        const user = await this.userRepository.create({
            email: data.email,
            password: hashedPassword,
            name: data.name ?? null,
        });

        const { password: _password, ...userWithoutPassword } = user;
        return { user: userWithoutPassword };
    }

    async login(data: LoginInput) {
        const user = await this.userRepository.findByEmail(data.email);

        if (!user) {
            throw new ApiError(401, 'Invalid email or password');
        }

        const isPasswordValid = await bcrypt.compare(data.password, user.password);

        if (!isPasswordValid) {
            throw new ApiError(401, 'Invalid email or password');
        }


        const tokens = await tokenService.generateTokenPair({
            id: user.id,
            email: user.email,
            role: user.role,
        });

        const { password: _password, ...userWithoutPassword } = user;
        return { user: userWithoutPassword, tokens };
    }

    async refreshTokens(refreshToken: string): Promise<TokenPair> {
        try {
            return await tokenService.refreshTokens(refreshToken);
        } catch {
            throw new ApiError(401, 'Invalid or expired refresh token');
        }
    }

    async logout(refreshToken: string): Promise<void> {
        await tokenService.revokeRefreshToken(refreshToken);
    }

    async logoutAll(userId: number): Promise<void> {
        await tokenService.revokeAllUserTokens(userId);
    }
}




