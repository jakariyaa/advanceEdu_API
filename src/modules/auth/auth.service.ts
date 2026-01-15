import { prisma } from '../../common/lib/prisma';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { ApiError } from '../../common/middleware/error-handler';
import { z } from 'zod';
import { registerSchema, loginSchema } from './auth.schema';

type RegisterInput = z.infer<typeof registerSchema>['body'];
type LoginInput = z.infer<typeof loginSchema>['body'];

export class AuthService {
    async register(data: RegisterInput) {
        const existingUser = await prisma.user.findUnique({
            where: { email: data.email },
        });

        if (existingUser) {
            throw new ApiError(409, 'User already exists');
        }

        const hashedPassword = await bcrypt.hash(data.password, 10);

        const user = await prisma.user.create({
            data: {
                email: data.email,
                password: hashedPassword,
                name: data.name ?? null,
            },
        });

        const { password: _password, ...userWithoutPassword } = user;
        return { user: userWithoutPassword };
    }

    async login(data: LoginInput) {
        const user = await prisma.user.findUnique({
            where: { email: data.email },
        });

        if (!user) {
            throw new ApiError(401, 'Invalid email or password');
        }

        const isPasswordValid = await bcrypt.compare(data.password, user.password);

        if (!isPasswordValid) {
            throw new ApiError(401, 'Invalid email or password');
        }

        const jwtSecret = process.env['JWT_SECRET'];
        if (!jwtSecret) {
            throw new ApiError(500, 'JWT secret not configured');
        }

        const expiresIn = (process.env['JWT_EXPIRES_IN'] || '1d') as import('ms').StringValue;
        const token = jwt.sign(
            { userId: user.id, email: user.email },
            jwtSecret,
            { expiresIn }
        );

        const { password: _password, ...userWithoutPassword } = user;
        return { user: userWithoutPassword, token };
    }
}
