import { prisma } from '../../common/lib/prisma';
import { ApiError } from '../../common/middleware/error-handler';

export class UserService {
    async getUserProfile(userId: number) {
        const user = await prisma.user.findUnique({
            where: { id: userId },
        });

        if (!user) {
            throw new ApiError(404, 'User not found');
        }

        const { password: _password, ...userWithoutPassword } = user;
        return { user: userWithoutPassword };
    }
}
