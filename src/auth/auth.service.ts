import { Injectable } from '@nestjs/common';
import { AuthBody } from './auth.controller';
import { PrismaService } from 'src/prisma.service';
import { hash, compare } from 'bcrypt';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly jwtService: JwtService,
  ) {}
  async login({ authBody }: { authBody: AuthBody }) {
    const { email, password } = authBody;
    // const hashPassword = await this.hashPassword({ password });

    const userExist = await this.prisma.user.findUnique({
      where: { email: email },
    });

    if (!userExist) {
      throw new Error('Erreur utilisateur inconnu');
    }

    const isPasswordValid = await this.isPasswordValid({
      password,
      hashedPassword: userExist.password,
    });

    if (!isPasswordValid) {
      throw new Error('Erreur email ou mot de pass incorrect');
    }

    return await this.authenticateUser({ userId: userExist.id });
  }

  private async hashPassword({ password }: { password: string }) {
    const hashedPassword = await hash(password, 10);
    return hashedPassword;
  }

  private async isPasswordValid({
    password,
    hashedPassword,
  }: {
    password: string;
    hashedPassword: string;
  }) {
    const isPasswordValid = await compare(password, hashedPassword);
    return isPasswordValid;
  }

  private async authenticateUser({ userId }: { userId: string }) {
    const payload = { sub: userId };
    return {
      access_token: this.jwtService.sign(payload),
    };
  }
}
