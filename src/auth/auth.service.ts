import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import * as argon from 'argon2'
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService, private jwt: JwtService, private config: ConfigService) { }
  async signup(dto: AuthDto) {
    // generar password hash
    const hash = await argon.hash(dto.password)
    // guardar usuario nuevo en db
    try {
      const user = await this.prisma.user.create({
        data: {
          email: dto.email,
          hash
        },
      })
      delete user.hash
      // retornar usuario nuevo
      return this.signToken(user.id, user.email)
    } catch (error) {
      if (error.code === 'P2002') {
        throw new ForbiddenException('Credentials taken')
      }
      throw error
    }
  }

 async signin(dto: AuthDto) {
    // encontrar usuario por email
    const user = await this.prisma.user.findUnique({
      where: {
        email: dto.email,
      }
    })
    // si usuario no existe tirar excepcion
    if (!user) throw new ForbiddenException('Credentials incorrect')
    // comparar contraseña
    const pwMatches = await argon.verify(user.hash, dto.password)
    // si no concuerdan tirar excepcion
    if(!pwMatches) throw new ForbiddenException('Credentials incorrect')

    return this.signToken(user.id, user.email)
  }

  async signToken(userId: Number, email: string) {
    const payload = {
      sub: userId,
      email
    }

    const secret = this.config.get('JWT_SECRET')

    const token = await this.jwt.signAsync(payload, {
      expiresIn: '15m',
      secret: secret
    })

    return {
      access_token: token
    }
  }
}
