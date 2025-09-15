import { ForbiddenException, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UserService } from 'src/user/user.service';
import * as bcrypt from 'bcrypt';
import { AuthDto } from './dtos/auth.dto';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AuthService {
    constructor(
        private readonly userService: UserService,
        private readonly jwtService: JwtService,
        private readonly configService: ConfigService
    ) { }

    async validateUser(username: string, pass: string) {
        const user = await this.userService.findOne(username)
        if (user && await bcrypt.compare(pass, user.password)) {
            const { password, ...result } = user
            return result
        }
        return null;
    }

    async login(user) {
        const payload = { username: user.username, sub: user._id }

        const access_token = this.jwtService.sign(payload, {
            secret: this.configService.get<string>('ACCESS_TOKEN_SECRET'),
            expiresIn: '1h'
        })

        const refresh_token = this.jwtService.sign(payload, {
            secret: this.configService.get<string>('REFRESH_TOKEN_SECRET'),
            expiresIn: '7d'
        })

        await this.userService.updateRefreshToken(user._id, refresh_token)

        return {
            ...user,
            password: undefined, __v: undefined, refreshToken: undefined,
            access_token, refresh_token
        }
    }

    async register(data: AuthDto) {
        const { username, password } = data
        return await this.userService.create(username, password)
    }

    async refresh(refreshToken: string) {
        try {
            const payload = this.jwtService.verify(refreshToken, { secret: 'refresh-secret' })

            const user = await this.userService.findById(payload.sub)
            if (!user) throw new ForbiddenException('User does not exist')
            if (user.refreshToken !== refreshToken) throw new ForbiddenException('Invalid refresh token')

            const access_token = this.jwtService.sign(
                { sub: user._id, username: user.username },
                {
                    secret: this.configService.get<string>('ACCESS_TOKEN_SECRET'),
                    expiresIn: '1h'
                }
            )

            return { access_token }
        } catch (error) {
            throw new UnauthorizedException('Invalid refresh token')
        }
    }

    async logout(userId: string) {
        await this.userService.removeRefreshToken(userId)
    }
}
