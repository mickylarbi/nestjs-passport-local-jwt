import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UserService } from 'src/user/user.service';
import * as bcrypt from 'bcrypt';
import { AuthDto } from './dtos/auth.dto';

@Injectable()
export class AuthService {
    constructor(
        private readonly userService: UserService,
        private readonly jwtService: JwtService
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
        const payload = { username: user.username, sub: user.userId }
        return { access_token: this.jwtService.sign(payload) }
    }

    async register(data: AuthDto) {
        const { username, password } = data
        return await this.userService.create(username, password)
    }
}
