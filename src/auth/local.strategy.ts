import { BadRequestException, Injectable, UnauthorizedException } from "@nestjs/common";
import { PassportStrategy } from "@nestjs/passport";
import { Strategy } from "passport-local";
import { AuthService } from "./auth.service";
import { AuthDto } from "./dtos/auth.dto";
import { validate } from "class-validator";

@Injectable()
export class LocalStrategy extends PassportStrategy(Strategy) {
    constructor(private readonly authService: AuthService) {
        super()
    }

    async validate(...body: string[]) {
        const [username, password] = body

        const data: AuthDto = new AuthDto()
        data.username = username
        data.password = password

        const error = await validate(data, { whitelist: true })
        if (error.length) throw new BadRequestException(error.map(e => e.constraints))

        const user = await this.authService.validateUser(username, password)
        if (user) return user

        throw new UnauthorizedException()
    }
}