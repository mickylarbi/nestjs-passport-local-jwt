import { Body, Controller, Post, Req, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { LocalAuthGuard } from './local-auth.guard';
import { AuthDto } from './dtos/auth.dto';

@Controller('auth')
export class AuthController {
    constructor(private readonly authService: AuthService) { }

    @UseGuards(LocalAuthGuard)
    @Post('login')
    async login(@Req() req) {
        return await this.authService.login(req.user)
    }

    @Post('signup')
    async signup(@Body() body: AuthDto) {
        await this.authService.register(body)
        return await this.authService.login(body)
    }
}
