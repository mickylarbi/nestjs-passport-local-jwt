import { Body, Controller, Post, Req, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { LocalAuthGuard } from './local-auth.guard';
import { AuthDto } from './dtos/auth.dto';
import { JwtAuthGuard } from './jwt-auth.guard';

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
        const user = await this.authService.register(body)
        return await this.authService.login(body)
    }

    @Post('refresh')
    async refresh(@Body() body: { refreshToken: string }) {
        return this.authService.refresh(body.refreshToken)
    }

    @UseGuards(JwtAuthGuard)
    @Post('logout')
    async logout(@Req() req) {
        return this.authService.logout(req.user.userId)
    }
}
