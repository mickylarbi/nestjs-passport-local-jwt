import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtModuleOptions, JwtOptionsFactory } from '@nestjs/jwt';

@Injectable()
export class JwtConfigService implements JwtOptionsFactory {
    constructor(private configService: ConfigService) { }

    createJwtOptions(): Promise<JwtModuleOptions> | JwtModuleOptions {
        return {
            secret: this.configService.get<string>('ACCESS_TOKEN_SECRET'),
            signOptions: { expiresIn: '1h' },
        }
    }
} 