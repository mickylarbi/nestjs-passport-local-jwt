import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { MongooseOptionsFactory, MongooseModuleOptions } from '@nestjs/mongoose';

@Injectable()
export class MongooseConfigService implements MongooseOptionsFactory {
    constructor(private configService: ConfigService) { }

    createMongooseOptions(): MongooseModuleOptions {
        return {
            uri: this.configService.get<string>('MONGO_URI'),
            retryAttempts: 5,
            retryDelay: 3000,
        };
    }
} 