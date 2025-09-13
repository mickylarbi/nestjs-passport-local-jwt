import { Injectable } from '@nestjs/common';
import * as bcrypt from 'bcrypt';

@Injectable()
export class UserService {
    private readonly users = [
        {
            userId: 1,
            username: 'john',
            password: bcrypt.hashSync('changeme', 10), // hash password
        },
        {
            userId: 2,
            username: 'maria',
            password: bcrypt.hashSync('guess', 10),
        },
    ];

    async findOne(username: string) {
        return this.users.find(u => u.username === username)
    }
}
