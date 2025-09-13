import { ConflictException, Injectable } from '@nestjs/common';
import * as bcrypt from 'bcrypt';

@Injectable()
export class UserService {
    private readonly users = [
        {
            userId: 1,
            username: 'john',
            password: bcrypt.hashSync('changeme', 10),
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

    async create(username: string, password: string) {
        const user = await this.findOne(username)
        if (user) throw new ConflictException('A user already exists with the given username')

        const hashedPassword = await bcrypt.hash(password, 10)
        const userId = this.getNewUserId()

        const newUser = {
            userId, username,
            password: hashedPassword
        }
        this.users.push(newUser)

        return { ...newUser, password: undefined }
    }


    private getNewUserId() {
        let userId = this.users.length
        while (this.users.some(u => u.userId === userId)) ++userId

        return userId
    }
}
