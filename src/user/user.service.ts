import { ConflictException, ForbiddenException, Injectable } from '@nestjs/common';
import * as bcrypt from 'bcrypt';


export type User = {
    userId: number
    username: string
    password: string
    refreshToken?: string
}

@Injectable()
export class UserService {
    private users: User[] = [];

    async findOne(username: string) {
        return this.users.find(u => u.username === username)
    }
    async findById(userId: number) {
        return this.users.find(u => u.userId === userId)
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

    async updateRefreshToken(userId: number, refreshToken: string) {
        if (this.users.some(u => userId === u.userId)) {
            this.users = this.users
                .map(u => userId === u.userId ? { ...u, refreshToken } : u)
            return
        }
        throw new ForbiddenException('User does not exist')
    }

    async removeRefreshToken(userId: number) {
        if (this.users.some(u => userId === u.userId)) {
            this.users = this.users
                .map(u => userId === u.userId ? { ...u, refreshToken: undefined } : u)
            return
        }
        throw new ForbiddenException('User does not exist')
    }


    // PRIVATE


    private getNewUserId() {
        let userId = this.users.length
        while (this.users.some(u => u.userId === userId)) ++userId

        return userId
    }
}
