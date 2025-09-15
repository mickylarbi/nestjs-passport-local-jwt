import { ConflictException, ForbiddenException, Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import * as bcrypt from 'bcrypt';
import { User } from './user.schema';
import { Model } from 'mongoose';


@Injectable()
export class UserService {
    constructor(@InjectModel(User.name) private userModel: Model<User>) { }


    async findOne(username: string) {
        return (await this.userModel.findOne({ username }).exec())?.toObject()
    }
    async findById(id: string) {
        return (await this.userModel.findById(id).exec())?.toObject()
    }

    async create(username: string, password: string) {
        const user = await this.findOne(username)
        if (user) throw new ConflictException('A user already exists with the given username')

        const hashedPassword = await bcrypt.hash(password, 10)

        const newUser = new this.userModel({
            username,
            password: hashedPassword
        })

        return { ...(await newUser.save()).toObject(), password: undefined, __v: undefined, refreshToken: undefined }
    }

    async updateRefreshToken(userId: string, refreshToken: string) {
        if (await this.userModel.exists({ _id: userId }).exec()) {
            await this.userModel.findByIdAndUpdate(userId, { refreshToken }).exec()
            return
        }
        throw new ForbiddenException('User does not exist')
    }

    async removeRefreshToken(userId: string) {
        if (await this.userModel.exists({ _id: userId }).exec()) {
            await this.userModel.findByIdAndUpdate(userId, { refreshToken: null }).exec()
            return
        }
        throw new ForbiddenException('User does not exist')
    }
}