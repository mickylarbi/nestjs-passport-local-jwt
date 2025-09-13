import { ApiProperty } from "@nestjs/swagger"
import { Transform } from "class-transformer"
import { IsNotEmpty, isString, IsString } from "class-validator"

export class AuthDto {

    @ApiProperty()
    @Transform(({ value }) => isString(value) ? value.trim() : value)
    @IsString()
    @IsNotEmpty()
    username: string

    @ApiProperty()
    @IsString()
    @IsNotEmpty()
    password: string

}