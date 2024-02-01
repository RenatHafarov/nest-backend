import { IsInt, IsNotEmpty, IsNumber, IsOptional, IsString, isNumber, isString } from "class-validator";



export class CreateNftDto {

    @IsString()
    @IsNotEmpty()
    name: string;

    @IsString()
    @IsNotEmpty()
    price: string;

    @IsString()
    @IsNotEmpty()
    categoryes: string;

    @IsNumber()
    @IsNotEmpty()
    stacking: number;

    @IsString()
    @IsNotEmpty()
    descripton: string;

}

export class EditNftDto {

    @IsString()
    @IsOptional()
    price: string;

    @IsInt()
    @IsOptional()
    stacking: number;

    @IsString()
    @IsNotEmpty()
    categoryes: string;

    @IsString()
    @IsOptional()
    description: string;




}