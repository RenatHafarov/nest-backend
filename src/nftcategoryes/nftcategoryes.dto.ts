import { IsNotEmpty, IsNumber, IsOptional, IsString, isString } from "class-validator";



export class CreateCategoryDto {
    @IsString()
    @IsNotEmpty()
    name: string;

    @IsString()
    @IsNotEmpty()
    nftid: string;

}

export class EditCategoryDto {

    @IsString()
    @IsOptional()
    name: string;

    @IsString()
    @IsOptional()
    nftid: string;



}