import { BadRequestException, ForbiddenException, Injectable } from '@nestjs/common';
import { JwtPayLoad } from 'src/auth/interfaces';
import { CreateCategoryDto, EditCategoryDto } from './nftcategoryes.dto';
import { PrismaService } from 'src/prisma/prisma.service';
import { Role } from '@prisma/client';

@Injectable()
export class NftcategoryesService {
    constructor(private prismaService: PrismaService) { }



    async createCategory(dto: CreateCategoryDto, user: JwtPayLoad) {
        if (!user.roles.includes(Role.ADMIN)) {
            throw new ForbiddenException()
        }
        return this.prismaService.category.create({
            data: {
                name: dto.name,
                nftid: dto.nftid
            }
        })
    }

    async editCateory(id: string, user: JwtPayLoad, dto: EditCategoryDto) {
        if (!user.roles.includes(Role.ADMIN)) {
            throw new ForbiddenException()
        }

        const nft = await this.prismaService.category.findFirst({ where: { id: id } })
        if (!nft) { throw new BadRequestException() }


        return this.prismaService.category.update({
            where: { id: id },
            data: dto,
        });
    }





    async deleteCaregory(id: string, user: JwtPayLoad) {
        if (!user.roles.includes(Role.ADMIN)) {
            throw new ForbiddenException()
        }
        return this.prismaService.category.delete({ where: { id: id } })
    }
}
