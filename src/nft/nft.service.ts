import { BadRequestException, ForbiddenException, Injectable } from '@nestjs/common';
import { Nft, Prisma, Role } from '@prisma/client';
import { JwtPayLoad } from 'src/auth/interfaces';
import { PrismaService } from 'src/prisma/prisma.service';
import { EditNftDto } from './nft.dto';

@Injectable()
export class NftService {


    constructor(private prismaService: PrismaService) { }




    async createNft(nft: Partial<Nft>, user: JwtPayLoad) {
        if (!user.roles.includes(Role.ADMIN)) {
            throw new ForbiddenException()
        }


        this.prismaService.category.create({
            data: {
                name: nft.categoryes,
                nftid: nft.nftId
            }
        })

        return this.prismaService.nft.create({
            data: {
                name: nft.name,
                categoryes: nft.categoryes,
                description: nft.description,
                stacking: nft.stacking

            }
        })



    }



    async find(filters: { categoryes?: string; name?: string; price?: string; stacking?: number; }) {
        return this.prismaService.nft.findMany({
            where: filters,
        });



    }


    async editNft(id: string, user: JwtPayLoad, dto: EditNftDto): Promise<Nft> {
        if (!user.roles.includes(Role.ADMIN)) {
            throw new ForbiddenException()
        }

        const nft = await this.prismaService.nft.findFirst({ where: { nftId: id } })
        if (!nft) { throw new BadRequestException() }


        return this.prismaService.nft.update({
            where: { nftId: id },
            data: dto,
        });

    }

    async deleteNft(nftid: string, user: JwtPayLoad) {
        if (!user.roles.includes(Role.ADMIN)) {
            throw new ForbiddenException()
        }


        return this.prismaService.nft.delete({ where: { nftId: nftid } });

    }







}
