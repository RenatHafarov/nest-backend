import { CurrentUser, Roles } from '@common/common/decorators';
import { Controller, Delete, Get, Param, ParseUUIDPipe, Post, Query, UseGuards } from '@nestjs/common';
import { Role } from '@prisma/client';
import { RolesGuard } from 'src/auth/guards/roles.guard';
import { NftService } from './nft.service';
import { JwtPayLoad } from 'src/auth/interfaces';
import { CreateNftDto, EditNftDto } from './nft.dto';
import { PrismaService } from 'src/prisma/prisma.service';

@Controller('nft')
export class NftController {
    stakingService: any;


    constructor(private nftService: NftService,
        private prismaService: PrismaService) { }




    @Get()
    async findAll() {
        return this.prismaService.nft.findMany();
    }

    @Get()
    async find(@Query() filters: { categoryes?: string; name?: string; price?: string; stacking?: number; }) {
        return this.nftService.find(filters);
    }


   

    @UseGuards(RolesGuard)
    @Roles(Role.ADMIN)
    @Post()
    async createNft(dto: CreateNftDto, @CurrentUser() user: JwtPayLoad) {
        return this.nftService.createNft(dto, user)
    }

    @UseGuards(RolesGuard)
    @Roles(Role.ADMIN)
    @Post(':id')
    async editNft(@Param('id', ParseUUIDPipe) id: string, @CurrentUser() user: JwtPayLoad, dto: EditNftDto) {
        return this.nftService.editNft(id, user, dto)
    }

    @UseGuards(RolesGuard)
    @Roles(Role.ADMIN)
    @Delete(':id')
    async deleteNft(@Param('id', ParseUUIDPipe) id: string, @CurrentUser() user: JwtPayLoad) {
        return this.nftService.deleteNft(id, user);
    }















}
