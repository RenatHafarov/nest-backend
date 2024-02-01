import { Controller, Delete, Get, Param, ParseUUIDPipe, Post, UseGuards } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { NftcategoryesService } from './nftcategoryes.service';
import { RolesGuard } from 'src/auth/guards/roles.guard';
import { CurrentUser, Roles } from '@common/common/decorators';
import { Role } from '@prisma/client';
import { CreateCategoryDto, EditCategoryDto } from './nftcategoryes.dto';
import { JwtPayLoad } from 'src/auth/interfaces';

@Controller('nftcategoryes')
export class NftcategoryesController {

    constructor(private categoryesService: NftcategoryesService,
        private prismaService: PrismaService) { }




    @Get()
    async findAll() {
        return this.prismaService.category.findMany()
    }
    
    @UseGuards(RolesGuard)
    @Roles(Role.ADMIN)
    @Post()
    async createCategory(dto: CreateCategoryDto, @CurrentUser() user: JwtPayLoad) {
        return this.categoryesService.createCategory(dto, user);
    }

    @UseGuards(RolesGuard)
    @Roles(Role.ADMIN)
    @Post(':id')
    async editCategory(@Param('id', ParseUUIDPipe) id: string, @CurrentUser() user: JwtPayLoad, dto: EditCategoryDto) {
        return this.categoryesService.editCateory(id, user, dto)
    }

    @UseGuards(RolesGuard)
    @Roles(Role.ADMIN)
    @Delete(':id')
    async deleteCategory(@Param('id', ParseUUIDPipe) id: string, @CurrentUser() user: JwtPayLoad) {
        return this.categoryesService.deleteCaregory(id, user);
    }

}
